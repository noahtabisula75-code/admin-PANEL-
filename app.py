import os
import secrets
from datetime import datetime, timedelta
from functools import wraps

from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

# Configuration
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', secrets.token_hex(32))

# Use DATABASE_URL from environment (Render provides PostgreSQL), fallback to SQLite
database_url = os.environ.get('DATABASE_URL', 'sqlite:///keys.db')
if database_url.startswith("postgres://"):
    database_url = database_url.replace("postgres://", "postgresql://", 1)
app.config['SQLALCHEMY_DATABASE_URI'] = database_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


# ==================== MODELS ====================

class Admin(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


class LicenseKey(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(64), unique=True, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime, nullable=True)
    is_active = db.Column(db.Boolean, default=True)
    notes = db.Column(db.String(200), nullable=True)

    def is_expired(self):
        if self.expires_at is None:
            return False
        return datetime.utcnow() > self.expires_at

    def status(self):
        if not self.is_active:
            return "Revoked"
        if self.is_expired():
            return "Expired"
        return "Active"


@login_manager.user_loader
def load_user(user_id):
    return Admin.query.get(int(user_id))


# ==================== HELPERS ====================

def generate_key():
    """Generate a random license key."""
    return secrets.token_hex(16).upper()  # 32 characters


def admin_required(f):
    """Ensure user is logged in as admin."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function


# ==================== ROUTES ====================

@app.route('/')
def index():
    return redirect(url_for('dashboard'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        admin = Admin.query.filter_by(username=username).first()
        if admin and admin.check_password(password):
            login_user(admin)
            flash('Logged in successfully!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password', 'danger')
    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))


@app.route('/dashboard')
@admin_required
def dashboard():
    keys = LicenseKey.query.order_by(LicenseKey.created_at.desc()).all()
    return render_template('dashboard.html', keys=keys, now=datetime.utcnow())


@app.route('/create', methods=['GET', 'POST'])
@admin_required
def create_key():
    if request.method == 'POST':
        expires_days = request.form.get('expires_days')
        notes = request.form.get('notes', '')

        key = generate_key()
        new_key = LicenseKey(key=key, notes=notes)

        if expires_days and expires_days.strip():
            try:
                days = int(expires_days)
                new_key.expires_at = datetime.utcnow() + timedelta(days=days)
            except ValueError:
                flash('Invalid expiration days, key created without expiration.', 'warning')

        db.session.add(new_key)
        db.session.commit()
        flash(f'Key created successfully: {key}', 'success')
        return redirect(url_for('dashboard'))

    return render_template('create_key.html')


@app.route('/revoke/<int:key_id>')
@admin_required
def revoke_key(key_id):
    key = LicenseKey.query.get_or_404(key_id)
    key.is_active = False
    db.session.commit()
    flash(f'Key {key.key} has been revoked.', 'warning')
    return redirect(url_for('dashboard'))


@app.route('/activate/<int:key_id>')
@admin_required
def activate_key(key_id):
    key = LicenseKey.query.get_or_404(key_id)
    key.is_active = True
    db.session.commit()
    flash(f'Key {key.key} has been activated.', 'success')
    return redirect(url_for('dashboard'))


@app.route('/delete/<int:key_id>')
@admin_required
def delete_key(key_id):
    key = LicenseKey.query.get_or_404(key_id)
    db.session.delete(key)
    db.session.commit()
    flash(f'Key {key.key} has been deleted permanently.', 'danger')
    return redirect(url_for('dashboard'))


# Optional API endpoint for external validation (e.g., from your checker)
@app.route('/api/validate_key', methods=['POST'])
def validate_key():
    data = request.get_json()
    if not data:
        return {'valid': False, 'message': 'Invalid request'}, 400

    key = data.get('key')
    if not key:
        return {'valid': False, 'message': 'Key required'}, 400

    license_key = LicenseKey.query.filter_by(key=key).first()
    if license_key and license_key.is_active and not license_key.is_expired():
        return {
            'valid': True,
            'expires': license_key.expires_at.isoformat() if license_key.expires_at else None,
            'notes': license_key.notes
        }
    return {'valid': False, 'message': 'Invalid or expired key'}, 403


# ==================== INIT DB ====================

def init_db():
    db.create_all()
    # Create default admin if none exists
    if not Admin.query.first():
        admin = Admin(username='admin')
        admin.set_password('admin123')  # CHANGE THIS PASSWORD!
        db.session.add(admin)
        db.session.commit()
        print("Default admin created: username='admin', password='admin123'")


# ==================== RUN ====================

if __name__ == '__main__':
    with app.app_context():
        init_db()
    # For local development only; Render uses gunicorn
    app.run(debug=False, host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))