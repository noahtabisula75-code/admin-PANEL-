import os
import secrets
from datetime import datetime, timedelta
from functools import wraps

from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

# Hardcoded secret key (change in production)
app.config['SECRET_KEY'] = 'my-ultra-secure-fixed-key-2024-change-this'

# Database configuration
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

    def get_id(self):
        return f"admin_{self.id}"


class Reseller(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    full_name = db.Column(db.String(120), nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    balance_days = db.Column(db.Integer, default=0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # Relationship
    keys = db.relationship('LicenseKey', backref='reseller', lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def get_id(self):
        return f"reseller_{self.id}"


class ReferralCode(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    code = db.Column(db.String(32), unique=True, nullable=False)
    balance_days = db.Column(db.Integer, nullable=False)
    is_used = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    used_by_reseller_id = db.Column(db.Integer, db.ForeignKey('reseller.id'), nullable=True)


class LicenseKey(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(64), unique=True, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime, nullable=True)
    is_active = db.Column(db.Boolean, default=True)
    notes = db.Column(db.String(200), nullable=True)

    # Who created it? (admin or reseller)
    created_by_admin_id = db.Column(db.Integer, db.ForeignKey('admin.id'), nullable=True)
    created_by_reseller_id = db.Column(db.Integer, db.ForeignKey('reseller.id'), nullable=True)

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
    if user_id.startswith("admin_"):
        return Admin.query.get(int(user_id[6:]))
    elif user_id.startswith("reseller_"):
        return Reseller.query.get(int(user_id[9:]))
    return None


# ==================== HELPERS ====================

def generate_key():
    return secrets.token_hex(16).upper()

def generate_referral_code():
    return secrets.token_hex(4).upper()  # 8 characters


def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not isinstance(current_user, Admin):
            flash('Admin access required.', 'danger')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function


def reseller_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not isinstance(current_user, Reseller):
            flash('Reseller access required.', 'danger')
            return redirect(url_for('reseller_login'))
        return f(*args, **kwargs)
    return decorated_function


# ==================== DATABASE INIT ====================

@app.before_request
def ensure_database():
    db.create_all()
    if not Admin.query.first():
        admin = Admin(username='admin')
        admin.set_password('admin123')
        db.session.add(admin)
        db.session.commit()
        print("✅ Default admin created.")


# ==================== ADMIN ROUTES ====================

@app.route('/')
def index():
    return redirect(url_for('dashboard'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        if isinstance(current_user, Admin):
            return redirect(url_for('dashboard'))
        else:
            return redirect(url_for('reseller_dashboard'))
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        admin = Admin.query.filter_by(username=username).first()
        if admin and admin.check_password(password):
            login_user(admin)
            flash('Logged in successfully!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid admin credentials', 'danger')
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
    keys = LicenseKey.query.filter_by(created_by_admin_id=current_user.id).order_by(LicenseKey.created_at.desc()).all()
    resellers = Reseller.query.all()
    referral_codes = ReferralCode.query.order_by(ReferralCode.created_at.desc()).all()
    return render_template('dashboard.html', keys=keys, resellers=resellers, referral_codes=referral_codes, now=datetime.utcnow())


@app.route('/create', methods=['GET', 'POST'])
@admin_required
def create_key():
    if request.method == 'POST':
        expires_days = request.form.get('expires_days')
        notes = request.form.get('notes', '')

        key = generate_key()
        new_key = LicenseKey(key=key, notes=notes, created_by_admin_id=current_user.id)

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


@app.route('/generate-referral', methods=['POST'])
@admin_required
def generate_referral():
    balance = request.form.get('balance', type=int)
    if not balance or balance <= 0:
        flash('Invalid balance amount.', 'danger')
        return redirect(url_for('dashboard'))

    code = generate_referral_code()
    while ReferralCode.query.filter_by(code=code).first():
        code = generate_referral_code()

    referral = ReferralCode(code=code, balance_days=balance)
    db.session.add(referral)
    db.session.commit()
    flash(f'Referral code generated: {code} (Balance: {balance} days)', 'success')
    return redirect(url_for('dashboard'))


# ==================== RESELLER ROUTES ====================

@app.route('/reseller/register', methods=['GET', 'POST'])
def reseller_register():
    if current_user.is_authenticated:
        return redirect(url_for('reseller_dashboard'))
    if request.method == 'POST':
        username = request.form.get('username')
        full_name = request.form.get('full_name')
        password = request.form.get('password')
        password_confirm = request.form.get('password_confirm')
        referral_code = request.form.get('referral_code')

        if password != password_confirm:
            flash('Passwords do not match.', 'danger')
            return render_template('reseller_register.html')

        existing = Reseller.query.filter_by(username=username).first()
        if existing:
            flash('Username already taken.', 'danger')
            return render_template('reseller_register.html')

        # Validate referral code
        ref = ReferralCode.query.filter_by(code=referral_code, is_used=False).first()
        if not ref:
            flash('Invalid or already used referral code.', 'danger')
            return render_template('reseller_register.html')

        reseller = Reseller(username=username, full_name=full_name, balance_days=ref.balance_days)
        reseller.set_password(password)

        ref.is_used = True
        ref.used_by_reseller_id = reseller.id

        db.session.add(reseller)
        db.session.commit()
        flash('Registration successful! You can now log in.', 'success')
        return redirect(url_for('reseller_login'))

    return render_template('reseller_register.html')


@app.route('/reseller/login', methods=['GET', 'POST'])
def reseller_login():
    if current_user.is_authenticated:
        if isinstance(current_user, Reseller):
            return redirect(url_for('reseller_dashboard'))
        else:
            return redirect(url_for('dashboard'))
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        reseller = Reseller.query.filter_by(username=username).first()
        if reseller and reseller.check_password(password):
            login_user(reseller)
            flash('Logged in successfully!', 'success')
            return redirect(url_for('reseller_dashboard'))
        else:
            flash('Invalid username or password', 'danger')
    return render_template('reseller_login.html')


@app.route('/reseller/dashboard')
@reseller_required
def reseller_dashboard():
    keys = LicenseKey.query.filter_by(created_by_reseller_id=current_user.id).order_by(LicenseKey.created_at.desc()).all()
    return render_template('reseller_dashboard.html', keys=keys, now=datetime.utcnow())


@app.route('/reseller/create', methods=['GET', 'POST'])
@reseller_required
def reseller_create_key():
    if request.method == 'POST':
        expires_days = request.form.get('expires_days', type=int)
        notes = request.form.get('notes', '')

        if not expires_days or expires_days <= 0:
            flash('Please enter valid expiration days.', 'danger')
            return redirect(url_for('reseller_create_key'))

        if current_user.balance_days < expires_days:
            flash(f'Insufficient balance. You have {current_user.balance_days} days left.', 'danger')
            return redirect(url_for('reseller_create_key'))

        key = generate_key()
        new_key = LicenseKey(
            key=key,
            notes=notes,
            expires_at=datetime.utcnow() + timedelta(days=expires_days),
            created_by_reseller_id=current_user.id
        )

        current_user.balance_days -= expires_days
        db.session.add(new_key)
        db.session.commit()
        flash(f'Key created successfully: {key} (Used {expires_days} days)', 'success')
        return redirect(url_for('reseller_dashboard'))

    return render_template('reseller_create_key.html')


@app.route('/reseller/revoke/<int:key_id>')
@reseller_required
def reseller_revoke_key(key_id):
    key = LicenseKey.query.get_or_404(key_id)
    if key.created_by_reseller_id != current_user.id:
        flash('Unauthorized.', 'danger')
        return redirect(url_for('reseller_dashboard'))
    key.is_active = False
    db.session.commit()
    flash(f'Key {key.key} has been revoked.', 'warning')
    return redirect(url_for('reseller_dashboard'))


@app.route('/reseller/activate/<int:key_id>')
@reseller_required
def reseller_activate_key(key_id):
    key = LicenseKey.query.get_or_404(key_id)
    if key.created_by_reseller_id != current_user.id:
        flash('Unauthorized.', 'danger')
        return redirect(url_for('reseller_dashboard'))
    key.is_active = True
    db.session.commit()
    flash(f'Key {key.key} has been activated.', 'success')
    return redirect(url_for('reseller_dashboard'))


# ==================== API ENDPOINT ====================

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


# ==================== RUN ====================

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)
