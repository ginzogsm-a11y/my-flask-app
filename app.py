
import os
from flask import Flask, render_template, url_for, flash, redirect, request, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, BooleanField
from wtforms.validators import DataRequired, Length, Email, EqualTo, ValidationError
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv
from datetime import datetime
import user_agents
import pymysql
from itsdangerous import URLSafeTimedSerializer

# تحميل المتغيرات من .env
load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'your-secret-key')

# إعداد قاعدة البيانات
db_uri = f"mysql+pymysql://{os.getenv('DB_USER')}:{os.getenv('DB_PASSWORD')}@{os.getenv('DB_HOST')}/{os.getenv('DB_NAME')}?charset=utf8mb4"
app.config['SQLALCHEMY_DATABASE_URI'] = db_uri
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'

# الموديلات
class UserDevice(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    device_info = db.Column(db.String(200), nullable=False)
    ip_address = db.Column(db.String(50))
    last_login = db.Column(db.DateTime, default=datetime.utcnow)
    user_agent = db.Column(db.Text)

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    phone = db.Column(db.String(20), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    is_active = db.Column(db.Boolean, default=False)
    is_admin = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    devices = db.relationship('UserDevice', backref='user', lazy=True, cascade='all, delete-orphan')

    def __repr__(self):
        return f"User('{self.username}', '{self.email}')"

    def get_reset_token(self, expires_sec=1800):
        s = URLSafeTimedSerializer(app.config['SECRET_KEY'])
        return s.dumps({'user_id': self.id})

    @staticmethod
    def verify_reset_token(token):
        s = URLSafeTimedSerializer(app.config['SECRET_KEY'])
        try:
            user_id = s.loads(token, max_age=1800)['user_id']
        except Exception:
            return None
        return User.query.get(user_id)

# الفورمز
class RegistrationForm(FlaskForm):
    username = StringField('اسم المستخدم', validators=[DataRequired(), Length(min=2, max=20)])
    email = StringField('البريد الإلكتروني', validators=[DataRequired(), Email()])
    phone = StringField('رقم الهاتف', validators=[DataRequired(), Length(min=10, max=20)])
    password = PasswordField('كلمة المرور', validators=[DataRequired()])
    confirm_password = PasswordField('تأكيد كلمة المرور', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('تسجيل')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('اسم المستخدم مستخدم مسبقاً.')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError('البريد مستخدم مسبقاً.')

    def validate_phone(self, phone):
        user = User.query.filter_by(phone=phone.data).first()
        if user:
            raise ValidationError('رقم الهاتف مستخدم مسبقاً.')

class LoginForm(FlaskForm):
    login = StringField('اسم المستخدم أو البريد الإلكتروني', validators=[DataRequired()])
    password = PasswordField('كلمة المرور', validators=[DataRequired()])
    remember = BooleanField('تذكرني')
    submit = SubmitField('تسجيل الدخول')

class RequestResetForm(FlaskForm):
    email = StringField('البريد الإلكتروني', validators=[DataRequired(), Email()])
    submit = SubmitField('طلب إعادة تعيين كلمة المرور')

class ResetPasswordForm(FlaskForm):
    password = PasswordField('كلمة المرور الجديدة', validators=[DataRequired()])
    confirm_password = PasswordField('تأكيد كلمة المرور', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('إعادة تعيين كلمة المرور')

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# دوال مساعدة
def get_client_info():
    ip_address = request.headers.get('X-Forwarded-For', request.remote_addr)
    user_agent = request.user_agent.string
    device_info = str(user_agents.parse(user_agent))
    return ip_address, user_agent, device_info

# الروتات
@app.route("/")
def home():
    if current_user.is_authenticated:
        return redirect(url_for('account'))
    return redirect(url_for('login'))

@app.route("/register", methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_pw = generate_password_hash(form.password.data)
        user = User(username=form.username.data, email=form.email.data, phone=form.phone.data, password=hashed_pw)
        db.session.add(user)
        db.session.commit()
        flash('تم إنشاء الحساب بنجاح! بانتظار التفعيل.', 'info')
        return redirect(url_for('login'))
    return render_template("register.html", form=form)

@app.route("/login", methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter((User.email==form.login.data) | (User.username==form.login.data)).first()
        if user and check_password_hash(user.password, form.password.data):
            if not user.is_active:
                flash('الحساب غير مفعل بعد.', 'warning')
                return redirect(url_for('login'))
            login_user(user, remember=form.remember.data)
            flash('تم تسجيل الدخول بنجاح!', 'success')
            return redirect(url_for('account'))
        else:
            flash('بيانات الدخول غير صحيحة.', 'danger')
    return render_template("login.html", form=form)

@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))

@app.route("/account")
@login_required
def account():
    return render_template("account.html")

@app.route("/admin")
@login_required
def admin():
    if not current_user.is_admin:
        flash('غير مصرح لك بالدخول.', 'danger')
        return redirect(url_for('home'))
    users = User.query.all()
    return render_template("admin.html", users=users)

@app.route("/admin/activate/<int:user_id>", methods=['POST'])
@login_required
def activate_user(user_id):
    if not current_user.is_admin:
        return redirect(url_for('home'))
    user = User.query.get_or_404(user_id)
    user.is_active = True
    db.session.commit()
    flash(f"تم تفعيل {user.username}", 'success')
    return redirect(url_for('admin'))

@app.route("/reset_password", methods=['GET', 'POST'])
def reset_request():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = RequestResetForm()
    if form.validate_on_submit():
        flash('تم إرسال رابط إعادة التعيين (وهمي).', 'info')
        return redirect(url_for('login'))
    return render_template("reset_request.html", form=form)

@app.route("/reset_password/<token>", methods=['GET', 'POST'])
def reset_token(token):
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    user = User.verify_reset_token(token)
    if not user:
        flash('الرابط غير صالح.', 'warning')
        return redirect(url_for('reset_request'))
    form = ResetPasswordForm()
    if form.validate_on_submit():
        hashed_pw = generate_password_hash(form.password.data)
        user.password = hashed_pw
        db.session.commit()
        flash('تم تغيير كلمة المرور بنجاح!', 'success')
        return redirect(url_for('login'))
    return render_template("reset_token.html", form=form)

def create_tables():
    with app.app_context():
        db.create_all()

if __name__ == "__main__":
    create_tables()
    app.run(debug=True)
