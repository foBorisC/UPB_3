import os
from datetime import datetime, timedelta, UTC

from flask import Flask, render_template, redirect, url_for, request
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, EqualTo
from flask_login import login_required, LoginManager, UserMixin, login_user, logout_user, current_user
from flask_sqlalchemy import SQLAlchemy

from SafePasswords import PasswordManager
from utility_methods import *

app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///data.db'
app.config['SECRET_KEY'] = 'upb'

db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)
pm = PasswordManager()
login_manager.login_view = 'login'

'''
    Tabulka pre pouzivatelov:
    - id: jedinecne id pouzivatela
    - username: meno pouzivatela

    TODO: tabulku je treba doimplementovat
'''


class User(db.Model, UserMixin):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(512), unique=True, nullable=False)
    password = db.Column(db.String(512), unique=False, nullable=False)

    # brute force
    failed_attempts = db.Column(db.Integer, default=0)
    locked_until = db.Column(db.DateTime, nullable=True)

    def __repr__(self):
        return f'<User {self.username}>'


class LoginIpWindow(db.Model):
    __tablename__ = 'login_ip_window'
    id = db.Column(db.Integer, primary_key=True)
    ip = db.Column(db.String(45), index=True, nullable=False)
    window_start = db.Column(db.DateTime, nullable=False, index=True)
    attempts = db.Column(db.Integer, default=0, nullable=False)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


with app.app_context():
    db.create_all()

    '''test_user = User(username='test', password='test')
    db.session.add(test_user)
    db.session.commit()
'''


class LoginForm(FlaskForm):
    username = StringField('Username', validators=[InputRequired()])
    password = PasswordField('Password', validators=[InputRequired()])
    submit = SubmitField('Login')


class RegisterForm(FlaskForm):
    username = StringField('Username', validators=[InputRequired()])
    password = PasswordField('Password', validators=[InputRequired()])
    confirm_password = PasswordField('Confirm Password',
                                     validators=[InputRequired(), EqualTo('password', message='Passwords must match')])
    submit = SubmitField('Register')


MAX_IP_ATTEMPTS = 10
IP_WINDOW_SECONDS = 60

MAX_USER_ATTEMPTS = 5
USER_LOCK_MINUTES = 15

BAD_PASSWORDS: set = set()

def client_ip():
    return request.headers.get("X-Forwarded-For", request.remote_addr) or "unknown"


def is_ip_rate_limited(ip: str) -> bool:
    now = datetime.now(UTC)
    win = LoginIpWindow.query.filter_by(ip=ip).order_by(LoginIpWindow.window_start.desc()).first()
    if win:
        ws = win.window_start
        if ws.tzinfo is None:
            ws = ws.replace(tzinfo=UTC)
    if not win or (now - (ws if win else now)).total_seconds() > IP_WINDOW_SECONDS:
        win = LoginIpWindow(ip=ip, window_start=now, attempts=0)
        db.session.add(win)
        db.session.commit()
    return win.attempts >= MAX_IP_ATTEMPTS


def bump_ip_attempt(ip: str):
    now = datetime.now(UTC)
    win = LoginIpWindow.query.filter_by(ip=ip).order_by(LoginIpWindow.window_start.desc()).first()

    if not win or (now - (win.window_start.replace(
            tzinfo=UTC) if win and win.window_start.tzinfo is None else win.window_start)).total_seconds() > IP_WINDOW_SECONDS:
        win = LoginIpWindow(ip=ip, window_start=now, attempts=0)
        db.session.add(win)
    win.attempts = (win.attempts or 0) + 1
    db.session.commit()


def load_bad_passwords(filepath: str):
    global BAD_PASSWORDS
    BAD_PASSWORDS.clear()
    if not os.path.exists(filepath):
        print(f"Dictionary does not exist: {filepath}")
        return
    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            word = line.strip()
            if not word:
                continue
            BAD_PASSWORDS.add(word.lower())
    print(f"Loaded {len(BAD_PASSWORDS)} bad passwords.")


@app.route('/')
@login_required
def home():
    return render_template('home.html', username=current_user.username)


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()

    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data

        # IP rate-limit
        ip = client_ip()
        if is_ip_rate_limited(ip):
            print("Too many attempts from this IP. Try later.")
            return render_template('login.html', form=form), 429  # ⬅️ Too Many Requests

        user = User.query.filter_by(username=username).first()

        now = datetime.now(UTC)
        if user and user.locked_until:
            lu = user.locked_until.replace(tzinfo=UTC) if user.locked_until.tzinfo is None else user.locked_until
            if lu > now:
                print("Account temporarily locked.")
                bump_ip_attempt(ip)
                return render_template('login.html', form=form), 423  # ⬅️ Locked

        if user and pm.verify_password(password, user.password):
            user.failed_attempts = 0
            user.locked_until = None
            db.session.commit()
            login_user(user)
            print('Verify prebehlo uspesne')
            return redirect(url_for('home'))

        bump_ip_attempt(ip)
        if user:
            user.failed_attempts = (user.failed_attempts or 0) + 1
            if user.failed_attempts >= MAX_USER_ATTEMPTS:
                user.locked_until = datetime.now(UTC) + timedelta(minutes=USER_LOCK_MINUTES)
                user.failed_attempts = 0
            db.session.commit()

        return render_template('login.html', form=form), 401  # ⬅️ Unauthorized

    return render_template('login.html', form=form)


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()

    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data

        try:
            check_password(password, BAD_PASSWORDS, username)

        except InvalidPasswordError as e:
            print("Custom error caught:", e)
            return render_template('register.html', form=form)
        except Exception as e:
            print("General error caught:", e)
            return render_template('register.html', form=form)

        else:
            print("Password is valid.")

            if User.query.filter_by(username=username).first():
                print("Username already exists.")
                return render_template('register.html', form=form)

            hashed = pm.hash_password(password)
            new_user = User(username=username, password=hashed)

            db.session.add(new_user)
            db.session.commit()

            return redirect(url_for('login'))
        finally:
            print("Password validation attempted.")
    return render_template('register.html', form=form)


@login_required
@app.route('/logout', methods=['POST'])
def logout():
    logout_user()
    return redirect(url_for('login'))


if __name__ == '__main__':
    load_bad_passwords('common_passwords.txt')
    app.run(port=1337)
