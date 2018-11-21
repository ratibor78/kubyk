import os
from app import db
from app import app
from functools import wraps
from flask_wtf import FlaskForm
from wtforms.validators import (InputRequired, Length, DataRequired)
from wtforms import (StringField, PasswordField, SelectField)
from werkzeug.security import generate_password_hash, check_password_hash
from flask import (render_template, url_for, request, redirect)
from flask_login import (
    LoginManager, UserMixin, login_user,
    login_required, logout_user, current_user
)


pwd = os.path.abspath(os.path.dirname(os.path.realpath(__file__)))

app.config['SECRET_KEY'] = 'Thisissupposedtobesecret!'
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(15), unique=True)
    password = db.Column(db.String(80))
    level = db.Column(db.String(5))

    def set_password(self, password):
        self.password = generate_password_hash(password, method='sha256')


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


def requires_admin_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        role = current_user.level
        if not role or role != 'admin':
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated


class LoginForm(FlaskForm):
    username = StringField('username', validators=[InputRequired(), Length(min=2, max=35)]) # NOQA
    password = PasswordField('password', validators=[InputRequired(), Length(min=1, max=80)]) # NOQA


class CreateForm(FlaskForm):
    username = StringField('Username', validators=[InputRequired(), Length(min=2, max=35)]) # NOQA
    password = PasswordField('Password', validators=[InputRequired(), Length(min=1, max=80)]) # NOQA
    level = SelectField('Access Level', validators=[DataRequired()], choices=[("", ""), ("admin", "admin"), ("user", "user")]) # NOQA


class ChangeForm(FlaskForm):
    password = PasswordField('password') # NOQA
    level = SelectField('Access Level', validators=[DataRequired()], choices=[("admin", "admin"), ("user", "user")]) # NOQA


@app.route('/users')
@login_required
@requires_admin_auth
def users():
    users = User.query.all()
    return render_template('users.html', users=users, user=current_user.username, role=current_user.level) # NOQA


@app.route('/userdel/<user>', methods=['GET', 'POST'])
@login_required
@requires_admin_auth
def userdel(user):
    form = LoginForm()
    if request.method == 'POST':
        User.query.filter_by(username=user).delete()
        db.session.commit()
        return redirect(url_for('users'))
    return render_template('delete.html', user=user, form=form) # NOQA


@app.route('/')
@app.route('/login', methods=['GET', 'POST'])
def login():
    error = ''
    form = LoginForm()
    if form.validate_on_submit():
        print(form.username.data)
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if check_password_hash(user.password, form.password.data):
                login_user(user)
                return redirect(url_for('index'))
        error = 'Invalid Username or Password !'
        return render_template('login.html', form=form, error=error) # NOQA
    else:
        if request.method == 'POST':
            error = 'Empty or not valid input'
        return render_template('login.html', form=form, error=error)
    return render_template('login.html', form=form, error=error)


@app.route('/create', methods=['GET', 'POST'])
@login_required
@requires_admin_auth
def create():
    error = ''
    form = CreateForm()
    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data, method='sha256') # NOQA
        new_user = User(username=form.username.data, password=hashed_password, level=form.level.data) # NOQA
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('users'))
    else:
        if request.method == 'POST':
            error = 'Empty or not valid input'
        return render_template('create.html', form=form, error=error)
    return render_template('create.html', form=form)


@app.route('/changeuser/<username>', methods=['GET', 'POST'])
@login_required
@requires_admin_auth
def changeuser(username):
    error = ''
    getlevel = User.query.filter_by(username=username).first_or_404()
    level = getlevel.level
    form = ChangeForm(level=level)
    if form.validate_on_submit():
        user = User.query.filter_by(username=username).first_or_404()
        if form.password.data != '':
            user.set_password(form.password.data)
        user.level = form.level.data
        db.session.add(user)
        db.session.commit()
        return redirect(url_for('users'))
    else:
        if request.method == 'POST':
            error = 'Empty or not valid input'
        return render_template('changeuser.html', username=username, form=form, error=error) # NOQA
    return render_template('changeuser.html', username=username, form=form) # NOQA


@app.route('/index')
@login_required
def index():
    return render_template('index.html', user=current_user.username, role=current_user.level) # NOQA


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))
