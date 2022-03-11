from os import access
from flask import Flask, render_template, flash, redirect, url_for, request
from flask_wtf import FlaskForm
from wtforms import StringField, IntegerField, PasswordField, BooleanField, SubmitField, RadioField
from wtforms.validators import ValidationError, DataRequired, Email, EqualTo
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.urls import url_parse
from flask_login import LoginManager, UserMixin, current_user, login_user, logout_user, login_required
from functools import wraps

app = Flask(__name__)
login = LoginManager(app)
login.login_view = 'login'
login.login_message_category = 'danger'  # sets flash category for the default message 'Please log in to access this page.'

app.config.from_pyfile('config.py')
db = SQLAlchemy(app)

##################   Forms    #############################
class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember_me = BooleanField('Remember Me')
    submit = SubmitField('Sign In')


class RegistrationForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired()])
    username = StringField('Username', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm = PasswordField('Repeat Password', validators=[DataRequired(), EqualTo('password')])
    access = RadioField('I AM:', coerce=int, choices=[(1, "manager"), (0, "user")])
    submit = SubmitField('Register')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user is not None:
            raise ValidationError('Please use a different username.')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user is not None:
            raise ValidationError('Please use a different email address.')



class NewUserForm(FlaskForm):
    name = StringField('Name: ', validators=[DataRequired()])
    username = StringField('Username: ', validators=[DataRequired()])
    email = StringField('Email: ', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm = PasswordField('Repeat Password', validators=[DataRequired(), EqualTo('password')])
    access = IntegerField('Access: ')
    manager = IntegerField('Manager: ')

    submit = SubmitField('Create User')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user is not None:
            raise ValidationError('Please use a different username.')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user is not None:
            raise ValidationError('Please use a different email address.')


class UserDetailForm(FlaskForm):
    id = IntegerField('Id: ')
    name = StringField('Name: ', validators=[DataRequired()])
    username = StringField('Username: ', validators=[DataRequired()])
    email = StringField('Email: ', validators=[DataRequired(), Email()])
    access = IntegerField('Access: ')
    manager = IntegerField('Manager: ')


class AccountDetailForm(FlaskForm):
    id = IntegerField('Id: ')
    name = StringField('Name: ', validators=[DataRequired()])
    username = StringField('Username: ', validators=[DataRequired()])
    email = StringField('Email: ', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm = PasswordField('Repeat Password', validators=[DataRequired(), EqualTo('password')])
    manager = IntegerField('Manager: ')


ACCESS = {
    'user': 0,
    'manager': 1,
    'admin': 2
}


class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer(), primary_key=True)
    name = db.Column(db.String(100))
    email = db.Column(db.String(100))
    username = db.Column(db.String(30))
    password_hash = db.Column(db.String(128))
    access = db.Column(db.Integer())
    manager = db.Column(db.Integer())

    def __init__(self, name="", email="", password="", username="", access=ACCESS, manager=""):
        self.name = name
        self.email = email
        self.username = username
        self.password = generate_password_hash(password)
        self.access = access
        self.manager = manager

    def is_admin(self):
        return self.access == ACCESS['admin']

    def is_manager(self):
        return self.access == ACCESS['manager']

    def is_user(self):
        return self.access == ACCESS['user']

    def allowed(self, access_level):
        return self.access >= access_level

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return '<User {0}>'.format(self.username)


@login.user_loader
def load_user(id):
    return User.query.get(int(id))  # if this changes to a string, remove int


### custom wrap to determine access level ###
def requires_access_level(access_level):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated:  # the user is not logged in
                return redirect(url_for('login'))

            # user = User.query.filter_by(id=current_user.id).first()

            if not current_user.allowed(access_level):
                flash('You do not have access to this resource.', 'danger')
                return redirect(url_for('index'))
            return f(*args, **kwargs)

        return decorated_function

    return decorator


#### Routes ####

# index
@app.route('/')
@app.route('/index')
def index():
    return render_template('index.html', pageTitle='Flask App Home Page')


# registration
@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(name=form.name.data, username=form.username.data, email=form.email.data, access=form.access.data )
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        flash('Congratulations, you are now a registered user!', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', pageTitle='Register | My Flask App', form=form)



# user login
@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if current_user.is_authenticated:
        print(current_user, 'currentuser')
        return redirect(url_for('index'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user is None or not user.check_password(form.password.data):
            flash('Invalid username or password', 'danger')
            return redirect(url_for('login'))
        login_user(user, remember=form.remember_me.data)
        next_page = request.args.get('next')
        if not next_page or url_parse(next_page).netloc != '':
            next_page = url_for('index')
        flash('You are now logged in', 'success')
        return redirect(next_page)
    return render_template('login.html', pageTitle='Login | My Flask App', form=form)


# logout
@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have successfully logged out.', 'success')
    return redirect(url_for('index'))


################ user level functionality ###################

@app.route('/account', methods=['GET', 'POST'])
@login_required
def account():
    user = User.query.get_or_404(current_user.id)
    form = AccountDetailForm()

    if form.validate_on_submit():
        user.name = form.name.data
        user.username = form.username.data
        user.email = form.email.data
        user.set_password(form.password.data)

        db.session.commit()
        flash('Your account has been updated.', 'success')
        return redirect(url_for('account'))

    form.name.data = user.name
    form.email.data = user.email

    return render_template('account_detail.html', form=form, pageTitle='Your Account')


# manger level access funcationality

# dashboard
@app.route('/dashboard')
@requires_access_level(ACCESS['manager'])
def dashboard():
    return render_template('dashboard.html', pageTitle='My Flask App Dashboard')

#manager control panel
@app.route('/managercontrolpanel')
@requires_access_level(ACCESS['manager'])
def manager_control_panel():
    all_users = User.query.filter_by(access=0,manager=current_user.id )
    return render_template('control_panel.html',users=all_users, pagetitle='Manager Control Panel')



# ADMIN LEVEL FUNCTIONALITY
# control panel
@app.route('/control_panel')
@requires_access_level(ACCESS['admin'])
def control_panel():
    all_users = User.query.all()
    return render_template('control_panel.html', users=all_users,usersonly=all_users, pageTitle='My Flask App Control Panel')


# user details & update for admin
@app.route('/user_detail/<int:user_id>', methods=['GET', 'POST'])
@requires_access_level(ACCESS['admin'])
def user_detail(user_id):
    user = User.query.get_or_404(user_id)
    form = UserDetailForm()
    form.id.data = user.id
    form.name.data = user.name
    form.email.data = user.email
    form.username.data = user.username
    form.access.data = user.access
    return render_template('user_detail.html', form=form, pageTitle='User Details')

# user details & update for manager
@app.route('/user_detail_manager/<int:user_id>', methods=['GET', 'POST'])
@requires_access_level(ACCESS['manager'])
def user_detail_manager(user_id):
    user = User.query.get_or_404(user_id)
    form = UserDetailForm()
    form.id.data = user.id
    form.name.data = user.name
    form.email.data = user.email
    form.username.data = user.username
    form.manager.data = user.manager
    form.access.data = user.access
    
    return render_template('user_detail_manager.html', form=form, pageTitle='User Details')



# update user for admin
@app.route('/update_user/<int:user_id>', methods=['POST'])
@requires_access_level(ACCESS['admin'])
def update_user(user_id):
    user = User.query.get_or_404(user_id)
    form = UserDetailForm()

    orig_user = user.username  # get user details stored in the database - save username into a variable

    if form.validate_on_submit():
        user.name = form.name.data
        user.email = form.email.data

        new_user = form.username.data

        if new_user != orig_user:  # if the form data is not the same as the original username
            valid_user = User.query.filter_by(username=new_user).first()  # query the database for the username
            if valid_user is not None:
                flash("That username is already taken...", 'danger')
                return redirect(url_for('control_panel'))

        # if the values are the same, we can move on.
        user.username = form.username.data
        user.access = request.form['access_lvl']
        db.session.commit()
        flash('The user has been updated.', 'success')
        return redirect(url_for('control_panel'))

    return redirect(url_for('control_panel'))

# update user for manager
@app.route('/update_user_manager/<int:user_id>', methods=['POST'])
@requires_access_level(ACCESS['manager'])
def update_user_manager(user_id):
    user = User.query.get_or_404(user_id)
    form = UserDetailForm()

    orig_user = user.username  # get user details stored in the database - save username into a variable

    if form.validate_on_submit():
        user.name = form.name.data
        user.email = form.email.data

        new_user = form.username.data

        if new_user != orig_user:  # if the form data is not the same as the original username
            valid_user = User.query.filter_by(username=new_user).first()  # query the database for the username
            if valid_user is not None:
                flash("That username is already taken...", 'danger')
                return redirect(url_for('manager_control_panel'))

        # if the values are the same, we can move on.
        user.username = form.username.data
        user.access = request.form['access_lvl']
        db.session.commit()
        flash('The user has been updated.', 'success')
        return redirect(url_for('manager_control_panel'))

    return redirect(url_for('manager_control_panel'))


# delete user for admin
@app.route('/delete_user/<int:user_id>', methods=['POST'])
@requires_access_level(ACCESS['admin'])
def delete_user(user_id):
    if request.method == 'POST':  # if it's a POST request, delete the friend from the database
        user = User.query.get_or_404(user_id)
        db.session.delete(user)
        db.session.commit()
        flash('User has been deleted.', 'success')
        return redirect(url_for('control_panel'))

    return redirect(url_for('control_panel'))

# delete user for manager
@app.route('/delete_user_manager/<int:user_id>', methods=['POST'])
@requires_access_level(ACCESS['manager'])
def delete_user_manager(user_id):
    if request.method == 'POST':  # if it's a POST request, delete the friend from the database
        user = User.query.get_or_404(user_id)
        db.session.delete(user)
        db.session.commit()
        flash('User has been deleted.', 'success')
        return redirect(url_for('manager_control_panel'))
    
    return redirect(url_for('manager_control_panel'))


# new user by admin
@app.route('/new_user', methods=['GET', 'POST'])
@requires_access_level(ACCESS['admin'])
def new_user():
    form = NewUserForm()

    if request.method == 'POST' and form.validate_on_submit():
        user = User(name=form.name.data, username=form.username.data, email=form.email.data)
        user.set_password(form.password.data)
        user.access = request.form['access_lvl']
        db.session.add(user)
        db.session.commit()
        flash('User has been successfully created.', 'success')
        return redirect(url_for('login'))

    return render_template('new_user.html', pageTitle='New User | My Flask App', form=form)

# new user by manager
@app.route('/new_user_manager', methods=['GET', 'POST'])
@requires_access_level(ACCESS['manager'])
def new_user_manager():
    form = NewUserForm()

    if request.method == 'POST' and form.validate_on_submit():
        manager = current_user.id
        user = User(name=form.name.data, username=form.username.data, email=form.email.data, manager = manager)
        user.set_password(form.password.data)
        user.access = request.form['access_lvl']
        db.session.add(user)
        db.session.commit()
        flash('User has been successfully created.', 'success')
        return redirect(url_for('login'))

    return render_template('new_user_manager.html', pageTitle='New User | My Flask App', form=form)


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=80, debug=True)
