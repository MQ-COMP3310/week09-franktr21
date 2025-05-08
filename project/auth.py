# Exercise 9.2.4 – SQL Injection Fix:
# I fixed the SQL injection by replacing raw SQL with a secure SQLAlchemy ORM query:user = User.query.filter_by(email=email).first()
# This protects against SQL injection by automatically escaping input.
# - Testing with SQL injection payloads like `' OR '1'='1` and confirming no login bypass
# - Running the app and confirming normal user signup/login still works


from flask import Blueprint, render_template, request, flash, redirect, url_for
from flask_login import login_user, login_required, logout_user
from werkzeug.security import generate_password_hash, check_password_hash
from .models import User
from . import db, app

auth = Blueprint('auth', __name__)

@auth.route('/login')
def login():
    return render_template('login.html')

@auth.route('/login', methods=['POST'])
def login_post():
    email = request.form.get('email')
    password = request.form.get('password')
    remember = True if request.form.get('remember') else False

    user = User.query.filter_by(email=email).first()

    # check if the user actually exists
    # take the user-supplied password and compare it with the stored password
    if not user or not check_password_hash(user.password, password):
        flash('Please check your login details and try again.')
        app.logger.warning("User login failed")
        return redirect(url_for('auth.login')) # if the user doesn't exist or password is wrong, reload the page

    # if the above check passes, then we know the user has the right credentials
    login_user(user, remember=remember)
    return redirect(url_for('main.profile'))

@auth.route('/signup')
def signup():
    return render_template('signup.html')

@auth.route('/signup', methods=['POST'])
def signup_post():
    email = request.form.get('email')
    name = request.form.get('name')
    password = request.form.get('password')

    user = User.query.filter_by(email=email).first()
    if user: # if a user is found, we want to redirect back to signup page so user can try again
        flash('Email address already exists')  # 'flash' function stores a message accessible in the template code.
        app.logger.debug("User email already exists")
        return redirect(url_for('auth.signup'))

    # create a new user with the form data. TODO: Hash the password so the plaintext version isn't saved.
    new_user = User(email=email, name=name, password=generate_password_hash(password, method='pbkdf2:sha256'))

    # add the new user to the database
    db.session.add(new_user)
    db.session.commit()

    return redirect(url_for('auth.login'))

@auth.route('/logout')
@login_required
def logout():
    logout_user();
    return redirect(url_for('main.index'))

# See https://www.digitalocean.com/community/tutorials/how-to-add-authentication-to-your-app-with-flask-login for more information
