from flask import Blueprint, render_template, redirect, url_for, request, flash
from . import db
from .models import User
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import current_user, login_required, login_user, logout_user


auth = Blueprint('auth', __name__)

"""************************ API for handling the login form and validating it**********************"""
@auth.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password1 = request.form.get('password1')
        remember = True if request.form.get('remember') else False

        user = User.query.filter_by(email=email).first()
        # check if the user actually exists
        # take the user-supplied password, hash it, and compare it to the hashed password in the database
        if not user or not check_password_hash(user.password1, password1):
            flash('Please check your login details and try again.')
            return redirect(url_for('auth.login')) # if the user doesn't exist or password is wrong, reload the page      

        login_user(user, remember)
        return redirect(url_for('main.profile'))
    return render_template('login.html')

"""************************ API for handling the signup form and validating it**********************"""
@auth.route('/signup', methods=['GET', 'POST'])
def sign_up():
    # code to validate and add user to the database
    if request.method =='POST':
        name = request.form.get('name')
        email = request.form.get('email')
        password1 = request.form.get('password1')
        password2 = request.form.get('password2')

        # If this returns a user, then the email already exists in the database
        user = User.query.filter_by(email=email).first() 

        # if a user is found, we want to redirect back to signup page so user can try again
        if user: 
            flash('Email address already exists')
            return redirect(url_for('auth.sign_up'))

        # create a new user with the form data. Hash the password so the plaintext version isn't saved.
        new_user = User(name=name, email=email, password1=generate_password_hash(password1, method='sha256'), password2=generate_password_hash(password2, method='sha256'))

        # add the new user to the database
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('auth.login'))

    return render_template('sign_up.html')


@auth.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect (url_for('main.home_page'))

