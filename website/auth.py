from flask import Blueprint, render_template, request, flash, redirect, url_for, session
from werkzeug.security import generate_password_hash, check_password_hash
from .models import User
from . import db
from flask_login import login_user, login_required, logout_user, current_user
import requests
import os
from dotenv import load_dotenv

load_dotenv()

# Blueprint setup
auth = Blueprint('auth', __name__)

# Auth0 settings
AUTH0_DOMAIN = os.getenv('AUTH0_DOMAIN')
CLIENT_ID = os.getenv('CLIENT_ID')
CLIENT_SECRET = os.getenv('CLIENT_SECRET')
CALLBACK_URL = os.getenv('CALLBACK_URL')

def get_auth0_authorization_url():
    """Generate the Auth0 authorization URL."""
    return (f"https://{AUTH0_DOMAIN}/authorize"
            f"?response_type=code"
            f"&client_id={CLIENT_ID}"
            f"&redirect_uri={CALLBACK_URL}"
            f"&scope=openid%20profile%20email")

@auth.route('/login_with_auth0')
def login_with_auth0():
    """Redirect to Auth0 login page."""
    auth0_url = get_auth0_authorization_url()
    return redirect(auth0_url)

@auth.route('/callback')
def callback():
    """Handle the Auth0 callback."""
    code = request.args.get('code')
    if not code:
        return "Missing authorization code.", 400

    token_url = f"https://{AUTH0_DOMAIN}/oauth/token"
    token_data = {
        'grant_type': 'authorization_code',
        'client_id': CLIENT_ID,
        'client_secret': CLIENT_SECRET,
        'code': code,
        'redirect_uri': CALLBACK_URL
    }
    
    token_r = requests.post(token_url, json=token_data)
    
    # Check if the response is valid JSON
    try:
        token_info = token_r.json()
    except requests.exceptions.JSONDecodeError:
        return "Error decoding JSON response from Auth0.", 500
    
    if token_r.status_code != 200:
        error_info = token_info.get('error_description', 'Unknown error')
        return f"Error obtaining token: {error_info}", token_r.status_code

    session['access_token'] = token_info.get('access_token')
    return redirect(url_for('auth.profile'))

@auth.route('/profile')
@login_required
def profile():
    """Render the profile page if the user is authenticated."""
    if 'access_token' not in session:
        return redirect(url_for('auth.login'))
    return 'You are logged in! <a href="/logout">Log out</a>'

@auth.route('/logout')
@login_required
def logout():
    """Log out the user and clear the session."""
    logout_user()
    session.pop('access_token', None)
    return redirect(f"https://{AUTH0_DOMAIN}/v2/logout"
                    f"?client_id={CLIENT_ID}"
                    f"&returnTo={url_for('auth.login', _external=True)}")

@auth.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        
        user = User.query.filter_by(email=email).first()
        if user:
            if check_password_hash(user.passsword, password):
                flash('Logged in successfully', category='success')
                login_user(user, remember=True)
                return redirect(url_for('views.home'))
            else:
                flash('Incorrect password', category='error')
        else:
            flash('Email does not exist', category='error')
    
    return render_template("login.html", user=current_user)

@auth.route('/sign-up', methods=['GET', 'POST'])
def sign_up():
    if request.method == 'POST':
        email = request.form.get('email')
        first_name = request.form.get('firstName')
        password1 = request.form.get('password1')
        password2 = request.form.get('password2')

        user = User.query.filter_by(email=email).first()
        if user:
            flash('Email already exists', category='error')
        elif len(email) < 4:
            flash('Email must be greater than 4 characters', category='error')
        elif len(first_name) < 2:
            flash('First name must be greater than 2 characters', category='error')
        elif password1 != password2:
            flash('Passwords do not match', category='error')
        elif len(password1) < 7:
            flash('Password must be greater than 7 characters', category='error')
        else:
            new_user = User(email=email, first_name=first_name, passsword=generate_password_hash(password1, method='sha256'))
            db.session.add(new_user)
            db.session.commit()
            login_user(new_user, remember=True)
            flash('Account created', category='success')
            return redirect(url_for('views.home'))

    return render_template("signup.html", user=current_user)
