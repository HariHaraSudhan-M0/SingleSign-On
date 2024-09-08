from flask import Blueprint, render_template, flash, request, redirect, url_for, session
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import login_user, login_required, logout_user, current_user
from .models import User
from . import db
import requests
import os
from dotenv import load_dotenv
import uuid  # For generating a state parameter

load_dotenv()

auth = Blueprint('auth', __name__)

# Auth0 configuration
AUTH0_DOMAIN = os.getenv('AUTH0_DOMAIN')
CLIENT_ID = os.getenv('CLIENT_ID')
CLIENT_SECRET = os.getenv('CLIENT_SECRET')
CALLBACK_URL = os.getenv('CALLBACK_URL')

def get_auth0_authorization_url(state):
    """Generate the Auth0 authorization URL."""
    return (f"https://{AUTH0_DOMAIN}/authorize"
            f"?response_type=code"
            f"&client_id={CLIENT_ID}"
            f"&redirect_uri={CALLBACK_URL}"
            f"&scope=openid%20profile%20email"
            f"&state={state}")

@auth.route('/login_with_auth0')
def login_with_auth0():
    """Redirect to Auth0 login page."""
    state = str(uuid.uuid4())  # Generate a unique state parameter
    session['state'] = state    # Store the state in the session
    auth0_url = get_auth0_authorization_url(state)
    return redirect(auth0_url)

@auth.route('/callback')
def callback():
    """Handle the Auth0 callback."""
    code = request.args.get('code')
    state = request.args.get('state')

    print(f"Callback received with code: {code} and state: {state}")
    print(f"Session state: {session.get('state')}")

    # Verify state parameter
    if state != session.get('state'):
        return "Invalid state parameter.", 400

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
    
    print(f"Token response status: {token_r.status_code}")
    print(f"Token response content: {token_r.text}")

    if token_r.status_code != 200:
        return f"Error obtaining token: {token_r.text}", token_r.status_code

    try:
        token_info = token_r.json()
    except ValueError:
        return "Error decoding JSON response from Auth0.", 500

    session['access_token'] = token_info.get('access_token')

    # Fetch user profile information from Auth0
    user_info_url = f"https://{AUTH0_DOMAIN}/userinfo"
    headers = {'Authorization': f"Bearer {session['access_token']}"}
    user_info_r = requests.get(user_info_url, headers=headers)

    print(f"User info response status: {user_info_r.status_code}")
    print(f"User info response content: {user_info_r.text}")

    if user_info_r.status_code == 200:
        user_info = user_info_r.json()
        user = User.query.filter_by(email=user_info['email']).first()
        if not user:
            user = User(
                email=user_info['email'],
                first_name=user_info.get('given_name', 'No Name'),
                passsword=generate_password_hash(str(uuid.uuid4()))
            )
            db.session.add(user)
            db.session.commit()
        
        login_user(user, remember=True)
    else:
        return f"Error fetching user info: {user_info_r.text}", user_info_r.status_code

    return redirect(url_for('views.home'))

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

@auth.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('auth.login'))

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
            new_user = User(email=email, first_name=first_name, passsword=generate_password_hash(password1))
            db.session.add(new_user)
            db.session.commit()
            login_user(new_user, remember=True)
            flash('Account created', category='success')
            return redirect(url_for('views.home'))

    return render_template("signup.html", user=current_user)
