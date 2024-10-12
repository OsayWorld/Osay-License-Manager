from flask import Blueprint, render_template, redirect, url_for, request, flash
from flask_login import login_user, logout_user, login_required
from models.user import User
from extensions import db
from werkzeug.security import generate_password_hash, check_password_hash
import re
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer
from config import Config


# Initialize the Mail instance
mail = Mail()

# Create a serializer for generating reset tokens
s = URLSafeTimedSerializer(Config.SECRET_KEY)

auth_bp = Blueprint('auth', __name__)

# Regular expression for validating email format
EMAIL_REGEX = r'^[a-z0-9]+[\._]?[a-z0-9]+[@]\w+[.]\w{2,3}$'

# Password strength validation
def validate_password(password):
    if len(password) < 8:
        return False, "Password must be at least 8 characters long."
    if not any(char.isdigit() for char in password):
        return False, "Password must contain at least one digit."
    if not any(char.isupper() for char in password):
        return False, "Password must contain at least one uppercase letter."
    return True, None

# Email format validation
def validate_email(email):
    if re.match(EMAIL_REGEX, email):
        return True
    return False

# Login route
@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()

        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('general.dashboard'))
        else:
            flash('Login failed. Check your email or password and try again.')
    return render_template('login.html')

# Signup route
@auth_bp.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']

        # Validate email format
        if not validate_email(email):
            flash('Invalid email format. Please provide a valid email.')
            return redirect(url_for('auth.signup'))

        # Check if username or email already exists
        if User.query.filter_by(username=username).first():
            flash('Username already exists. Please choose a different one.')
            return redirect(url_for('auth.signup'))
        if User.query.filter_by(email=email).first():
            flash('An account with this email already exists.')
            return redirect(url_for('auth.signup'))

        # Validate password strength
        valid_password, message = validate_password(password)
        if not valid_password:
            flash(message)
            return redirect(url_for('auth.signup'))

        # Create a new user
        new_user = User(
            username=username,
            email=email,
            password=generate_password_hash(password)
        )
        db.session.add(new_user)
        db.session.commit()

        # Automatically log the user in after successful registration
        login_user(new_user)
        flash('Signup successful! Welcome to the dashboard.')
        return redirect(url_for('general.dashboard'))
    return render_template('signup.html')

# Logout route
@auth_bp.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out successfully.')
    return redirect(url_for('auth.login'))

# Password Reset Request Route
@auth_bp.route('/reset_request', methods=['GET', 'POST'])
def reset_request():
    if request.method == 'POST':
        email = request.form['email']
        user = User.query.filter_by(email=email).first()
        
        if user:
            token = s.dumps(email, salt='email-reset-salt')
            reset_url = url_for('auth.reset_password', token=token, _external=True)
            msg = Message('Password Reset Request',
                          sender=Config.MAIL_USERNAME,
                          recipients=[email])
            msg.body = f'Please click the link to reset your password: {reset_url}'
            mail.send(msg)
            flash('An email has been sent with instructions to reset your password.', 'info')
            return redirect(url_for('auth.login'))
        else:
            flash('Email address not found.', 'warning')
    return render_template('reset_request.html')

# Password Reset Confirmation Route
@auth_bp.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    try:
        email = s.loads(token, salt='email-reset-salt', max_age=3600)  # 1 hour expiration
    except Exception as e:
        flash('The reset link is invalid or has expired.', 'warning')
        return redirect(url_for('auth.reset_request'))

    user = User.query.filter_by(email=email).first()

    if request.method == 'POST':
        new_password = request.form['password']
        valid_password, message = validate_password(new_password)

        if not valid_password:
            flash(message)
            return redirect(url_for('auth.reset_password', token=token))

        user.password = generate_password_hash(new_password)
        db.session.commit()
        flash('Your password has been updated! You can now log in.', 'success')
        return redirect(url_for('auth.login'))

    return render_template('reset_password.html', token=token)