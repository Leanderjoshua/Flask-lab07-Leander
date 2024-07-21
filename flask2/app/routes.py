from flask import render_template, request, redirect, url_for, flash, session
from app import app, db
from werkzeug.security import generate_password_hash, check_password_hash
from app.models import User
import re

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/sign_up', methods=['GET', 'POST'])
def sign_up():
    if request.method == 'POST':
        first_name = request.form['first_name']
        last_name = request.form['last_name']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        messages = []

        # Validate passwords
        if password != confirm_password:
            messages.append('Passwords do not match!')

        if not validate_password(password):
            messages.append(
                'Password must be at least 8 characters long.<br>'
                'At least one uppercase letter.<br>'
                'At least one lowercase letter.<br>'
                'At least one special character.<br>'
                'At least one numerical character.'
            )

        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            messages.append('Username already exists!')

        if messages:
            return redirect(url_for('error_page', messages='|'.join(messages)))
        
        hashed_password = generate_password_hash(password)  # Default method 'pbkdf2:sha256'
        new_user = User(first_name=first_name, last_name=last_name, email=email, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        flash('Sign up successful! Please log in.', 'success')
        return redirect(url_for('thankyou'))

    return render_template('sign_up.html')

def validate_password(password):
    """Validate password with specific requirements."""
    if len(password) < 8:
        return False
    if not re.search(r'[A-Z]', password):
        return False
    if not re.search(r'[a-z]', password):
        return False
    if not re.search(r'[0-9]', password):
        return False
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        return False
    return True

@app.route('/sign_in', methods=['GET', 'POST'])
def sign_in():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        user = User.query.filter_by(email=email).first()

        # Debugging information
        if user:
            print(f"Stored Hash: {user.password}")
            print(f"Password Input: {password}")
            print(f"Hash Check Result: {check_password_hash(user.password, password)}")

        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            return redirect(url_for('secret_page'))

        # Redirect to error page with message
        return redirect(url_for('error_page', message='Invalid Username or Password!'))

    return render_template('sign_in.html')

@app.route('/secret_page')
def secret_page():
    if 'user_id' not in session:
        return redirect(url_for('sign_in'))
    return render_template('secret_page.html')

@app.route('/thankyou')
def thankyou():
    return render_template('thankyou.html')

@app.route('/view_users')
def view_users():
    if 'user_id' not in session:
        return redirect(url_for('sign_in'))
    
    users = User.query.all()
    return render_template('view_users.html', users=users)

@app.route('/error_page')
def error_page():
    messages = request.args.get('messages', '')
    message_list = messages.split('|') if messages else []
    message = request.args.get('message', '')
    return render_template('error.html', messages=message_list, message=message)
