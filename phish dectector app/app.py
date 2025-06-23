from flask import Flask, render_template, request, redirect, url_for, flash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import re
from datetime import datetime

# --- Application Setup ---
app = Flask(__name__)
app.config['SECRET_KEY'] = 'a_very_secret_key_for_phish_shield_2025'

# --- User Authentication Setup ---
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'  # type: ignore

# In-memory user store (for simplicity)
# For a real application, you would use a database.
users = {
    'elijah david': {
        'username': 'elijah david',
        'password_hash': generate_password_hash('elijah123'),
        'name': 'David Elijah'
    }
}

class User(UserMixin):
    id: str | None = None

@login_manager.user_loader
def load_user(username):
    if username not in users:
        return
    user = User()
    user.id = username
    return user

# --- Phishing Analysis Logic ---
def analyze_email(email_content):
    """
    Analyzes the email content for phishing indicators.
    Returns a dictionary with a score, classification, and reasons.
    """
    score = 100
    reasons = []
    content_lower = email_content.lower()

    # Define phishing indicators with weights and reasons
    # Format: (regex, weight, reason)
    indicators = [
        # High-risk indicators
        (r'verify( your)? (account|identity|information)|update( your)? payment|confirm( your)? (identity|credentials|account)', 35, "Suspicious request to verify or update sensitive information."),
        (r'urgent|immediate attention|action required|security alert|required action|account locked|suspend(ed|sion)|audit', 25, "Uses urgent or threatening language to create panic."),
        (r'bit\.ly|tinyurl\.com|goo\.gl', 30, "Uses a URL shortener, which can hide the real destination."),
        (r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', 35, "Contains a raw IP address as a link."),
        (r'dear valued (customer|employee|user)', 20, "Uses a generic, impersonal greeting."),
        (r'spelling errors|grammatical mistakes', 15, "Contains obvious spelling or grammar errors."),
        (r'won a prize|lottery|claim your reward', 25, "Unsolicited claim of winning a prize or lottery."),
        (r'bank|paypal|amazon|netflix|irs', 10, "Mentions a common phishing target like a bank or popular service."),
        (r'password|credit card|social security number|credentials', 30, "Directly asks for sensitive credentials."),
        # Suspicious domain (not ending with .com, .org, .net, or using a lookalike domain)
        (r'https?://(?![\w.-]*techglobal-inc\.com)[\w.-]+\.(?!com|org|net)[a-z]{2,6}', 30, "Contains a suspicious or non-corporate domain in a link."),
        # Legitimate indicators (increase score)
        (r'sincerely|best regards|cordially|stay secure', -10, "Uses a professional closing."),
        (r'unsubscribe', -5, "Contains a standard 'unsubscribe' link.")
    ]

    for pattern, weight, reason in indicators:
        if re.search(pattern, email_content, re.IGNORECASE):
            score -= weight
            reasons.append(reason)
    
    # Normalize score to be between 0 and 100
    score = max(0, min(100, score))

    # Determine classification based on score
    if score >= 70:
        classification = "Legitimate"
    elif 40 <= score < 70:
        classification = "Suspicious"
    else:
        classification = "Phish"

    if not reasons:
        reasons.append("No specific indicators found. The email appears to be safe, but always remain cautious.")

    return {
        'score': score,
        'classification': classification,
        'reasons': reasons
    }

def get_greeting():
    """Returns a time-appropriate greeting."""
    hour = datetime.now().hour
    if 5 <= hour < 12:
        return "Good Morning"
    elif 12 <= hour < 18:
        return "Good Afternoon"
    else:
        return "Good Evening"

# --- Web Page Routes ---

@app.route('/')
def index():
    """Serves the main page, which is the login page."""
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if username in users and check_password_hash(users[username]['password_hash'], password):
            user = User()
            user.id = username
            login_user(user)
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password. Please try again.', 'error')
    
    return render_template('index.html')

@app.route('/dashboard')
@login_required
def dashboard():
    """Serves the main dashboard after a user logs in."""
    greeting = get_greeting()
    user_name = users[current_user.id]['name']
    return render_template('dashboard.html', greeting=greeting, user_name=user_name)

@app.route('/analyze', methods=['POST'])
@login_required
def analyze():
    """Handles the email analysis request from the dashboard."""
    email_content = request.form.get('email_content', '')
    sender_name = request.form.get('sender_name', 'a sender')

    if not email_content:
        flash('Email content cannot be empty.', 'error')
        return redirect(url_for('dashboard'))

    result = analyze_email(email_content)
    return render_template('result.html', result=result, sender_name=sender_name, email_content=email_content)

@app.route('/about')
def about():
    """Serves the about page with developer information."""
    developer_info = {
        'name': 'Phish shield',
        'institution': 'Ave Maria University',
        'reg_number': 'Amup/Sci/130/21'
    }
    return render_template('about.html', developer=developer_info)

@app.route('/logout')
@login_required
def logout():
    """Logs the current user out."""
    logout_user()
    flash('You have been successfully logged out.', 'success')
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True, port=5070) 