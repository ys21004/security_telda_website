from flask import Flask, render_template, request, redirect, url_for
from flask_bcrypt import Bcrypt

app = Flask(__name__)
bcrypt = Bcrypt(app)

# Simple dictionary to store user credentials and roles (for demonstration purposes)
# In a real application, use a secure database to store user information
users = {
    'user1': {
        'username': 'user1',
        'password': bcrypt.generate_password_hash('password1').decode('utf-8'),  # Hashed password
        'role': 'user'
    },
    'admin1': {
        'username': 'admin1',
        'password': bcrypt.generate_password_hash('adminpassword1').decode('utf-8'),  # Hashed password
        'role': 'admin'
    }
}

# Sample transaction data for users (for demonstration purposes)
user_transactions = {
    'user1': [
        {"id": 1, "amount": 100, "description": "Purchase 1"},
        {"id": 2, "amount": 50, "description": "Purchase 2"}
    ],
    # Add more transactions for other users as needed
}

@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Check if username exists and passwords match
        if username in users and bcrypt.check_password_hash(users[username]['password'], password):
            # Redirect to appropriate page based on user role
            if username == 'admin1' and password == 'adminpassword1':
                return redirect(url_for('admin_dashboard'))
            elif users[username]['role'] == 'admin':
                return redirect(url_for('admin_dashboard'))
            else:
                return redirect(url_for('user_dashboard'))
        else:
            return render_template('login.html', message='Invalid username or password')

    return render_template('login.html')

@app.route('/admin-dashboard')
def admin_dashboard():
    # You can implement session management to protect this route
    return render_template('admin_dashboard.html')

@app.route('/user-dashboard')
def user_dashboard():
    # Get logged-in username (session management)
    logged_in_user = 'user1'  # For demonstration

    # Fetch transaction history for the logged-in user
    transactions = user_transactions.get(logged_in_user, [])

    return render_template('user_dashboard.html', transactions=transactions)

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        role = 'user'  # Default role for new signups

        # Check if username already exists
        if username in users:
            return render_template('signup.html', message='Username already exists. Please choose a different one.')

        # Password criteria: at least 8 characters with 1 capital letter and 1 number
        if not (len(password) >= 8 and any(char.isupper() for char in password) and any(char.isdigit() for char in password)):
            return render_template('signup.html', message='Password must include at least 8 characters with 1 capital letter and 1 number.')

        # Add the new user to the users dictionary with hashed password
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        users[username] = {'username': username, 'password': hashed_password, 'role': role}

        # Redirect to login page after successful signup
        return redirect(url_for('login'))

    return render_template('signup.html')

if __name__ == '__main__':
    app.run(debug=True)
