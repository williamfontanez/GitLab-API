from flask import Flask, request, render_template, redirect, url_for, jsonify, flash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email, Length, EqualTo, ValidationError
import requests
import os

GITLAB_TOKEN = os.getenv('gitlab_token')
GITLAB_PROJECT_ID = os.getenv('gitlab_project_id')

users = {}

app = Flask(__name__)
app.secret_key = os.getenv('app_secret_key')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

class User(db.Model, UserMixin):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    def __repr__(self):
        return '<User %r>' % self.username

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return f'<User {self.username}>'

    def get_id(self):
           return (self.email)

    def __repr__(self):
        return '<User %r>' % self.username

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Register')

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

@app.before_request
def create_tables():
    db.create_all()

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.filter_by(email=user_id).first()

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        user = User.query.filter_by(email=email).first()
        if user and user.check_password(password):
            login_user(user)
            flash('Logged in successfully.')
            return redirect(url_for('index'))
        else:
            flash('Invalid email or password.')

    return render_template('login.html')

@app.route('/landing-page')
def landing_page():
    return render_template('landing-page.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            flash('Email already registered.', 'warning')
            return redirect(url_for('register'))
        else:
            try:
                new_user = User(username=form.username.data, email=form.email.data)
                new_user.set_password(form.password.data)
                db.session.add(new_user)
                db.session.commit()

                login_user(new_user)
                flash('Registration successful. Welcome!', 'success')
                return redirect(url_for('index')) 
            except Exception as e:
                db.session.rollback()
                flash('An error occurred. Please try again.', 'error')
                app.logger.error(f'Registration error: {e}')
    return render_template('register.html', form=form)

@app.route('/dashboard')
@login_required
def dashboard():
    return f'Hello, {current_user.id}! <a href="/logout">Logout</a>'

@app.route('/contacts')
def contacts():
    return render_template('contacts/contacts.html')

@app.route('/')
def first_page():
    return redirect(url_for('landing_page'))


@app.route('/index')
@login_required
def index():
    return render_template('index/index.html')

@app.route('/ticket-dashboard')
def ticket_dashboard():
    page = request.args.get('page', 1, type=int)
    per_page = 10

    headers = {'PRIVATE-TOKEN': GITLAB_TOKEN}
    url = f'https://gitlab.com/api/v4/projects/{GITLAB_PROJECT_ID}/issues?scope=all&per_page={per_page}&page={page}'

    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        issues = response.json()
        return render_template('tickets/tickets_dashboard.html', issues=issues, page=page)
    else:
        error_message = f"Failed to fetch issues from GitLab. Status Code: {response.status_code}"
        return render_template('tickets/tickets_dashboard.html', error_message=error_message)
    headers = {'PRIVATE-TOKEN': GITLAB_TOKEN}
    url = f'https://gitlab.com/api/v4/projects/{GITLAB_PROJECT_ID}/issues?scope=all'

    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        issues = response.json()[20:40]
        return render_template('tickets/tickets_dashboard2.html', issues=issues)
    else:
        error_message = f"Failed to fetch issues from GitLab. Status Code: {response.status_code}"
        return render_template('tickets/tickets_dashboard2.html', error_message=error_message)

@app.route('/create_issues', methods=['GET', 'POST'])
def create_issues():
    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        headers = {
            'PRIVATE-TOKEN': GITLAB_TOKEN,
            'Content-Type': 'application/json'
        }
        url = f'https://gitlab.com/api/v4/projects/{GITLAB_PROJECT_ID}/issues'
        data = {
            'title': title,
            'description': description
        }
        response = requests.post(url, headers=headers, json=data)
        if response.status_code == 201:
            return render_template('tickets/tickets_dashboard.html', title=title)
        else:
            error_message = f"Failed to create issue in GitLab. Status Code: {response.status_code}"
            return render_template('tickets/create_issue_form.html', error=error_message)

@app.route('/create_issue', methods=['POST'])
def create_issue():
    title = request.form['title']
    description = request.form['description']
    issue_type = request.form['issueType']
    watch_ticket = 'watch' in request.form

    labels = f"A::B::{issue_type.replace(' ', '')}"
    if watch_ticket:
        labels += ",Watch"
    
    assignee_id = 'williamfontanez' if issue_type == 'Create New Account' else 'ticket-assess-token'

    url = f'https://gitlab.com/api/v4/projects/{GITLAB_PROJECT_ID}/issues'
    data = {
        'title': title,
        'description': description,
        'labels': labels,
        # 'assignee_id': assignee_id, # Uncomment and replace with actual ID after fetching from GitLab
    }

    headers = {
        'PRIVATE-TOKEN': GITLAB_TOKEN
    }

    response = requests.post(url, headers=headers, data=data)
    if response.status_code == 201:
        return jsonify({"success": True, "message": "Issue created successfully"})
    else:
        return jsonify({"success": False, "message": "Failed to create issue"}), 400

@app.route('/total_issues')
def total_issues():
    headers = {'PRIVATE-TOKEN': GITLAB_TOKEN}
    url = f'https://gitlab.com/api/v4/projects/{GITLAB_PROJECT_ID}/issues?scope=all'

    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        issues = response.json()
        total_issues_count = len(issues)
        issue_titles = [issue['title'] for issue in issues]
        return render_template('tickets/issues_template.html', total_issues=total_issues_count, issue_titles=issue_titles)
    else:
        error_message = f"Failed to fetch issues from GitLab. Status Code: {response.status_code}"
        return render_template('tickets/issues_template.html', error_message=error_message)                                            

@app.route('/ticket-issue')
def ticket_issue():
    return render_template('tickets/ticket_issue.html')

@app.route('/reports-dashboard')
def reports_dashboard():
    return render_template('reports/reports_dashboard.html')

@app.route('/notifications-dashboard')
def notifications_dashboard():
    return render_template('notifications/notifications_dashboard.html')

@app.route('/knowledge-base')
def knowledge_base():
    return render_template('knowledge_base/knowledge_base.html')

@app.route('/profile')
def profile():
    return render_template('profile/profile.html')

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True, port=5000, ssl_context=('ssl_context/localhost.pem', 'ssl_context/localhost-key.pem'))