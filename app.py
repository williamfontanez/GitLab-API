from flask import Flask, request, render_template, redirect, url_for
import requests
import os

GITLAB_TOKEN = os.getenv('gitlab_token')
GITLAB_PROJECT_ID = os.getenv('gitlab_project_id')

AZURE_TENANT_ID = os.getenv('azure_tenant_id')
AZURE_CLIENT_ID = os.getenv('azure_client_id')
AZURE_CLIENT_SECRET = os.getenv('azure_client_secret')
SUBSCRIPTION_ID = os.getenv('subscription_id')
FLASK_SECRET_KEY = os.getenv('flask_secret_key')

app = Flask(__name__)



@app.route('/')
def index():
    return render_template('index.html')

#region this region
#region
@app.route('/ticket-dashboard')
def ticket_dashboard():
    return render_template('tickets/tickets_dashboard.html')

@app.route('/create_issue', methods=['GET', 'POST'])
def create_issue():
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
            return render_template('tickets/success_page.html', title=title)
        else:
            error_message = f"Failed to create issue in GitLab. Status Code: {response.status_code}"
            return render_template('tickets/create_issue_form.html', error=error_message)
    else:
        return render_template('tickets/create_issue_form.html')

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

# @app.route('/watched_issues')
# def watched_issues():
#     headers = {'PRIVATE-TOKEN': GITLAB_TOKEN}
#     url = f'https://gitlab.com/api/v4/projects/{GITLAB_PROJECT_ID}/issues?scope=all'

#     response = requests.get(url, headers=headers)
#     if response.status_code == 200:
#         issues = response.json()
#         watched_issues = filter(watched, issues)
#         return watched_issues
#     else:
#         error_message = f"Failed to fetch issues from GitLab. Status Code: {response.status_code}"
#         return render_template('tickets/issues_template.html', error_message=error_message)

#endregion
#endregion
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
    return render_template('index.html')

@app.route('/debug')
def debug():
    headers = {'PRIVATE-TOKEN': GITLAB_TOKEN}
    url = f'https:///gitlab.com/api/v4/projects/{GITLAB_PROJECT_ID}/issues?scope=all'
    print(f"URL: {url}")
    print(f"Headers: {headers}")
    response = requests.get(url, headers=headers)
    return f"Status Code: {response.status_code}, Response Body: {response.text}", 200


if __name__ == '__main__':
    app.run(debug=True, port=5000, ssl_context=('ssl_context/localhost.pem', 'ssl_context/localhost-key.pem'))