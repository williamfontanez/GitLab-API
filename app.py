from flask import Flask, jsonify, render_template
import requests
import os

app = Flask(__name__)

GITLAB_TOKEN = os.getenv('gitlab_token')
GITLAB_PROJECT_ID = os.getenv('gitlab_project_id')


@app.route('/create_issue', methods=['POST'])
def create_issue():
    headers = {
        'PRIVATE-TOKEN': GITLAB_TOKEN,
        'Content-Type': 'application/json'
    }
    url = f'https://gitlab.com/api/v4/projects/{GITLAB_PROJECT_ID}/issues'
    
    data = {
        'title': 'Example Issue Title',
        'description': 'This is a detailed description of the issue.'
    }

    response = requests.post(url, headers=headers, json=data)
    if response.status_code == 201: 
        issue = response.json()
        return jsonify(issue)

    else:
        error_message = f"Failed to create issue in GitLab. Status Code: {response.status_code}"
        return ((jsonify({'error': error_message}), response.status_code),(render_template('issues_template.html', total_issues=error_message)))

@app.route('/total_issues')
def total_issues():
    headers = {
        'PRIVATE-TOKEN': GITLAB_TOKEN
        }
    url = f'https://gitlab.com/api/v4/projects/{GITLAB_PROJECT_ID}/issues?scope=all'

    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        issues = response.json()
        total_issues_count = len(issues)
        return ((return jsonify({'total_issues': len(issues)}))(render_template('issues_template.html', total_issues=error_message)))
    else:
        error_message = f"Failed to fetch issues from GitLab. Status Code: {response.status_code}"
        return ((return jsonify({'total_issues': len(issues)}))(render_template('issues_template.html', total_issues=error_message)))
        
@app.route('/debug')
def debug():
    headers = {'PRIVATE-TOKEN': GITLAB_TOKEN}
    url = f'https://gitlab.com/api/v4/projects/{GITLAB_PROJECT_ID}/issues?scope=all'
    print(f"URL: {url}")
    print(f"Headers: {headers}")
    response = requests.get(url, headers=headers)
    return f"Status Code: {response.status_code}, Response Body: {response.text}", 200

if __name__ == '__main__':
    app.run(debug=True, port=5000, ssl_context=('ssl_context/localhost.pem', 'ssl_context/localhost-key.pem'))