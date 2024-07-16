from flask import Flask, render_template, request, redirect, url_for, session
from flask_pymongo import PyMongo
from bson.objectid import ObjectId
from authlib.integrations.flask_client import OAuth
import os
import hashlib
from functools import wraps
from datetime import datetime, timedelta
from urllib.parse import urlencode

app = Flask(__name__)
app.config["MONGO_URI"] = "mongodb://localhost:27017/todoDB"
app.config["SECRET_KEY"] = os.urandom(24)

mongo = PyMongo(app)

# Okta Configurations
app.config['OKTA_CLIENT_ID'] = 'RZCfP93XM17kbWbPHto4l0BSjyKyX9ya'
app.config['OKTA_CLIENT_SECRET'] = 'bl_LcxbsIsOSr_lCmj8-8qD0wPc8C9XGv17UV8cEI19nWSQ4Le-WY10fsX_TXOQ5'
app.config['OKTA_AUTHORITY'] = 'https://dev-2j6p6u8m7na6tage.us.auth0.com'

oauth = OAuth(app)
okta = oauth.register(
    name='okta',
    client_id=app.config['OKTA_CLIENT_ID'],
    client_secret=app.config['OKTA_CLIENT_SECRET'],
    server_metadata_url=f"{app.config['OKTA_AUTHORITY']}/.well-known/openid-configuration",
    client_kwargs={
        'scope': 'openid profile email',
    }
)

def generate_nonce():
    return hashlib.sha256(os.urandom(16)).hexdigest()

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'okta_token' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

@app.before_request
def before_request():
    session.permanent = True
    app.permanent_session_lifetime = timedelta(minutes=5)

@app.route('/')
@login_required
def index():
    todos = mongo.db.todos.find()
    return render_template('index.html', todos=todos)

@app.route('/add', methods=['POST'])
@login_required
def add_todo():
    task = request.form.get('task')
    description = request.form.get('description')
    priority = request.form.get('priority', 'low')
    date_created = datetime.now()
    mongo.db.todos.insert_one({
        'task': task,
        'description': description,
        'priority': priority,
        'date_created': date_created,
        'is_done': False
    })
    return redirect(url_for('index'))

@app.route('/update_priority/<id>', methods=['POST'])
@login_required
def update_priority(id):
    new_priority = request.form.get('priority')
    mongo.db.todos.update_one(
        {'_id': ObjectId(id)},
        {'$set': {'priority': new_priority}}
    )
    return redirect(url_for('index'))

@app.route('/mark_done/<id>')
@login_required
def mark_done(id):
    mongo.db.todos.update_one(
        {'_id': ObjectId(id)},
        {'$set': {'is_done': True}}
    )
    return redirect(url_for('index'))

@app.route('/delete/<id>')
@login_required
def delete(id):
    mongo.db.todos.delete_one({'_id': ObjectId(id)})
    return redirect(url_for('index'))

@app.route('/login')
def login():
    nonce = generate_nonce()
    session['nonce'] = nonce
    redirect_uri = url_for('authorize', _external=True)
    return okta.authorize_redirect(redirect_uri, nonce=nonce)

@app.route('/authorize')
def authorize():
    token = okta.authorize_access_token()
    nonce = session.pop('nonce', None)
    if nonce is None:
        return "Nonce not found", 400
    user = okta.parse_id_token(token, nonce=nonce)
    session['okta_token'] = token
    session['user'] = user
    return redirect('/')

@app.route('/logout')
@login_required
def logout():
    id_token = session.get('okta_token', {}).get('id_token')
    session.pop('okta_token', None)
    session.pop('user', None)
    if id_token:
        okta_logout_url = f"{app.config['OKTA_AUTHORITY']}/v1/logout"
        params = {
            'id_token_hint': id_token,
            'post_logout_redirect_uri': url_for('index', _external=True)
        }
        logout_url = f"{okta_logout_url}?{urlencode(params)}"
        return redirect(logout_url)
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)
