from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from datetime import datetime
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://radius:radius@localhost/radius'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)

class RadCheck(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), nullable=False)
    attribute = db.Column(db.String(64), nullable=False)
    op = db.Column(db.String(2), nullable=False)
    value = db.Column(db.String(253), nullable=False)

class RadAcct(db.Model):
    radacctid = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), nullable=False)
    acctstarttime = db.Column(db.DateTime)
    acctstoptime = db.Column(db.DateTime)
    nasipaddress = db.Column(db.String(15))
    framedipaddress = db.Column(db.String(15))
    acctterminatecause = db.Column(db.String(32))

class NASClient(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nasname = db.Column(db.String(128), nullable=False)
    shortname = db.Column(db.String(32), nullable=False)
    secret = db.Column(db.String(64), nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Routes
@app.route('/')
@login_required
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and user.password == password:  # In production, use proper password hashing
            login_user(user)
            return redirect(url_for('index'))
        flash('Invalid username or password')
    return render_template('login.html')

@app.route('/users')
@login_required
def users():
    radius_users = RadCheck.query.filter_by(attribute='Cleartext-Password').all()
    return render_template('users.html', users=radius_users)

@app.route('/add_user', methods=['GET', 'POST'])
@login_required
def add_user():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        # Add user to RadCheck table
        new_user = RadCheck(
            username=username,
            attribute='Cleartext-Password',
            op=':=',
            value=password
        )
        
        # Add session limit
        session_limit = RadCheck(
            username=username,
            attribute='Simultaneous-Use',
            op=':=',
            value='1'  # Limit to 1 session
        )
        
        try:
            db.session.add(new_user)
            db.session.add(session_limit)
            db.session.commit()
            flash('User added successfully')
            return redirect(url_for('users'))
        except Exception as e:
            db.session.rollback()
            flash(f'Error adding user: {str(e)}')
    
    return render_template('add_user.html')

@app.route('/nas_clients')
@login_required
def nas_clients():
    clients = NASClient.query.all()
    return render_template('nas_clients.html', clients=clients)

@app.route('/add_nas', methods=['GET', 'POST'])
@login_required
def add_nas():
    if request.method == 'POST':
        nasname = request.form['nasname']
        shortname = request.form['shortname']
        secret = request.form['secret']
        
        new_client = NASClient(
            nasname=nasname,
            shortname=shortname,
            secret=secret
        )
        
        try:
            db.session.add(new_client)
            db.session.commit()
            flash('NAS client added successfully')
            return redirect(url_for('nas_clients'))
        except Exception as e:
            db.session.rollback()
            flash(f'Error adding NAS client: {str(e)}')
    
    return render_template('add_nas.html')

@app.route('/active_sessions')
@login_required
def active_sessions():
    sessions = RadAcct.query.filter_by(acctstoptime=None).all()
    return render_template('active_sessions.html', sessions=sessions)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        # Create admin user if it doesn't exist
        admin = User.query.filter_by(username='admin').first()
        if not admin:
            admin = User(username='admin', password='admin', is_admin=True)
            db.session.add(admin)
            db.session.commit()
    app.run(debug=True)
