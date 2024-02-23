from flask import Flask, jsonify, request
import random
# from flask_wtf.csrf import CSRFProtect
import re
from flask_bcrypt import Bcrypt
from flask_cors import CORS
from flask_jwt_extended import JWTManager, set_access_cookies, create_access_token, jwt_required, get_jwt_identity, unset_jwt_cookies
from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy
from models import db, User, Report, Task
from datetime import datetime, time
import os
from dotenv import load_dotenv


load_dotenv()
app = Flask(__name__) 

CORS(app, supports_credentials=True)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = os.getenv('SQLALCHEMY_TRACK_MODIFICATIONS')
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY')
app.config['JWT_COOKIE_SECURE'] = os.getenv('JWT_COOKIE_SECURE')
app.config['JWT_COOKIE_CSRF_PROTECT'] = os.getenv('JWT_COOKIE_CSRF_PROTECT')


migrate = Migrate(app, db)
db.init_app(app)

with app.app_context():
    db.create_all()


bcrypt = Bcrypt(app)
jwt = JWTManager(app)


def is_valid_email(email):
    email_regex = re.compile(r'^[\w\.-]+@[\w\.-]+\.\w+$')
    return email_regex.match(email) is not None

@app.route('/signup', methods=['POST'])

def signup():
    data = request.json

    name = data.get('name')
    email = data.get('email')
    password = data.get('password')

    if not name or not email or not password:
        return jsonify({'message': 'check if you have entered email or password'}), 400
    
    if not is_valid_email(email):
        return jsonify({'message': 'Invalid email format'}), 400

    if User.query.filter_by(name=name).first() or User.query.filter_by(email=email).first():
        return jsonify({'message': 'Username or email already exists'}), 400

    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

    new_user = User(name=name, email=email, password=hashed_password)
    db.session.add(new_user)
    db.session.commit()

    access_token = create_access_token(identity=new_user.id)
    resp = jsonify({'message': 'User registered successfully!', 
                    'name': name,
                    'email':email,
                    'password':hashed_password,
                    'token': access_token})
    set_access_cookies(resp, access_token)
    return resp, 201

@app.route('/login', methods=['POST'])

def login():
    data = request.json

    name = data.get('name')
    password = data.get('password')
    email = data.get('email')
    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

    if not name or not password:
        return jsonify({'message': 'Incomplete data'}), 400

    user = User.query.filter_by(name=name).first()

    if not user or not bcrypt.check_password_hash(user.password, password):
        resp = jsonify({'message': 'Invalid credentials'})
        unset_jwt_cookies(resp)
        return resp, 401

    access_token = create_access_token(identity=user.id)
    resp = jsonify({
        'name': name,
        'password':hashed_password,
        'token': access_token
                    })
    set_access_cookies(resp, access_token)
    return resp, 200

@app.route('/user/<string:name>', methods=['PATCH'])
@jwt_required()

def update_user(name):
    current_user_id = request.current_user_id
    current_user = User.query.get(current_user_id)

    if not current_user or not bcrypt.check_password_hash(current_user.password, request.json.get('current_password')):
        return jsonify({'message': 'Invalid credentials'}), 401

    user_to_update = User.query.filter_by(name=name).first()

    if not user_to_update:
        return jsonify({'message': 'User not found'}), 404

    data = request.json

    
    if 'new_username' in data:
        user_to_update.name = data['new_username']
    if 'new_email' in data:
        user_to_update.email = data['new_email']
    if 'new_password' in data:
        user_to_update.password = bcrypt.generate_password_hash(data['new_password']).decode('utf-8')

    db.session.commit()

    return jsonify({'message': 'User updated successfully'}), 200

@app.route('/user/<string:name>', methods=['DELETE'])
@jwt_required()

def delete_user(name):
    current_user_id = request.current_user_id
    current_user = User.query.get(current_user_id)

    if not current_user or not bcrypt.check_password_hash(current_user.password, request.json.get('password')):
        return jsonify({'message': 'Invalid credentials'}), 401

    user_to_delete = User.query.filter_by(name=name).first()

    if not user_to_delete:
        return jsonify({'message': 'User not found'}), 404

    db.session.delete(user_to_delete)
    db.session.commit()

    return jsonify({'message': 'User deleted successfully'}), 200

@app.route('/users', methods=['GET'])
@jwt_required()

def get_users():
    users = User.query.all()
    user_data = [{
        'id': user.id,
        'username': user.username,
        'email': user.email
    } for user in users]
    return jsonify(user_data)

@app.route('/logout', methods=['POST'])
def logout():
    resp = jsonify({'logout': True})
    unset_jwt_cookies(resp)
    return resp, 200

@app.route('/create_task', methods=['POST'])
@jwt_required()
def create_task():
    data = request.json
    date = datetime.strptime(data['date'], '%Y-%m-%d').date()
    time_parts = data['time'].split(':')
    time_obj = time(int(time_parts[0]), int(time_parts[1]))

    new_task = Task(
        task_name=data['task_name'],
        duration=data['duration'],
        category=data['category'],
        description=data['description'],
        date=date,
        time=time_obj,
        status=data['status'],
        user_id=data['user_id']
    )
    db.session.add(new_task)
    db.session.commit()

    if new_task.status == 'completed':
        Task.create_report_entry(new_task)

    return jsonify({
        'task_name': data['task_name'],
        'duration': data['duration'],
        'category': data['category'],
        'description': data['description'],
        'message': 'Task created successfully'
    }), 201

@app.route('/get_tasks', methods=['GET'])
@jwt_required()
def get_ongoing_tasks():
    ongoing_tasks = Task.query.filter_by(status='ongoing').all()
    output = []
    for task in ongoing_tasks:
        task_data = {
            'id': task.id,
            'task_name': task.task_name,
            'duration': task.duration,
            'category': task.category,
            'description': task.description,
            'date': task.date.strftime('%Y-%m-%d'),
            'time': task.time.strftime('%H:%M:%S'),
            'status': task.status,
            'user_id': task.user_id
        }
        output.append(task_data)
    return jsonify({'tasks': output})

@app.route('/update_task/<int:id>', methods=['PUT'])
@jwt_required()
def update_task(id):
    task = Task.query.get_or_404(id)
    data = request.json

    task.task_name = data['task_name']
    task.duration = data['duration']
    task.category = data['category']
    task.description = data['description']
    task.status = data['status']

    if task.status == 'completed' and not task.report_id:
        Task.create_report_entry(task)

    db.session.commit()
    return jsonify({'message': 'Task updated successfully',
                    'task_name':data['task_name'],
                    'duration':data['duration'],
                    'category':data['category'],
                    'description':data['description'], 
                    })

@app.route('/delete_task/<int:id>', methods=['DELETE'])
@jwt_required()
def delete_task(id):
    task = Task.query.get_or_404(id)
    db.session.delete(task)
    db.session.commit()
    return jsonify({'message': 'Task deleted successfully'})

@app.route('/get_reports', methods=['GET'])
@jwt_required()
def get_reports():
    reports = Report.query.all()
    output = []
    for report in reports:
        report_data = {
            'id': report.id,
            'date': report.date.strftime('%Y-%m-%d'),
            'time': report.time.strftime('%H:%M:%S'),
            'task': report.task,
            'project': report.project,
            'duration': report.duration,
            'category': report.category
        }
        output.append(report_data)
    return jsonify({'reports': output})

@app.route('/delete_report/<int:id>', methods=['DELETE'])
@jwt_required()
def delete_report(id):
    report = Report.query.get_or_404(id)
    db.session.delete(report)
    db.session.commit()
    return jsonify({'message': 'Report deleted successfully'})


if __name__ == '__main__':
    app.run(debug=True)