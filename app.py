from flask import Flask, jsonify, request
import random
from flask_wtf.csrf import CSRFProtect
from flask_mail import Mail, Message
import re
from models import db, User, Task
from flask_bcrypt import Bcrypt
from flask_cors import CORS
from flask_jwt_extended import JWTManager, set_access_cookies, create_access_token, jwt_required, get_jwt_identity, unset_jwt_cookies

app = Flask(__name__)
CORS(app, supports_credentials=True)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'M1U5T6VDFH68'  
app.config['JWT_SECRET_KEY'] = 'FG89JK07GVC5' 
app.config['JWT_TOKEN_LOCATION'] = ['cookies']
app.config['JWT_COOKIE_SECURE'] = True  
app.config['JWT_COOKIE_CSRF_PROTECT'] = False


mail = Mail(app)
db.init_app(app)

with app.app_context():
    db.create_all()

csrf = CSRFProtect(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)


def is_valid_email(email):
    email_regex = re.compile(r'^[\w\.-]+@[\w\.-]+\.\w+$')
    return email_regex.match(email) is not None

@app.route('/signup', methods=['POST'])
@csrf.exempt
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
@csrf.exempt
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
@csrf.exempt
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
@csrf.exempt
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
@csrf.exempt
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

@app.route('/task', methods=['POST'])
@jwt_required()
@csrf.exempt
def create_task():
    data = request.json
    new_task = Task(
        task_name=data['task_name'],
        category=data['category'],
        description=data['description'],
        duration=data['duration'],
        date=data['date'],
        time=data['time'],
        status = data['status']
    )
    db.session.add(new_task)
    db.session.commit()
    
    return jsonify(
        message="Task created successfully",
        task_id=new_task.id,
        task_name=data['task_name'],
        category=data['category'],
        duration=data['duration'],
        description=data['description'],
        date=data['date'],
        time=data['time'],
        status=new_task.status  
    ), 201

@app.route('/task/<int:task_id>', methods=['DELETE'])
@jwt_required()
@csrf.exempt
def delete_task(task_id):
    task = Task.query.get(task_id)
    if task:
        task.status = True 
        db.session.commit()
        return jsonify(message="Task deleted successfully"), 200
    else:
        return jsonify(error="Task not found"), 404

@app.route('/task/<int:task_id>', methods=['PUT'])
@jwt_required()
@csrf.exempt
def update_task(task_id):
    task = Task.query.get(task_id)
    if task:
        data = request.json
        task.task_name = data.get('task_name', task.task_name)
        task.category = data.get('category', task.category)
        task.description = data.get('description', task.description)
        task.duration = data.get('duration', task.duration)
        task.date = data.get('date', task.date)
        task.time = data.get('time', task.time)
        db.session.commit()
        return jsonify(message="Task updated successfully"), 200
    else:
        return jsonify(error="Task not found"), 404

@app.route('/tasks', methods=['GET'])
@jwt_required()
@csrf.exempt
def get_tasks():
    tasks = Task.query.filter_by(status=False).all()  
    task_data = [{
        'task_id': task.id,
        'task_name': task.task_name,
        'category': task.category,
        'description': task.description,
        'duration': task.duration,
        'date': task.date,
        'time': task.time,
        'status': task.status  
    } for task in tasks]

    return jsonify(task_data)

if __name__ == '__main__':
    app.run(debug=True)