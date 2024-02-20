
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from flask import Flask

# Initialize Flask app
# app = Flask(__name__)

# Initialize SQLAlchemy
db = SQLAlchemy()
class User(db.Model):

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String, nullable=False)
    email = db.Column(db.String, nullable=False, unique=True)
    password = db.Column(db.String, nullable=False, unique=True)
    report_data = db.relationship('Report', backref='user', lazy=True)
    
    tasks = db.relationship('Task', backref='user', lazy=True)


class Report(db.Model):

    id = db.Column(db.Integer, primary_key=True)
    date = db.Column(db.DateTime(),default=datetime.utcnow().date())
    time = db.Column(db.DateTime(),default=datetime.utcnow().time())
    task = db.Column(db.String, nullable=False)
    project = db.Column(db.String, nullable=False)
    duration = db.Column(db.Integer, nullable=False)  
    category = db.Column(db.String, nullable=False)
    status = db.Column(db.String, nullable=False)
    
    
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'),  nullable=False)
    tasks = db.relationship('Task', backref='report', lazy=True)

class Task(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    task_name = db.Column(db.String, nullable=False)
    duration = db.Column(db.Integer, nullable=False)  
    category = db.Column(db.String, nullable=False)
    description = db.Column(db.String, nullable=False)
    date = db.Column(db.DateTime(),default=datetime.utcnow().date())
    time = db.Column(db.DateTime(),default=datetime)
    status = db.Column(db.String, nullable=False)

    # Define the foreign keys
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    report_id = db.Column(db.Integer, db.ForeignKey('report.id'), nullable=False)

    # @validates('status')
    # def validate_status(self, key, value):
    #     if value not in ['ongoing', 'completed']:
    #         raise ValueError("Status must be either 'ongoing' or 'completed'.")
    #     return value
