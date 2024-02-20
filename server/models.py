# from sqlalchemy.orm import relationship
from datetime import datetime
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
# Create an engine to connect to a database
# engine = create_engine('sqlite:///pomo.db', )

db = SQLAlchemy()

class User(db.Model):
    # __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String, nullable=False)
    email = db.Column(db.String, nullable=False, unique=True)
    password = db.Column(db.String, nullable=False, unique=True)
    report_data = db.relationship('Report', backref='user', lazy=True)


class Report(db.Model):
    # __tablename__ = 'report'

    id = db.Column(db.Integer, primary_key=True)
    date = datetime.utcnow().date()
    time = datetime.utcnow().time()
    task = db.Column(db.String, nullable=False)
    project = db.Column(db.String, nullable=False)
    # user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'),  nullable=False)
    # user = db.relationship('User', backref=db.backref('report', lazy=True))


