from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import validates
from sqlalchemy import Time, DateTime
from datetime import datetime

db = SQLAlchemy()

class User(db.Model):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)


class Report(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    date = db.Column(DateTime, default=datetime.utcnow)
    time = db.Column(Time, default=datetime.utcnow)
    task = db.Column(db.String, nullable=False)
    project = db.Column(db.String, nullable=False)
    duration = db.Column(db.Integer, nullable=False)
    category = db.Column(db.String, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

class Task(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String, nullable=False)
    category = db.Column(db.String, nullable=False)
    description = db.Column(db.String, nullable=False)
    date = db.Column(db.String(20))
    hours = db.Column(db.String(20))
    minutes = db.Column(db.String(20))
    seconds = db.Column(db.String(20))
    status = db.Column(db.String, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    report_id = db.Column(db.Integer, db.ForeignKey('report.id'), nullable=True)

    
    @staticmethod
    def create_report_entry(task):
        report_entry = Report(
            title=task.title,
            category=task.category,
            description=task.description,
            date=task.date,
            hours=task.hours,
            minutes=task.minutes,
            seconds=task.seconds,
            user_id=task.user_id,
            
        )
        db.session.add(report_entry)
        db.session.commit()
        
    @validates('status')
    def validate_status(self, key, value):
        if value not in ['ongoing', 'completed']:
            raise ValueError("Status must be either 'ongoing' or 'completed'.")
        return value

class FormData(db.Model):
    __tablename__ = "form_data"
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100))
    category = db.Column(db.String(100))
    description = db.Column(db.Text)
    date = db.Column(db.String(20))
    hours = db.Column(db.String(20))
    minutes = db.Column(db.String(20))
    seconds = db.Column(db.String(20))
    
    def serialize(self):
        return {
            'id': self.id,
            'title': self.title,
            'category': self.category,
            'description': self.description,
            'date': self.date,
            'hours': self.hours,
            'minutes': self.minutes,
            'seconds': self.seconds
        }