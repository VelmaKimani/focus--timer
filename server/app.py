from flask import Flask
from models import db, User , Report

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] ='sqlite:///pomo.db'
db.init_app(app)
with app.app_context():
    db.create_all()
if __name__ == '__main__':
 app.run(port =1245 ,debug=True)