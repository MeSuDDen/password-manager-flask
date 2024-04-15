from app import db
from flask_login import UserMixin

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    reset_token = db.Column(db.String(100))
    reset_token_expiration = db.Column(db.DateTime)
    avatar_path = db.Column(db.String(255))

class Password(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    password = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(120), nullable=False)
    username = db.Column(db.String(80), nullable=False)
    phone_number = db.Column(db.String(20))
    icon = db.Column(db.String(100))
    category = db.Column(db.String(50))
    color = db.Column(db.String(20))
    description = db.Column(db.Text)
    website = db.Column(db.String(200))