import email
from enum import unique
from unicodedata import name
from . import db
#Flask-Login can manage user sessions.
#UserMixin adds Flask-Login attributes to the model so that Flask-Login can work with it.
from flask_login import UserMixin


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200))
    email = db.Column(db.String(200), unique=True)
    password1 = db.Column(db.String(200))
    password2 = db.Column(db.String(200))