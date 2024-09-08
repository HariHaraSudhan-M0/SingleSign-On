from . import db
from flask_login import UserMixin  #custom class 
from sqlalchemy.sql import func

class Book(db.Model):
    id = db.Column(db.Integer,primary_key=True)#auto incremented
    book_name = db.Column(db.String(200))
    author_name = db.Column(db.String(100))
    user_id = db.Column(db.Integer,db.ForeignKey('user.id'))

class User(db.Model,UserMixin): #login with usermixin
    id = db.Column(db.Integer,primary_key=True)
    email = db.Column(db.String(100),unique=True)
    passsword = db.Column(db.String(100))
    first_name = db.Column(db.String(100))
    Book = db.relationship('Book')
    