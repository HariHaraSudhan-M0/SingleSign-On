from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from os import path
from sqlalchemy import create_engine

db=SQLAlchemy()
DB_NAME="database.db"

def create_app():
    app=Flask(__name__)

    app.config['SECRET_KEY']='asdfghjkl'
    app.config['SQLALCHEMY_DATABASE_URI']=f'sqlite:///{DB_NAME}'
    db.init_app(app)
    from .views import views
    from .auth import auth
    app.register_blueprint(views,url_prefix='/')
    app.register_blueprint(auth,url_prefix='/')

    from .models import User, Book
    with app.app_context():
        db.create_all()

    return app


    