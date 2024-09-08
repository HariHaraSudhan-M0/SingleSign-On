from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from os import path
from flask_login import LoginManager
import os

db = SQLAlchemy()
DB_NAME = "database.db"

def create_app():
    app = Flask(__name__)

    app.config['SECRET_KEY'] = 'asdfghjkl'
    db_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), DB_NAME)
    app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{db_path}'
    db.init_app(app)
   
    from .views import views
    from .auth import auth
    app.register_blueprint(views, url_prefix='/')
    app.register_blueprint(auth, url_prefix='/')

    login_manager = LoginManager()
    login_manager.login_view = 'auth.login'
    login_manager.init_app(app)
    
    @login_manager.user_loader
    def load_user(id):
        return User.query.get(int(id))
    
    from .models import User, Book
    with app.app_context():
        if not path.exists(db_path):
            db.create_all()
            print('Database created and tables are set up.')
        else:
            print('Database already exists.')
    
    return app
