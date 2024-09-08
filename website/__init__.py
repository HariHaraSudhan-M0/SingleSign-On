from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, current_user
from os import path  # Import the path module here

db = SQLAlchemy()
DB_NAME = "database.db"

def create_app():
    app = Flask(__name__)
    app.config['SECRET_KEY'] = 'asdfghjkl'
    app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{DB_NAME}'
    db.init_app(app)

    from .views import views
    from .auth import auth

    app.register_blueprint(views, url_prefix='/')
    app.register_blueprint(auth, url_prefix='/')

    # Initialize LoginManager
    login_manager = LoginManager()
    login_manager.login_view = 'auth.login'
    login_manager.init_app(app)

    @login_manager.user_loader
    def load_user(id):
        from .models import User  # Import User model inside the function to avoid circular imports
        return User.query.get(int(id))

    # Context processor to make 'current_user' available in all templates
    @app.context_processor
    def inject_user():
        return dict(user=current_user)

    from .models import User, Book
    if not path.exists('website/' + DB_NAME):
        with app.app_context():
            db.create_all()
            print('Database created and tables are set up.')
    else:
        print('Database already exists.')

    return app
