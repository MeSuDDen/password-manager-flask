from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_migrate import Migrate

app = Flask(__name__, template_folder='../templates', static_folder='../static')
app.config.from_pyfile('config.py')
app.config['UPLOAD_FOLDER'] = 'static/uploads'

db = SQLAlchemy(app)
migrate = Migrate(app, db, directory="migrations")

login_manager = LoginManager(app)
login_manager.login_view = 'login'

from app import routes, models
