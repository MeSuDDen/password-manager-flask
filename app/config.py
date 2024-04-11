import os
from datetime import timedelta

basedir = os.path.abspath(os.path.dirname(__file__))
SQLALCHEMY_DATABASE_URI = 'sqlite:///' + os.path.join(basedir, 'app.db')
SECRET_KEY = 'your_secret_key'
PERMANENT_SESSION_LIFETIME = timedelta(minutes=1)
SESSION_REFRESH_EACH_REQUEST = True