from flask import Flask
from flask_bootstrap import Bootstrap
from flask_moment import Moment
from flask_mail import Mail
from flask_sqlalchemy import SQLAlchemy
from config import config, basedir
from flask_login import LoginManager
from flask_pagedown import PageDown
from flask_ckeditor import CKEditor
from flask_avatars import Avatars
from flask_whooshee import Whooshee
from flask_oauthlib.client import OAuth

bootstrap = Bootstrap()
mail = Mail()
moment = Moment()
pagedown = PageDown()
db = SQLAlchemy()
login_manager = LoginManager()
ckeditor = CKEditor()
avatars = Avatars()
whooshee = Whooshee()
oauth = OAuth()

login_manager.session_protection = 'strong'
login_manager.login_view = 'auth.login'

from .models import *


def create_app(config_name):
    app = Flask(__name__)
    app.config.from_object(config[config_name])
    config[config_name].init_app(app)
    bootstrap.init_app(app)
    mail.init_app(app)
    moment.init_app(app)
    db.init_app(app)
    login_manager.init_app(app)
    pagedown.init_app(app)
    ckeditor.init_app(app)
    avatars.init_app(app)
    oauth.init_app(app)
    whooshee.init_app(app)


    from .main import main as main_blueprint
    app.register_blueprint(main_blueprint)

    from .auth import auth as auth_blueprint
    app.register_blueprint(auth_blueprint, url_prefix='/auth')

    from .api import api as api_blueprint
    app.register_blueprint(api_blueprint, url_prefix='/api/v1')

    from .oauth import oauth_bp as oauth_blueprint
    app.register_blueprint(oauth_blueprint)

    return app
