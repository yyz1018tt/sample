from flask import Blueprint

oauth_bp = Blueprint('oauth', __name__)

from . import views