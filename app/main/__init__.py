from flask import Blueprint

from app.models import Permission

main = Blueprint('main', __name__)

from . import view, errors
from ..models import Category


@main.app_context_processor
def inject_permissions():
    return dict(Permission=Permission)


@main.app_context_processor
def categories():
    categories = Category.query.order_by(Category.name).all()
    return dict(categories=categories)