from functools import wraps
from flask import abort, flash, Markup,url_for, redirect
from flask_login import current_user
from .models import Permission


def permission_required(permission):
    def decorator(f):
        @wraps(f)
        def decorator_function(*arg, **kwargs):
            if not current_user.can(permission):
                abort(403)
            return f(*arg, **kwargs)
        return decorator_function
    return decorator


def admin_required(f):
    return permission_required(Permission.ADMINISTER)(f)


def confirm_required(func):
    @wraps(func)
    def decorated_function(*args, **kwargs):
        if not current_user.confirmed:
            message = Markup(
                'Please confirm your account first.'
                'Not receive the email?'
                '<a class="alert-link" href="%s">Resend Confirm Email</a>' %
                url_for('auth.resend_confirm_email'))
            flash(message, 'warning')
            return redirect(url_for('main.index'))
        return func(*args, **kwargs)
    return decorated_function
