import os
from . import oauth_bp
from app import oauth, db
from flask import abort, redirect, url_for, flash
from flask_login import current_user, login_user
from ..models import User
import json


github = oauth.remote_app(
    name='github',
    consumer_key=os.getenv('GITHUB_CLIENT_ID'),
    consumer_secret=os.getenv('GITHUB_CLIENT_SECRET'),
    request_token_params={'scope': 'user'},
    base_url='https://api.github.com/',
    request_token_url=None,
    access_token_method='POST',
    access_token_url='https://github.com/login/oauth/access_token',
    authorize_url='https://github.com/login/oauth/authorize',
)

providers = {
    'github': github
}

profile_endpoints = {
    'github': 'user'
}


def get_social_profile(provider, access_token):
    profile_endpoint = profile_endpoints[provider.name]
    response = provider.get(profile_endpoint, token=access_token)
    '''
    in_json = json.dumps(response.data)
    print(json.loads(in_json))
    '''

    if provider.name == 'github':
        name = response.data.get('login')
        website = response.data.get('blog')
        github = response.data.get('html_url')
        email = response.data.get('email')
        bio = response.data.get('bio')
        loc = response.data.get('location')
    return name, website, github, email, bio, loc


@oauth_bp.route('/login/<provider_name>')
def oauth_login(provider_name):
    if provider_name not in providers.keys():
        abort(404)
    if current_user.is_authenticated:
        return redirect(url_for('main.index'))

    callback = url_for('.oauth_callback', provider_name=provider_name, _external=True)
    return providers[provider_name].authorize(callback=callback)


@oauth_bp.route('/callback/<provider_name>')
def oauth_callback(provider_name):
    if provider_name not in providers.keys():
        abort(404)

    provider = providers[provider_name]
    response = provider.authorized_response()

    if response is not None:
        access_token = response.get('access_token')
    else:
        access_token = None

    if access_token is None:
        flash('Access denied, please try again.')
        return redirect(url_for('auth.login'))

    name, website, github, email, bio, loc = get_social_profile(provider, access_token)

    user = User.query.filter_by(email=email).first()
    if user is None:
        user = User(
            email=email,
            username=name,
            about_me=bio,
            location=loc
        )
        user.confirmed = True
        db.session.add(user)
        db.session.commit()
        login_user(user, remember=True)
        return redirect(url_for('main.user', username=name))
    login_user(user, remember=True)
    return redirect(url_for('main.index'))
