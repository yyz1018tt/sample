from flask import render_template, session, redirect, url_for, current_app, flash, request, make_response, abort, \
    send_from_directory
from . import main
from .forms import EditProfileForm, EditProfileAdminForm, CommentForm, PostForm, CategoryForm
from .. import db
from app.models import User
from flask_sqlalchemy import get_debug_queries
from app.email import send_email
from ..decorators import permission_required, admin_required
from ..models import Permission
from flask_login import login_required, current_user
from flask import abort
from ..models import Role, Post, Comment, Category
from ..utils import redirect_back


@main.after_app_request
def after_request(response):
    for query in get_debug_queries():
        if query.duration >= current_app.config['FLASKY_SLOW_DB_QUERY_TIME']:
            current_app.logger.warning(
                'Slow query: %s\nParameters: %s\nDuration: %fs\nContext: %s\n'
                % (query.statement, query.parameters, query.duration,
                   query.context))
    return response


@main.route('/shutdown')
def server_shutdown():
    if not current_app.testing:
        abort(404)
    shutdown = request.environ.get('werkzeug.server.shutdown')
    if not shutdown:
        abort(500)
    shutdown()
    return 'Shutting down...'


@main.route('/edit/<int:id>', methods=['GET', 'POST'])
@login_required
def edit(id):
    post = Post.query.get_or_404(id)
    if current_user != post.author and not current_user.can(Permission.ADMINISTER):
        abort(403)
    form = PostForm()
    if form.validate_on_submit():
        post.title = form.title.data
        post.body = form.body.data
        post.category = Category.query.get(form.category.data)
        db.session.add(post)
        db.session.commit()
        flash('The post has been updated')
        return redirect(url_for('.post', id=post.id))
    form.body.data = post.body
    form.title.data = post.title
    form.category.data = post.category_id
    return render_template('edit_post.html', form=form)


@main.route('/post/<int:id>/delete', methods=['GET', 'POST'])
@login_required
def delete_post(id):
    post = Post.query.get_or_404(id)
    db.session.delete(post)
    db.session.commit()
    flash('Post deleted.')
    return redirect_back()


@main.route('/comment/<int:id>/delete', methods=['GET', 'POST'])
@login_required
def delete_comment(id):
    comment = Comment.query.get_or_404(id)
    db.session.delete(comment)
    db.session.commit()
    flash('Comment deleted.')
    return redirect(url_for('.post', id=comment.post_id))


@main.route('/change-theme/<theme_name>')
def change_theme(theme_name):
    if theme_name not in current_app.config['THEMES'].keys():
        abort(404)

    respones = make_response(redirect_back())
    respones.set_cookie('theme', theme_name, max_age=60*60*24*30)
    return respones


@main.route('/post/<int:id>', methods=['GET', 'POST'])
def post(id):
    post = Post.query.get_or_404(id)
    form = CommentForm()
    if form.validate_on_submit():
        comment = Comment(body=form.body.data, post=post, author=current_user._get_current_object())
        db.session.add(comment)
        flash('Your comment has been published.')
        return redirect(url_for('.post', id=post.id, page=-1))
    page = request.args.get('page', 1, type=int)
    if page == -1:
        page = (post.comments.count() - 1)//20 + 1
    pagination = post.comments.order_by(Comment.timestamp.asc()).paginate(page, error_out=False)
    comments_num = pagination.total
    comments = pagination.items
    return render_template('post.html',
                           posts=[post],
                           form=form,
                           comments=comments,
                           pagination=pagination,
                           comments_num=comments_num,
                           post=post)


@main.route('/show-post/<int:post_id>', methods=['GET', 'POST'])
def show_post(post_id):
    post = Post.query.get_or_404(post_id)
    form = CommentForm()
    if form.validate_on_submit():
        comment = Comment(body=form.body.data, post=post, author=current_user._get_current_object())
        db.session.add(comment)
        flash('Your comment has been published.')
        return redirect(url_for('.post', id=post.id, page=-1))
    page = request.args.get('page', 1, type=int)
    if page == -1:
        page = (post.comments.count() - 1) // 20 + 1
    pagination = post.comments.order_by(Comment.timestamp.asc()).paginate(page, error_out=False)
    comments_num = pagination.total
    comments = pagination.items
    return render_template('show_post.html',
                           posts=[post],
                           form=form,
                           comments=comments,
                           pagination=pagination,
                           comments_num=comments_num,
                           p=post)


@main.route('/', methods=['GET', 'POST'])
def index():
    page = request.args.get('page', 1, type=int)
    show_followed = False
    if current_user.is_authenticated:
        show_followed = bool(request.cookies.get('show_followed', ''))
    if show_followed:
        query = current_user.followed_posts
    else:
        query = Post.query
    pagination = query.order_by(Post.timestamp.desc()).paginate(page, error_out=False)
    posts = pagination.items
    return render_template('sample_index.html',
                           posts=posts,
                           pagination=pagination,
                           show_followed=show_followed)


@main.route('/category/<int:category_id>')
def show_category(category_id):
    category = Category.query.get_or_404(category_id)
    page = request.args.get('page', 1, type=int)
    pagination = Post.query.with_parent(category).order_by(Post.timestamp.desc()).paginate(page, error_out=False)
    posts = pagination.items
    return render_template('category.html',
                           category=category,
                           pagination=pagination,
                           posts=posts)


@main.route('/all')
@login_required
def show_all():
    resp = make_response(redirect(url_for('.index')))
    resp.set_cookie('show_followed', '', max_age=30*24*60*60)
    return resp


@main.route('/followed')
@login_required
def show_followed():
    resp = make_response(redirect(url_for('.index')))
    resp.set_cookie('show_followed', '1', max_age=30*24*60*60)
    return resp


@main.route('/admin')
@login_required
@admin_required
def for_admin_only():
    return 'For administrator only'


@main.route('/moderate')
@login_required
@permission_required(Permission.MODERATE_COMMENTS)
def moderate():
    page = request.args.get('page', 1, type=int)
    pagination = Comment.query.order_by(Comment.timestamp.desc()).paginate(page, error_out=False)
    comments = pagination.items
    return render_template('moderate.html', pagination=pagination, page=page, comments=comments)


@main.route('/moderate/enable/<int:id>')
@login_required
@permission_required(Permission.MODERATE_COMMENTS)
def moderate_enable(id):
    comment = Comment.query.get_or_404(id)
    comment.disable = False
    db.session.add(comment)
    return redirect(url_for('.moderate', page=request.args.get('page', 1, type=int)))


@main.route('/moderate/disable/<int:id>')
@login_required
@permission_required(Permission.MODERATE_COMMENTS)
def moderate_disable(id):
    comment = Comment.query.get_or_404(id)
    comment.disable = True
    db.session.add(comment)
    return redirect(url_for('.moderate', page=request.args.get('page', 1, type=int)))


@main.route('/user/<username>')
def user(username):
    user = User.query.filter_by(username=username).first()
    page = request.args.get('page', 1, type=int)
    pagination = user.posts.order_by(Post.timestamp.desc()).paginate(page, error_out=False)
    posts = pagination.items
    return render_template('sample_user.html', user=user, pagination=pagination, posts=posts)


@main.route('/follow/<username>')
@login_required
@permission_required(Permission.FOLLOW)
def follow(username):
    user = User.query.filter_by(username=username).first()
    if user is None:
        flash('Invalid User!')
        return redirect(url_for('.index'))
    if current_user.is_following(user):
        flash('You have already followed this user.')
        return redirect(url_for('.user', username=username))
    current_user.follow(user)
    flash('You are following %s.' % username)
    return redirect(url_for('.user', username=username))


@main.route('/unfollow/<username>')
@login_required
@permission_required(Permission.FOLLOW)
def unfollow(username):
    user = User.query.filter_by(username=username).first()
    if user is None:
        flash('Invalid User!')
        return redirect(url_for('.index'))
    if not current_user.is_following(user):
        flash('You are not following this user.')
        return redirect(url_for('.user', username=username))
    current_user.unfollow(user)
    flash('You are not following %s anymore.' % username)
    return redirect(url_for('.user', username=username))


@main.route('/followers/<username>')
def followers(username):
    user = User.query.filter_by(username=username).first()
    if user is None:
        flash('Invalid User.')
        return redirect(url_for('.index'))
    page = request.args.get('page', 1, type=int)
    pagination = user.followers.paginate(page, error_out=False)
    follows = [{'user': item.follower, 'timestamp': item.timestamp}
               for item in pagination.items]
    return render_template('followers.html', user=user, pagination=pagination, follows=follows,
                           title='Followers of', endpoint='.followers')


@main.route('/followed-by/<username>')
def followed_by(username):
    user = User.query.filter_by(username=username).first()
    if user is None:
        flash('Invalid user.')
        return redirect(url_for('.index'))
    page = request.args.get('page', 1, type=int)
    pagination = user.followed.paginate(page, error_out=False)
    follows = [{'user': item.followed, 'timestamp': item.timestamp}
               for item in pagination.items]
    return render_template('followers.html', user=user, title="Followed by",
                           endpoint='.followed_by', pagination=pagination,
                           follows=follows)


@main.route('/edit-profile', methods=['GET', 'POST'])
@login_required
def edit_profile():
    form = EditProfileForm()
    if form.validate_on_submit():
        current_user.name = form.name.data
        current_user.location = form.location.data
        current_user.about_me = form.about_me.data
        db.session.add(current_user)
        flash('Your profile has been updated')
        return redirect(url_for('.user', username=current_user.username))
    form.name.data = current_user.name
    form.location.data = current_user.location
    form.about_me.data = current_user.about_me
    return render_template('auth/settings/edit_profile.html', form=form)


@main.route('/edit-profile/<int:id>', methods=['GET', 'POST'])
@login_required
@admin_required
def edit_profile_admin(id):
    user = User.query.get_or_404(id)
    form = EditProfileAdminForm(user=user)
    if form.validate_on_submit():
        user.email = form.email.data
        user.username = form.username.data
        user.confirmed = form.confirmed.data
        user.role = Role.query.get(form.role.data)
        user.name = form.name.data
        user.location = form.location.data
        user.about_me = form.about_me.data
        db.session.add(user)
        flash('The profile has been updated')
        return redirect(url_for('.user', username=user.username))
    form.email.data = user.email
    form.username.data = user.username
    form.confirmed.data = user.confirmed
    form.role.data = user.role_id
    form.name.data = user.name
    form.location.data = user.location
    form.about_me.data = user.about_me
    return render_template('auth/settings/edit_profile.html', form=form, user=user)


@main.route('/post/new', methods=['GET', 'POST'])
@login_required
def new_post():
    form = PostForm()
    if form.validate_on_submit():
        title = form.title.data
        category = Category.query.get(form.category.data)
        body = form.body.data
        post = Post(title=title, category=category, body=body, author=current_user._get_current_object())
        db.session.add(post)
        db.session.commit()
        flash('Post created')
        return redirect(url_for('main.index'))
    return render_template('new_post.html', form=form)


@main.route('/category/new', methods=['GET', 'POST'])
@login_required
def new_category():
    form = CategoryForm()
    if form.validate_on_submit():
        name = form.category.data
        category = Category(name=name)
        db.session.add(category)
        db.session.commit()
        flash('New category created')
        return redirect(url_for('main.index'))
    return render_template('new_category.html', form=form)


@main.route('/post/manage')
@login_required
def manage_post():
    page = request.args.get('page', 1, type=int)
    pagination = Post.query.order_by(Post.timestamp.desc()).paginate(page, error_out=False)
    posts = pagination.items
    return render_template('manage_post.html', page=page, pagination=pagination, posts=posts)


@main.route('/category/manage')
@login_required
def manage_category():
    page = request.args.get('page', 1, type=int)
    pagination = Category.query.order_by(Category.id).paginate(page, error_out=False)
    return render_template('manage_category.html', pagination=pagination, page=page)


@main.route('/category/<int:category_id>/delete', methods=['GET', 'POST'])
@login_required
@admin_required
def delete_category(category_id):
    category = Category.query.get_or_404(category_id)
    if category.name == 'Default':
        flash('You can not delete Default category!')
        return redirect('.delete_category')
    category.delete()
    flash('Category deleted.')
    return redirect(url_for('.manage_category'))


@main.route('/set-comment/<int:post_id>', methods=['GET', 'POST'])
@login_required
def set_comment(post_id):
    post = Post.query.get_or_404(post_id)
    if post.can_comment:
        post.can_comment = False
    else:
        post.can_comment = True
    db.session.commit()
    return redirect_back()


@main.route('/avatars/<path:filename>', methods=['GET', 'POST'])
def get_avatar(filename):
    return send_from_directory(current_app.config['AVATARS_SAVE_PATH'], filename)


@main.route('/search')
def search():
    q = request.args.get('q', '')
    if q == '':
        flash('Enter key about posts, category or user', 'warning')
        return redirect_back()

    category = request.args.get('category', 'Post')
    page = request.args.get('page', 1, type=int)
    if category == 'User':
        pagination = User.query.whooshee_search(q).paginate(page, error_out=False)
    elif category == 'Post':
        pagination = Post.query.whooshee_search(q).paginate(page, error_out=False)
    else:
        pagination = Category.query.whooshee_search(q).paginate(page, error_out=False)
    results = pagination.items
    return render_template('search.html', q=q, category=category, pagination=pagination, results=results)


