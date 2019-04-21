from wtforms import StringField, SubmitField, BooleanField, SelectField, TextAreaField, IntegerField
from wtforms.validators import DataRequired, Email, Regexp, ValidationError
from flask_wtf import FlaskForm
from wtforms.validators import Length
from ..models import Role, User, Category
from flask_pagedown.fields import PageDownField
from flask_ckeditor import CKEditorField


class EditProfileForm(FlaskForm):
    name = StringField('Real name', validators=[Length(0, 64)])
    location = StringField('Your location', validators=[Length(0, 64)])
    about_me = TextAreaField('About me', validators=[Length(0, 64)])
    submit = SubmitField('Submit')


class EditProfileAdminForm(FlaskForm):
    email = StringField('Email address', validators=[DataRequired(), Length(1, 64), Email()])
    username = StringField('Username', validators=[DataRequired(),
                                                   Length(1, 64),
                                                   Regexp('^[A-Za-z][A-Za-z0-9_.]*$', 0, 'Username must have only letters,'
                                                          'numbers, dots or underscores')])
    confirmed = BooleanField('Confirmed')
    role = SelectField('Role', coerce=int)
    name = StringField('Name', validators=[Length(0, 64)])
    location = StringField('Location', validators=[Length(0, 64)])
    about_me = TextAreaField('About me', render_kw={'placeholder':'Please input something about you'})
    submit = SubmitField('Submit')

    def __init__(self, user, *args, **kwargs):
        super(EditProfileAdminForm, self).__init__(*args, **kwargs)
        self.role.choices = [(role.id, role.name) for role in Role.query.order_by(Role.name).all()]
        self.user = user

    def validate_email(self, field):
        if field.data != self.user.email and User.query.filter_by(email=field.data).first():
            raise ValidationError('Email already registered')

    def validate_username(self, field):
        if field.data != self.user.username and User.query.filter_by(username=field.data).first():
            raise ValidationError('Username already in use')


class PostForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired(), Length(1, 64)])
    category = SelectField('Category', coerce=int, default=1)
    body = CKEditorField('Body', validators=[DataRequired()])
    submit = SubmitField('Submit')

    def __init__(self, *args, **kwargs):
        super(PostForm, self).__init__(*args, **kwargs)
        self.category.choices = [(category.id, category.name)
                                 for category in Category.query.order_by(Category.name).all()]


class CommentForm(FlaskForm):
    body = CKEditorField('Comment in here.', validators=[DataRequired()])
    submit = SubmitField('Submit')


class CategoryForm(FlaskForm):
    category = StringField('New category', validators=[DataRequired(), Length(1, 20)])
    submit = SubmitField('Submit')

    def validate_name(self, field):
        if Category.query.filter_by(name=field.data).first():
            raise ValidationError('Category already existed')

