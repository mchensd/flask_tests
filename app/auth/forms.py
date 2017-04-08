from flask_login import current_user
from flask_wtf import Form
from wtforms import StringField, PasswordField, SubmitField, BooleanField
from wtforms import ValidationError
from wtforms.validators import Required, Length, Email, Regexp, EqualTo
from ..models import User

class LoginForm(Form):
    email = StringField("Email:", validators=[Required(), Email(), Length(1,64)])
    password = PasswordField("Password:", validators=[Required()])
    remember_me = BooleanField("Keep me logged in")
    submit = SubmitField("Log In")

class RegistrationForm(Form):
    email = StringField("Email:", validators=[Required(), Length(1, 64), Email(message="Enter a real email fool!")])  # change mssage
    username = StringField("Username", validators=[Required(), Length(1, 64), Regexp("^[A-Za-z][A-Za-z0-9_.]*$", flags=0,  # change 1
                                                                      message="Usernames must have only letters, numbers, dots, or underscores")])
    password = PasswordField("Password", validators=[Required(), Length(1,64), EqualTo('password2', message="Passwords Must Match")])
    password2 = PasswordField("Confirm Password", validators=[Required()])
    submit = SubmitField("Register")
    def validate_email(self, field):
        if User.query.filter_by(email=field.data).first():
            raise ValidationError("Error: Email is Already Registered")

    def validate_username(self, field):
        if User.query.filter_by(username=field.data).first():
            raise ValidationError("Error: Username is already being used")

class PasswordChangeForm(Form):
    old = PasswordField("Old Password", validators=[Required()])

    new = PasswordField("New Password", validators=[Required(), EqualTo('new_confirm', message="Passwords must match!")])
    new_confirm = PasswordField("Confirm your new password")
    submit = SubmitField("Change Password")

class NewPasswordForm(PasswordChangeForm):
    old = None

class ResetPasswordForm(Form):
    email = StringField("Enter your email to reset your password", validators=[Length(1,64), Email(message="Not a valid email")])
    submit = SubmitField("Send Email")

    def validate_email(self, field):
        if not User.query.filter_by(email=field.data).first():
            raise ValidationError("That email is not registered")

