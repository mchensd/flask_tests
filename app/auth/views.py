from flask import render_template, redirect, url_for, flash, request
from flask_login import login_user, logout_user, current_user
from .. import db
from .forms import LoginForm, RegistrationForm, PasswordChangeForm, ResetPasswordForm, NewPasswordForm
from ..models import User
from . import auth
from flask_login import login_required
from .. import email

@auth.route("/login", methods=['GET', 'POST'])
def login():
    form = LoginForm()

    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        pw_in = form.password.data
        if user is not None and user.verify_password(pw_in):
            login_user(user, form.remember_me.data)
            flash("Successfully logged in!")

            next = request.args.get('next')
            return redirect(next or url_for("main.index"))

        flash('Invalid username or password')

    return render_template('auth/login.html', form=form)

@auth.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for('main.index'))


@auth.route("/register", methods=['GET','POST'])
def register():
    form = RegistrationForm()

    if form.validate_on_submit():
        user = User(email=form.email.data, username=form.username.data, password=form.password.data)
        db.session.add(user)
        db.session.commit()

        token = user.generate_confirmation_token()
        email.send_email(user.email, "Confirm Your Account", 'auth/email/confirm', user=user, token=token)

        flash('A confirmation link has been sent to you by email.')

        return redirect(url_for('auth.login'))
    return render_template('auth/register.html', form=form)

@auth.route('/confirm/<token>')
@login_required
def confirm(token):
    if current_user.confirmed:
        return redirect(url_for("main.index"))
    if current_user.confirm(token):
        flash("You have confirmed your account. Thanks!")
    else:
        flash("Error: Invalid Confirmation")
    return redirect(url_for("main.index"))

@auth.before_app_request
def before_request():
    print("request endpoint: %r" % request.endpoint)
    if current_user.is_authenticated and not current_user.confirmed and request.endpoint[:5] != 'auth.' and request.endpoint != 'static':
        return redirect(url_for('auth.unconfirmed'))


@auth.route('/confirm')  # resend confirmation email
@login_required
def resend_confirmation():
    token = current_user.generate_confirmation_token()
    email.send_email(current_user.email, "Confirm Your Account", 'auth/email/confirm', user=current_user, token=token)
    flash("A new confirmation link has been sent to you by email")
    return redirect(url_for("main.index"))

@auth.route('/unconfirmed')
def unconfirmed():
    if current_user.is_anonymous or current_user.confirmed:
        return redirect(url_for("main.index"))
    return render_template('auth/unconfirmed.html')

@auth.route('/change-password', methods=['GET','POST'])
@login_required
def change_pw():

    form = PasswordChangeForm()

    if form.validate_on_submit():
        print(form.old.data)
        print(form.new.data)

        if not current_user.verify_password(form.old.data):
            flash("You incorrectly entered your old password")

        else:
            current_user.password = form.new.data
            flash("Successfully changed password!")
        return redirect(url_for("auth.change_pw"))

    return render_template("auth/change_pw.html", form=form)

@auth.route("reset-password", methods=['GET','POST'])
def reset_pw():
    form = ResetPasswordForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        token = user.generate_confirmation_token()
        email.send_email(form.email.data, "Reset Your Password", 'auth/email/reset', token=token)
        flash("An email has been sent with instructions to reset your password")

        return redirect(url_for('auth.reset_pw'))
    return render_template('auth/reset_pw.html', form=form)

@auth.route("reset-password/<token>", methods=['GET','POST'])
def reset(token):
    if current_user.confirm(token):
        form = NewPasswordForm()
        if form.validate_on_submit():
            current_user.password = form.new.data
            db.session.add(current_user)
            flash("Successfully Reset Password!")
            return redirect(url_for("auth.login"))
        return render_template('auth/new_pw.html', form=form)
    else:
        flash("Error: Invalid Link")

    return redirect(url_for('main.index'))

#TODO: Reset password, how to verify url/token?