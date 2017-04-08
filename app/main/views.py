from flask import render_template
from flask_login import login_required
from . import main


@main.route("/")
def index():
    return render_template("index.html")


@main.route("/content")
@login_required
def content():
    return render_template("content.html")
