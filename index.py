#!/usr/bin/env python

from flask import Flask, render_template, redirect, url_for, session
from flask_wtf import Form
from wtforms.fields import PasswordField, SelectField, StringField, SubmitField
from wtforms.validators import Required

app = Flask(__name__)
app.config['SECRET_KEY'] = 'CHANGE!ME'
app.jinja_env.trim_blocks = True
app.jinja_env.lstrip_blocks = True


@app.route('/')
def index():
	return render_template('index.html')


if __name__ == '__main__':
	app.run(host='0.0.0.0', port=5000, debug=True)
