#!/usr/bin/env python

from flask import Flask, render_template, redirect, url_for, session
from flask_wtf import Form
import ldap
from redis import Redis
from wtforms.fields import PasswordField, SelectField, StringField, SubmitField
from wtforms.validators import Required

app = Flask(__name__)
app.config.from_pyfile('index.cfg')
app.jinja_env.trim_blocks = True
app.jinja_env.lstrip_blocks = True

rdb = Redis(host='127.0.0.1', password='foobared')


class LoginForm(Form):
	user = StringField('Username', validators=[Required()])
	pswd = PasswordField('Password', validators=[Required()])
	submit = SubmitField('Login')


@app.route('/')
def index():
	return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
	form = LoginForm()
	if form.validate_on_submit():
		# TODO implement login with LDAP
		return redirect(url_for('index'))
	return render_template('login.html', form=form)

if __name__ == '__main__':
	app.run(host='0.0.0.0', port=5000)
