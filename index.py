#!/usr/bin/env python

from flask import Flask, render_template, redirect, url_for, session
from flask_wtf import Form
import ldap
from redis import Redis
import uuid
from wtforms.fields import PasswordField, SelectField, StringField, SubmitField
from wtforms.validators import Required

app = Flask(__name__)
app.config.from_pyfile('config.cfg')
app.jinja_env.trim_blocks = True
app.jinja_env.lstrip_blocks = True

rdb = Redis(host=app.config.get('REDIS_HOST', '127.0.0.1'), password=app.config.get('REDIS_PSWD'))


class ReadonlyStringField(StringField):
	def __call__(self, *args, **kwargs):
		kwargs.setdefault('readonly', True)
		return super(ReadonlyStringField, self).__call__(*args, **kwargs)

class EditForm(Form):
	user = ReadonlyStringField('Username')
	pswd = PasswordField('Password')
	submit = SubmitField('Submit')

class LoginForm(Form):
	user = StringField('Username', validators=[Required()])
	pswd = PasswordField('Password', validators=[Required()])
	submit = SubmitField('Login')


@app.route('/')
def index():
	nav = None
	if 'uuid' in session:
		nav = ['edit', 'logout']
	else:
		nav = ['login']

	return render_template('index.html', nav=nav)


@app.route('/edit', methods=['GET', 'POST'])
def edit():
	if 'uuid' not in session:
		return redirect(url_for('index'))

	nav = ['edit', 'logout']
	form = EditForm()
	user = rdb.hgetall(session['uuid'])['user']
	form.user.data = user
	return render_template('edit.html', form=form, nav=nav)

@app.route('/login', methods=['GET', 'POST'])
def login():
	nav = ['login']
	form = LoginForm()

	if form.validate_on_submit():
		user = 'cn=' + form.user.data + ',' + app.config.get('LDAP_BASE','')
		pswd = form.pswd.data
		l = ldap.initialize(app.config.get('LDAP_URI', 'ldaps://127.0.0.1'))
		try:
			l.simple_bind_s(user, pswd)
		except ldap.INVALID_CREDENTIALS as e:
			form.pswd.errors.append(e.message['desc'])
			l.unbind_s()
			return render_template('login.html', form=form, nav=nav)
		l.unbind_s()

		session['uuid'] = str(uuid.uuid4())
		credentials = { 'user': user, 'pswd': pswd }
		rdb.hmset(session['uuid'], credentials)
		# TODO refactor this are reuse, make session timeout a config variable
		rdb.expire(session['uuid'], 3600)

		return redirect(url_for('index'))
	return render_template('login.html', form=form, nav=nav)


@app.route('/logout')
def logout():
	if 'uuid' in session:
		rdb.delete(session['uuid'])
		del session['uuid']
	return redirect(url_for('index'))


if __name__ == '__main__':
	app.run(host='0.0.0.0', port=5000)
