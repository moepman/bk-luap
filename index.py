#!/usr/bin/env python

from flask import Flask, render_template, redirect, url_for, session
from flask_wtf import Form
import ldap
from redis import Redis
import uuid
from wtforms.fields import IntegerField, PasswordField, SelectField, StringField, SubmitField
from wtforms.validators import EqualTo, Required

app = Flask(__name__)
app.config.from_pyfile('config.cfg')
app.jinja_env.trim_blocks = True
app.jinja_env.lstrip_blocks = True

rdb = Redis(host=app.config.get('REDIS_HOST', '127.0.0.1'), password=app.config.get('REDIS_PSWD'))


class ReadonlyStringField(StringField):
	def __call__(self, *args, **kwargs):
		kwargs.setdefault('readonly', True)
		return super(ReadonlyStringField, self).__call__(*args, **kwargs)

class CreateForm(Form):
	user = StringField('Username', validators = [Required()])
	uid = IntegerField('User ID', validators = [Required()])
	gn = StringField('Given Name', validators = [Required()])
	sn = StringField('Family Name', validators = [Required()])
	pwd1 = PasswordField('Password', validators = [Required()])
	pwd2 = PasswordField('Password (repeat)', validators = [Required(), EqualTo('pwd1', "Passwords must match")])
	submit = SubmitField('Submit')

class EditForm(Form):
	user = ReadonlyStringField('Username')
	pwd1 = PasswordField('New Password', validators = [Required()])
	pwd2 = PasswordField('New Password (repeat)', validators = [Required(), EqualTo('pwd1', "Passwords must match")])
	submit = SubmitField('Submit')

class LoginForm(Form):
	user = StringField('Username', validators=[Required()])
	pswd = PasswordField('Password', validators=[Required()])
	submit = SubmitField('Login')


def isAdmin():
	return isLoggedin() and rdb.hget(session['uuid'], 'user') in app.config.get('ADMINS', [])

def isLoggedin():
	return 'uuid' in session and rdb.exists(session['uuid'])


def buildNav():
	nav = []
	if isLoggedin():
		nav.append('edit')
		if isAdmin():
			nav.append('create')
		nav.append('logout')
	else:
		nav.append('login')
	return nav


@app.route('/')
def index():

	return render_template('index.html', nav=buildNav())


@app.route('/create', methods=['GET', 'POST'])
def create():
	if not isLoggedin():
		return render_template('error.html', message="You are not logged in. Please log in first.", nav=buildNav())

	form = CreateForm()

	if form.validate_on_submit():
		l = ldap.initialize(app.config.get('LDAP_URI', 'ldaps://127.0.0.1'))
		try:
			l.simple_bind_s(rdb.hget(session['uuid'], 'user'), rdb.hget(session['uuid'], 'pswd'))
			# TODO implement
			#l.add_s()
		except:
			l.unbind_s()
		else:
			# TODO display success message
			l.unbind_s()
			pass

	return render_template('create.html', form=form, nav=buildNav())


@app.route('/edit', methods=['GET', 'POST'])
def edit():
	if not isLoggedin():
		return render_template('error.html', message="You are not logged in. Please log in first.", nav=buildNav())

	form = EditForm()
	user = rdb.hget(session['uuid'], 'user')

	if form.validate_on_submit():
		opwd = rdb.hget(session['uuid'], 'pswd')
		npwd = form.pwd1.data
		l = ldap.initialize(app.config.get('LDAP_URI', 'ldaps://127.0.0.1'))
		try:
			l.simple_bind_s(user, opwd)
			l.passwd_s(user, opwd, npwd)
		except ldap.INVALID_CREDENTIALS as e:
			form.user.errors.append(e.message['desc'])
			l.unbind_s()
			return render_template('edit.html', form=form, nav=buildNav())
		else:
			# TODO display success message
			rdb.hset(session['uuid'], 'pswd', npwd)
			l.unbind_s()
			return redirect(url_for('index'))

	form.user.data = user
	return render_template('edit.html', form=form, nav=buildNav())


@app.route('/login', methods=['GET', 'POST'])
def login():
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
			return render_template('login.html', form=form, nav=buildNav())
		l.unbind_s()

		session['uuid'] = str(uuid.uuid4())
		credentials = { 'user': user, 'pswd': pswd }
		rdb.hmset(session['uuid'], credentials)
		# TODO refactor this and reuse
		rdb.expire(session['uuid'], app.config.get('SESSION_TIMEOUT', 3600))

		return redirect(url_for('index'))
	return render_template('login.html', form=form, nav=buildNav())


@app.route('/logout')
def logout():
	if 'uuid' in session:
		rdb.delete(session['uuid'])
		del session['uuid']
	return redirect(url_for('index'))


if __name__ == '__main__':
	app.run(host='0.0.0.0', port=5000)
