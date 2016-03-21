#!/usr/bin/env python

from flask import Flask, render_template, redirect, url_for, session
from flask_wtf import Form
import ldap
import ldap.modlist
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
			d = {
				'user' : form.user.data,
				'uid' : form.uid.data,
				'gn' : form.gn.data,
				'sn' : form.sn.data,
			}

			# add user
			user_dn = app.config.get('USER_DN').format(**d)
			attrs = {}
			for k,v in app.config.get('USER_ATTRS').iteritems():
				if type(v) == str:
					attrs[k] = v.format(**d)
				elif isinstance(v, list):
					attrs[k] = []
					for e in v:
						attrs[k].append(e.format(**d))
			l.add_s(user_dn, ldap.modlist.addModlist(attrs))

			# add user to group
			group_dn = app.config.get('GROUP_DN').format(**d)
			l.modify_s(group_dn, [(ldap.MOD_ADD, 'memberUid', str(form.user.data))])

		except ldap.LDAPError as e:
			l.unbind_s()
			return render_template('error.html', message=e.message['desc'] + ": " + e.message['info'], nav=buildNav())
		else:
			l.unbind_s()
			return render_template('success.html', message="User successfully created.", nav=buildNav())

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
			rdb.hset(session['uuid'], 'pswd', npwd)
			l.unbind_s()
			return render_template('success.html', message="User successfully edited.", nav=buildNav())

	form.user.data = user
	return render_template('edit.html', form=form, nav=buildNav())


@app.route('/login', methods=['GET', 'POST'])
def login():
	form = LoginForm()

	if form.validate_on_submit():
		user = ""
		if form.user.data.endswith(app.config.get('LDAP_BASE','')):
			user = form.user.data
		else:
			user = app.config.get('USER_DN').format(user=form.user.data)
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
