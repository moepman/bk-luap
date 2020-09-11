#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import uuid

import ldap
import ldap.modlist
from flask import Flask, render_template, redirect, url_for, session
from flask_wtf import FlaskForm
from passlib.hash import ldap_salted_sha1
from redis import Redis
from wtforms.fields import IntegerField, PasswordField, StringField, SelectField, SubmitField
from wtforms.validators import EqualTo, DataRequired

app = Flask(__name__)
app.config.from_pyfile('config.cfg')
app.jinja_env.trim_blocks = True
app.jinja_env.lstrip_blocks = True

rdb = Redis(host=app.config.get('REDIS_HOST', '127.0.0.1'), password=app.config.get('REDIS_PASSWD'), decode_responses=True)

ldap.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_DEMAND)
ldap.set_option(ldap.OPT_REFERRALS, 0)
if 'LDAP_CA' in app.config.keys():
    ldap.set_option(ldap.OPT_X_TLS_CACERTFILE, app.config.get('LDAP_CA'))


class CreateForm(FlaskForm):
    user = StringField('Username', validators=[DataRequired()])
    uid = IntegerField('User ID', validators=[DataRequired()])
    gn = StringField('Given Name', validators=[DataRequired()])
    sn = StringField('Family Name', validators=[DataRequired()])
    pwd1 = PasswordField('Password', validators=[DataRequired()])
    pwd2 = PasswordField('Password (repeat)', validators=[DataRequired(), EqualTo('pwd1', "Passwords must match")])
    group_pri = SelectField('Primary group', validators=[DataRequired()])
    submit = SubmitField('Submit')


class EditForm(FlaskForm):
    user = StringField('Username', render_kw={'readonly': True})
    pwd1 = PasswordField('New Password', validators=[DataRequired()])
    pwd2 = PasswordField('New Password (repeat)', validators=[DataRequired(), EqualTo('pwd1', "Passwords must match")])
    submit = SubmitField('Submit')


class LoginForm(FlaskForm):
    user = StringField('Username', validators=[DataRequired()])
    pswd = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')


def make_secret(password):
    return ldap_salted_sha1.encrypt(password)


def is_admin():
    return is_loggedin() and rdb.hget(session['uuid'], 'user') in app.config.get('ADMINS', [])


def is_loggedin():
    return 'uuid' in session and rdb.exists(session['uuid'])


def build_nav():
    nav = []
    if is_loggedin():
        nav.append(('Edit own Account', 'edit'))
        if is_admin():
            nav.append(('List Accounts', 'list_users'))
            nav.append(('Create Account', 'create'))
        nav.append(('Logout', 'logout'))
    else:
        nav.append(('Login', 'login'))
    return nav


def get_groups():
    ldap_connection = ldap.initialize(app.config.get('LDAP_URI', 'ldaps://127.0.0.1'))
    ldap_connection.simple_bind_s(rdb.hget(session['uuid'], 'user'), rdb.hget(session['uuid'], 'pswd'))
    sr = ldap_connection.search_s(app.config.get('LDAP_BASE'), ldap.SCOPE_SUBTREE, app.config.get('GROUP_FILTER'), ['cn', 'gidNumber'])
    groups = {attr['cn'][0].decode(errors='ignore'): {'gidNumber': attr['gidNumber'][0].decode(errors='ignore'), 'dn': dn} for dn, attr in sr}
    return groups


@app.route('/')
def index():
    return render_template('index.html', nav=build_nav())


@app.route('/create', methods=['GET', 'POST'])
def create():
    if not is_loggedin():
        return render_template('error.html', message="You are not logged in. Please log in first.", nav=build_nav())

    if not is_admin():
        return render_template('error.html', message="You do not have administrative privileges. Please log in using an administrative account.",
                               nav=build_nav())

    form = CreateForm()
    groups = get_groups()
    form.group_pri.choices = [(group, group) for group in groups.keys()]

    if form.validate_on_submit():
        ldap_connection = ldap.initialize(app.config.get('LDAP_URI', 'ldaps://127.0.0.1'))
        try:
            ldap_connection.simple_bind_s(rdb.hget(session['uuid'], 'user'), rdb.hget(session['uuid'], 'pswd'))
            user_data = {
                'user': form.user.data,
                'uid': form.uid.data,
                'gn': form.gn.data,
                'sn': form.sn.data,
                'pass': make_secret(form.pwd1.data),
                'gid': groups[form.group_pri.data]['gidNumber']
            }

            # add user
            user_dn = app.config.get('USER_DN').format(**user_data)
            attrs = {}
            for key, value in app.config.get('USER_ATTRS').items():
                if isinstance(value, str):
                    attrs[key] = value.format(**user_data).encode()
                elif isinstance(value, list):
                    attrs[key] = []
                    for element in value:
                        attrs[key].append(element.format(**user_data).encode())
            ldap_connection.add_s(user_dn, ldap.modlist.addModlist(attrs))

            # add user to group
            group_dn = groups[form.group_pri.data]['dn']
            ldap_connection.modify_s(group_dn, [(ldap.MOD_ADD, 'memberUid', str(form.user.data).encode())])

        except ldap.LDAPError as err:
            ldap_connection.unbind_s()
            message = "LDAP Error"
            if 'desc' in err.args[0]:
                message = message + " " + err.args[0]['desc']
            if 'info' in err.args[0]:
                message = message + ": " + err.args[0]['info']
            return render_template('error.html', message=message, nav=build_nav())
        else:
            ldap_connection.unbind_s()
            return render_template('success.html', message="User successfully created.", nav=build_nav())

    return render_template('create.html', form=form, nav=build_nav())


@app.route('/edit', methods=['GET', 'POST'])
def edit():
    if not is_loggedin():
        return render_template('error.html', message="You are not logged in. Please log in first.", nav=build_nav())

    form = EditForm()
    creds = rdb.hgetall(session['uuid'])

    if form.validate_on_submit():
        npwd = form.pwd1.data
        ldap_connection = ldap.initialize(app.config.get('LDAP_URI', 'ldaps://127.0.0.1'))
        try:
            ldap_connection.simple_bind_s(creds['user'], creds['pswd'])
            ldap_connection.passwd_s(creds['user'], creds['pswd'], npwd)
        except ldap.INVALID_CREDENTIALS:
            form.user.errors.append('Invalid credentials')
            ldap_connection.unbind_s()
            return render_template('edit.html', form=form, nav=build_nav())
        else:
            rdb.hset(session['uuid'], 'pswd', npwd)
            ldap_connection.unbind_s()
            return render_template('success.html', message="User successfully edited.", nav=build_nav())

    form.user.data = creds['user']
    return render_template('edit.html', form=form, nav=build_nav())


@app.route('/list')
def list_users():
    if not is_loggedin():
        return render_template('error.html', message="You are not logged in. Please log in first.", nav=build_nav())

    if not is_admin():
        return render_template('error.html', message="You do not have administrative privileges. Please log in using an administrative account.",
                               nav=build_nav())

    ldap_connection = ldap.initialize(app.config.get('LDAP_URI', 'ldaps://127.0.0.1'))
    ldap_connection.simple_bind_s(rdb.hget(session['uuid'], 'user'), rdb.hget(session['uuid'], 'pswd'))
    sr = ldap_connection.search_s(app.config.get('LDAP_BASE'), ldap.SCOPE_SUBTREE, '(objectClass=posixAccount)', ['cn', 'uidNumber'])
    accounts = [(attr['cn'][0].decode(errors='ignore'), attr['uidNumber'][0].decode(errors='ignore'), dn) for dn, attr in sr]
    return render_template('list.html', accounts=accounts, nav=build_nav())


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()

    if form.validate_on_submit():
        if form.user.data.endswith(app.config.get('LDAP_BASE', '')):
            user = form.user.data
        else:
            user = app.config.get('USER_DN').format(user=form.user.data)
        pswd = form.pswd.data
        ldap_connection = ldap.initialize(app.config.get('LDAP_URI', 'ldaps://127.0.0.1'))
        try:
            ldap_connection.simple_bind_s(user, pswd)
        except ldap.INVALID_CREDENTIALS:
            form.pswd.errors.append('Invalid credentials')
            ldap_connection.unbind_s()
            return render_template('login.html', form=form, nav=build_nav())
        ldap_connection.unbind_s()

        session['uuid'] = str(uuid.uuid4())
        credentials = {'user': user, 'pswd': pswd}
        rdb.hmset(session['uuid'], credentials)
        # TODO refactor this and reuse
        rdb.expire(session['uuid'], app.config.get('SESSION_TIMEOUT', 3600))

        return redirect(url_for('index'))
    return render_template('login.html', form=form, nav=build_nav())


@app.route('/logout')
def logout():
    if 'uuid' in session:
        rdb.delete(session['uuid'])
        del session['uuid']
    return redirect(url_for('index'))


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
