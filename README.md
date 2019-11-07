# Binary Kitchen: Directory Self-Service

## Overview

This Directory Self-Service is intended as a portal that allow Users to change their LDAP passwords and also supports the creations of new users based on a simple template.

## Requirements

* Flask >= 1.0.0
* Flask-WTF >= 0.14
* passlib >= 1.7.0
* python-ldap >= 3.1.0
* redis >= 3.1.0

## uWSGI

To use dss with uWSGI create a file called uwsgi.ini from the provided example and change the socket and optinally the chdir,uid and gid settings. You can use `/usr/bin/uwsgi --ini /path/to/dss/uwsgi.ini` to start your instance.

## Misc

Source code is under MIT license, powered by Flask and Bootstrap.
