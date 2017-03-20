# Binary Kitchen: Directory Self-Service

## Overview

TBA

## Requirements

* passlib >= 1.6.0
* py-flask >= 0.10
* py-flask-wtf >= 0.10
* py-ldap >= 2.4.15
* py-redis >= 2.10

## uWSGI

To use dss with uWSGI create a file called uwsgi.ini from the provided example and change the socket and optinally the chroot setting. You can use `/usr/bin/uwsgi --ini /path/to/dss/uwsgi.ini` to start your instance.

## Misc

Source code is under MIT license, powered by Flask and Bootstrap.
