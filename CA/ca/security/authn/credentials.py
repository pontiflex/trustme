"""
Copyright 2012 Pontiflex, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""

from ca.security.authn.user import User

from ca.models import DBSession


"""This file contains functions used to validate user credentials. The validation
functions are currently testing placeholders and perform no rigorous analysis of the
input beyond basic size constraints and existence checking"""


def validate_username(username, allow_existing=False):
	if len(username) < 3:
		return 'Username must be at least 3 characters long'
	if not allow_existing and DBSession.query(User).filter(User.login == username).count() > 0:
		return 'Username already taken'
	return ''

def validate_email(email):
	return ''

def validate_passwords(passwords):
	if passwords[0] != passwords[1]:
		return "Passwords don't match"
	password = passwords[0]
	if len(password) < 8:
		return 'Password must be at least 8 characters long'
	return ''
