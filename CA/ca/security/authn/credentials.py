from ca.security.authn.user import User

from ca.models import DBSession


def validate_username(username):
	if len(username) < 3:
		return 'Username must be at least 3 characters long'
	if DBSession.query(User).filter(User.login == username).count() > 0:
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
