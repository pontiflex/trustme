from ca.security.authz.capability import AdminCapability
from ca.security.authn.user import User

from ca.models import DBSession

from pyramid.security import remember
from pyramid.httpexceptions import HTTPFound
from pyramid.view import view_config


ROUTE = 'setup_admin'
TEMPLATE = 'ca:templates/security/setup/admin.pt'


def needs_admin(info, request):
	return DBSession.query(User).count() == 0


def _validate_username(username):
	if len(username) < 3:
		return 'Username must be at least 3 characters long'
	return ''

def _validate_email(email):
	return ''

def _validate_password(password):
	if len(password) < 8:
		return 'Password must be at least 8 characters long'
	return ''


@view_config(route_name=ROUTE, renderer=TEMPLATE)
def setup_admin(request):
	name_length = User.login.property.columns[0].type.length
	mail_length = User.email.property.columns[0].type.length

	username, email, pass1, pass2, message = '', '', '', '', ''

	if 'form.submitted' in request.params:
		username = request.POST['username']
		email = request.POST['email']
		pass1 = request.POST['pass1'].encode('utf-8')
		pass2 = request.POST['pass2'].encode('utf-8')
		if not message:	message = _validate_username(username)
		if not message:	message = _validate_email(email)
		if not message:	message = _validate_password(pass1)
		if not message and pass1 != pass2:
			message = "Passwords don't match"
		if not message:
			user = User(username, email, pass1)
			DBSession.add(user)
			DBSession.add(AdminCapability(user))
			return HTTPFound(location=request.route_url('home'),
							 headers=remember(request, username))

	return dict(
		name_length = name_length,
		mail_length = mail_length,
		message = message,
		username = username,
		email = email,
		pass1 = pass1,
		pass2 = pass2
		)

