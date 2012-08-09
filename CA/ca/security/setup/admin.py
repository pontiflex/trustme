from ca.security.authz.capability import AdminCapability, GrantCapability
from ca.security.authz.actions.newuser import NewUser
from ca.security.authz.access import FILTER as FILTER_ACCESS, EXIT as PROCESS_ACCESS

from ca.security.authn.user import User
from ca.security.authn.credentials import (
		validate_username,
		validate_email,
		validate_passwords,
	)

from ca.models import DBSession

from pyramid.security import remember
from pyramid.httpexceptions import HTTPFound
from pyramid.view import view_config


TEMPLATE = 'ca:templates/security/setup/admin.pt'


def needs_admin(info, request):
	return DBSession.query(User).count() == 0


@view_config(route_name='home', renderer=TEMPLATE, custom_predicates=(needs_admin,))
def setup_admin(request):
	mail_field = 'email', User.email.property.columns[0].type.length
	pass_fields = 'pass1', 'pass2', 'pass3', 'pass4'
	submitted = 'newuser.submitted'

	email, passwords, message = '', ('', '', '', ''), ''
	email = 'douglasm@pontiflex.com'
	passwords = ('password', 'password', 'password1', 'password1')

	if submitted in request.params:
		email = request.POST[mail_field[0]]
		passwords = (request.POST[pass_fields[0]].encode('utf-8'),
					 request.POST[pass_fields[1]].encode('utf-8'),
					 request.POST[pass_fields[2]].encode('utf-8'),
					 request.POST[pass_fields[3]].encode('utf-8'),)
		if not message:	message = validate_email(email)
		if not message:	message = validate_passwords((passwords[0], passwords[1]))
		if not message:	message = validate_passwords((passwords[2], passwords[3]))
		if not message and passwords[0] == passwords[2]:
			message = 'ROOT and USERS passwords must be different'
		if not message:
			priv_root = User('ROOT', email, passwords[0])
			DBSession.add(priv_root)
			DBSession.add(AdminCapability(priv_root))

			user_root = User('USERS', email, passwords[2])
			DBSession.add(user_root)
			for access_type in FILTER_ACCESS + PROCESS_ACCESS:
				grant = GrantCapability(user_root, NewUser.subtype(), access_type)				
				DBSession.add(grant)
				access = grant.grant(user_root)
				DBSession.add(access)
				if access_type == FILTER_ACCESS[0]:
					DBSession.add(access.auto())

			return HTTPFound(location=request.route_url('home'),
							 headers=remember(request, 'USERS'))

	return dict(
		mail_field = mail_field,
		pass_fields = pass_fields,
		message = message,
		email = email,
		passwords = passwords,
		submitted = submitted,
		)

