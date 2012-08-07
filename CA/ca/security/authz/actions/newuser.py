from ca.security.authz.access import Access
from ca.security.authz.action import Action
from ca.security.authz.capability import AccessCapability

from ca.security.authz.fields.str_ import StrField

from ca.security.authn.user import User
from ca.security.authn.credentials import (
		validate_username,
		validate_email,
		validate_passwords,
	)

from ca.models import DBSession

from pyramid.httpexceptions import HTTPBadRequest, HTTPForbidden, HTTPNotFound
from pyramid.security import remember, Authenticated
from pyramid.response import Response
from pyramid.view import view_config

from sqlalchemy import Column, ForeignKey, Integer, PickleType
from sqlalchemy.exc import IntegrityError


POLY_ID = 'newuser'
TEMPLATE = 'ca:templates/security/authz/actions/newuser.pt'



@view_config(route_name='request_user', renderer=TEMPLATE, permission=Authenticated)
def request_user(request):
	name_field = 'username', User.login.property.columns[0].type.length
	mail_field = 'email', User.email.property.columns[0].type.length
	pass_fields = 'pass1', 'pass2'
	submitted = 'newuser.submitted'

	username, email, passwords, message = '', '', ('', ''), ''
	username = 'bob'
	email = 'douglasm@pontiflex.com'
	passwords = ('password', 'password')

	if submitted in request.params:
		username = request.POST[name_field[0]]
		email = request.POST[mail_field[0]]
		passwords = (request.POST[pass_fields[0]].encode('utf-8'),
					 request.POST[pass_fields[1]].encode('utf-8'),)
		if not message:	message = validate_username(username)
		if not message:	message = validate_email(email)
		if not message:	message = validate_passwords(passwords)
		if not message:
			new = NewUser(User(username, email, passwords[0]))
			return Access(request).perform(new)	

	return dict(
		name_field = name_field,
		mail_field = mail_field,
		pass_fields = pass_fields,
		message = message,
		username = username,
		email = email,
		passwords = passwords,
		submitted = submitted,
		)

@view_config(route_name='approve_user', renderer=TEMPLATE, permission=Authenticated)
def approve_user(request):
	action_field = 'action_id'

	performed = None
	access = Access(request)
	allowable = access.allowable(POLY_ID)
	if action_field in request.POST:
		action = DBSession.query(NewUser).get(request.POST[action_field])
		if action is None or action not in allowable:
			raise HTTPNotFound('Invalid action id')
		access.perform(action, allowable[action][0])
		performed = action
	options = ''
	nonce = request.session.get_csrf_token()
	for action in allowable:
		if action is performed:
			continue
		form = '<input type="hidden" name="%s" value="%i" />' % (action_field, action.id)
		for field in action.fields:
			options += '%s<br/>' % (field)
		options += AccessCapability.access(nonce, allowable[action], request.url, 'Confirm', form=form) + '<br/>'
	return Response(options)
	
	


class NewUser(Action):
	__tablename__ = 'new_users'
	__mapper_args__ = {'polymorphic_identity':POLY_ID}
	id = Column(Integer, ForeignKey(Action.id), primary_key=True)
	user = Column(PickleType, nullable=False)

	def __init__(self, user):
		super(NewUser, self).__init__()
		self.user = user

		self.fields.append(StrField(self, 'login', user.login))
		self.fields.append(StrField(self, 'email', user.email))

	def perform(self):
		try:
			DBSession.add(self.user)
		except IntegrityError:
			raise HTTPBadRequest('Username already taken')
		return Response('Account successfully created')

