from ca.security.authz.access import Access
from ca.security.authz.action import Action

from ca.security.authz.fields.str_ import StrField

from ca.security.authn.user import User
from ca.security.authn.credentials import (
		validate_username,
		validate_email,
		validate_passwords,
	)

from ca.models import DBSession

from pyramid.httpexceptions import HTTPFound, HTTPBadRequest, HTTPNotFound
from pyramid.security import remember, Authenticated
from pyramid.response import Response
from pyramid.view import view_config

from sqlalchemy import Column, ForeignKey, Integer, PickleType
from sqlalchemy.exc import IntegrityError


POLY_ID = 'newuser'
TEMPLATE = 'ca:templates/security/authz/actions/newuser.pt'


#@view_config(route_name='check_user')
def check_user(request):
	# TODO
	return Response()

@view_config(route_name='new_user', renderer=TEMPLATE, permission=Authenticated)
def new_user(request):
	name_field = 'username', User.login.property.columns[0].type.length
	mail_field = 'email', User.email.property.columns[0].type.length
	pass_fields = 'pass1', 'pass2'
	submitted = 'newuser.submitted'

	username, email, passwords, message = '', '', ('', ''), ''

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

	caps, actions = Access.allowable(request, POLY_ID)
	print '+' * 100
	for cap in caps:
		print cap.action_type, cap.access_type
	print '=' * 50
	for action in actions:
		print action.serial
		print '*' * 50
	print '-' * 100

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
		return HTTPFound(headers=remember(request, self.user.login))

