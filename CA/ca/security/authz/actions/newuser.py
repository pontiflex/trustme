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

from ca.security.ui.check import check_page
from ca.security.ui.review import review_page

from ca.models import DBSession

from pyramid.httpexceptions import HTTPBadRequest, HTTPForbidden, HTTPNotFound
from pyramid.security import remember, Authenticated
from pyramid.response import Response
from pyramid.view import view_config

from sqlalchemy import Column, ForeignKey, Integer, PickleType
from sqlalchemy.exc import IntegrityError


TEMPLATE = 'ca:templates/security/authz/actions/newuser.pt'
CHECK_TEMPLATE = 'ca:templates/security/ui/check/default.pt'
REVIEW_TEMPLATE = 'ca:templates/security/ui/review/default.pt'



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
	
	


class NewUser(Action):
	__tablename__ = 'new_users'
	__mapper_args__ = {'polymorphic_identity':'newuser'}
	id = Column(Integer, ForeignKey(Action.id), primary_key=True)
	user = Column(PickleType, nullable=False)

	def __init__(self, user):
		super(NewUser, self).__init__()
		self.user = user

		self.fields.append(StrField(self, 'login', user.login))
		self.fields.append(StrField(self, 'email', user.email))

	@classmethod
	def readable(cls):
		return 'new user'

	def perform(self):
		if DBSession.query(User).filter(User.login == self.user.login).count() > 0:
			return HTTPBadRequest('That username already exists')
		DBSession.add(self.user)			
		return 'Account successfully created'

	def render(self, mode):
		params = dict(action=self, mode=mode)
		return 'ca:templates/security/ui/render/newuser.pt', params

@view_config(route_name='check', match_param='type=user', renderer=CHECK_TEMPLATE)
def check_user(request):
	return check_page(request, NewUser)

@view_config(route_name='review', match_param='type=user', renderer=REVIEW_TEMPLATE)
def approve_user(request):
	return review_page(request, NewUser)


