from ca.models import DBSession
from ca.security.authn.user import User

from pyramid.response import Response
from pyramid.view import view_config


@view_config(route_name='home', renderer='templates/home.pt')
def home(request):
	user = User.authenticated(request)
	user_msg = ('You are not currently logged in.' if not user
				else 'You are currently logged in as %s.' % user.login)
	return dict(user=user_msg, project='CA')

@view_config(route_name='test')
def sandbox(request):
	return Response()

