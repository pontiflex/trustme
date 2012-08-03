from ca.models import DBSession
from ca.security.authn.user import User

from pyramid.response import Response
from pyramid.view import view_config

from sqlalchemy.exc import DBAPIError


@view_config(route_name='home', renderer='templates/home.pt')
def home(request):
	request.session
	try:
		one = DBSession.query(User).filter(User.login=='root').first()
	except DBAPIError:
		return Response(conn_err_msg, content_type='text/plain', status_int=500)

	user = User.authenticated(request)
	user_msg = ('You are not currently logged in.' if not user
				else 'You are currently logged in as %s.' % user.login)
	return dict(user=user_msg, project='CA')

conn_err_msg = """\
Pyramid is having a problem using your SQL database.  The problem
might be caused by one of the following things:

1.  You may need to run the "initialize_CA_db" script
    to initialize your database tables.  Check your virtual 
    environment's "bin" directory for this script and try to run it.

2.  Your database server may not be running.  Check that the
    database server referred to by the "sqlalchemy.url" setting in
    your "development.ini" file is running.

After you fix the problem, please restart the Pyramid application to
try it again.
"""




from ca.security.authz.access import Access
from ca.security.authz.action import Action, Field
from ca.security.authz.constraint import OrConstraint, AndConstraint
from ca.security.authz.predicate import predicate

class Test(Field):
	__mapper_args__ = {'polymorphic_identity':'test'}

	@predicate
	@classmethod
	def foo(cls, *args, **kwargs):
		return (Action.id.in_(DBSession.query(Action.id).join(Test)))

@view_config(route_name='test')
def sandbox(request):
	print '+' * 50

	access = Access(request)
	cons = OrConstraint(None, Test, 'foo')
	cons2 = AndConstraint(cons, Test, 'foo')
	cons.query(access).all()

	print '-' * 50

	user = User.authenticated(request)
	if user is not None:
		return Response(allow(request, user.capabilities, '/'))
	return Response()

