from .models import DBSession
from security.authorization import capability_finder
from security.authorization import CapabilityAuthorizationPolicy

import pyramid.tweens
from pyramid.authentication import AuthTktAuthenticationPolicy
from pyramid.config import Configurator

from pyramid_beaker import session_factory_from_settings

from sqlalchemy import engine_from_config


AUTH_SECRET = 'thisisasecret'
AUTH_SECURE = False
AUTH_COOKIE = 'AUTH_TICKET'
AUTH_TIMEOUT = 600
AUTH_REISSUE = AUTH_TIMEOUT // 10


def main(global_config, **settings):
	""" This function returns a Pyramid WSGI application.
	"""
	engine = engine_from_config(settings, 'sqlalchemy.')
	DBSession.configure(bind=engine)

	config = Configurator(settings=settings)
	
	session_factory = session_factory_from_settings(settings)
	config.set_session_factory(session_factory)

	authn_policy = AuthTktAuthenticationPolicy(AUTH_SECRET, secure=AUTH_SECURE,
			http_only=True, include_ip=True, cookie_name=AUTH_COOKIE, wild_domain=False,
			timeout=AUTH_TIMEOUT, reissue_time=AUTH_REISSUE, callback=capability_finder)
	authz_policy = CapabilityAuthorizationPolicy()
	config.set_authentication_policy(authn_policy)
	config.set_authorization_policy(authz_policy)

	config.add_static_view('static', 'static', cache_max_age=3600)
	config.add_route('home', '/')
	config.add_route('test', '/test')
	config.add_route('login', '/login')
	config.add_route('logout', '/logout')

	config.scan()
	return config.make_wsgi_app()
