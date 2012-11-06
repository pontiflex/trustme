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

