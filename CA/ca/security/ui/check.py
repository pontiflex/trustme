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

from ca.security.ui.literal import HTML
from ca.security.ui.render import render

from ca.security.authz.access import Access
from ca.security.authz.action import Action

from ca.models import DBSession

from pyramid.httpexceptions import HTTPException, HTTPNotFound
from pyramid.view import view_config


TEMPLATE = 'ca:templates/security/ui/check.pt'


def __check(action_class, serial):
	req = (DBSession.query(action_class)
			.filter(Action.serial == serial)
			.first())
	if req is None:
		return HTTPNotFound('Invalid serial number')
	if Access.processed(req, True):
		return req.render('approved', True)
	if Access.processed(req, False):
		return req.render('denied', True)
	if Access.filtered(req):
		return req.render('pending', True)
	return req.render('rejected', True)

def check_page(request, action_class, **kwargs):
	serial, serial_field, form_field = '', 'SERIAL', 'FORM'
	anon = form_field not in request.POST

	answer = ''
	if serial_field in request.POST:
		serial = request.POST[serial_field]
		res = __check(action_class, serial)
		if isinstance(res, HTTPException):
			if anon: raise res
			answer = res.detail
		else:
			answer = render(res[0], res[1], request)
			if anon: return rendered

	params = dict(serial=serial, serial_field=serial_field, form_field=form_field)
	form = render(TEMPLATE, params)

	return dict(form=HTML(form), answer=HTML(answer), **kwargs)


