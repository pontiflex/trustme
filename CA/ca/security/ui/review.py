from ca.security.ui.literal import HTML
from ca.security.ui.render import render

from ca.security.authz.access import Access, EXIT
from ca.security.authz.action import Action
from ca.security.authz.policy import offer_creds, check_creds

from ca.models import DBSession

from pyramid.httpexceptions import (
		HTTPException,
		HTTPBadRequest,
		HTTPForbidden,
		HTTPNotFound,
	)
from pyramid.security import Authenticated
from pyramid.view import view_config


FORM_TEMPLATE = 'ca:templates/security/ui/review.pt'


def review_page(request, action_class, **kwargs):
	access = Access(request)
	allowable = access.allowable(action_class)
	if allowable is False:
		simple = action_class.readable()
		raise HTTPForbidden("You don't have sufficient permissions to review %s requests" % simple)

	serial_field = 'SERIAL'

	answer = ''
	POST = request.POST
	if serial_field in POST and (EXIT[0] in POST or EXIT[1] in POST):
		serial = POST[serial_field]
		action = DBSession.query(action_class).filter(Action.serial == serial).first()
		if action is None:
			raise HTTPNotFound('Invalid serial number')
		if action not in allowable:
			raise HTTPForbidden('Action not available for processing')
		if EXIT[0] in POST and EXIT[1] in POST:
			raise ValueError('Both "%s" and "%s" specified in form' % EXIT)
		choice = EXIT[1] if EXIT[1] in POST else EXIT[0]
		caps = [c for c in allowable[action] if c.access_type == choice]
		try:
			answer = access.perform_with_one(action, caps)
		except HTTPException as e:
			answer = e.detail
		else:
			del allowable[action]

	forms = []
	form_params = dict(serial_field=serial_field)
	button_options = {EXIT[0]:'Allow', EXIT[1]:'Deny'}
	for action, caps in allowable.iteritems():
		render_template, render_params = action.render('pending')
		form_params['info'] = HTML(render(render_template, render_params, request))
		form_params['serial'] = action.serial
		form_params['credentials'] = offer_creds(request, caps)
		choices = set((c.access_type for c in caps))
		form_params['buttons'] = ((c, button_options[c]) for c in choices)
		forms.append(HTML(render(FORM_TEMPLATE, form_params, request)))
	if not forms:
		forms.append('No requests are available for processing')
	
	return dict(forms=forms, answer=HTML(answer), **kwargs)


	
