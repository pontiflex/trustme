from ca.security.ui.literal import HTML

from ca.security.authz.access import Access, EXIT
from ca.security.authz.action import Action
from ca.security.authz.capability import Capability, TEMPLATE as CAP_TEMPLATE

from ca.models import DBSession

from pyramid.httpexceptions import (
		HTTPException,
		HTTPBadRequest,
		HTTPForbidden,
		HTTPNotFound,
	)
from pyramid.renderers import render
from pyramid.security import Authenticated
from pyramid.view import view_config


FORM_TEMPLATE = 'ca:templates/security/ui/review.pt'


def review_page(request, action_class, **kwargs):
	# Back up the content type, in case it gets changed by a renderer
	content_type = request.response.content_type
	try:
		access = Access(request)
		allowable = access.allowable(action_class.subtype())
		if allowable is False:
			simple = action_class.readable()
			raise HTTPForbidden("You don't have sufficient permissions to review %s requests" % simple)
		present = Capability.present(request.session.get_csrf_token())

		serial_field = 'SERIAL'
		cap_field = 'CAPS'

		answer = ''
		POST = request.POST
		if serial_field in POST and (EXIT[0] in POST or EXIT[1] in POST):
			serial = POST[serial_field]
			choice = EXIT[0] if EXIT[0] in POST else EXIT[1]
			action = DBSession.query(action_class).filter(Action.serial == serial).first()
			if action is None:
				raise HTTPNotFound('Invalid serial number')
			if action not in allowable:
				raise HTTPForbidden('Action not available for processing')
			tokens = POST.getall(cap_field)
			caps = [c for c in allowable[action] if present(c) in tokens
												 and c.access_type == choice]
			if not caps:
				return HTTPForbidden('Provided capabilities are insufficient')
			try:
				answer = access.perform(action, caps[0])
			except HTTPException as e:
				answer = e.detail
			else:
				del allowable[action]

		forms = []
		cap_params = dict(post_key=cap_field, hash_func=present)
		form_params = dict(serial_field=serial_field)
		button_options = {EXIT[0]:'Allow', EXIT[1]:'Deny'}
		for action, caps in allowable.iteritems():
			cap_params['capabilities'] = caps
			render_template, render_params = action.render('pending')
			form_params['info'] = HTML(render(render_template, render_params, request))
			form_params['serial'] = action.serial
			form_params['credentials'] = HTML(render(CAP_TEMPLATE, cap_params, request))
			choices = set((c.access_type for c in caps))
			form_params['buttons'] = ((c, button_options[c]) for c in choices)
			forms.append(HTML(render(FORM_TEMPLATE, form_params, request)))
		if not forms:
			forms.append('No requests are available for processing')
	finally:
		request.response.content_type = content_type
	
	return dict(forms=forms, answer=HTML(answer), **kwargs)


	
