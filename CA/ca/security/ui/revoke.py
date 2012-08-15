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


FORM_TEMPLATE = 'ca:templates/security/ui/revoke.pt'


def revoke_page(request, action_class, **kwargs):
	access = Access(request)
	revocable = access.revocable(action_class)
	if revocable is False:
		simple = action_class.readable()
		raise HTTPForbidden("You don't have sufficient permissions to revoke %s requests" % simple)

	serial_field = 'SERIAL'

	answer = ''
	POST = request.POST
	if serial_field in POST:
		serial = POST[serial_field]
		action = DBSession.query(action_class).filter(Action.serial == serial).first()
		if action is None:
			raise HTTPNotFound('Invalid serial number')
		if action not in revocable:
			raise HTTPForbidden('Action not available for revocation')
		try:
			answer = access.perform_with_one(action, revocable[action])
		except HTTPException as e:
			answer = e.detail
		else:
			del revocable[action]

	forms = []
	form_params = dict(serial_field=serial_field, button='Revoke')
	button_options = {EXIT[0]:'Allow', EXIT[1]:'Deny'}
	for action, caps in revocable.iteritems():
		render_template, render_params = action.render('approved')
		form_params['info'] = HTML(render(render_template, render_params, request))
		form_params['serial'] = action.serial
		form_params['credentials'] = offer_creds(request, caps)
		forms.append(HTML(render(FORM_TEMPLATE, form_params, request)))
	if not forms:
		forms.append('No requests are available for revocation')
	
	return dict(forms=forms, answer=HTML(answer), **kwargs)


	
