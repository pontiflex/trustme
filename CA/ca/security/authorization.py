from capability import Capability
from user import User

from pyramid.security import Everyone, Authenticated
from pyramid.view import view_config

from itertools import imap


AUTH_POST_KEY = '_capabilities_'




class CapabilityAuthorizationPolicy:
	def permits(self, context, principals, permission):
		allowed = {}
		for p in principals:
			split = p.split(':')
			if split[0] == 'capability' and len(split) == 3:
				perms = allowed.get(split[1], [])
				perms.append(split[2])
				allowed[split[1]] = perms

		for p in permission.split(';'):
			split = p.split(':')
			if split[0] == 'capability' and len(split) >= 3:
				perms = allowed.get(split[1], [])
				for access in split[2:]:
					if access not in perms:
						return False
				
		return True

	def principals_allowed_by_permission(self, context, permission):
		raise NotImplementedError()




def capability_finder(userid, request):
	principals = [Everyone]
	user = User.get(userid)
	if user is not None:
		principals.append('user:%s' % userid)
		principals.append(Authenticated)
		tokens = request.POST.getall(AUTH_POST_KEY)
		presented = Capability.presented(user, request.session.get_csrf_token())
		principals.extend((('capability:%s:%s' % (c.action, c.type))
							for c in imap(presented, tokens)
							if c is not None and c.user is user))
	print principals
	return principals

def allow(request, caps, target=None, button='Go', id=None, form=''):
	if not caps:
		return ''
	present = Capability.present(request.session.get_csrf_token())
	keys = ''.join(('<input type="hidden" name="%s" value="%s" />'
						% (AUTH_POST_KEY, cap)
					 for cap in map(present, caps)))
	if target is None:
		return keys
	id = ' ' if id is None else ' id="%s" ' % str(id)
	open = '<form%smethod="POST" action="%s">%s' % (id, target, keys)
	close = '%s<input type="submit" value="%s" /></form>' % (form, button)
	return open + close

def clear(request):
	def callback(req, resp):
		resp.delete_cookie(AUTH_POST_KEY)
	request.add_response_callback(callback)










