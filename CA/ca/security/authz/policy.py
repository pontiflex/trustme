from ca.security.authz.capability import AccessCapability
from ca.constants.security.authz.values import AUTH_POST_KEY

from ca.security.authn.user import User

from ca.security.ui.literal import HTML

from pyramid.security import Everyone, Authenticated, NO_PERMISSION_REQUIRED
from pyramid.view import view_config

from itertools import imap


DETECTED_CSRF = 'ca.security.authz.policy.__detected_csrf__'


class CapabilityAuthorizationPolicy:
	def permits(self, context, principals, permission):
		# Return True if no permission is needed
		if permission == NO_PERMISSION_REQUIRED:
			return True

		allowed = {}
		user = None
		every, authn = False, False

		for p in principals:
			# Record if Everyone or Authenticated are found in the principals
			if p == Everyone:        every = True
			elif p == Authenticated: authn = True

			# Otherwise, this should be an application principal
			else:				
				split = p.split(':')
				# If this is a capability principal, record its type
				if split[0] == 'capability' and len(split) == 3:
					perms = allowed.get(split[1], [])
					perms.append(split[2])
					allowed[split[1]] = perms
				# If this is a user principal, record the login. Make sure
				# that at most one user principal appears in the list
				elif split[0] == 'user' and len(split) == 2:
					if user is not None:
						raise ValueError('Principals cannot contain more than one user. '
										 + 'Found %s after %s.'
										 % (user, split[1]))
					user = split[1]

		for p in permission.split(';'):
			# If Everyone or Authenticated are required but weren't presented, reject
			if p == Everyone:
				if not every: return False
			elif p == Authenticated:
				if not authn: return False
			# Otherwise, this should be an application permission
			else:
				split = p.split(':')
				# If this is a capability permission, make sure that all required
				# access types were presented for the permission's action type
				if split[0] == 'capability' and len(split) >= 3:
					perms = allowed.get(split[1], [])
					for access in split[2:]:
						if access not in perms:
							return False
				# If this is a user permission, make sure that user was presented
				elif split[0] == 'user' and len(split) == 2:
					if user != split[1]:
						return False
				# Fail closed on an unknown permission
				else:
					raise ValueError('Found unknown permission %s.' % p)
				
		return True

	def principals_allowed_by_permission(self, context, permission):
		raise NotImplementedError()


def offer_creds(request, caps=[None]):
	digest = AccessCapability.present(request.session.get_csrf_token())
	ret = ''
	for cap in caps:
		ret += '<input type="hidden" name="%s" value="%s" />\n' % (AUTH_POST_KEY, digest(cap))
	return HTML(ret)

def check_creds(request, caps=[None]):
	user = User.authenticated(request)
	digest = AccessCapability.present(request.session.get_csrf_token())
	offered = set(request.POST.getall(AUTH_POST_KEY))
	if caps is None:
		caps = [None] if user is None else AccessCapability.usable(user=user)
	return [c for c in caps if digest(c) in offered and (c is None or c.user == user)]


def capability_finder(userid, request):
	# Always include the Everyone principal
	principals = [Everyone]

	# Make sure a user with the provided id actually exists
	user = User.get(userid)
	if user is not None:
		# Include the given user's principal and the Authenticated principal
		principals.append('user:%s' % userid)
		principals.append(Authenticated)

		# Grab the hash tokens present in the request and the hash lookup
		# function for all of the user's valid and applicable capabilities
		tokens = request.POST.getall(AUTH_POST_KEY)
		presented = AccessCapability.presented(user, request.session.get_csrf_token())

		# Add "capability:<action_type>:<access_type>" to the principals for
		# each capability which was correctly presented as a token in the request
		principals.extend((('capability:%s:%s' % (c.action_class.__name__, c.access_type))
							for c in imap(presented, tokens)
							if c is not None))
	return principals

