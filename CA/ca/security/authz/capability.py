from ca.security.algorithms import default_hash as h, default_mac as mac
from ca.security.algorithms import to64, from64, size64
from ca.security.algorithms import rand64, slow_equals

from ca.security.authn.user import User
from ca.constants.security.authz.values import AUTH_POST_KEY

from ca.models import Base, DBSession

from pyramid.httpexceptions import HTTPFound, HTTPUnauthorized

from sqlalchemy import or_, not_
from sqlalchemy import Column, Sequence, ForeignKey
from sqlalchemy import String, Integer, Enum, Boolean, PickleType
from sqlalchemy.orm import relationship, backref, reconstructor

from time import time


CAP_BYTES = 40

ACCESS_USE = 'access'
GRANT_USE = 'grant'
ADMIN_USE = 'admin'
FILTER_USE = 'filter'
USES = (ACCESS_USE, GRANT_USE, ADMIN_USE, FILTER_USE)
ADMIN_USES = (ADMIN_USE,)
NORMAL_USES = (ACCESS_USE, GRANT_USE, FILTER_USE)


class Capability(Base):
	__tablename__ = 'capabilities'
	__mapper_args__ = {'polymorphic_on':'use', 'with_polymorphic':'*'}

	id = Column(Integer, Sequence('capability_id_seq'), primary_key=True)
	parent_id = Column(Integer, ForeignKey('%s.id' % __tablename__))
	user_id = Column(Integer, ForeignKey(User.id), nullable=False)
	use = Column(Enum(*USES, name='cap_use_types'), nullable=False)

	key = Column(String(size64(CAP_BYTES)), nullable=False)
	action_type = Column(String(30))
	access_type = Column(String(30))

	# FIXME: This should really have a ForeignKey constraint on it
	revoked = Column(Integer, default=None)
	start_time = Column(Integer)
	end_time = Column(Integer)

	delegates = relationship(lambda:Capability, backref=backref('parent', remote_side=[id]))
	user = relationship(User, backref=backref('capabilities'))

	def __new__(cls, *args, **kwargs):
		# Prevent the creation of raw Capability objects
		if cls is Capability:
			raise TypeError('Capability cannot be directly instantiatied')
		return super(Capability, cls).__new__(cls, *args, **kwargs)

	def __init__(self, user, action_type=None, access_type=None, start_time=None, end_time=None, parent=None):
		# Make sure the given user is allowed to have this capability
		if user.is_admin():
			if self.use not in ADMIN_USES:
				raise ValueError("The administrator can't have a capability of type %s" % self.use)
		elif self.use not in NORMAL_USES:
			raise ValueError('Only the administrator can have a capability of type %s' % self.use)

		if parent is not None:
			# Action/access types default to those of a non-admin parent
			if parent.use != ADMIN_USE:
				action_type = parent.action_type
				access_type = parent.access_type
			# Missing start/end times default to those of the parent,
			# while given ones must fall within any limits set by the parent
			if start_time is None: start_time = parent.start_time
			else: start_time = (start_time
					if parent.start_time is None
					else max(start_time, parent.start_time))
			if end_time is None: end_time = parent.end_time
			else: end_time = (end_time
					if parent.end_time is None
					else min(end_time, parent.end_time))

		# Set all the values
		self.user = user
		self.key = rand64(CAP_BYTES)
		self.parent = parent
		self.action_type = action_type
		self.access_type = access_type
		self.start_time = start_time
		self.end_time = end_time

		# Call the reconstructor on new instances as well
		self._init()

	@reconstructor
	def _init(self):
		# Cache local validity
		self._valid, _ = self.__local_valid()

	@staticmethod
	def present(nonce):
		# The function returns a MAC where the key is the given nonce
		# and the plaintext is the unique "key" of a capability
		h = mac.create(nonce)
		def pres(cap):
			h2 = h.copy()
			h2.update(cap.key)
			return to64(h2.digest())
		return pres

	@classmethod
	def presented(cls, user, nonce):
		# Grab the hashing function
		p = cls.present(nonce)
		# Grab the user's capabilities of the given type
		caps = cls.usable(user=user)
		# Compute a dictionary of the hash tokens for each capability
		d = {p(c):c for c in caps}
		# The resulting function looks up the given token in the dictionary
		return lambda(k): d.get(k)

	@classmethod
	def usable(cls, t=None, user=None, action_type=None, access_types=None):
		t = time() // 1 if t is None else t
		query = DBSession.query(cls)
		if user is not None:
			query = query.filter(Capability.user == user)
		if action_type is not None:
			query = query.filter(Capability.action_type == action_type)
		if access_types is not None:
			query = query.filter(Capability.access_type.in_(access_types))
		query = (query.filter(Capability.revoked == None)
					 .filter( or_(Capability.start_time == None,
								  Capability.start_time <= t))
					 .filter( or_(Capability.end_time == None,
								  Capability.end_time >= t)))
		return [cap for cap in query if cap.valid()]

	def __local_valid(self):
		# Check for revocation
		if self.revoked is not None:
			return False, self.revoked
		now = time() // 1
		# Check for early use...
		if self.start_time is not None and now < self.start_time:
			return False, None
		# ...and expiration
		elif self.end_time is not None and now > self.end_time:			
			return False, None
		return True, None

	def valid(self, give_revoked=False):
		# If the cache reads valid, recheck the local validity
		if self._valid:	self._valid, self.revoked = self.__local_valid()

		# If the cache still reads valid, check the recursive
		# parental validity, and save the revoker if one is found
		if self._valid:
			self._valid, self.revoked = ((True, None)
										if self.parent is None
										else self.parent.valid(True))

		# Return the cached validity, and the revoker if requested
		return self._valid, self.revoked if give_revoked else self._valid

	def revoke(self, child):
		# If the capability is already revoked, return its revoker
		if child.revoked is not None:
			return child.revoked

		# Don't allow revocation unless the target capability
		# is a descendant of the calling capability
		parent = child.parent
		while parent is not None:
			# If we find a revoked parent (including the caller)
			# along the way, use that revocation instead
			if parent.revoked is not None:
				child.revoked = parent.revoked
				return child.revoked
			# Break out if the traversal finds the caller
			if parent is self:
				break
			# Otherwise keep traversing up the tree
			parent = child.parent
		# No revocation occurs if the caller wasn't found
		if parent is None:
			return None

		# Mark the child as revoked by this capability
		child.revoked = self.id
		return child.revoked

	def relinquish(self):
		# The capability "revokes" and returns itself
		self.revoked = self.id
		return self

	def constrain(self, constraint):
		if self.constraint is not None:
			raise ValueError('Capability already constrained')
		if constraint is not None and constraint.capability is not None:
			raise ValueError('Constraint already applied')
		self.constraint = constraint
		return self




class AccessCapability(Capability):
	__mapper_args__ = {'polymorphic_identity':ACCESS_USE}

	def auto(self, constraint=None, start_time=None, end_time=None):
		return (FilterCapability(self.user, parent=self, start_time=start_time,
														 end_time=end_time)
				.constrain(constraint))

	@classmethod
	def access(cls, nonce, caps, target=None, button='Go', id=None, form=''):
		# Grab the function to compute hash tokens for the capabilities
		present = cls.present(nonce)
		# Compute the tokens and create a hidden input for each one
		keys = ''.join(('<input type="hidden" name="%s" value="%s" />'
							% (AUTH_POST_KEY, cap)
						 for cap in map(present, caps)))
		# If no target was given, just return the hidden inputs
		if target is None:
			return keys
		# Otherwise return a form with the given id, non-token contents, and button label
		id = ' ' if id is None else ' id="%s" ' % str(id)
		target = ' ' if target is None else ' action="%s"' % str(target)
		open = '<form%smethod="POST"%s>%s' % (id, target, keys)
		close = '%s<input type="submit" value="%s" /></form>' % (form, button)
		return open + close

class GrantCapability(Capability):
	__mapper_args__ = {'polymorphic_identity':GRANT_USE}

	def grant(self, user, constraint=None, start_time=None, end_time=None, grant=False):
		Cap = GrantCapability if grant else AccessCapability
		return (Cap(user, parent=self, start_time=start_time, end_time=end_time)
				.constrain(constraint))

class AdminCapability(Capability):
	__mapper_args__ = {'polymorphic_identity':ADMIN_USE}

	def grant(self, user, action_type, access_type, constraint=None, start_time=None, end_time=None, grant=False):
		Cap = GrantCapability if grant else AccessCapability
		return (Cap(user, action_type, access_type, start_time, end_time, self)
					.constrain(constraint))

class FilterCapability(Capability):
	__mapper_args__ = {'polymorphic_identity':FILTER_USE}

