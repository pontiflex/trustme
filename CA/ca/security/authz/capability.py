from ca.security.algorithms import default_hash as h, default_mac as mac
from ca.security.algorithms import to64, from64, size64
from ca.security.algorithms import rand64, slow_equals
from ca.security.authn.user import User

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
		if cls is Capability:
			raise TypeError('Capability cannot be directly instantiatied')
		return super(Capability, cls).__new__(cls, *args, **kwargs)

	def __init__(self, user, action_type=None, access_type=None, start_time=None, end_time=None, parent=None):
		if user.is_admin():
			if self.use not in ADMIN_USES:
				raise ValueError("The administrator can't have a capability of type %s" % self.use)
		elif self.use not in NORMAL_USES:
			raise ValueError('Only the administrator can have a capability of type %s' % self.use)

		if parent is not None and parent.use != ADMIN_USE:
			action_type = parent.action_type
			access_type = parent.access_type

		self.user = user
		self.key = rand64(CAP_BYTES)
		self.parent = parent
		self.action_type = action_type
		self.access_type = access_type
		self.start_time = start_time
		self.end_time = end_time

		self._init()

	@reconstructor
	def _init(self):
		self._valid = self._localvalid()

	@staticmethod
	def present(nonce):
		h = mac.create(nonce)
		def pres(cap):
			h2 = h.copy()
			h2.update(cap.key)
			return to64(h2.digest())
		return pres

	@classmethod
	def presented(cls, user, nonce):
		p = cls.present(nonce)
		# Collisions are only probabilistically impossible here
		d = {p(c):c for c in user.capabilities if c.valid()}
		print '\n' * 10
		print d
		return lambda(k): d.get(k)

	@classmethod
	def maybe_valid(cls, t=None):
		if t is None: t = time() // 1
		return (DBSession.query(FilterCapability)
						 .filter(Capability.revoked == None)
						 .filter( or_(Capability.start_time == None,
									  Capability.start_time <= t))
						 .filter( or_(Capability.end_time == None,
									  Capability.end_time >= t)))	

	def _localvalid(self):
		if self.revoked is not None:
			return False
		now = time() // 1
		if self.start_time is not None and now < self.start_time:
			return False
		elif self.end_time is not None and now > self.end_time:
			return False
		return True

	def valid(self):
		self._valid = (self._valid and self._localvalid()
					   and (self.parent is None or self.parent.valid()))
		return self._valid

	def revoke(self, child):
		parent = child.parent
		while parent is not None and parent is not self:
			parent = child.parent
		if parent is None:
			return False
		child.revoked = self.id
		return True

	def relinquish(self):
		self.revoked = self.id
		return self

	def constrain(self, constraint):
		if self.constraint is not None:
			raise ValueError()
		if constraint is not None and constraint.capability is not None:
			raise ValueError()
		self.constraint = constraint
		return self
		


class AccessCapability(Capability):
	__mapper_args__ = {'polymorphic_identity':ACCESS_USE}

	def auto(self, constraint=None, start_time=None, end_time=None):
		return (FilterCapability(self.user, parent=self, start_time=start_time,
														 end_time=end_time)
				.constrain(constraint))

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

