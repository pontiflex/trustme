from algorithms import default_hash as h, default_mac as mac
from algorithms import to64, from64, size64
from algorithms import rand64, slow_equals
from user import User

from ..models import Base, DBSession

from pyramid.httpexceptions import HTTPFound, HTTPUnauthorized

from sqlalchemy import or_, not_
from sqlalchemy import Column, Sequence, ForeignKey
from sqlalchemy import String, Integer, Enum, Boolean, PickleType
from sqlalchemy.orm import relationship, backref, reconstructor

from time import time


CAP_BYTES = 40


class Capability(Base):
	__tablename__ = 'capabilities'
	__mapper_args__ = {'polymorphic_on':'use', 'with_polymorphic':'*'}

	id = Column(Integer, Sequence('capability_id_seq'), primary_key=True)
	parent_id = Column(Integer, ForeignKey('%s.id' % __tablename__))
	user_id = Column(Integer, ForeignKey(User.id), nullable=False)
	use = Column(Enum('access', 'grant', 'filter', name='cap_use_types'), nullable=False)

	key = Column(String(size64(CAP_BYTES)), nullable=False)
	action_type = Column(String(30), nullable=False)
	access_type = Column(String(30), nullable=False)

	revoked = Column(Boolean, nullable=False, default=False)
	start_time = Column(Integer)
	end_time = Column(Integer)

	delegates = relationship(lambda:Capability, backref=backref('parent', remote_side=[id]))
	user = relationship(User, backref=backref('capabilities'))

	def __new__(cls, *args, **kwargs):
		if cls is Capability:
			raise TypeError('Capability cannot be directly instantiatied')
		return super(Capability, cls).__new__(cls, *args, **kwargs)

	def __init__(self, user, action_type=None, access_type=None, start_time=None, end_time=None, parent=None):
		self.user = user
		self.key = rand64(CAP_BYTES)

		if parent is None:
			self.parent = None
			if action_type is None: raise ValueError()
			if access_type is None: raise ValueError()
			self.action_type = action_type
			self.access_type = access_type
		else:
			if not parent.valid(): raise ValueError()
			self.parent = parent
			self.action_type = parent.action_type
			self.access_type = parent.access_type
			if start_time is None: start_time = parent.start_time
			if end_time is None: end_time = parent.end_time

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
						 .filter(not_(Capability.revoked))
						 .filter( or_(Capability.start_time == None,
									  Capability.start_time <= t))
						 .filter( or_(Capability.end_time == None,
									  Capability.end_time >= t)))	

	def _localvalid(self):
		if self.revoked:
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
		if child not in self.delegates:
			return False
		child.revoked = True

	def relinquish(self):
		self.revoked = True
		return self

	def constrain(self, constraint):
		if self.constraint is not None:
			raise ValueError()
		if constraint is not None and constraint.capability is not None:
			raise ValueError()
		self.constraint = constraint
		return self
		


class AccessCapability(Capability):
	__mapper_args__ = {'polymorphic_identity':'access'}

	def auto(self, constraint=None, start_time=None, end_time=None):
		return (FilterCapability(self.user, parent=self, start_time=start_time,
														 end_time=end_time)
				.constrain(constraint))

class GrantCapability(Capability):
	__mapper_args__ = {'polymorphic_identity':'grant'}

	def grant(self, user, constraint=None, start_time=None, end_time=None, grant=False):
		Cap = GrantCapability if grant else AccessCapability
		return (Cap(user, parent=self, start_time=start_time, end_time=end_time)
				.constrain(constraint))

class FilterCapability(Capability):
	__mapper_args__ = {'polymorphic_identity':'filter'}

