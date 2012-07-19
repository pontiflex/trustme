from action import Action
from capability import Capability, FilterCapability
from predicate import predicate

from ..models import Base, DBSession

from pyramid.httpexceptions import HTTPUnauthorized

from sqlalchemy import and_, not_
from sqlalchemy import Column, Sequence, ForeignKey
from sqlalchemy import String, Integer, Boolean
from sqlalchemy.orm import relationship, backref

from time import time


ADDR_LENGTH = 39
ENTRY = 'request'
FILTER = ('accept', 'reject')
EXIT = ('allow', 'deny')


class Access(Base):
	__tablename__ = 'accesses'

	id = Column(Integer, Sequence('access_id_seq'), primary_key=True)
	action_id = Column(Integer, ForeignKey(Action.id), nullable=False, index=True)
	cap_id = Column(Integer, ForeignKey(Capability.id))

	time = Column(Integer, nullable=False)
	address = Column(String(ADDR_LENGTH))
	allowed = Column(Boolean, nullable=False)

	action = relationship(Action, backref=backref('accesses', order_by=time))
	capability = relationship(Capability, backref=backref('accesses', order_by=time))

	def __init__(self, request, capability=None, allowed=None):
		if isinstance(request, Access):
			self.action = request.action
			self.address = request.address
			self.time = request.time
			self.vetted = True
		else:
			self.address = request.client_addr
			self.time = time() // 1
			self.vetted = False
		self.capability = capability

	@staticmethod
	def requested(action):
		request = (DBSession.query(Access)
						.filter(Access.action == action)
						.filter(Access.capability is None).first())
		ret = (request is not None)
		assert ret or action not in DBSession
		return ret

	@staticmethod
	def filtered(action, success_only=True):
		if success_only: cond = (Capability.access_type == FILTER[0])
		else:			 cond = (Capability.access_type.in_(FILTER))
		request = (DBSession.query(Access).join(Capability)
						.filter(Access.action == self.action)
						.filter(cond)
					.first())
		return request is not None

	@staticmethod
	def processed(action, success_only=True):
		if success_only: cond = (Capability.access_type == EXIT[0])
		else:			 cond = (Capability.access_type.in_(EXIT))
		request = (DBSession.query(Access).join(Capability)
						.filter(Access.action == self.action)
						.filter(cond)
					.first())
		return request is not None

	def action_type(self):
		if self.capability is None:
			return None if self.action is None else self.action.type
		return self.capability.action_type

	def access_type(self):
		return ENTRY if self.capability is None else self.capability.access_type

	def _allows(self, action):
		assert self.action is None
		if self.capability:
			if action.type != self.action_type():
				return False
			if self.capability.constraint is None:
				return False
			return self.capability.constraint.allows(action)
		return True

	def _filters(self, *access_types):
		# Grab all filters from the database that aren't obviously revoked or
		# expired and act on the appropriate action and access types
		filters = (FilterCapability.maybe_valid(self.time)
						.filter(Capability.action_type == self.action_type())
						.filter(Capability.access_type in access_types))
		# Restrict the filters to those that are actually valid. Two different
		# filters can't use the same constraint object since the relationship is
		# based on a single field in the constraint. Otherwise, there could be a
		# vulnerability here if a constraint key got overwritten in the map
		return {f.constraint:f for f in filters if f.valid()}

	def perform(self, action=None):
		# Don't perform the access again
		if self.allowed is not None: return

		# If the action parameter was passed, set the action
		# In either case, the action must be set
		action = self.action if action is None else action
		assert action is not None
		self.action = action

		try:

			# Set allowed to False by default to prevent repeat execution
			# If this access wasn't vetted by a previous one, make sure
			# that it actually allows the supplied action
			self.allowed = False
			if not self.vetted and not self._allows(action):
				raise HTTPUnauthorized()
			self.allowed = True

			at = self.access_type()
			if at in FILTER:
				# Make sure that the action has been requested before making any
				# attempt to process its filtration
				if not self.vetted and not self.requested(self.action):
					raise HTTPUnauthorized()

			if at in EXIT:
				# Make sure that the action has been filtered before making any
				# attempt to process its execution
				if not self.vetted and not self.filtered(self.action):
					raise HTTPUnauthorized()
				# Perform the action if appropriate
				if at is EXIT[0]:
					self.action.perform()
				# No further processing is required, just log the access
				return
			elif at is FILTER[1]:
				# No further processing is required, just log the access
				return
			elif at is FILTER[0]:				
				# If this access is letting the action through the filter, failure to
				# take further automatic action should simply stop execution. Possible
				# automatic accesses are drawn from the EXIT list
				types = EXIT
				def fail(): return True
			elif at is ENTER:
				# If this access is a new request, failure should raise an unauthorized
				# exception and store the failed access. Possible automatic accesses are
				# drawn from the FILTER list
				types = FILTER
				def fail():
					raise HTTPUnauthorized()
			else: assert False		# No other types of access are defined

			# If there are any empty filters, or no filters actually match the
			# action, then the attempt at automatic access fails
			filters = self._filters(types)
			if None in filters: return fail()
			filters = {f:c for f,c in filters.iteritems() if f.allows(self.action)}
			if not filters: return fail()

			def children(allowed, type):
				def make(cap):
					child = Access(self, cap)
					child.allowed = allowed
					return child
				of_type = lambda(cap):(cap.access_type == type)
				return map(make, filter(of_type, filters.itervalues()))

			# Retrieve the types of automatic access that were triggered
			# and process them accordingly
			applied = set((c.access_type for c in caps()))
			neg = []
			pos = []
			if FILTER[1] in applied:
				neg = children(True, FILTER[1])
				pos = children(False, FILTER[0])
			elif FILTER[0] in applied:
				pos = children(True, FILTER[0])
			if EXIT[1] in applied:
				neg = children(True, EXIT[1])
				pos = children(False, EXIT[0])
			elif EXIT[0] in applied:
				pos = children(True, EXIT[0])

			# All allowed and denied automatic accesses are logged. If only
			# affirmative accesses were triggered, perform the first one (all
			# should be equivalent, since access predicates are based only on
			# the shared time and address fields)
			DBSession.add_all(neg)
			DBSession.add_all(pos)
			if neg: return fail()
			else: pos[0].perform()

		except:
			# In the event of an exception, set the action as not allowed and reraise
			self.allowed = False
			raise
		finally:
			# We should always log the access attempt
			DBSession.add(self)

			

	def targets(self):
		if self.capability is None:
			return []
		if self.capability.constraint is None:
			return []
		targets = self.capability.constraint.query(self)

		at = self.access_type()
		if at in FILTER:
			return targets.join(Access).filter(Access.capability is None)
		elif at in EXIT:
			return (targets.join(Access).join(Capability)
							.filter(Capability.access_type == FILTER[0])
							.distinct())
		else: assert False

