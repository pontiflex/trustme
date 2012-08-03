from ca.security.authz.action import Action
from ca.security.authz.capability import Capability, FilterCapability
from ca.security.authz.predicate import predicate

from ca.models import Base, DBSession

from pyramid.httpexceptions import HTTPForbidden

from sqlalchemy import and_, not_
from sqlalchemy import Column, Sequence, ForeignKey
from sqlalchemy import String, Integer, Boolean
from sqlalchemy.orm import relationship, backref

from time import time


ADDR_LENGTH = 39
ENTER = 'request'
FILTER = ('accept', 'reject')
EXIT = ('approve', 'deny')


class Access(Base):
	__tablename__ = 'accesses'

	id = Column(Integer, Sequence('access_id_seq'), primary_key=True)
	action_id = Column(Integer, ForeignKey(Action.id), nullable=False, index=True)
	cap_id = Column(Integer, ForeignKey(Capability.id))

	time = Column(Integer, nullable=False)
	address = Column(String(ADDR_LENGTH))

	# Initial requests are allowed as long as they matched some filter (accept OR reject)
	# Negative filter accesses are always allowed, while affirmatives are allowed only
	# if no negatives were triggered
	# Negative process accesses are always allowed, while affirmatives are allowed only
	# if no negatives were triggered
	allowed = Column(Boolean, nullable=False)

	# Accesses should never be implicitly added to the session, so save-update cascades are off
	action = relationship(Action, backref=backref('accesses', order_by=time, cascade=''), cascade=False)
	capability = relationship(Capability, backref=backref('accesses', order_by=time, cascade=''), cascade='')

	def __init__(self, request, capability=None):
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
		self.allowed = None

	@staticmethod
	def requested(action, success=True):
		return (DBSession.query(Access)
					.filter(Access.action == action)
					.filter(Access.capability == None)
				.count() > 0)

	@staticmethod
	def filtered(action, success=True):
		request = (DBSession.query(Access).join(Capability)
						.filter(Access.action == action)
						.filter(Access.allowed == True))
		count = request.filter(Capability.access_type.in_(FILTER)).count()

		if count == 0:		return False
		if success is None:	return True
		return success == (count == request.filter(Capability.access_type == FILTER[0]).count())

	@staticmethod
	def processed(action, success=True):
		request = (DBSession.query(Access).join(Capability)
						.filter(Access.action == action)
						.filter(Access.allowed == True))
		count = request.filter(Capability.access_type.in_(EXIT)).count()

		if count == 0:		return False
		if success is None:	return True
		return success == (count == request.filter(Capability.access_type == EXIT[0]).count())

	def action_type(self):
		if self.capability is None:
			return None if self.action is None else self.action.type
		return self.capability.action_type

	def access_type(self):
		return ENTER if self.capability is None else self.capability.access_type

	def _set_action_if_allowed(self, action):
		if action is None or self.action is not None:
			return False
		if self.capability is not None:
			if action.type != self.action_type():
				return False
			if self.capability.constraint is not None:
				if not self.capability.constraint.allows(action):
					return False
		self.action = action
		return True

	def _filters(self, *access_types):
		# Grab all filters from the database that aren't obviously revoked or
		# expired and act on the appropriate action and access types
		return (FilterCapability.maybe_valid(self.time)
						.filter(Capability.action_type == self.action_type())
						.filter(Capability.access_type.in_(access_types)))

	def perform(self, action=None, value=False):
		# Don't perform the access again. This is the only error condition which
		# should prevent the access from being logged
		if not self.vetted and self.allowed is not None:
			raise HTTPForbidden('Cannot perform access again')
		DBSession.add(self)

		try:

			# If this access wasn't vetted by a previous one, make sure
			# that it actually allows the supplied action
			if not self.vetted and not self._set_action_if_allowed(action):
				raise HTTPForbidden('Invalid capability')

			# By default the action is now allowed, unless there's an exception
			self.allowed = True
	
			at = self.access_type()
			if at in EXIT:
				# Make sure that the action has been filtered but not processed
				# before making any attempt to process its execution
				if not self.vetted:
					if not self.filtered(self.action):
						raise HTTPForbidden('Cannot process unfiltered action')
					if self.processed(self.action, None):
						raise HTTPForbidden('Cannot process action again')
				if at == EXIT[0]:
					# If the access is an approval for processing, perform the action
					return self.action.perform()
				# Otherwise, logging this access is enough to mark the action as denied
				return 'Denied'
			elif at in FILTER:
				# Make sure that the action has been requested but not filtered
				# before making any attempt to process its filtration
				if not self.vetted:
					if not self.requested(self.action):
						raise HTTPForbidden('Cannot filter unrequested action')
					if self.filtered(self.action, None):
						raise HTTPForbidden('Cannot filter action again')
				if at == FILTER[0]:
					# If this access is letting the action through the filter, failure to
					# take further automatic action should simply stop execution. Possible
					# automatic accesses are drawn from the EXIT list
					types = EXIT
					def fail(msg): return value
				else:
					# Otherwise, logging this access is enough to mark the action as rejected
					return 'Rejected'				
			elif at == ENTER:
				# If this access is a new request, failure should raise an unauthorized
				# exception and store the failed access. Possible automatic accesses are
				# drawn from the FILTER list
				types = FILTER
				value = action.serial
				def fail(msg): raise HTTPForbidden(msg)
			else: raise RuntimeError('%s is not a valid access type' % str(at))

			# If no filters actually match the action, then the attempt at automatic
			# access should fail closed immediately (lack of a no does not mean yes)
			filters = [cap for cap in self._filters(*types)
						   if cap.constraint is None
						   or cap.constraint.allows(self.action)]
			if not filters: return fail('No filters matched access')

			def children(allowed, type):
				def make(cap):
					child = Access(self, cap)
					child.allowed = allowed
					return child
				of_type = lambda(cap):(cap.access_type == type)
				return map(make, filter(of_type, filters))

			# Retrieve the types of automatic access that were triggered
			# and process them accordingly
			applied = set((c.access_type for c in filters))
			neg = []
			pos = []
			if FILTER[1] in applied:
				# Any filter rejected the access, then 
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
			do = neg[0] if neg else pos[0]
			value = do.perform(value=value)
			DBSession.add_all(neg)
			DBSession.add_all(pos)

		except:
			# In the event of an exception, set the access as not allowed and reraise
			self.allowed = False
			raise
		finally:
			# Mark the access as not vetted to prevent repeat access during this session
			self.vetted = False
		return value

			

	def targets(self):
		if self.capability is None:
			return []
		if self.capability.constraint is None:
			return []
		targets = self.capability.constraint.query(self)

		at = self.access_type()
		if at in FILTER:
			return targets.join(Access).filter(Access.capability == None)
		elif at in EXIT:
			return (targets.join(Access).join(Capability)
							.filter(Capability.access_type == FILTER[0])
							.distinct())
		else: assert False
