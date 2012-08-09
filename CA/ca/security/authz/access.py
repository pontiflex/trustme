from ca.security.authz.action import Action
from ca.security.authz.capability import (
		Capability,
		AccessCapability,
		FilterCapability,
	)
from ca.security.authz.predicate import predicate

from ca.security.authn.user import User

from ca.models import Base, DBSession

from pyramid.httpexceptions import HTTPAccepted, HTTPForbidden

from sqlalchemy import and_, or_, not_
from sqlalchemy import Column, Sequence, ForeignKey
from sqlalchemy import String, Integer, Boolean
from sqlalchemy.orm import relationship, backref

from time import time


ADDR_LENGTH = 39
ENTER = 'request'
FILTER = ('accept', 'reject')
EXIT = ('approve', 'deny')


class Access(object):
	def __init__(self, request):
		self.user = User.authenticated(request)
		self.address = request.client_addr
		self.time = time() // 1
		self.__performed = False

	def record(self, action, capability, allowed):
		return AccessRecord(self, action, capability, allowed)

	def save(self, *args, **kwargs):
		DBSession.add(self.record(*args, **kwargs))

	def allowable(self, action):
		pending = (self.filtered, lambda(a): self.processed(a, None))
		return self.__acceptable(action, EXIT, pending)

	def filters(self, action, auto):
		def degenerate(a):
			return True if isinstance(a, Action) else {}
		q1 = degenerate if auto else self.requested
		requested = (q1, lambda(a): self.filtered(a, None))
		return self.__acceptable(action, FILTER, requested, auto)

	def processes(self, action, auto):
		q1 = lambda(a): not self.filtered(a, False) if auto else self.filtered(a, True)
		filtered = (q1, lambda(a): self.processed(a, None))
		return self.__acceptable(action, EXIT, filtered, auto)

	def __acceptable(self, action, access_types, q_funcs, auto=False):
		if isinstance(action, Action):
			action_type, obj = action.type, True			
			if not q_funcs[0](action) or q_funcs[1](action):
				return []
		else:
			action_type, obj = action, False
			query = q_funcs[0](action).except_(q_funcs[1](action))

		if not auto and self.user is None:
			return False
		cap_cls = FilterCapability if auto else AccessCapability
		caps = cap_cls.usable(user=(None if auto else self.user),
							  action_type=action_type,
							  access_types=access_types)
		if not caps:
			return False
		ret = [] if obj else {}
		for cap in caps:
			cons = cap.constraint
			if obj:
				if cons is None or cons.allows(action, self):
					ret.append(cap)
			else:
				q = query if cons is None else query.filter(cons.condition(self))
				for action in q:
					cap_list = ret.get(action, [])
					cap_list.append(cap)
					ret[action] = cap_list
		return ret

	@classmethod
	def requested(cls, action):
		if isinstance(action, Action):
			return action in cls.requested(action.type)
		return (DBSession.query(Action)
					.join(AccessRecord)
					.filter(AccessRecord.capability == None)
					.distinct())

	@classmethod
	def filtered(cls, action, success=True):
		if isinstance(action, Action):
			if action not in cls.filtered(action.type, success=None): return False
			elif success is None: return True
			else: return success != (action in cls.filtered(action.type, success=False))
		query = (DBSession.query(Action)
					.join(AccessRecord).join(Capability)
					.filter(AccessRecord.allowed == True))
		if success is None:
			query = query.filter(Capability.access_type.in_(FILTER))
		else:
			query = query.filter(Capability.access_type ==
						 (FILTER[0] if success else FILTER[1]))
		return query.distinct()		

	@classmethod
	def processed(cls, action, success=True):
		if isinstance(action, Action):
			if action not in cls.processed(action.type, success=None): return False
			elif success is None: return True
			else: return success != (action in cls.processed(action.type, success=False))
		query = (DBSession.query(Action)
					.join(AccessRecord).join(Capability)
					.filter(AccessRecord.allowed == True))
		if success is None:
			query = query.filter(Capability.access_type.in_(EXIT))
		else:
			query = query.filter(Capability.access_type ==
						 (EXIT[0] if success else EXIT[1]))
		return query.distinct()

	def perform(self, action, capability=None):
		ret = self.__perform(action, capability)
		self.__performed = True
		return ret

	def __perform(self, action, capability, vetted=False, value=None):
		# Don't perform the access again
		if not vetted and self.__performed:
			raise HTTPForbidden('Cannot perform access again')
		allowed = True

		try:

			if capability is None:
				at = ENTER
			else:
				at = capability.access_type
				# Verify that the action is allowed by the capability
				if not vetted:
					cons = capability.constraint
					if cons is not None and not cons.allows(action, self):
						raise HTTPForbidden('Invalid capability')

			if at in EXIT:
				# Make sure that the action has been filtered but not processed
				# before making any attempt to process its execution
				if not vetted and not self.processes(action, False):
					raise HTTPForbidden('Action not available for processing')
				if at == EXIT[0]:
					# If the access is an approval for processing, perform the action
					return action.perform()
				# Otherwise, logging this access is enough to mark the action as denied
				return HTTPForbidden('DENIED')  if vetted else 'Request marked as denied'
			elif at in FILTER:
				# Filtering is only done automatically
				if not vetted:
					raise RuntimeError('Request filtering must be automatic')
				if at == FILTER[0]:
					# If this access is letting the action through the filter, failure to
					# take further automatic action should simply stop execution. Possible
					# automatic accesses are drawn from the EXIT list
					types = EXIT
					filters = self.processes(action, True)
					def fail(msg): return value
				else:
					# Otherwise, logging this access is enough to mark the action as rejected
					return HTTPForbidden('Request Rejected')
			elif at == ENTER:
				# If this access is a new request, failure should raise an unauthorized
				# exception and store the failed access. Possible automatic accesses are
				# drawn from the FILTER list
				types = FILTER
				filters = self.filters(action, True)
				value = HTTPAccepted(action.serial)
				def fail(msg): raise HTTPForbidden(msg)
			else: raise RuntimeError('%s is not a valid access type' % str(at))

			# If no filters actually match the action, then the attempt at automatic
			# access should fail closed immediately (lack of a no does not mean yes)
			if not filters: return fail('No filters matched access')

			pos = [cap for cap in filters if cap.access_type == types[0]]
			neg = [cap for cap in filters if cap.access_type == types[1]]
			if neg:
				# If any negative filters were triggered, perform a negative access
				self.__perform(action, neg[0], True, value)
				DBSession.add_all((self.record(action, cap, True) for cap in neg[1:]))
				DBSession.add_all((self.record(action, cap, False) for cap in pos))
			else:
				# Otherwise, perform a positive access
				self.__perform(action, pos[0], True, value)
				DBSession.add_all((self.record(action, cap, True) for cap in pos[1:]))

		except:
			allowed = False
			raise
		finally:
			self.save(action, capability, allowed)

		if value is None:
			raise RuntimeException('Illegal return state')
		return value
		





class AccessRecord(Base):
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

	def __init__(self, info, action, capability, allowed):
		self.address = info.address
		self.time = info.time
		self.action = action
		self.capability = capability
		self.allowed = allowed

