from ca.security.authz.action import Action
from ca.security.authz.capability import Capability
from ca.security.authz.predicate import get_predicate

from ca.models import Base, DBSession

from sqlalchemy import and_, or_, not_
from sqlalchemy import Column, ForeignKey, Sequence
from sqlalchemy import Integer, Boolean, String, PickleType
from sqlalchemy.orm import relationship, backref, reconstructor
from sqlalchemy.ext.declarative import declared_attr


class Constraint(Base):
	__tablename__ = 'constraints'
	id = Column(Integer, Sequence('constraint_id_seq'), primary_key=True)
	type = Column(String(50), nullable=False)
	predicate = Column(String(30), nullable=False)
	args = Column(PickleType, nullable=False)
	kwargs = Column(PickleType, nullable=False)

	@declared_attr
	def __mapper_args__(cls):
		if cls.__name__ == 'Constraint':
			return {'polymorphic_on':cls.type}
		else:
			return {'polymorphic_identity':cls.__name__}

	def __new__(cls, *args, **kwargs):
		if not issubclass(cls, Concrete):
			raise TypeError('%s cannot be directly instantiated' % cls.__name__)
		return super(Constraint, cls).__new__(cls, *args, **kwargs)

	def __init__(self, predicate, *args, **kwargs):
		self.predicate = predicate.__name__
		self.args = args
		self.kwargs = kwargs

	def condition(self, access_info, action_class=None):
		action_class = self._action_class(action_class)
		target = self._target(action_class, access_info)
		conds = [get_predicate(target, self.predicate)(*self.args, **self.kwargs)]
		conds.extend((child.condition(access_info, action_class) for child in self.children))
		cond = self._negate(self._merge(*conds))
		return cond

	def query(self, access_info, action_class=None):
		action_class = self._action_class(action_class)
		return DBSession.query(action_class).filter(self.condition(access_info, action_class))

	def allows(self, action, access_info, action_class=None):
		action_class = self._action_class(action_class)
		return (isinstance(action, action_class)
				and action in self.query(access_info, action_class))

	def constrain(self, subconstraint):
		if subconstraint is not None and subconstraint.clause is not None:
			raise ValueError('Constraint already applied')
		self.constraint = subconstraint
		return self



class Concrete(object): pass

class BaseConstraint(Constraint):
	__tablename__ = 'base_constraints'
	id = Column(Integer, ForeignKey(Constraint.id), primary_key=True)
	cap_id = Column(Integer, ForeignKey(Capability.id))
	capability = relationship(Capability,
				backref=backref('constraint', uselist=False))

	def _action_class(self, action_class):
		if action_class is None:
			if self.capability is None:
				raise ValueError('Action class must be specified when no capability is bound')
			action_class = self.capability.action_class
		return action_class

class SubConstraint(Constraint):	
	__tablename__ = 'sub_constraints'
	id = Column(Integer, ForeignKey(Constraint.id), primary_key=True)
	clause_id = Column(Integer, ForeignKey(id))	
	clause = relationship(lambda:Constraint, remote_side=[id],
				backref=backref('children', order_by=id))

	def _action_class(self, action_class):
		if action_class is None:
			raise ValueError('Action class must be specified when no capability is bound')

class AndConstraint(object):
	def _merge(self, conds):
		return and_(conds)

class OrConstraint(object):
	def _merge(self, conds):
		return or_(conds)

class NegatedConstraint(object):
	def _negate(self, cond):
		return not_(cond)

class LiteralConstraint(object):
	def _negate(self, cond):
		return cond

class ActionConstraint(object):
	def _target(self, action_class, access_info):
		return action_class

class AccessConstraint(object):
	def _target(self, action_class, access_info):
		return access_info
	
class AndBaseConstraint(BaseConstraint, AndConstraint, LiteralConstraint, ActionConstraint, Concrete): pass
class OrBaseConstraint(BaseConstraint, OrConstraint, LiteralConstraint, ActionConstraint, Concrete): pass
class NandBaseConstraint(BaseConstraint, AndConstraint, NegatedConstraint, ActionConstraint, Concrete): pass
class NorBaseConstraint(BaseConstraint, OrConstraint, NegatedConstraint, ActionConstraint, Concrete): pass
class AndBaseAccessConstraint(BaseConstraint, AndConstraint, LiteralConstraint, ActionConstraint, Concrete): pass
class OrBaseAccessConstraint(BaseConstraint, OrConstraint, LiteralConstraint, ActionConstraint, Concrete): pass
class NandBaseAccessConstraint(BaseConstraint, AndConstraint, NegatedConstraint, ActionConstraint, Concrete): pass
class NorBaseAccessConstraint(BaseConstraint, OrConstraint, NegatedConstraint, ActionConstraint, Concrete): pass
class AndSubConstraint(SubConstraint, AndConstraint, LiteralConstraint, ActionConstraint, Concrete): pass
class OrSubConstraint(SubConstraint, OrConstraint, LiteralConstraint, ActionConstraint, Concrete): pass
class NandSubConstraint(SubConstraint, AndConstraint, NegatedConstraint, ActionConstraint, Concrete): pass
class NorSubConstraint(SubConstraint, OrConstraint, NegatedConstraint, ActionConstraint, Concrete): pass
class AndSubAccessConstraint(SubConstraint, AndConstraint, LiteralConstraint, ActionConstraint, Concrete): pass
class OrSubAccessConstraint(SubConstraint, OrConstraint, LiteralConstraint, ActionConstraint, Concrete): pass
class NandSubAccessConstraint(SubConstraint, AndConstraint, NegatedConstraint, ActionConstraint, Concrete): pass
class NorSubAccessConstraint(SubConstraint, OrConstraint, NegatedConstraint, ActionConstraint, Concrete): pass

