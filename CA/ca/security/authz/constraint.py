from ca.security.authz.action import Action, Field
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
	__mapper_args__ = {'polymorphic_on':'conjunctive'}
	id = Column(Integer, Sequence('constraint_id_seq'), primary_key=True)
	cap_id = Column(Integer, ForeignKey(Capability.id))
	clause_id = Column(Integer, ForeignKey(id))
	negated = Column(Boolean, nullable=False, default=False)
	conjunctive = Column(Boolean, nullable=False)

	field = Column(PickleType)
	predicate = Column(String(30), nullable=False)
	args = Column(PickleType, nullable=False)
	kwargs = Column(PickleType, nullable=False)

	capability = relationship(Capability,
				backref=backref('constraint', uselist=False))
	clause = relationship(lambda:Constraint, remote_side=[id],
				backref=backref('children', order_by=id))

	def __new__(cls, *args, **kwargs):
		if cls is Constraint:
			raise TypeError('Constraint cannot be directly instantiatied')
		return super(Constraint, cls).__new__(cls, *args, **kwargs)

	def __init__(self, field, predicate, negated=False, args=[], kwargs={}, clause=None):
		self.field = field
		self.predicate = predicate
		self.negated = negated
		self.args = args
		self.kwargs = kwargs
		self.clause = clause

	def condition(self, access_info):
		field = access_info if self.field is None else self.field
		conds = [get_predicate(field, self.predicate)(*self.args, **self.kwargs)]
		conds.extend((child.condition(access_info) for child in self.children))
		cond = and_(*conds) if self.conjunctive else or_(*conds)
		if self.negated: cond = not_(cond)
		return cond

	def query(self, access_info):
		return DBSession.query(Action).filter(self.condition(access_info))

	def allows(self, action, access_info):
		return action in self.query(access_info)

class AndConstraint(Constraint):
	__mapper_args__ = {'polymorphic_identity':True}

class OrConstraint(Constraint):
	__mapper_args__ = {'polymorphic_identity':False}

