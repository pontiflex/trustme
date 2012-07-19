from ..action import Action, FieldType
from ..predicate import predicate

from sqlalchemy import Column, Integer

import operator


class IntField(FieldType):
	__tablename__ = 'intfields'
	__mapper_args__ = {'polymorphic_identity':'int'}
	value = Column(Integer, nullable=False)

	def __init__(self, action, name, value):
		super().__init__(action, name)
		self.value = value

	@classmethod
	def _op(cls, name, op, value):
		return Action.id.in_(cls.name_query(name).filter(op(cls.value, value)))

	@predicate
	@classmethod
	def gt(cls, name, value): return cls._op(name, operator.gt, value)

	@predicate
	@classmethod
	def lt(cls, name, value): return cls._op(name, operator.lt, value)

	@predicate
	@classmethod
	def eq(cls, name, value): return cls._op(name, operator.eq, value)

