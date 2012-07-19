from ..action import Action, FieldType
from ..predicate import predicate

from sqlalchemy import Column, String


LENGTH = 100


class StrField(FieldType):
	__tablename__ = 'strfields'
	__mapper_args__ = {'polymorphic_identity':'str'}
	value = Column(String(LENGTH), nullable=False)

	def __init__(self, action, name, value):
		super().__init__(action, name)
		self.value = value

	@predicate
	@classmethod
	def like(cls, name, pattern):
		return Action.id.in_(cls.name_query(name).filter(cls.value.like_(pattern)))

	@predicate
	@classmethod
	def equals(cls, name, value):
		return Action.id.in_(cls.name_query(name).filter(cls.value==value))

