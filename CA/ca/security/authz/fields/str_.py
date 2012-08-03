from ca.security.authz.action import Action, Field
from ca.security.authz.predicate import predicate

from sqlalchemy import Column, ForeignKey, Integer, String


LENGTH = 100


class StrField(Field):
	__tablename__ = 'strfields'
	__mapper_args__ = {'polymorphic_identity':'str'}
	id = Column(Integer, ForeignKey(Field.id), primary_key=True)
	value = Column(String(LENGTH), nullable=False)

	def __init__(self, action, name, value):
		super(StrField, self).__init__(action, name)
		self.value = value

	@predicate
	@classmethod
	def like(cls, name, pattern):
		return Action.id.in_(cls.name_query(name).filter(cls.value.like_(pattern)))

	@predicate
	@classmethod
	def equals(cls, name, value):
		return Action.id.in_(cls.name_query(name).filter(cls.value==value))

