from ca.security.algorithms import size64, rand64

from ca.models import Base, DBSession

from sqlalchemy import Column, ForeignKey, Sequence, Index
from sqlalchemy import Integer, String
from sqlalchemy.orm import relationship, backref, reconstructor
from sqlalchemy.ext.declarative import declared_attr


SERIAL_BYTES = 32


class Action(Base):
	__tablename__ = 'actions'
	__mapper_args__ = {'polymorphic_on':'type',  'with_polymorphic':'*'}

	id = Column(Integer, Sequence('action_id_seq'), primary_key=True)
	type = Column(String(30), nullable=False)
	serial = Column(String(size64(SERIAL_BYTES)), nullable=False, unique=True)

	def __new__(cls, *args, **kwargs):
		if cls is Action:
			raise TypeError('Action cannot be directly instantiatied')
		return super(Action, cls).__new__(cls, *args, **kwargs)

	def __init__(self):
		self.serial = rand64(SERIAL_BYTES)

	def perform(self):	pass


class Field(Base):
	__tablename__ = 'fields'
	__mapper_args__ = {'polymorphic_on':'type',  'with_polymorphic':'*'}
	__table_args__ = (Index('field_index', 'action_id', 'name', unique=True), )

	id = Column(Integer, Sequence('field_id_seq'), primary_key=True)
	type = Column(String(30), nullable=False)
	
	action_id = Column(Integer, ForeignKey(Action.id))
	name = Column(String(30), nullable=False)

	action = relationship(Action, backref=backref('fields'))

	def __new__(cls, *args, **kwargs):
		if cls is Field:
			raise TypeError('Field cannot be directly instantiatied')
		return super(Field, cls).__new__(cls, *args, **kwargs)

	def __init__(self, action, name):
		self.action = action
		self.name = name

	@classmethod
	def name_query(cls, name):
		return DBSession.query(Action.id).join(cls).filter(cls.name == name)

