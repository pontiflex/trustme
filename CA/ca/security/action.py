from predicate import predicate

from ..models import Base, DBSession

from sqlalchemy import Column, ForeignKey, Sequence
from sqlalchemy import Integer, String
from sqlalchemy.orm import relationship, backref, reconstructor
from sqlalchemy.orm.collections import column_mapped_collection
from sqlalchemy.ext.declarative import declared_attr


class Action(Base):
	__tablename__ = 'actions'
	__mapper_args__ = {'polymorphic_on':'type',  'with_polymorphic':'*'}

	id = Column(Integer, Sequence('action_id_seq'), primary_key=True)
	type = Column(String(30), nullable=False)

	def __new__(cls, *args, **kwargs):
		if cls is Action:
			raise TypeError('Action cannot be directly instantiatied')
		return super(Action, cls).__new__(cls, *args, **kwargs)

class Field(Base):
	__tablename__ = 'fields'
	__mapper_args__ = {'polymorphic_on':'type',  'with_polymorphic':'*'}

	id = Column(Integer, Sequence('field_id_seq'), primary_key=True)
	action_id = Column(Integer, ForeignKey(Action.id), index=True)
	name = Column(String(30), primary_key=True)
	type = Column(String(30), nullable=False)

	action = relationship(Action, backref=backref('fields', 
					 collection_class=column_mapped_collection(name)))

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

class FieldType(Field):
	__abstract__ = True

	def __init__(self, action, name):
		super().__init__(action, name)

	@declared_attr
	def id(cls):
		return Column(Integer, ForeignKey(Field.id), primary_key=True)

class AllowAll(object):
	@predicate
	@staticmethod
	def allow_all(*args, **kwargs):
		return (Action.id != 0)

