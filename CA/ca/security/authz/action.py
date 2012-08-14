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

	@classmethod
	def subtype(cls):
		return cls.__mapper_args__.get('polymorphic_identity')

	@classmethod
	def readable(cls):
		return cls.subtype()

	def perform(self, request): pass

	def render(self, mode):
		if status:
			return 'ca:templates/security/ui/status/default.pt', dict(mode=mode)
		params = dict(action=self, mode=mode)
		return 'ca:templates/security/ui/render/default.pt', params


