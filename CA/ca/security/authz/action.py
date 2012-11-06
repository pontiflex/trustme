"""
Copyright 2012 Pontiflex, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""

from ca.security.algorithms import size64, rand64

from ca.models import Base

from sqlalchemy import Column, Sequence, Integer, String


SERIAL_BYTES = 32


class Action(Base):
	__tablename__ = 'actions'
	__mapper_args__ = {'polymorphic_on':'type',  'with_polymorphic':'*'}

	id = Column(Integer, Sequence('action_id_seq'), primary_key=True)
	type = Column(String(30), nullable=False)
	serial = Column(String(size64(SERIAL_BYTES)), nullable=False, unique=True)

	def __new__(cls, *args, **kwargs):
		if cls is Action:
			raise TypeError('%s cannot be directly instantiatied' % cls.__name__)
		return super(Action, cls).__new__(cls, *args, **kwargs)

	def __init__(self):
		self.serial = rand64(SERIAL_BYTES)

	@classmethod
	def subtype(cls):
		return cls.__mapper_args__.get('polymorphic_identity')

	@classmethod
	def readable(cls):
		return cls.subtype()

	def perform(self, request):
		return 'Action successfully performed'

	def revoke(self, request):
		return 'Action result revoked'

	def render(self, mode, status=False):
		if status:
			return 'ca:templates/security/ui/status/default.pt', dict(mode=mode)
		params = dict(action=self, mode=mode)
		return 'ca:templates/security/ui/render/default.pt', params


