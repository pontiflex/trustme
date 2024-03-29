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

from ca.security.algorithms import size64, to64, from64
from ca.security.algorithms import secure_random, slow_equals
from ca.security.algorithms import pbkdf2_hmac_sha256, get_algorithm

from ca.models import Base, DBSession

from pyramid.security import authenticated_userid

from sqlalchemy import Column, Integer, String, Sequence
from sqlalchemy.orm import relationship


"""This file defines the User class, which bundles database-mapped fields pertaining
to an individual user account"""


# FIXME: These should be configurable in the .ini file
# The default password algorithm is pbkdf2_sha_256
PASSWORD_ALG = pbkdf2_hmac_sha256
# The default password hash length is 32
PASSWORD_BYTES = 32
# The default number of rounds used in password hashing is 1000
PASSWORD_ROUNDS = 1000
# The default salt length is 16 bytes
SALT_BYTES = 16


class User(Base):
	__tablename__ = 'users'
	id = Column(Integer, Sequence('user_id_seq'), primary_key=True)

	login = Column(String(30), nullable=False, unique=True)
	email = Column(String(60), nullable=False)

	password = Column(String(size64(PASSWORD_BYTES)), nullable=False)
	salt = Column(String(size64(SALT_BYTES)), nullable=False)
	algorithm = Column(String(30), nullable=False)
	work_factor = Column(Integer, nullable=False)

	def __init__(self, login, email, password):
		"""Takes a validated username, email, and password, and initializes a User"""
		# Simply save the username and email
		self.login = login
		self.email = email

		# Generate a random salt and compute the password hash using the defaults
		salt = secure_random(SALT_BYTES)
		digest = PASSWORD_ALG(password, salt, PASSWORD_ROUNDS)[:PASSWORD_BYTES]
		# Save the password hash, along with the salt, algorithm, and work factor
		# used to compute it
		self.password = to64(digest)
		self.salt = to64(salt)
		self.algorithm = PASSWORD_ALG.name
		self.work_factor = PASSWORD_ROUNDS

	def is_admin(self):
		"""Check if this user is the ROOT admin account"""
		return DBSession.query(User).get(1) is self

	@classmethod
	def get(cls, userid):
		"""Take a username and return the corresponding User, if it exists"""
		if userid:
			return DBSession.query(cls).filter(cls.login==userid).first()
		return None

	@classmethod
	def authenticated(cls, request):
		"""Take a Pyramid request object and return the authenticated User, if any"""
		userid = authenticated_userid(request)
		return cls.get(userid)

	@classmethod
	def verify(cls, login, password):
		"""Take a username and password and return the corresponding user, if it exists
		and the provided password is correct"""
		# FIXME: minor timing attack to check if user exists
		# Grab data about the user from the database using their login. Deny
		# the login attempt if the specified user doesn't exist.
		user = cls.get(login)
		if user is None:
			return None

		# Retrieve the algorithm and parameters from the database to determine
		# which hashing function to use. These may not be the same as the current
		# standard, so be sure the correct paramaters are being used to produce
		# the same hash as the one stored in the database.
		stored_pass = from64(user.password)
		stored_dig_len = len(stored_pass)
		stored_salt = from64(user.salt)
		stored_salt_len = len(stored_salt)
		stored_alg = get_algorithm(user.algorithm)
		stored_work = user.work_factor
		presented = stored_alg(password, stored_salt, stored_work)[:stored_dig_len]

		# Make sure the comparison is done using this special operation, to avoid
		# timing attacks. The execution time of the comparison MUST NOT DEPEND ON
		# THE LOCATIONS OF ANY DIFFERENCES. If the credentials presented don't match
		# the database, deny the login attempt.
		if not slow_equals(presented, stored_pass):
			return None

		# If the stored hashing parameters don't match the current standard,
		# update them. Note that THIS MUST ONLY BE DONE ONCE THE PASSWORD HAS
		# BEEN VERIFIED using the stored values, or the account could be updated
		# to use invalid credentials. Which would be very bad.
		if (stored_alg is not PASSWORD_ALG or stored_dig_len != PASSWORD_BYTES or
				stored_salt_len != SALT_BYTES or stored_work != PASSWORD_ROUNDS):
			salt = secure_random(SALT_BYTES)
			stream = PASSWORD_ALG(password, salt, PASSWORD_ROUNDS)
			user.password = to64(stream[:PASSWORD_BYTES])
			user.salt = to64(salt)
			user.algorithm = PASSWORD_ALG.name
			user.work_factor = PASSWORD_ROUNDS

		return user

