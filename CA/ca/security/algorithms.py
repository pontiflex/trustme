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

import hashlib
import hmac
import os
import base64
import struct
from itertools import imap, islice, count
from operator import xor, or_


""" This file contains machinery for defining and retrieving cryptographic algorithms,
as well as additional utilities like a wrapper around secure random and aliases
for calls to base64 conversion."""


# A private mapping from algorithm name to algorithm object
_algorithms = {}

def get_algorithm(name):
	"""Take the name of an algorithm and return the algorithm"""
	# Retrieve the algorithm from the map by name	
	global _algorithms
	return _algorithms.get(name)

def _add_algorithm(alg):
	"""Take a named algorithm and add a mapping for it"""
	# Retrieve the algorithm's name and add a mapping for it
	global _algorithms
	_algorithms[alg.name] = alg





# Begin hash definitions...

def hash_def(name, func):
	"""Take a name and a standard python hash function, map the name to a new TrustMe
	hash function, and return that function"""
	# Grab the hash output length (in bytes)
	length = func().digest_size
	# Define a function which creates, updates, and executes the hash all at once
	def h(msg):
		digest = func()
		digest.update(msg)
		return digest.digest()
	# Attach the given name to it
	h.name = name
	# Attach the digest length to it
	h.length = length
	# Attach the raw creation function to it
	h.create = func
	# Add the mapping
	_add_algorithm(h)
	# Return the new function
	return h

# Define sha1, with the name 'SHA1'
sha1   = hash_def('SHA1'  , hashlib.sha1)
# Define sha256, with the name 'SHA256'
sha256 = hash_def('SHA256', hashlib.sha256)

# Set sha256 as the default hash function
default_hash = sha256





# Begin MAC definitions...

def hmac_def(h):
	"""Take a TrustMe hash function, create a TrustMe HMAC function based on the
	underlying standard hash function, save the new function under 'HMAC-<name>',
	and return the new function"""
	# Define a function which creates a new standard HMAC using the underlying hash
	# and a given key and message, then returns the resulting digest
	def prf(key, msg):
		return hmac.new(key, msg, h.create).digest()
	# Attach the prefixed name to it
	prf.name = 'HMAC-' + h.name
	# Set its digest length to that of the underlying function
	prf.length = h.length
	# Attach a function which creates the standard HMAC with just a key
	prf.create = lambda(key): hmac.new(key, None, h.create)
	# Add the mapping
	_add_algorithm(prf)
	# Return the function
	return prf

# Define hmac_sha1 using sha1
hmac_sha1   = hmac_def(sha1)
# Define hmac_sha256 using sha256
hmac_sha256 = hmac_def(sha256)

# Set the default MAC to hmac_sha256
default_mac = hmac_sha256





# Begin password-based key derivation definitions...

class Stream:
	"""Wrapper around an iterator which can be accessed using slice notation, lazily
	loading from the underlying iterator as necessary"""
	def __init__(self, it):
		"""Takes an iterator and initializes a Stream"""
		# Save the given iterator and initialize a cache for the loaded values
		self.__it = it
		self.__cache = []

	def __getitem__(self, index):
		"""Takes a slice index and returns that slice of the iterator's values"""
		# Grab the end value from the index and make sure it's non-negative
		end = index.stop if hasattr(index, 'stop') else index
		if end < 0:
			raise ValueError('Negative indices not supported')
		# Determine how many indices need to be loaded, and load them if necessary
		n = end - len(self.__cache)
		if n > 0:
			self.__cache.extend(islice(self.__it, n))
		# Join the sliced values into a string and return it
		return ''.join(self.__cache[index])

def password_stream(func):
	"""Take a function that produces a generator out of a password, salt, and round
	count and return a function that returns a Stream using the output of the given
	generator function"""
	def stream(password, salt, rounds):
		return Stream(func(password, salt, rounds))
	return stream

"""See http://www.ietf.org/rfc/rfc2898.txt for the official definition,
   and https://github.com/mitsuhiko/python-pbkdf2/blob/master/pbkdf2.py
   for a good reference implementation."""
def pbkdf2_def(prf):
	"""Take a TrustMe PRF, create a TrustMe PBKDF2 function based on the	given prf,
	save the new function under 'PBKDF2-<name>', and return the new function"""

	# The PBKDF2 process repeatedly XORs together a PRF
	# (keyed using the password) of the previous iteration
	# to generate each block of the keystream. For convenient
	# access, this function implements it as a generator.
	def stream(password, salt, rounds):
		for i in count(1):
			U = prf(password, salt + struct.pack(">I", i))
			block = map(ord, U)
			for step in xrange(rounds-1):
				U = prf(password, U)
				block = map(xor, block, imap(ord, U))
			for b in block:					
				yield chr(b)

	# Create a Stream-producing function from the 'stream' generator function
	derive = password_stream(stream)
	# Attach the prefixed name to it
	derive.name = 'PBKDF2-' + prf.name
	# Add the mapping
	_add_algorithm(derive)
	# Return the function
	return derive

# Define pbkdf2_hmac_sha1 using hmac_sha1
pbkdf2_hmac_sha1   = pbkdf2_def(hmac_sha1)
# Define pbkdf2_hmac_sha256 using hmac_sha256
pbkdf2_hmac_sha256 = pbkdf2_def(hmac_sha256)





def secure_random(nBytes):
	"""Wrapper around os.urandom"""
	return os.urandom(nBytes)


def slow_equals(a, b):
	"""Takes two strings and compares them without allowing timing attacks to determine
	the content of an unknown string using a known one"""
	if len(a) != len(b):
		return False
	return 0 == reduce(or_, imap(xor, imap(ord, a), imap(ord, b)))



def size64(num, bits=True):
	"""If 'bits' is true, return the size of 'num' bits in base-64, else return
	the size of 'num' bytes in base-64 (return values are always in bytes)"""
	# Compute the number of bits
	if not bits:
		num = num * 8
	# Divide the number of bits by 6 (base-two log of 64) then add 2 for padding
	return ((num + 5) // 6) + 2

def to64(msg):
	"""Wrapper around base64.b64encode"""
	return base64.b64encode(msg)

def from64(msg):
	"""Wrapper around base64.b64decode"""
	return base64.b64decode(msg)

def rand64(size):
	"""Return a base64-encoded random number of size 'bytes'"""
	return to64(secure_random(size))

