import hashlib
import hmac
import os
import base64
import struct
from itertools import imap, islice, count
from operator import xor, or_


_algorithms = {}

def get_algorithm(name):
	global _algorithms
	if name not in _algorithms:
		return None
	return _algorithms[name]

def _add_algorithm(alg):
	global _algorithms
	_algorithms[alg.name] = alg





# Begin hash definitions...

def hash_def(name, func):
	length = func().digest_size
	def h(msg):
		digest = func()
		digest.update(msg)
		return digest.digest()
	h.name = name
	h.length = length
	h.create = func
	_add_algorithm(h)
	return h

sha1   = hash_def('SHA1'  , hashlib.sha1)
sha256 = hash_def('SHA256', hashlib.sha256)

default_hash = sha256





# Begin MAC definitions...

def hmac_def(h):
	def prf(key, msg):
		return hmac.new(key, msg, h.create).digest()
	prf.name = 'HMAC-' + h.name
	prf.length = h.length
	prf.create = lambda(key): hmac.new(key, None, h.create)
	_add_algorithm(prf)
	return prf

hmac_sha1   = hmac_def(sha1)
hmac_sha256 = hmac_def(sha256)

default_mac = hmac_sha256





# Begin password-based key derivation definitions...

class Stream:
	def __init__(self, it):
		self.it = it
		self.cache = []

	def __getitem__(self, index):
		end = index.stop if hasattr(index, 'stop') else index
		n = end - len(self.cache)
		if n > 0:
			self.cache.extend(islice(self.it, n))
		return ''.join(self.cache[index])

def password_stream(func):
	def stream(password, salt, rounds):
		return Stream(func(password, salt, rounds))
	return stream

"""See http://www.ietf.org/rfc/rfc2898.txt for the official definition,
   and https://github.com/mitsuhiko/python-pbkdf2/blob/master/pbkdf2.py
   for a good reference implementation."""
def pbkdf2_def(prf):

	"""The PBKDF2 process repeatedly XORs together a PRF
	   (keyed using the password) of the previous iteration
	   to generate each block of the keystream. For convenient
	   access, this function implements it as a sliceable
	   generator."""
	def stream(password, salt, rounds):
		for i in count(1):
			U = prf(password, salt + struct.pack(">I", i))
			block = map(ord, U)
			for step in xrange(rounds-1):
				U = prf(password, U)
				block = map(xor, block, imap(ord, U))
			for b in block:					
				yield chr(b)

	derive = password_stream(stream)
	derive.name = 'PBKDF2-' + prf.name
	_add_algorithm(derive)
	return derive

pbkdf2_hmac_sha1   = pbkdf2_def(hmac_sha1)
pbkdf2_hmac_sha256 = pbkdf2_def(hmac_sha256)





def secure_random(nBytes):
	return os.urandom(nBytes)


def slow_equals(a, b):
	if len(a) != len(b):
		return False
	return 0 == reduce(or_, imap(xor, imap(ord, a), imap(ord, b)))



def size64(num, bits=True):
	if not bits:
		num = num * 8
	return ((num + 5) // 6) + 2

def to64(msg):
	return base64.b64encode(msg)

def from64(msg):
	return base64.b64decode(msg)

def rand64(size):
	return to64(secure_random(size))

