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

from ca.security.authority.openssl import invoke, RawInput

from getpass import getpass


"""This file contains classes for parsing and retrieving CA configuration arguments
from the .ini file used to launch TrustMe"""


# Configuration key for parsed CA arguments
CA_KEY = '__CA__'
# Replacement pattern for CA configuration keys
CA_PATTERN = 'ca.%s.%s'
# Prompt for CA key password if not supplied in config
PROMPT = 'Please enter private key password for CA "%s":'


def _set_ca(settings, name, key, value):
	"""Helper function for saving a configured CA value"""
	cas = settings.get(CA_KEY, {})
	ca = cas.get(name, {})
	ca[key] = value
	cas[name] = ca
	settings[CA_KEY] = cas

def _get_ca(request, name, key):
	"""Helper function for retrieving a configured CA value"""
	return request.registry.settings.get(CA_KEY, {}).get(name, {}).get(key)


class Secrets(object):
	"""Class to encapsulate sensitive configured values for a TrustMe CA"""
	KEY = '__SECRETS__'

	def __init__(self, certFile, keyFile, passArg):
		"""Takes the names of a certificate file and private key file and an
		openssl-style password argument to unlock the key file"""
		# Validate and dump the certificate file into memory
		with invoke('x509', certFile) as (out, err):
			self.__cert = out.read()
		# Decrypt, validate, and dump the private key into memory
		with invoke('rsa', keyFile, passin=passArg) as (out, err):
			self.__key = out.read()

	@property
	def cert(self):
		"""Property which provides the certificate as a RawInput"""
		return RawInput(self.__cert)

	@property
	def key(self):
		"""Property which provides the decrypted private key as a RawInput"""
		return RawInput(self.__key)

	@classmethod
	def parse_config(cls, settings, name='default'):
		"""Class method which parses the configuration for ca 'name' out of the
		configuration dictionary 'settings'"""
		# Compute the optional password configuration key
		passKey = CA_PATTERN % (name, 'pass')
		# Compute the required certificate and private key configuration keys
		required = [CA_PATTERN % (name, key) for key in ('cert', 'key')]
		# Make sure all the required keys are present
		for k in required:
			if k not in settings:
				raise ValueError('Missing key %s in config file' % k)
		# Retrieve the certificate and private key arguments
		certFile = settings.pop(required[0])
		keyFile = settings.pop(required[1])
		# Retrieve the password if configured, else prompt the user for it
		if passKey in settings:
			passArg = settings.pop(passKey)
		else:
			with RawInput(getpass(PROMPT % name)) as passin:
				passArg = 'file:%s' % passin
		# Save a new Secrets instance with the configured arguments
		_set_ca(settings, name, cls.KEY, cls(certFile, keyFile, passArg))

	@classmethod
	def from_request(cls, request, name='default'):
		"""Class method to retrieve the configured secrets from a Pyramid request"""
		return _get_ca(request, name, cls.KEY)


class RevokeDB(object):
	"""Class to encapsulate certificate revocation options for a TrustMe CA"""
	KEY = '__CRL_DB__'

	def __init__(self, dbFile, crlFile):
		"""Takes the path to a revoked certificate database file and the path at which
		to place newly generated CRLs"""
		# Create a minimal openssl config file to pass the non-command-line args
		self.__config = '[ ca ]\ndefault_ca = CA\n[ CA ]\ndatabase = %s' % dbFile
		# Save the CRL path and create the file if it doesn't exist already
		self.crlFile = crlFile
		open(crlFile, 'a')

	@property
	def config(self):
		"""Property which provides the CA config file as a RawInput"""
		return RawInput(self.__config)

	@classmethod
	def parse_config(cls, settings, name='default'):
		"""Class method which parses the configuration for ca 'name' out of the
		configuration dictionary 'settings'"""
		# Compute the required database and crl file configuration keys
		required = [CA_PATTERN % (name, key) for key in ('database', 'crl')]
		# Make sure all the required keys are present
		for k in required:
			if k not in settings:
				raise ValueError('Missing key %s in config file' % k)
		# Retrieve the database file and crl file arguments
		dbFile = settings.pop(required[0])
		crlFile = settings.pop(required[1])
		# Save a new RevokeDB instance with the configured arguments
		_set_ca(settings, name, cls.KEY, cls(dbFile, crlFile))

	@classmethod
	def from_request(cls, request, name='default'):
		"""Class method to retrieve the configured revocation options from a Pyramid
		request object"""
		return _get_ca(request, name, cls.KEY)

