from ca.security.authority.openssl import invoke, RawInput

from getpass import getpass


CA_KEY = '__CA__'
CA_PATTERN = 'ca.%s.%s'
PROMPT = 'Please enter private key password for CA "%s":'


def _set_ca(settings, name, key, value):
	cas = settings.get(CA_KEY, {})
	ca = cas.get(name, {})
	ca[key] = value
	cas[name] = ca
	settings[CA_KEY] = cas

def _get_ca(request, name, key):
	return request.registry.settings.get(CA_KEY, {}).get(name, {}).get(key)


class Secrets(object):
	KEY = '__SECRETS__'

	def __init__(self, certFile, keyFile, passArg):
		with invoke('x509', certFile) as (out, err):
			self.__cert = out.read()
		with invoke('rsa', keyFile, passin=passArg) as (out, err):
			self.__key = out.read()

	@property
	def cert(self):
		return RawInput(self.__cert)

	@property
	def key(self):
		return RawInput(self.__key)

	@classmethod
	def parse_config(cls, settings, name='default'):
		passKey = CA_PATTERN % (name, 'pass')
		required = [CA_PATTERN % (name, key) for key in ('cert', 'key')]
		for k in required:
			if k not in settings:
				raise ValueError('Missing key %s in config file' % k)
		certFile = settings.pop(required[0])
		keyFile = settings.pop(required[1])
		if passKey in settings:
			passArg = settings.pop(passKey)
		else:
			with RawInput(getpass(PROMPT % name)) as passin:
				passArg = 'file:%s' % passin
		_set_ca(settings, name, cls.KEY, cls(certFile, keyFile, passArg))

	@classmethod
	def from_request(cls, request, name='default'):
		return _get_ca(request, name, cls.KEY)


class RevokeDB(object):
	KEY = '__CRL_DB__'

	def __init__(self, dbFile, crlFile):
		self.__config = '[ ca ]\ndefault_ca = CA\n[ CA ]\ndatabase = %s' % dbFile
		self.crlFile = crlFile
		open(crlFile, 'a')

	@property
	def config(self):
		return RawInput(self.__config)

	@classmethod
	def parse_config(cls, settings, name='default'):
		required = [CA_PATTERN % (name, key) for key in ('database', 'crl')]
		for k in required:
			if k not in settings:
				raise ValueError('Missing key %s in config file' % k)
		dbFile = settings.pop(required[0])
		crlFile = settings.pop(required[1])
		_set_ca(settings, name, cls.KEY, cls(dbFile, crlFile))

	@classmethod
	def from_request(cls, request, name='default'):
		return _get_ca(request, name, cls.KEY)

