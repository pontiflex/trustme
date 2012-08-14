from ca.security.authority.openssl import invoke, RawInput

from getpass import getpass


CA_KEY = '__CA__'
CA_PATTERN = 'ca.%s.%s'
PROMPT = 'Please enter private key password for CA "%s":'


class Secrets(object):
	def __init__(self, certFile, keyFile, passArg):
		with invoke('x509', certFile) as (out, err):
			self.cert = out.read()
		with invoke('rsa', keyFile, passin=passArg) as (out, err):
			self.key = out.read()

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
		ca = settings.get(CA_KEY, {})
		ca[name] = Secrets(certFile, keyFile, passArg)
		settings[CA_KEY] = ca

	@classmethod
	def from_request(cls, request, name='default'):
		return request.registry.settings.get(CA_KEY, {}).get(name)
		
