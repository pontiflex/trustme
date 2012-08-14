from tempfile import mkstemp
from stat import ST_SIZE

import os
import subprocess


LIBKEY = '~lib'
OPENSSL = '/usr/bin/openssl'


class RawInput(object):
	def __init__(self, data):
		self.__file = open(mkstemp()[1], 'w')
		self.__file.write(data)
		self.__file.flush()

	def __enter__(self):
		return self.__file.name

	def __exit__(self, type, value, traceback):
		self.__file.close()

class RawOutput(object):
	def __init__(self, out, err):
		try:
			self.out = open(out[1])
			self.err = open(err[1])
		finally:
			os.close(out[0])
			os.close(err[0])

	def __enter__(self):
		return self.out, self.err

	def __exit__(self, type, value, traceback):
		self.out.close()
		self.err.close()

class OpenSSLError(StandardError):
	def __init__(self, code, res):
		self.code, self.res = code, res

def invoke(cmd, in_=None, *args, **kwargs):
	params = (kwargs.pop(LIBKEY, OPENSSL), cmd)
	for arg in kwargs:
		params += ('-%s' % str(arg), str(kwargs[arg]))
	for flag in args:
		params += ('-%s' % flag,)
	if in_ is not None:
		if isinstance(in_, str):
			params += ('-in', in_)
		elif hasattr(in_, '__iter__'):
			params += ('-infiles',) + tuple(in_)
	out, err = mkstemp(), mkstemp()
	code = subprocess.call(params, stdout=out[0], stderr=err[0])
	res = RawOutput(out, err)
	if code != 0:
		raise OpenSSLError(code, res)
	return res	

