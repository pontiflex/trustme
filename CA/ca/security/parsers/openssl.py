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
	try:
		outf, errf = open(out[1]), open(err[1])
		if code != 0:
			raise OpenSSLError(code, outf, errf)
		return outf, errf
	finally:
		os.close(out[0])
		os.close(err[0])

class OpenSSLError(StandardError):
	def __init__(self, code, out, err):
		self.code, self.out, self.err = code, out, err

