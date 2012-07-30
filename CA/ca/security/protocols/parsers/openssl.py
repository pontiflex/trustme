from tempfile import mkstemp
from stat import ST_SIZE

import os
import subprocess


LIBKEY = '~lib'
OPENSSL = '/usr/bin/openssl'


def invoke(cmd, path=None, *args, **kwargs):
	args = (kwargs.pop(LIBKEY, OPENSSL), cmd)
	if path is not None:
		args += ('-in', path)
	for arg in kwargs:
		args += ('-%s' % str(arg), str(kwargs[arg]))
	for flag in args:
		args + ('-%s' % flag,)
	out, err = mkstemp(), mkstemp()
	code = subprocess.call(args, stdout=out[0], stderr=err[0])
	try:
		data = open(out[1]) if os.stat(err[1])[ST_SIZE] == 0 else None
		return code, data
	finally:
		os.close(out[0])
		os.close(err[0])


	


