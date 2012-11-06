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

from tempfile import mkstemp
from stat import ST_SIZE

import os
import subprocess


"""This file defines a function and supporting classes for cleanly making
arbitrary calls to openssl"""


LIBKEY = '!lib'
OPENSSL = '/usr/bin/openssl'


class RawInput(object):
	"""Wrapper which provides a handle to a temporary file containing
	the supplied data when used in the 'with, as' idiom"""
	def __init__(self, data):
		"""Takes raw data to be placed in the temp file"""
		# Create a new temporary file and save a handle for it
		f = mkstemp()
		self.__file = open(f[1], 'w')
		os.close(f[0])
		# Write the input data to the file and flush it out
		self.__file.write(data)
		self.__file.flush()

	def __enter__(self):
		return self.__file.name

	def __exit__(self, type, value, traceback):
		self.__file.close()

class RawOutput(object):
	"""Wrapper which provides handles to temporary files containing the stdout
	and stderr from an openssl invocation"""
	def __init__(self, out, err):
		"""Takes a mkstemp definition (raw fd, file name) for out and err"""
		try:
			# Open the out and err files by name to get a usable handle
			self.out = open(out[1])
			self.err = open(err[1])
		finally:
			# Close the unfriendly raw descriptors
			os.close(out[0])
			os.close(err[0])

	def __enter__(self):
		return self.out, self.err

	def __exit__(self, type, value, traceback):
		self.out.close()
		self.err.close()

class OpenSSLError(StandardError):
	"""A class representing an error during an openssl invocation"""
	def __init__(self, code, res):
		"""Takes a numeric return code and a RawOutput object"""
		self.code, self.res = code, res

def invoke(cmd, in_=None, *args, **kwargs):
	"""Take an openssl verb, input file(s), and both flag and keywork arguments, and
	returns the result of an openssl call using the given parameters"""
	# Grab the openssl binary and cmd parameter as the first two subprocess arguments
	params = (kwargs.pop(LIBKEY, OPENSSL), cmd)
	# Add in the keyword arguments
	for arg in kwargs:
		params += ('-%s' % str(arg), str(kwargs[arg]))
	# Add in the flag arguments
	for flag in args:
		params += ('-%s' % flag,)
	# Add in the input file(s)
	if in_ is not None:
		if isinstance(in_, str):
			params += ('-in', in_)
		elif hasattr(in_, '__iter__'):
			params += ('-infiles',) + tuple(in_)
	# Print a debug message showing the parameters
	print 'INVOKING%s' % ('.' * 100)
	print params
	# Perform the invocation, redirecting stdout and stderr to temp files
	out, err = mkstemp(), mkstemp()
	code = subprocess.call(params, stdout=out[0], stderr=err[0])
	res = RawOutput(out, err)
	# If there was an error, raise it, else return the result
	if code != 0:
		raise OpenSSLError(code, res)
	return res	

