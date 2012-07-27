import os
from tempfile import mkstemp

class Parser(object):
	
	def __init__(self, *channels):
		self.__tmps = {c:(mkstemp(), mkstemp()) for c in channels}

	def __check(self, throw=True):
		if self.__tmps is None:
			if throw: raise IOError('This parser is closed')
			else    : return False
		return True

	def __getattr__(self, name):
		self.__check()
		tmp = self.__tmps.get(name, None)
		if tmp is None:
			raise AttributeError()
		return lambda(in_):tmp[0][0] if in_ else tmp[1][0]

	def close(self):
		if not self.__check(False):
			return
		try:
			channels = {c:(open(f[0][1], 'r'), open(f[1][1], 'r'))
					   for c,f in self.__tmps.iteritems()}
			self._parse(**channels)
		finally:
			for f in self.__tmps.itervalues():
				os.close(f[0][0])
				os.close(f[1][0])
			for f in channels.itervalues():
				f[0].close()
				f[1].close()
			self.__tmps = None

	def _parse(self, **channels): pass

