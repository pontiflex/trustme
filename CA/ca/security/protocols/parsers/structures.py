import re
from base64 import b64decode

STRIP_LINE = re.compile('^\\-\\-\\-\\-\\-.+\\-\\-\\-\\-\\-$', re.M)


class Name(object):
	def __init__(self, info):
		self.struct = {}
		for subname in info:
			for elmt in subname:
				self.struct[elmt[0][1]] = elmt[1][1]

	def __repr__(self):	return repr(self.struct)
	def __getattr__(self, name):
		try:
			return self.struct[name]
		except KeyError:
			raise AttributeError()

class Attributes(object):
	def __init__(self, info):
		self.struct = {}
		for attr in info:
			vals = []
			for val in attr[1]:
				vals.append(val[1])
			self.struct[attr[0][1]] = vals

	def __repr__(self): return repr(self.struct)
	def __getattr__(self, name):
		try:
			return self.struct[name]
		except KeyError:
			raise AttributeError()

class Raw(object):
	def __init__(self, path, loc, *args, **kwargs):
		with open(path, 'r') as f:
			raw = ''.join(STRIP_LINE.sub('', f.read()).strip('\n').split('\n'))
			if kwargs.get('inform', 'pem') == 'pem':
				raw = b64decode(raw)
			start = loc[0] + loc[1]
			end = start + loc[2]
			self.struct = raw[start:end]

	def __repr__(self): return self.struct.encode('hex').upper()

