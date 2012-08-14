import re
from base64 import b64decode

STRIP_LINE = re.compile('^\\-\\-\\-\\-\\-.+\\-\\-\\-\\-\\-$', re.M)


class Name(dict):
	def __init__(self, info):
		dict.__init__(self)
		for subname in info:
			for elmt in subname:
				self[elmt[0][1]] = elmt[1][1]

class Attributes(dict):
	def __init__(self, info):
		dict.__init__(self)
		for attr in info:
			vals = []
			for val in attr[1]:
				vals.append(val[1])
			self[attr[0][1]] = vals

class Raw(str):
	def __new__(cls, path, loc, *args, **kwargs):
		with open(path, 'r') as f:
			raw = f.read().replace('\r\n', '\n').replace('\r', '\n')
			raw = ''.join(STRIP_LINE.sub('', raw).strip('\n').splitlines())
			if kwargs.get('inform', 'pem') == 'pem':
				raw = b64decode(raw)
			start = loc[0] + loc[1]
			end = start + loc[2]
			return str.__new__(cls, raw[start:end].encode('hex').upper())


