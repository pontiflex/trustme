from openssl import invoke, OpenSSLError

from base64 import b64decode
import re

RAW = ['BIT STRING', 'OCTET STRING']
ASN1_LINE = re.compile('^\s*(?P<index>\d+):\s*' +
							'd=\s*(?P<depth>\d+)\s+' +
							'hl=\s*(?P<header_length>\d+)\s+' +
							'l=\s*(?P<body_length>\d+)\s+' + 
							'(?P<class>prim|cons):\s*' +
							'(?P<type>[^:\s](?:[^:]?[^:\s]+)*)\s*' +
							'(?:(?:\\[HEX DUMP\\])?:(?P<value>.+))?$',
					   re.U)

class ASN1Struct(object):
	def __init__(self, path, *args, **kwargs):
		self.valid = None
		code, data, err = self._init_invoke('asn1parse', path, *args, **kwargs)
		self.struct = None
		if self.valid:
			matches = [ASN1_LINE.match(line).groupdict() for line in data]
			self.struct = self.__parse(matches)[0]
		else:
			err.close()
		data.close()

	def _init_invoke(self, *args, **kwargs):
		valid = self.valid if self.valid is not None else True
		try:
			out, err = invoke(*args, **kwargs)
			code = 0
			self.valid = valid
		except OpenSSLError as e:
			code, out, err = e.code, e.out, e.err
			print '=' * 100
			print err.read()
			err.seek(0)
			self.valid = False
		return code, out, err

	def __repr__(self):
		return self._repr(lambda:'\n%s' % self.__pretty(self.struct))

	def _repr(self, pretty):
		pretty = pretty() if self.valid else 'Invalid'
		return '<%s at %s: %s>' % (self.__class__.__name__, hex(id(self)), pretty)
		
	def __pretty(self, tree, depth=0):
		if isinstance(tree, list):
			ret = '    ' * (depth+1) + ':' + '\n'
			for child in tree:
				ret += self.__pretty(child, depth+1)
			return ret
		elif tree[2]:
			return '    ' * (depth+1) + str(tree[0]) + ' @ ' + str(tree[1]) + '\n'
		else:
			return '    ' * (depth+1) + str(tree[0]) + ' ' + str(tree[1]) + '\n'

	def __parse(self, lines, start=0, depth=0):
		line = lines[start]
		if line['class'] == 'prim':
			raw = False
			val = line['value']
			if val is None and line['type'] in RAW:
				raw = True
				val = (int(line['index']), int(line['header_length']),
					   int(line['body_length']))
			return (line['type'], val, raw), start+1 
		
		i, value = start+1, []
		while i < len(lines):
			d = int(lines[i]['depth'])
			if d > depth:
				v, i = self.__parse(lines, i, d)			
				value.append(v)
			else: break

		return value, i
			




if __name__ == '__main__':
	import sys
	test = ASN1Struct(sys.argv[1])
	print test

