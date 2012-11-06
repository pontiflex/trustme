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

from openssl import invoke, OpenSSLError

from base64 import b64decode
import re


"""This file contains a parser class for raw ASN1 structures"""


# List of primitives that contain raw data
RAW = ['BIT STRING', 'OCTET STRING']
# Regular expression to parse a line of output from the openssl asn1parse command
ASN1_LINE = re.compile('^\s*(?P<index>\d+):\s*' +
							'd=\s*(?P<depth>\d+)\s+' +
							'hl=\s*(?P<header_length>\d+)\s+' +
							'l=\s*(?P<body_length>\d+)\s+' + 
							'(?P<class>prim|cons):\s*' +
							'(?P<type>[^:\s](?:[^:]?[^:\s]+)*)\s*' +
							'(?:(?:\\[HEX DUMP\\])?:(?P<value>.+))?$',
					   re.U)


class ASN1Struct(object):
	"""Raw ASN1 structure parser class"""
	def __init__(self, path, *args, **kwargs):
		self.valid = None
		code, res = self._init_invoke('asn1parse', path, *args, **kwargs)
		self.struct = None
		with res as (data, err):
			if self.valid:
				matches = [ASN1_LINE.match(line).groupdict() for line in data]
				self.struct = self.__parse(matches)[0]

	def _init_invoke(self, *args, **kwargs):
		valid = self.valid if self.valid is not None else True
		try:
			res = invoke(*args, **kwargs)
			code = 0
			self.valid = valid
		except OpenSSLError as e:
			code, res = e.code, e.res
			print '=' * 100
			print res.err.read()
			res.err.seek(0)
			self.valid = False
		return code, res

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

