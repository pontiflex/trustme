from parser import Parser

from base64 import b64decode
import re
import subprocess

asn1_line = re.compile('^\s*(?P<index>\d+):\s*' +
							'd=\s*(?P<depth>\d+)\s+' +
							'hl=\s*(?P<header_length>\d+)\s+' +
							'l=\s*(?P<body_length>\d+)\s+' + 
							'(?P<class>prim|cons):\s*' +
							'(?P<type>[^:\s](?:[^:]?[^:\s]+)*)\s*' +
							'(?:(?:\\[HEX DUMP\\])?:(?P<value>.+))?$',
					   re.U)

class ASN1Structure(Parser):
	def __init__(self, *channels):
		super(ASN1Structure, self).__init__('asn1', *channels)

	def _parse(self, asn1, **kwargs):
		parsed = [asn1_line.match(line).groupdict() for line in asn1[0]]
		parsed = self.__parse(parsed)[0]
		self.__print(parsed)
		
	def __print(self, tree, depth=0):
		if isinstance(tree, list):
			print '    ' * depth, ':'
			for child in tree:
				self.__print(child, depth+1)
		else:
			print '    ' * depth, tree[0], tree[1]

	def __parse(self, lines, start=0, depth=0):
		line = lines[start]
		if line['class'] == 'prim':
			return (line['type'], line['value']), start+1 
		
		i, value = start+1, []
		while i < len(lines):
			d = int(lines[i]['depth'])
			if d > depth:
				v, i = self.__parse(lines, i, d)			
				value.append(v)
			else: break

		return value, i
			




if __name__ == '__main__':
	test = ASN1Structure()

	parseArgs = ('/usr/bin/openssl', 'asn1parse', '-i', '-in', 'priv.key')
	subprocess.call(parseArgs, stdout=test.asn1(True), stderr=test.asn1(False))

	test.close()

