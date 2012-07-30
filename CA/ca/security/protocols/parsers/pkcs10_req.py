from asn1_struct import ASN1Struct
from openssl import invoke
from structures import Name, Attributes, Raw

CMD = 'req'


class PKCS10Request(ASN1Struct):
	def __init__(self, path, *args, **kwargs):
		super(PKCS10Request, self).__init__(path, *args, **kwargs)
		code, data = invoke(CMD, path, 'verify', *args, **kwargs)
		if data is None:
			self.valid = False
			return
		self.valid = True

		info = self.struct[0]
		self.version = int(info[0][1])
		self.name = Name(info[1])
		self.attributes = Attributes(info[3])

		self.key_alg = info[2][0][0][1]
		self.key_params = ASN1Struct(path, strparse=info[2][1][1][0])

		self.sig_alg = self.struct[1][0][1]
		sigloc = self.struct[2][1]
		self.signature = Raw(path, sigloc, *args, **kwargs)
		

	def __repr__(self):
		pretty = '\n%s' % self.__pretty() if self.valid else 'Invalid'
		return self._repr(pretty)

	def __pretty(self):
		ret  = '    Version: %i\n' % self.version
		ret += '    Name: %s\n' % self.name
		ret += '    Key Algorithm: %s\n' % self.key_alg
		ret += '    Key Params:\n        %s\n' % repr(self.key_params).replace('\n', '\n        ')
		ret += '    Attributes: %s\n' % self.attributes
		ret += '    Signature Algorithm: %s\n' % self.sig_alg
		ret += '    Signature: %s\n' % self.signature
		return ret




if __name__ == '__main__':
	import sys
	test = PKCS10Request(sys.argv[1])
	print test

