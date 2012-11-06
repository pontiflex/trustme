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

from asn1_struct import ASN1Struct
from structures import Name, Attributes, Raw


"""This file contains an ASN1Struct subclass for parsing PKCS#10 CSRs"""


class PKCS10Request(ASN1Struct):
	"""PKCS#10 CSR parser class"""
	def __init__(self, path, *args, **kwargs):
		"""Takes a path to the request file along with optional openssl parsing
		flags like 'inform'"""
		# First, parse the raw ASN1 structure using the super constuctor
		super(PKCS10Request, self).__init__(path, *args, **kwargs)
		# Verify that the CSR is properly formed
		inform = kwargs.get('inform', 'pem')
		self._init_invoke('req', path, 'verify', inform=inform)
		if not self.valid: return
	
		# Locate and save the substructures of note
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
		return self._repr(lambda:'\n%s' % self.__pretty())

	def __pretty(self):
		"""Pretty printing method to show the parsed structures"""
		ret  = '    Version: %i\n' % self.version
		ret += '    Name: %s\n' % self.name
		ret += '    Key Algorithm: %s\n' % self.key_alg
		ret += '    Key Params:\n        %s\n' % repr(self.key_params).replace('\n', '\n        ')
		ret += '    Attributes: %s\n' % self.attributes
		ret += '    Signature Algorithm: %s\n' % self.sig_alg
		ret += '    Signature: %s\n' % self.signature
		return ret



