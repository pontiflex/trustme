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

import re
from base64 import b64decode


"""This file contains wrappers around common ASN1 substructures"""


# Regular expression to locate the PEM delimiters around a raw file
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
			pem = (kwargs.get('inform', 'pem') == 'pem')
			if pem:	raw = STRIP_LINE.sub('', raw)
			raw = ''.join(raw.strip('\n').splitlines())
			if pem:	raw = b64decode(raw)
			start = loc[0] + loc[1]
			end = start + loc[2]
			return str.__new__(cls, raw[start:end].encode('hex').upper())


