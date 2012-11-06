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

from shorthand import TYPE, SEQ, SET, CHOICE

from pyasn1.type import univ


# FROM RFC 5754 (http://tools.ietf.org/html/rfc5754)


# -- Digest Algorithms

# id-sha224 OBJECT IDENTIFIER ::= {
#   joint-iso-itu-t(2) country(16) us(840) organization(1) gov(101)
#   csor(3) nistalgorithm(4) hashalgs(2) 4 }
id_sha224 = univ.ObjectIdentifier((2, 16, 840, 1, 101, 3, 4, 2, 4))

# id-sha256 OBJECT IDENTIFIER ::= {
#   joint-iso-itu-t(2) country(16) us(840) organization(1) gov(101)
#   csor(3) nistalgorithm(4) hashalgs(2) 1 }
id_sha256 = univ.ObjectIdentifier((2, 16, 840, 1, 101, 3, 4, 2, 1))

# id-sha384 OBJECT IDENTIFIER ::= {
#   joint-iso-itu-t(2) country(16) us(840) organization(1) gov(101)
#   csor(3) nistalgorithm(4) hashalgs(2) 2 }
id_sha384 = univ.ObjectIdentifier((2, 16, 840, 1, 101, 3, 4, 2, 2))

# id-sha512 OBJECT IDENTIFIER ::= {
#   joint-iso-itu-t(2) country(16) us(840) organization(1) gov(101)
#   csor(3) nistalgorithm(4) hashalgs(2) 3 }
id_sha512 = univ.ObjectIdentifier((2, 16, 840, 1, 101, 3, 4, 2, 3))


# -- Signature Algorithms

# -- DSA Signature

# id-dsa-with-sha224 OBJECT IDENTIFIER ::=  {
#   joint-iso-ccitt(2) country(16) us(840) organization(1) gov(101)
#   csor(3) algorithms(4) id-dsa-with-sha2(3) 1 }
id_dsa_with_sha224 = univ.ObjectIdentifier((2, 16, 840, 1, 101, 3, 4, 3, 1))

# id-dsa-with-sha256 OBJECT IDENTIFIER ::=  {
#   joint-iso-ccitt(2) country(16) us(840) organization(1) gov(101)
#   csor(3) algorithms(4) id-dsa-with-sha2(3) 2 }
id_dsa_with_sha256 = univ.ObjectIdentifier((2, 16, 840, 1, 101, 3, 4, 3, 2))


# -- RSA Signature

# sha224WithRSAEncryption OBJECT IDENTIFIER ::= { iso(1)
#   member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs-1(1) 14 }
sha224WithRSAEncryption = univ.ObjectIdentifier((1, 2, 840, 113549, 1, 1, 14))

# sha256WithRSAEncryption  OBJECT IDENTIFIER  ::=  { iso(1)
#   member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs-1(1) 11 }
sha256WithRSAEncryption = univ.ObjectIdentifier((1, 2, 840, 113549, 1, 1, 11))

# sha384WithRSAEncryption  OBJECT IDENTIFIER  ::=  { iso(1)
#   member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs-1(1) 12 }
sha384WithRSAEncryption = univ.ObjectIdentifier((1, 2, 840, 113549, 1, 1, 12))

# sha512WithRSAEncryption  OBJECT IDENTIFIER  ::=  { iso(1)
#   member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs-1(1) 13 }
sha512WithRSAEncryption = univ.ObjectIdentifier((1, 2, 840, 113549, 1, 1, 13))


# -- ECDSA Signature

# ecdsa-with-SHA224 OBJECT IDENTIFIER ::= { iso(1) member-body(2)
#   us(840) ansi-X9-62(10045) signatures(4) ecdsa-with-SHA2(3) 1 }
ecdsa_with_SHA224 = univ.ObjectIdentifier((1, 2, 840, 10045, 4, 3, 1))

# ecdsa-with-SHA256 OBJECT IDENTIFIER ::= { iso(1) member-body(2)
#   us(840)ansi-X9-62(10045) signatures(4) ecdsa-with-SHA2(3) 2 }
ecdsa_with_SHA256 = univ.ObjectIdentifier((1, 2, 840, 10045, 4, 3, 2))

# ecdsa-with-SHA384 OBJECT IDENTIFIER ::= { iso(1) member-body(2)
#   us(840) ansi-X9-62(10045) signatures(4) ecdsa-with-SHA2(3) 3 }
ecdsa_with_SHA384 = univ.ObjectIdentifier((1, 2, 840, 10045, 4, 3, 3))

# ecdsa-with-SHA512 OBJECT IDENTIFIER ::= { iso(1) member-body(2)
#   us(840) ansi-X9-62(10045) signatures(4) ecdsa-with-SHA2(3) 4 }
ecdsa_with_SHA512 = univ.ObjectIdentifier((1, 2, 840, 10045, 4, 3, 4))

