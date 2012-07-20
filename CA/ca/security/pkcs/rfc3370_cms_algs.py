from shorthand import TYPE, SEQ, SET, CHOICE

from pyasn1.type import tag, namedtype, namedval, univ, constraint, char, useful


# FROM RFC 3370 (http://tools.ietf.org/html/rfc3370)

"""CryptographicMessageSyntaxAlgorithms
       { iso(1) member-body(2) us(840) rsadsi(113549)
         pkcs(1) pkcs-9(9) smime(16) modules(0) cmsalg-2001(16) }

DEFINITIONS IMPLICIT TAGS ::=
BEGIN

-- EXPORTS All
-- The types and values defined in this module are exported for use
-- in the other ASN.1 modules.  Other applications may use them for
-- their own purposes.

IMPORTS
 -- Imports from RFC 3280 [PROFILE], Appendix A.1
       AlgorithmIdentifier
          FROM PKIX1Explicit88 { iso(1)
               identified-organization(3) dod(6) internet(1)
               security(5) mechanisms(5) pkix(7) mod(0)
               pkix1-explicit(18) } ;"""

# FIXME: Are these right?
DEFAULT_TAG = False
MAX = 2147483647


# -- Algorithm Identifiers

# sha-1 OBJECT IDENTIFIER ::= { iso(1) identified-organization(3)
#     oiw(14) secsig(3) algorithm(2) 26 }
sha_1 = univ.ObjectIdentifier((1, 3, 14, 3, 2, 26))

# md5 OBJECT IDENTIFIER ::= { iso(1) member-body(2) us(840)
#     rsadsi(113549) digestAlgorithm(2) 5 }
md5 = univ.ObjectIdentifier((1, 2, 840, 113549, 2, 5))

# id-dsa OBJECT IDENTIFIER ::=  { iso(1) member-body(2) us(840)
#    x9-57(10040) x9cm(4) 1 }
id_dsa = univ.ObjectIdentifier((1, 2, 840, 10040, 4, 1))

# id-dsa-with-sha1 OBJECT IDENTIFIER ::=  { iso(1) member-body(2)
#    us(840) x9-57 (10040) x9cm(4) 3 }
id_dsa_with_sha1 = univ.ObjectIdentifier((1, 2, 840, 10040, 4, 3))

# rsaEncryption OBJECT IDENTIFIER ::= { iso(1) member-body(2)
#     us(840) rsadsi(113549) pkcs(1) pkcs-1(1) 1 }
rsaEncryption = univ.ObjectIdentifier((1, 2, 840, 113549, 1, 1, 1))

# md5WithRSAEncryption OBJECT IDENTIFIER ::= { iso(1)
#    member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs-1(1) 4 }
md5WithRSAEncryption = univ.ObjectIdentifier((1, 2, 840, 113549, 1, 1, 4))

# sha1WithRSAEncryption OBJECT IDENTIFIER ::= { iso(1)
#    member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs-1(1) 5 }
sha1WithRSAEncryption = univ.ObjectIdentifier((1, 2, 840, 113549, 1, 1, 5))

# dh-public-number OBJECT IDENTIFIER ::= { iso(1) member-body(2)
#     us(840) ansi-x942(10046) number-type(2) 1 }
dh_public_number = univ.ObjectIdentifier((1, 2, 840, 10046, 2, 1))

# id-alg-ESDH OBJECT IDENTIFIER ::= { iso(1) member-body(2) us(840)
#     rsadsi(113549) pkcs(1) pkcs-9(9) smime(16) alg(3) 5 }
id_alg_ESDH = univ.ObjectIdentifier((1, 2, 840, 113549, 1, 9, 16, 3, 5))

# id-alg-SSDH OBJECT IDENTIFIER ::= { iso(1) member-body(2) us(840)
#    rsadsi(113549) pkcs(1) pkcs-9(9) smime(16) alg(3) 10 }
id_alg_SSDH = univ.ObjectIdentifier((1, 2, 840, 113549, 1, 9, 16, 3, 10))

# id-alg-CMS3DESwrap OBJECT IDENTIFIER ::= { iso(1) member-body(2)
#     us(840) rsadsi(113549) pkcs(1) pkcs-9(9) smime(16) alg(3) 6 }
id_alg_CMS3DESwrap = univ.ObjectIdentifier((1, 2, 840, 113549, 1, 9, 16, 3, 6))

# id-alg-CMSRC2wrap OBJECT IDENTIFIER ::= { iso(1) member-body(2)
#     us(840) rsadsi(113549) pkcs(1) pkcs-9(9) smime(16) alg(3) 7 }
id_alg_CMSRC2Swrap = univ.ObjectIdentifier((1, 2, 840, 113549, 1, 9, 16, 3, 7))

# rc2-cbc OBJECT IDENTIFIER ::= { iso(1) member-body(2) us(840)
#     rsadsi(113549) encryptionAlgorithm(3) 2 }
rc2_cbc = univ.ObjectIdentifier((1, 2, 840, 113549, 3, 2))

# des-ede3-cbc OBJECT IDENTIFIER ::= { iso(1) member-body(2)
#    us(840) rsadsi(113549) encryptionAlgorithm(3) 7 }
rc2_cbc = univ.ObjectIdentifier((1, 2, 840, 113549, 3, 7))

# hMAC-SHA1 OBJECT IDENTIFIER ::= { iso(1) identified-organization(3)
#     dod(6) internet(1) security(5) mechanisms(5) 8 1 2 }
hMAC_SHA1 = univ.ObjectIdentifier((1, 3, 6, 1, 5, 5, 8, 1, 2))

# id-PBKDF2 OBJECT IDENTIFIER ::= { iso(1) member-body(2) us(840)
#    rsadsi(113549) pkcs(1) pkcs-5(5) 12 }
id_PBKDF2 = univ.ObjectIdentifier((1, 2, 840, 113549, 1, 5, 12))


# -- Public Key Types

# Dss-Pub-Key ::= INTEGER  -- Y
class Dss_Pub_Key(univ.Integer): pass

# RSAPublicKey ::= SEQUENCE {
#  modulus INTEGER,  -- n
#  publicExponent INTEGER }  -- e
RSAPublicKey = SEQ(TYPE('modulus', univ.Integer()),
				   TYPE('publicExponent', univ.Integer()))

# DHPublicKey ::= INTEGER  -- y = g^x mod p
class DHPublicKey(univ.Integer): pass


# -- Signature Value Types

# Dss-Sig-Value ::= SEQUENCE {
#  r INTEGER,
#  s INTEGER }
Dss_Sig_Value = SEQ(TYPE('r', univ.Integer()),
					TYPE('s', univ.Integer()))


# -- Algorithm Identifier Parameter Types

# Dss-Parms ::= SEQUENCE {
#  p INTEGER,
#  q INTEGER,
#  g INTEGER }
Dss_Parms = SEQ(TYPE('p', univ.Integer()),
				TYPE('q', univ.Integer()),
				TYPE('g', univ.Integer()))

# ValidationParms ::= SEQUENCE {
#  seed BIT STRING,
#  pgenCounter INTEGER }
ValidationParms = SEQ(TYPE('seed', univ.BitString()),
					  TYPE('pgenCounter', univ.Integer()))

# DHDomainParameters ::= SEQUENCE {
#  p INTEGER,  -- odd prime, p=jq +1
#  g INTEGER,  -- generator, g
#  q INTEGER,  -- factor of p-1
#  j INTEGER OPTIONAL,  -- subgroup factor
#  validationParms ValidationParms OPTIONAL }
DHDomainParameters = SEQ(TYPE('p', univ.Integer()),
						 TYPE('g', univ.Integer()),
						 TYPE('q', univ.Integer()),
						 TYPE('j', univ.Integer(), optional=True),
						 TYPE('validationParms', ValidationParms(), optional=True))

# KeyWrapAlgorithm ::= AlgorithmIdentifier
class KeyWrapAlgorithm(AlgorithmIdentifier): pass

# RC2ParameterVersion ::= INTEGER
class RC2ParameterVersion(univ.Integer): pass

# RC2wrapParameter ::= RC2ParameterVersion
class RC2wrapParameter(RC2ParameterVersion): pass

# IV ::= OCTET STRING  -- exactly 8 octets
# FIXME: Constraint?
class IV(univ.OctetString): pass

# CBCParameter ::= IV
class CCBParameter(IV): pass

# RC2CBCParameter ::= SEQUENCE {
#   rc2ParameterVersion INTEGER,
#   iv OCTET STRING  }  -- exactly 8 octets
# FIXME: Should this actually use the defined types?
RC2CBCParameter = SEQ(TYPE('rc2ParameterVersion', univ.Integer()),
					  TYPE('iv', univ.OctetString()))

# PBKDF2-params ::= SEQUENCE {
#  salt CHOICE {
#    specified OCTET STRING,
#    otherSource AlgorithmIdentifier },
#  iterationCount INTEGER (1..MAX),
#  keyLength INTEGER (1..MAX) OPTIONAL,
#  prf AlgorithmIdentifier
#    DEFAULT { algorithm hMAC-SHA1, parameters NULL } }
PBKDF2_params = SEQ(TYPE('salt', CHOICE(TYPE('specified', univ.OctetString()),
										TYPE('otherSource', AlgorithmIdentifier())),
					TYPE('iterationCount', univ.Integer(),
						 subtypeSpec=constraint.ValueRangeConstraint(1, MAX)),
					TYPE('keyLength', univ.Integer(), optional=True,
						 subtypeSpec=constraint.ValueRangeConstraint(1, MAX)),
					TYPE('prf', AlgorithmIdentifier(algorithm=hMAC_SHA1, parameters=univ.Null())))

# END -- of CryptographicMessageSyntaxAlgorithms

