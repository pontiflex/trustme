from shorthand import TYPE, SEQ, SET, CHOICE

from pyasn1.type import tag, namedtype, namedval, univ, constraint, char, useful


# From RFC 2630 (http://tools.ietf.org/html/rfc2630)

"""CryptographicMessageSyntax
    { iso(1) member-body(2) us(840) rsadsi(113549)
      pkcs(1) pkcs-9(9) smime(16) modules(0) cms(1) }

DEFINITIONS IMPLICIT TAGS ::=
BEGIN

-- EXPORTS All
-- The types and values defined in this module are exported for use in
-- the other ASN.1 modules.  Other applications may use them for their
-- own purposes.

IMPORTS

  -- Directory Information Framework (X.501)
        Name
           FROM InformationFramework { joint-iso-itu-t ds(5) modules(1)
                informationFramework(1) 3 }

  -- Directory Authentication Framework (X.509)
        AlgorithmIdentifier, AttributeCertificate, Certificate,
        CertificateList, CertificateSerialNumber
           FROM AuthenticationFramework { joint-iso-itu-t ds(5)
                module(1) authenticationFramework(7) 3 } ;"""

# FIXME: Are these right?
DEFAULT_TAG = False
MAX = 2147483647


# -- Cryptographic Message Syntax

# ContentType ::= OBJECT IDENTIFIER
class ContentType(univ.ObjectIdentifier): pass


# ContentInfo ::= SEQUENCE {
#   contentType ContentType,
#   content [0] EXPLICIT ANY DEFINED BY contentType }
ContentInfo = SEQ(TYPE('contentType', ContentInfo()),
				  TYPE('content', univ.Any(), True))

# SignedData ::= SEQUENCE {
#   version CMSVersion,
#   digestAlgorithms DigestAlgorithmIdentifiers,
#   encapContentInfo EncapsulatedContentInfo,
#   certificates [0] IMPLICIT CertificateSet OPTIONAL,
#   crls [1] IMPLICIT CertificateRevocationLists OPTIONAL,
#   signerInfos SignerInfos }
SignedData = SEQ(TYPE('version', CMSVersion()),
				 TYPE('digestAlgorithms', DigestAlgorithmIdentifiers()),
				 TYPE('encapContentInfo', EncapsulatedContentInfo()),
				 TYPE('certificates', CertificateSet(), False, optional=True),
				 TYPE('crls', CertificateRevocationLists(), False, 1, optional=True),
				 TYPE('signerInfos', SignerInfos()))

# DigestAlgorithmIdentifiers ::= SET OF DigestAlgorithmIdentifier
class DigestAlgorithmIdentifiers(univ.SetOf):
	componentType = DigestAlgorithmIdentifiers()


# SignerInfos ::= SET OF SignerInfo
class SignerInfos(univ.SetOf):
	componentType = SignerInfo()


# EncapsulatedContentInfo ::= SEQUENCE {
#   eContentType ContentType,
#   eContent [0] EXPLICIT OCTET STRING OPTIONAL }
EncapsulatedContentInfo = SEQ(TYPE('eContentType', ContentType()),
							  TYPE('eContent', univ.OctetString(), True, optional=True))

# SignerInfo ::= SEQUENCE {
#   version CMSVersion,
#   sid SignerIdentifier,
#   digestAlgorithm DigestAlgorithmIdentifier,
#   signedAttrs [0] IMPLICIT SignedAttributes OPTIONAL,
#   signatureAlgorithm SignatureAlgorithmIdentifier,
#   signature SignatureValue,
#   unsignedAttrs [1] IMPLICIT UnsignedAttributes OPTIONAL }
SignerInfo = SEQ(TYPE('version', CMSVersion()),
				 TYPE('sid', SignerIdentifier()),
				 TYPE('digestAlgorithm', DigestAlgorithmIdentifier()),
				 TYPE('signedAttrs', SignedAttributes(), False, optional=True),
				 TYPE('signatureAlgorithm', SignatureAlgorithmIdentifier()),
				 TYPE('signature', SignatureValue()),
				 TYPE('unsignedAttrs', UnsignedAttributes(), False, 1, optional=True))

# SignerIdentifier ::= CHOICE {
#   issuerAndSerialNumber IssuerAndSerialNumber,
#   subjectKeyIdentifier [0] SubjectKeyIdentifier }
SignerIdentifier = CHOICE(TYPE('issuerAndSerialNumber', IssuerAndSerialNumber()),
						  TYPE('subjectKeyIdentifier', SubjectKeyIdentifier(), DEFAULT_TAG))

# SignedAttributes ::= SET SIZE (1..MAX) OF Attribute
class SignedAttributes(univ.SetOf):
	componentType = Attribute()
	subtypeSpec = constraint.ValueSizeConstraint(1, MAX)

# UnsignedAttributes ::= SET SIZE (1..MAX) OF Attribute
class UnsignedAttributes(univ.SetOf):
	componentType = Attribute()
	subtypeSpec = constraint.ValueSizeConstraint(1, MAX)

# Attribute ::= SEQUENCE {
#   attrType OBJECT IDENTIFIER,
#   attrValues SET OF AttributeValue }
Attribute = SEQ(TYPE('attrType', univ.ObjectIdentifier()),
				TYPE('attrValues', univ.SequenceOf().subtype(componentType=AttributeValue()))

# AttributeValue ::= ANY
class AttributeValue(univ.Any): pass

# SignatureValue ::= OCTET STRING
class SignatureValue(univ.OctetString): pass

# EnvelopedData ::= SEQUENCE {
#   version CMSVersion,
#   originatorInfo [0] IMPLICIT OriginatorInfo OPTIONAL,
#   recipientInfos RecipientInfos,
#   encryptedContentInfo EncryptedContentInfo,
#   unprotectedAttrs [1] IMPLICIT UnprotectedAttributes OPTIONAL }
EnvelopedData = SEQ(TYPE('version', CMSVersion(),
					TYPE('originatorInfo', OriginatorInfo(), False, optional=True),
					TYPE('recipientInfos', RecipientInfos()),
					TYPE('encryptedContentInfo', EncryptedContentInfo()),
					TYPE('unprotectedAttrs', UnprotectedAttributes(), False, 1, optional=True))


# OriginatorInfo ::= SEQUENCE {
#   certs [0] IMPLICIT CertificateSet OPTIONAL,
#   crls [1] IMPLICIT CertificateRevocationLists OPTIONAL }
OriginatorInfo = SEQ(TYPE('certs', CertificateSet(), False, optional=True),
					 TYPE('crls', CertificateRevocationLists(), False, 1, optional=True))

# RecipientInfos ::= SET OF RecipientInfo
class RecipientInfos(univ.SetOf):
	componentType = RecipientInfo()

# EncryptedContentInfo ::= SEQUENCE {
#   contentType ContentType,
#   contentEncryptionAlgorithm ContentEncryptionAlgorithmIdentifier,
#   encryptedContent [0] IMPLICIT EncryptedContent OPTIONAL }
EncryptedContentInfo = SEQ(TYPE('contentType', ContentType()),
						   TYPE('contentEncryptionAlgorithm', ContentEncryptionAlgorithmIdentifier()),
						   TYPE('encryptedContent', EncryptedContent(), False, optional=True))

# EncryptedContent ::= OCTET STRING
class EncryptedContent(univ.OctetString): pass

# UnprotectedAttributes ::= SET SIZE (1..MAX) OF Attribute
class UnprotectedAttributes(univ.SetOf):
	componentType = Attribute()
	subtypeSpec = constraint.ValueSizeConstraint(1, MAX)

# RecipientInfo ::= CHOICE {
#   ktri KeyTransRecipientInfo,
#   kari [1] KeyAgreeRecipientInfo,
#   kekri [2] KEKRecipientInfo }
RecipientInfo = CHOICE(TYPE('ktri', KeyTransRecipientInfo()),
					   TYPE('kari', KeyAgreeRecipientInfo(), DEFAULT_TAG, 1),
					   TYPE('kekri', KEKRecipientInfo(), DEFAULT_TAG, 2))

# EncryptedKey ::= OCTET STRING
class EncryptedKey(univ.OctetString): pass

#KeyTransRecipientInfo ::= SEQUENCE {
#  version CMSVersion,  -- always set to 0 or 2
#  rid RecipientIdentifier,
#  keyEncryptionAlgorithm KeyEncryptionAlgorithmIdentifier,
#  encryptedKey EncryptedKey }
# FIXME: Constraint?
KeyTransRecipientInfo = SEQ(TYPE('version', CMSVersion()),
							TYPE('rid', RecipientIdentifier()),
							TYPE('keyEncryptionAlgorithm' KeyEncryptionAlgorithmIdentifier()),
							TYPE('encryptedKey', EncryptedKey()))

# RecipientIdentifier ::= CHOICE {
#   issuerAndSerialNumber IssuerAndSerialNumber,
#   subjectKeyIdentifier [0] SubjectKeyIdentifier }
RecipientIdentifier = CHOICE(TYPE('issuerAndSerialNumber', IssuerAndSerialNumber()),
							 TYPE('subjectKeyIdentifier', SubjectKeyIdentifier(), DEFAULT_TAG))

# KeyAgreeRecipientInfo ::= SEQUENCE {
#   version CMSVersion,  -- always set to 3
#   originator [0] EXPLICIT OriginatorIdentifierOrKey,
#   ukm [1] EXPLICIT UserKeyingMaterial OPTIONAL,
#   keyEncryptionAlgorithm KeyEncryptionAlgorithmIdentifier,
#   recipientEncryptedKeys RecipientEncryptedKeys }
# FIXME: Constraint?
KeyAgreeRecipientInfo = SEQ(TYPE('version', CMSVersion()),
							TYPE('originator', OriginatorIdentifierKey(), True),
							TYPE('ukm', UserKeyingMaterial(), True, 1, optional=True),
							TYPE('keyEncryptionAlgorithm', KeyEncryptionAlgorithmIdentifier()),
							TYPE('recipientEncryptedKeys', RecipientEncryptedKeys()))

# OriginatorIdentifierOrKey ::= CHOICE {
#   issuerAndSerialNumber IssuerAndSerialNumber,
#   subjectKeyIdentifier [0] SubjectKeyIdentifier,
#   originatorKey [1] OriginatorPublicKey }
OriginatorIdentifierOrKey = CHOICE(TYPE('issuerAndSerialNumber', IssuerAndSerialNumber()),
								   TYPE('subjectKeyIdentifier', SubjectKeyIdentifier(), DEFAULT_TAG),
								   TYPE('originatorKey', OriginatorPublicKey(), DEFAULT_TAG, 1))

# OriginatorPublicKey ::= SEQUENCE {
#   algorithm AlgorithmIdentifier,
#   publicKey BIT STRING }
OriginatorPublicKey = SEQ(TYPE('algorithm', AlgorithmIdentifier()),
						  TYPE('publicKey', univ.BitString()))

# RecipientEncryptedKeys ::= SEQUENCE OF RecipientEncryptedKey
class RecipientEncryptedKeys(univ.SequenceOf):
	componentType = RecipientEncryptedKey()

# RecipientEncryptedKey ::= SEQUENCE {
#   rid KeyAgreeRecipientIdentifier,
#   encryptedKey EncryptedKey }
RecipientEncryptedKey = SEQ(TYPE('rid', KeyAgreeRecipientIdentifier()),
							TYPE('encryptedKey', EncryptedKey()))

# KeyAgreeRecipientIdentifier ::= CHOICE {
#   issuerAndSerialNumber IssuerAndSerialNumber,
#   rKeyId [0] IMPLICIT RecipientKeyIdentifier }
KeyAgreeRecipientIdentifier = CHOICE(TYPE('issuerAndSerialNumber', IssuerAndSerialNumber()),
									 TYPE('rKeyId', RecipientKeyIdentifier(), False))

# RecipientKeyIdentifier ::= SEQUENCE {
#   subjectKeyIdentifier SubjectKeyIdentifier,
#   date GeneralizedTime OPTIONAL,
#   other OtherKeyAttribute OPTIONAL }
RecipientKeyIdentifier = SEQ(TYPE('subjectKeyIdentifier', SubjectKeyIdentifier()),
							 TYPE('data', GeneralizedTime(), optional=True),
							 TYPE('other', OtherKeyAttribute(), optional=True))

# SubjectKeyIdentifier ::= OCTET STRING
class SubjectKeyIdentifier(univ.OctetString): pass

# KEKRecipientInfo ::= SEQUENCE {
#   version CMSVersion,  -- always set to 4
#   kekid KEKIdentifier,
#   keyEncryptionAlgorithm KeyEncryptionAlgorithmIdentifier,
#   encryptedKey EncryptedKey }
# FIXME: Constraint?
KEKRecipientInfo = SEQ(TYPE('version', CMSVersion()),
					   TYPE('kekid', KEKIdentifier()),
					   TYPE('keyEncryptionAlgorithm', KeyEncryptionAlgorithmIdentifier()),
					   TYPE('encryptedKey', EncryptedKey()))

# KEKIdentifier ::= SEQUENCE {
#   keyIdentifier OCTET STRING,
#   date GeneralizedTime OPTIONAL,
#   other OtherKeyAttribute OPTIONAL }
KEKIdentifier = SEQ(TYPE('keyIdentifier', univ.OctetString()),
					TYPE('data', useful.GeneralizedTime(), optional=True),
					TYPE('other', OtherKeyAttribute(), optional=True))

# DigestedData ::= SEQUENCE {
#   version CMSVersion,
#   digestAlgorithm DigestAlgorithmIdentifier,
#   encapContentInfo EncapsulatedContentInfo,
#   digest Digest }
DigestedData = SEQ(TYPE('version', CMSVersion()),
				   TYPE('digestAlgorithm', DigestAlgorithmIdentifier()),
				   TYPE('encapContentInfo', EncapsulatedContentInfo()),
				   TYPE('digest', Digest()))

# Digest ::= OCTET STRING
class Digest(univ.OctetString): pass

# EncryptedData ::= SEQUENCE {
#   version CMSVersion,
#   encryptedContentInfo EncryptedContentInfo,
#   unprotectedAttrs [1] IMPLICIT UnprotectedAttributes OPTIONAL }
EncryptedData = SEQ(TYPE('version', CMSVersion()),
					TYPE('encryptedContentInfo', EncryptedContentInfo()),
					TYPE('unprotectedAttrs', UnprotectedAttributes(), False, 1, optional=True))

# AuthenticatedData ::= SEQUENCE {
#   version CMSVersion,
#   originatorInfo [0] IMPLICIT OriginatorInfo OPTIONAL,
#   recipientInfos RecipientInfos,
#   macAlgorithm MessageAuthenticationCodeAlgorithm,
#   digestAlgorithm [1] DigestAlgorithmIdentifier OPTIONAL,
#   encapContentInfo EncapsulatedContentInfo,
#   authenticatedAttributes [2] IMPLICIT AuthAttributes OPTIONAL,
#   mac MessageAuthenticationCode,
#   unauthenticatedAttributes [3] IMPLICIT UnauthAttributes OPTIONAL }
AuthenticatedData = SEQ(TYPE('version', CMSVersion()),
						TYPE('originatorInfo', OriginatorInfo(), False, optional=True),
						TYPE('recipientInfos', RecipientInfos()),
						TYPE('macAlgorithm', MessageAuthenticationCodeAlgorithm()),
						TYPE('digestAlgorithm', DigestAlgorithmIdentifier(), DEFAULT_TAG, 1, optional=True),
						TYPE('encapContentInfo', EncapsulatedContentInfo()),
						TYPE('authenticatedAttributes', AuthAttributes(), False, 2, optional=True),
						TYPE('mac', MessageAuthenticationCode()),
						TYPE('unauthenticatedAttributes', UnauthAttributes(), False, 3, optional=True))

# AuthAttributes ::= SET SIZE (1..MAX) OF Attribute
class AuthAttributes(univ.SetOf):
	componentType = Attribute()
	subtypeSpec = constraint.ValueSizeConstraint(1, MAX)

# UnauthAttributes ::= SET SIZE (1..MAX) OF Attribute
class UnauthAttributes(univ.SetOf):
	componentType = Attribute()
	subtypeSpec = constraint.ValueSizeConstraint(1, MAX)

# MessageAuthenticationCode ::= OCTET STRING
class MessageAuthenticationCode(univ.OctetString): pass

# DigestAlgorithmIdentifier ::= AlgorithmIdentifier
class DigestAlgorithmIdentifier(AlgorithmIdentifier): pass

# SignatureAlgorithmIdentifier ::= AlgorithmIdentifier
class SignatureAlgorithmIdentifier(AlgorithmIdentifier): pass

# KeyEncryptionAlgorithmIdentifier ::= AlgorithmIdentifier
KeyEncryptionAlgorithmIdentifier(AlgorithmIdentifier): pass

# ContentEncryptionAlgorithmIdentifier ::= AlgorithmIdentifier
class ContentEncryptionAlgorithmIdentifier(AlgorithmIdentifier): pass

# MessageAuthenticationCodeAlgorithm ::= AlgorithmIdentifier
class MessageAuthenticationCodeAlgorithm(AlgorithmIdentifier): pass

# CertificateRevocationLists ::= SET OF CertificateList
class CertificateRevocationLists(univ.SetOf):
	componentType = CertificateList()

# CertificateChoices ::= CHOICE {
#   certificate Certificate,  -- See X.509
#   extendedCertificate [0] IMPLICIT ExtendedCertificate,  -- Obsolete
#   attrCert [1] IMPLICIT AttributeCertificate }  -- See X.509 & X9.57
# FIXME: What to do with obsolete?
CertificateChoices = CHOICE(TYPE('certificate', Certificate()),
							TYPE('extendedCertificate', ExtendedCertificate(), False),
							TYPE('attrCert', AttributeCertificate(), False, 1))

# CertificateSet ::= SET OF CertificateChoices
class CertificateSet(univ.SetOf):
	componentType = CertificateChoices()

# IssuerAndSerialNumber ::= SEQUENCE {
#   issuer Name,
#   serialNumber CertificateSerialNumber }
IssuerAndSerialNumber = SEQ(TYPE('issuer', Name()),
							TYPE('serialNumber', CertificateSerialNumber()))

# CMSVersion ::= INTEGER  { v0(0), v1(1), v2(2), v3(3), v4(4) }
class CMSVersion(univ.Integer):
	namedValues = namedval.NamedValues(('v0', 0), ('v1', 1), ('v2', 2),
									   ('v3', 3), ('v4', 4))

# UserKeyingMaterial ::= OCTET STRING
class UserKeyingMaterial(univ.OctetString): pass

# OtherKeyAttribute ::= SEQUENCE {
#   keyAttrId OBJECT IDENTIFIER,
#   keyAttr ANY DEFINED BY keyAttrId OPTIONAL }
OtherKeyAttribute = SEQ(TYPE('keyAttrId', univ.ObjectIdentifier()),
						TYPE('keyAttr', univ.Any(), optional=True))


# -- CMS Attributes

# MessageDigest ::= OCTET STRING
class MessageDigest(univ.OctetString): pass

# SigningTime  ::= Time
class SigningTime(Time): pass

# Time ::= CHOICE {
#   utcTime UTCTime,
#   generalTime GeneralizedTime }
Time = CHOICE(TYPE('utcTime', useful.UTCTime()),
			  TYPE('generalTime', useful.GeneralizedTime()))

# Countersignature ::= SignerInfo
class CounterSignature(SignerInfo): pass

# -- Algorithm Identifiers

# sha-1 OBJECT IDENTIFIER ::= { iso(1) identified-organization(3)
#     oiw(14) secsig(3) algorithm(2) 26 }
sha_1 = univ.ObjectIdentifier((1, 3, 14, 3, 2, 26))

# md5 OBJECT IDENTIFIER ::= { iso(1) member-body(2) us(840)
#     rsadsi(113549) digestAlgorithm(2) 5 }
md5 = univ.ObjectIdentifier((1, 2, 840, 113549, 2, 5))

# id-dsa-with-sha1 OBJECT IDENTIFIER ::=  { iso(1) member-body(2)
#    us(840) x9-57 (10040) x9cm(4) 3 }
id_dsa_with_sha1 = univ.ObjectIdentifier((1, 2, 840, 10040, 4, 3))

# rsaEncryption OBJECT IDENTIFIER ::= { iso(1) member-body(2)
#     us(840) rsadsi(113549) pkcs(1) pkcs-1(1) 1 }
rsaEncryption = univ.ObjectIdentifier((1, 2, 840, 113549, 1, 1, 1))

# dh-public-number OBJECT IDENTIFIER ::= { iso(1) member-body(2)
#     us(840) ansi-x942(10046) number-type(2) 1 }
dh_public_number = univ.ObjectIdentifier((1, 2, 840, 10046, 2, 1))

# id-alg-ESDH OBJECT IDENTIFIER ::= { iso(1) member-body(2) us(840)
#     rsadsi(113549) pkcs(1) pkcs-9(9) smime(16) alg(3) 5 }
id_alg_ESDH = univ.ObjectIdentifier((1, 2, 840, 113549, 1, 9, 16, 3, 5))

# id-alg-CMS3DESwrap OBJECT IDENTIFIER ::= { iso(1) member-body(2)
#     us(840) rsadsi(113549) pkcs(1) pkcs-9(9) smime(16) alg(3) 6 }
id_alg_CMS3DESwrap = univ.ObjectIdentifier((1, 2, 840, 113549, 1, 9, 16, 3, 6))

# id-alg-CMSRC2wrap OBJECT IDENTIFIER ::= { iso(1) member-body(2)
#     us(840) rsadsi(113549) pkcs(1) pkcs-9(9) smime(16) alg(3) 7 }
id_alg_CMSRC2Swrap = univ.ObjectIdentifier((1, 2, 840, 113549, 1, 9, 16, 3, 7))

# des-ede3-cbc OBJECT IDENTIFIER ::= { iso(1) member-body(2)
#     us(840) rsadsi(113549) encryptionAlgorithm(3) 7 }
des_ede3_cbc = univ.ObjectIdentifier((1, 2, 840, 113549, 1, 9, 3, 6))

# rc2-cbc OBJECT IDENTIFIER ::= { iso(1) member-body(2) us(840)
#     rsadsi(113549) encryptionAlgorithm(3) 2 }
rc2_cbc = univ.ObjectIdentifier((1, 2, 840, 113549, 3, 2))

# hMAC-SHA1 OBJECT IDENTIFIER ::= { iso(1) identified-organization(3)
#     dod(6) internet(1) security(5) mechanisms(5) 8 1 2 }
hMAC_SHA1 = univ.ObjectIdentifier((1, 3, 6, 1, 5, 5, 8, 1, 2))


# -- Algorithm Parameters

# KeyWrapAlgorithm ::= AlgorithmIdentifier
class KeyWrapAlgorithm(AlgorithmIdentifier): pass

# RC2wrapParameter ::= RC2ParameterVersion
class RC2wrapParameter(RC2ParameterVersion): pass

# RC2ParameterVersion ::= INTEGER
class RC2ParameterVersion(univ.Integer): pass

# CBCParameter ::= IV
class CCBParameter(IV): pass

# IV ::= OCTET STRING  -- exactly 8 octets
# FIXME: Constraint?
class IV(univ.OctetString): pass

# RC2CBCParameter ::= SEQUENCE {
#   rc2ParameterVersion INTEGER,
#   iv OCTET STRING  }  -- exactly 8 octets
# FIXME: Should this actually use the defined types?
RC2CBCParameter = SEQ(TYPE('rc2ParameterVersion', univ.Integer()),
					  TYPE('iv', univ.OctetString()))


# -- Content Type Object Identifiers

# id-ct-contentInfo OBJECT IDENTIFIER ::= { iso(1) member-body(2)
#     us(840) rsadsi(113549) pkcs(1) pkcs-9(9) smime(16)
#     ct(1) 6 }
id_ct_contentInfo = univ.ObjectIdentifier((1, 2, 840, 113549, 1, 9, 16, 1, 6))

# id-data OBJECT IDENTIFIER ::= { iso(1) member-body(2)
#     us(840) rsadsi(113549) pkcs(1) pkcs7(7) 1 }
id_data = univ.ObjectIdentifier((1, 2, 840, 113549, 1, 7, 1))

# id-signedData OBJECT IDENTIFIER ::= { iso(1) member-body(2)
#     us(840) rsadsi(113549) pkcs(1) pkcs7(7) 2 }
id_signedData = univ.ObjectIdentifier((1, 2, 840, 113549, 1, 7, 2))

# id-envelopedData OBJECT IDENTIFIER ::= { iso(1) member-body(2)
#     us(840) rsadsi(113549) pkcs(1) pkcs7(7) 3 }
id_envelopedData = univ.ObjectIdentifier((1, 2, 840, 113549, 1, 7, 3))

# id-digestedData OBJECT IDENTIFIER ::= { iso(1) member-body(2)
#     us(840) rsadsi(113549) pkcs(1) pkcs7(7) 5 }
id_digestedData = univ.ObjectIdentifier((1, 2, 840, 113549, 1, 7, 5))

# id-encryptedData OBJECT IDENTIFIER ::= { iso(1) member-body(2)
#     us(840) rsadsi(113549) pkcs(1) pkcs7(7) 6 }
id_encryptedData = univ.ObjectIdentifier((1, 2, 840, 113549, 1, 7, 6))

# id-ct-authData OBJECT IDENTIFIER ::= { iso(1) member-body(2)
#     us(840) rsadsi(113549) pkcs(1) pkcs-9(9) smime(16)
#     ct(1) 2 }
id_ct_authData = univ.ObjectIdentifier((1, 2, 840, 113549, 1, 9, 16, 1, 2))


# -- Attribute Object Identifiers

# id-contentType OBJECT IDENTIFIER ::= { iso(1) member-body(2)
#     us(840) rsadsi(113549) pkcs(1) pkcs9(9) 3 }
id_contentType = univ.ObjectIdentifier((1, 2, 840, 113549, 1, 9, 3))

# id-messageDigest OBJECT IDENTIFIER ::= { iso(1) member-body(2)
#     us(840) rsadsi(113549) pkcs(1) pkcs9(9) 4 }
id_messageDigest = univ.ObjectIdentifier((1, 2, 840, 113549, 1, 9, 4))

# id-signingTime OBJECT IDENTIFIER ::= { iso(1) member-body(2)
#     us(840) rsadsi(113549) pkcs(1) pkcs9(9) 5 }
id_signingTime = univ.ObjectIdentifier((1, 2, 840, 113549, 1, 9, 5))

# id-countersignature OBJECT IDENTIFIER ::= { iso(1) member-body(2)
#     us(840) rsadsi(113549) pkcs(1) pkcs9(9) 6 }
id_countersignature = univ.ObjectIdentifier((1, 2, 840, 113549, 1, 9, 6))


# -- Obsolete Extended Certificate syntax from PKCS#6

# ExtendedCertificate ::= SEQUENCE {
#   extendedCertificateInfo ExtendedCertificateInfo,
#   signatureAlgorithm SignatureAlgorithmIdentifier,
#   signature Signature }
ExtendedCertificate = SEQ(TYPE('extendedCertificateInfo', ExtendedCertificateInfo()),
						  TYPE('signatureAlgorithm', SignatureAlgorithmIdentifier()),
						  TYPE('signature', Signature()))

# ExtendedCertificateInfo ::= SEQUENCE {
#   version CMSVersion,
#   certificate Certificate,
#   attributes UnauthAttributes }
ExtendedCertificateInfo = SEQ(TYPE('version', CMSVersion()),
							  TYPE('certificate', Certificate()),
							  TYPE('attributes', UnauthAttributes()))

# Signature ::= BIT STRING
class Signature(univ.BitString): pass


#END -- of CryptographicMessageSyntax

