from shorthand import MAX, TYPE, SEQ, SET, SEQOF, SETOF, CHOICE

from pyasn1.type import tag, namedtype, namedval, univ, constraint, char, useful


# FROM RFC 5652 (http://tools.ietf.org/html/rfc5652)

"""CryptographicMessageSyntax2004
     { iso(1) member-body(2) us(840) rsadsi(113549)
       pkcs(1) pkcs-9(9) smime(16) modules(0) cms-2004(24) }

   DEFINITIONS IMPLICIT TAGS ::=
   BEGIN

   -- EXPORTS All
   -- The types and values defined in this module are exported for use
   -- in the other ASN.1 modules.  Other applications may use them for
   -- their own purposes.

   IMPORTS

     -- Imports from RFC 5280 [PROFILE], Appendix A.1
           AlgorithmIdentifier, Certificate, CertificateList,
           CertificateSerialNumber, Name
              FROM PKIX1Explicit88
                   { iso(1) identified-organization(3) dod(6)
                     internet(1) security(5) mechanisms(5) pkix(7)
                     mod(0) pkix1-explicit(18) }

     -- Imports from RFC 3281 [ACPROFILE], Appendix B
           AttributeCertificate
              FROM PKIXAttributeCertificate
                   { iso(1) identified-organization(3) dod(6)
                     internet(1) security(5) mechanisms(5) pkix(7)
                     mod(0) attribute-cert(12) }

     -- Imports from Appendix B of this document
           AttributeCertificateV1
              FROM AttributeCertificateVersion1
                   { iso(1) member-body(2) us(840) rsadsi(113549)
                     pkcs(1) pkcs-9(9) smime(16) modules(0)
                     v1AttrCert(15) } ;"""

from rfc5280_explicit import ( AlgorithmIdentifier, Certificate,
							   CertificateList, CertificateSerialNumber,
							   Name )

# Circular import
import rfc5652_attr_cert_v1 as rfc5652

# Circular import (use RFC5755, which obsoletes RFC3281)
import rfc5755_attr_cert_2008 as rfc5755

DEFAULT_TAG = False


# -- Cryptographic Message Syntax

# ContentType ::= OBJECT IDENTIFIER
class ContentType(univ.ObjectIdentifier): pass

# ContentInfo ::= SEQUENCE {
#   contentType ContentType,
#   content [0] EXPLICIT ANY DEFINED BY contentType }
ContentInfo = SEQ(TYPE('contentType', ContentType),
				  TYPE('content', univ.Any, True))

# CMSVersion ::= INTEGER  { v0(0), v1(1), v2(2), v3(3), v4(4), v5(5) }
class CMSVersion(univ.Integer):
	namedValues = namedval.NamedValues(('v0', 0), ('v1', 1), ('v2', 2),
									   ('v3', 3), ('v4', 4), ('v5', 5))












# Algorithm Identifiers

# DigestAlgorithmIdentifier ::= AlgorithmIdentifier
class DigestAlgorithmIdentifier(AlgorithmIdentifier): pass

# DigestAlgorithmIdentifiers ::= SET OF DigestAlgorithmIdentifier
DigestAlgorithmIdentifiers = SETOF(DigestAlgorithmIdentifier)

# SignatureAlgorithmIdentifier ::= AlgorithmIdentifier
class SignatureAlgorithmIdentifier(AlgorithmIdentifier): pass

# KeyEncryptionAlgorithmIdentifier ::= AlgorithmIdentifier
class KeyEncryptionAlgorithmIdentifier(AlgorithmIdentifier): pass

# ContentEncryptionAlgorithmIdentifier ::= AlgorithmIdentifier
class ContentEncryptionAlgorithmIdentifier(AlgorithmIdentifier): pass

# MessageAuthenticationCodeAlgorithm ::= AlgorithmIdentifier
class MessageAuthenticationCodeAlgorithm(AlgorithmIdentifier): pass

# KeyDerivationAlgorithmIdentifier ::= AlgorithmIdentifier
class KeyDerivationAlgorithmIdentifier(AlgorithmIdentifier): pass















# Raw types

# EncryptedContent ::= OCTET STRING
class EncryptedContent(univ.OctetString): pass

# Signature ::= BIT STRING
class Signature(univ.BitString): pass

# SubjectKeyIdentifier ::= OCTET STRING
class SubjectKeyIdentifier(univ.OctetString): pass

# SignatureValue ::= OCTET STRING
class SignatureValue(univ.OctetString): pass

# Digest ::= OCTET STRING
class Digest(univ.OctetString): pass

# MessageAuthenticationCode ::= OCTET STRING
class MessageAuthenticationCode(univ.OctetString): pass

# EncryptedKey ::= OCTET STRING
class EncryptedKey(univ.OctetString): pass

# UserKeyingMaterial ::= OCTET STRING
class UserKeyingMaterial(univ.OctetString): pass

# MessageDigest ::= OCTET STRING
class MessageDigest(univ.OctetString): pass
















# Time types

# Time ::= CHOICE {
#   utcTime UTCTime,
#   generalTime GeneralizedTime }
Time = CHOICE(TYPE('utcTime', useful.UTCTime),
			  TYPE('generalTime', useful.GeneralizedTime))

# SigningTime  ::= Time
class SigningTime(Time): pass
















# Attribute types

# AttributeValue ::= ANY
class AttributeValue(univ.Any): pass

# Attribute ::= SEQUENCE {
#   attrType OBJECT IDENTIFIER,
#   attrValues SET OF AttributeValue }
Attribute = SEQ(TYPE('attrType', univ.ObjectIdentifier),
				TYPE('attrValues', SEQOF(AttributeValue)))

# AuthAttributes ::= SET SIZE (1..MAX) OF Attribute
class AuthAttributes(univ.SetOf):
	componentType = Attribute()
	subtypeSpec = constraint.ValueSizeConstraint(1, MAX)

# UnauthAttributes ::= SET SIZE (1..MAX) OF Attribute
class UnauthAttributes(univ.SetOf):
	componentType = Attribute()
	subtypeSpec = constraint.ValueSizeConstraint(1, MAX)

# UnprotectedAttributes ::= SET SIZE (1..MAX) OF Attribute
class UnprotectedAttributes(univ.SetOf):
	componentType = Attribute()
	subtypeSpec = constraint.ValueSizeConstraint(1, MAX)

# SignedAttributes ::= SET SIZE (1..MAX) OF Attribute
class SignedAttributes(univ.SetOf):
	componentType = Attribute()
	subtypeSpec = constraint.ValueSizeConstraint(1, MAX)

# UnsignedAttributes ::= SET SIZE (1..MAX) OF Attribute
class UnsignedAttributes(univ.SetOf):
	componentType = Attribute()
	subtypeSpec = constraint.ValueSizeConstraint(1, MAX)

# OtherKeyAttribute ::= SEQUENCE {
#   keyAttrId OBJECT IDENTIFIER,
#   keyAttr ANY DEFINED BY keyAttrId OPTIONAL }
OtherKeyAttribute = SEQ(TYPE('keyAttrId', univ.ObjectIdentifier),
						TYPE('keyAttr', univ.Any, optional=True))















# Identifier types

# IssuerAndSerialNumber ::= SEQUENCE {
#   issuer Name,
#   serialNumber CertificateSerialNumber }
IssuerAndSerialNumber = SEQ(TYPE('issuer', Name),
							TYPE('serialNumber', CertificateSerialNumber))

# SignerIdentifier ::= CHOICE {
#   issuerAndSerialNumber IssuerAndSerialNumber,
#   subjectKeyIdentifier [0] SubjectKeyIdentifier }
SignerIdentifier = CHOICE(TYPE('issuerAndSerialNumber', IssuerAndSerialNumber),
						  TYPE('subjectKeyIdentifier', SubjectKeyIdentifier, DEFAULT_TAG))

# RecipientIdentifier ::= CHOICE {
#   issuerAndSerialNumber IssuerAndSerialNumber,
#   subjectKeyIdentifier [0] SubjectKeyIdentifier }
RecipientIdentifier = CHOICE(TYPE('issuerAndSerialNumber', IssuerAndSerialNumber),
							 TYPE('subjectKeyIdentifier', SubjectKeyIdentifier, DEFAULT_TAG))

# RecipientKeyIdentifier ::= SEQUENCE {
#   subjectKeyIdentifier SubjectKeyIdentifier,
#   date GeneralizedTime OPTIONAL,
#   other OtherKeyAttribute OPTIONAL }
RecipientKeyIdentifier = SEQ(TYPE('subjectKeyIdentifier', SubjectKeyIdentifier),
							 TYPE('data', useful.GeneralizedTime, optional=True),
							 TYPE('other', OtherKeyAttribute, optional=True))

# KeyAgreeRecipientIdentifier ::= CHOICE {
#   issuerAndSerialNumber IssuerAndSerialNumber,
#   rKeyId [0] IMPLICIT RecipientKeyIdentifier }
KeyAgreeRecipientIdentifier = CHOICE(TYPE('issuerAndSerialNumber', IssuerAndSerialNumber),
									 TYPE('rKeyId', RecipientKeyIdentifier, False))

# KEKIdentifier ::= SEQUENCE {
#   keyIdentifier OCTET STRING,
#   date GeneralizedTime OPTIONAL,
#   other OtherKeyAttribute OPTIONAL }
KEKIdentifier = SEQ(TYPE('keyIdentifier', univ.OctetString),
					TYPE('data', useful.GeneralizedTime, optional=True),
					TYPE('other', OtherKeyAttribute, optional=True))

# OriginatorPublicKey ::= SEQUENCE {
#   algorithm AlgorithmIdentifier,
#   publicKey BIT STRING }
OriginatorPublicKey = SEQ(TYPE('algorithm', AlgorithmIdentifier),
						  TYPE('publicKey', univ.BitString))

# OriginatorIdentifierOrKey ::= CHOICE {
#   issuerAndSerialNumber IssuerAndSerialNumber,
#   subjectKeyIdentifier [0] SubjectKeyIdentifier,
#   originatorKey [1] OriginatorPublicKey }
OriginatorIdentifierOrKey = CHOICE(TYPE('issuerAndSerialNumber', IssuerAndSerialNumber),
								   TYPE('subjectKeyIdentifier', SubjectKeyIdentifier, DEFAULT_TAG),
								   TYPE('originatorKey', OriginatorPublicKey, DEFAULT_TAG, 1))
















# Certificate types

# ExtendedCertificateInfo ::= SEQUENCE {
#   version CMSVersion,
#   certificate Certificate,
#   attributes UnauthAttributes }
ExtendedCertificateInfo = SEQ(TYPE('version', CMSVersion),
							  TYPE('certificate', Certificate),
							  TYPE('attributes', UnauthAttributes))

# ExtendedCertificate ::= SEQUENCE {
#   extendedCertificateInfo ExtendedCertificateInfo,
#   signatureAlgorithm SignatureAlgorithmIdentifier,
#   signature Signature }
ExtendedCertificate = SEQ(TYPE('extendedCertificateInfo', ExtendedCertificateInfo),
						  TYPE('signatureAlgorithm', SignatureAlgorithmIdentifier),
						  TYPE('signature', Signature))

#ExtendedCertificateOrCertificate ::= CHOICE {
#  certificate Certificate,
#  extendedCertificate [0] IMPLICIT ExtendedCertificate }
ExtendedCertificateOrCertificate = CHOICE(TYPE('certificate', Certificate),
										  TYPE('extendedCertificate', ExtendedCertificate, False))













# Attribute certificate types

# AttributeCertificateV2 ::= AttributeCertificate
class AttributeCertificateV2(rfc5755.AttributeCertificate): pass

# OtherCertificateFormat ::= SEQUENCE {
#   otherCertFormat OBJECT IDENTIFIER,
#   otherCert ANY DEFINED BY otherCertFormat }
OtherCertificateFormat = SEQ(TYPE('otherCertFormat', univ.ObjectIdentifier),
							 TYPE('otherCert', univ.Any))

# CertificateChoices ::= CHOICE {
#   certificate Certificate,
#   extendedCertificate [0] IMPLICIT ExtendedCertificate,  -- Obsolete
#   v1AttrCert [1] IMPLICIT AttributeCertificateV1,        -- Obsolete
#   v2AttrCert [2] IMPLICIT AttributeCertificateV2,
#   other [3] IMPLICIT OtherCertificateFormat }
# FIXME: What to do with obsolete?
CertificateChoices = CHOICE(TYPE('certificate', Certificate),
							TYPE('extendedCertificate', ExtendedCertificate, False),
							TYPE('v1AttrCert', rfc5652.AttributeCertificateV1, False, 1),
							TYPE('v2AttrCert', AttributeCertificateV2, False, 2),
							TYPE('other', OtherCertificateFormat, False, 3))

# CertificateSet ::= SET OF CertificateChoices
CertificateSet = SETOF(CertificateChoices)














# Info types

# EncapsulatedContentInfo ::= SEQUENCE {
#   eContentType ContentType,
#   eContent [0] EXPLICIT OCTET STRING OPTIONAL }
EncapsulatedContentInfo = SEQ(TYPE('eContentType', ContentType),
							  TYPE('eContent', univ.OctetString, True, optional=True))

# EncryptedContentInfo ::= SEQUENCE {
#   contentType ContentType,
#   contentEncryptionAlgorithm ContentEncryptionAlgorithmIdentifier,
#   encryptedContent [0] IMPLICIT EncryptedContent OPTIONAL }
EncryptedContentInfo = SEQ(TYPE('contentType', ContentType),
						   TYPE('contentEncryptionAlgorithm', ContentEncryptionAlgorithmIdentifier),
						   TYPE('encryptedContent', EncryptedContent, False, optional=True))

# SignerInfo ::= SEQUENCE {
#   version CMSVersion,
#   sid SignerIdentifier,
#   digestAlgorithm DigestAlgorithmIdentifier,
#   signedAttrs [0] IMPLICIT SignedAttributes OPTIONAL,
#   signatureAlgorithm SignatureAlgorithmIdentifier,
#   signature SignatureValue,
#   unsignedAttrs [1] IMPLICIT UnsignedAttributes OPTIONAL }
SignerInfo = SEQ(TYPE('version', CMSVersion),
				 TYPE('sid', SignerIdentifier),
				 TYPE('digestAlgorithm', DigestAlgorithmIdentifier),
				 TYPE('signedAttrs', SignedAttributes, False, optional=True),
				 TYPE('signatureAlgorithm', SignatureAlgorithmIdentifier),
				 TYPE('signature', SignatureValue),
				 TYPE('unsignedAttrs', UnsignedAttributes, False, 1, optional=True))


# Countersignature ::= SignerInfo
class CounterSignature(SignerInfo): pass

# SignerInfos ::= SET OF SignerInfo
class SignerInfos(univ.SetOf):
	componentType = SignerInfo()

# OtherRevocationInfoFormat ::= SEQUENCE {
#   otherRevInfoFormat OBJECT IDENTIFIER,
#   otherRevInfo ANY DEFINED BY otherRevInfoFormat }
OtherRevocationInfoFormat = SEQ(TYPE('otherRevInfoFormat', univ.ObjectIdentifier),
								TYPE('otherRevInfo', univ.Any))

# RevocationInfoChoice ::= CHOICE {
#   crl CertificateList,
#   other [1] IMPLICIT OtherRevocationInfoFormat }
RevocationInfoChoice = CHOICE(TYPE('crl', CertificateList),	
							  TYPE('other', OtherRevocationInfoFormat, False, 1))

# RevocationInfoChoices ::= SET OF RevocationInfoChoice
RevocationInfoChoices = SETOF(RevocationInfoChoice)

# OriginatorInfo ::= SEQUENCE {
#   certs [0] IMPLICIT CertificateSet OPTIONAL,
#   crls [1] IMPLICIT RevocationInfoChoices OPTIONAL }
OriginatorInfo = SEQ(TYPE('certs', CertificateSet, False, optional=True),
					 TYPE('crls', RevocationInfoChoices, False, 1, optional=True))

#KeyTransRecipientInfo ::= SEQUENCE {
#  version CMSVersion,  -- always set to 0 or 2
#  rid RecipientIdentifier,
#  keyEncryptionAlgorithm KeyEncryptionAlgorithmIdentifier,
#  encryptedKey EncryptedKey }
# FIXME: Constraint?
KeyTransRecipientInfo = SEQ(TYPE('version', CMSVersion),
							TYPE('rid', RecipientIdentifier),
							TYPE('keyEncryptionAlgorithm', KeyEncryptionAlgorithmIdentifier),
							TYPE('encryptedKey', EncryptedKey))

# RecipientEncryptedKey ::= SEQUENCE {
#   rid KeyAgreeRecipientIdentifier,
#   encryptedKey EncryptedKey }
RecipientEncryptedKey = SEQ(TYPE('rid', KeyAgreeRecipientIdentifier),
							TYPE('encryptedKey', EncryptedKey))

# RecipientEncryptedKeys ::= SEQUENCE OF RecipientEncryptedKey
class RecipientEncryptedKeys(univ.SequenceOf):
	componentType = RecipientEncryptedKey()

# KeyAgreeRecipientInfo ::= SEQUENCE {
#   version CMSVersion,  -- always set to 3
#   originator [0] EXPLICIT OriginatorIdentifierOrKey,
#   ukm [1] EXPLICIT UserKeyingMaterial OPTIONAL,
#   keyEncryptionAlgorithm KeyEncryptionAlgorithmIdentifier,
#   recipientEncryptedKeys RecipientEncryptedKeys }
# FIXME: Constraint?
KeyAgreeRecipientInfo = SEQ(TYPE('version', CMSVersion),
							TYPE('originator', OriginatorIdentifierOrKey, True),
							TYPE('ukm', UserKeyingMaterial, True, 1, optional=True),
							TYPE('keyEncryptionAlgorithm', KeyEncryptionAlgorithmIdentifier),
							TYPE('recipientEncryptedKeys', RecipientEncryptedKeys))

# KEKRecipientInfo ::= SEQUENCE {
#   version CMSVersion,  -- always set to 4
#   kekid KEKIdentifier,
#   keyEncryptionAlgorithm KeyEncryptionAlgorithmIdentifier,
#   encryptedKey EncryptedKey }
# FIXME: Constraint?
KEKRecipientInfo = SEQ(TYPE('version', CMSVersion),
					   TYPE('kekid', KEKIdentifier),
					   TYPE('keyEncryptionAlgorithm', KeyEncryptionAlgorithmIdentifier),
					   TYPE('encryptedKey', EncryptedKey))

# PasswordRecipientInfo ::= SEQUENCE {
#   version CMSVersion,   -- always set to 0
#   keyDerivationAlgorithm [0] KeyDerivationAlgorithmIdentifier
#                              OPTIONAL,
#   keyEncryptionAlgorithm KeyEncryptionAlgorithmIdentifier,
#   encryptedKey EncryptedKey }
# FIXME: Constraint?
PasswordRecipientInfo = SEQ(TYPE('version', CMSVersion),
							TYPE('keyDerivationAlgorithm', KeyDerivationAlgorithmIdentifier, DEFAULT_TAG, optional=True),
							TYPE('keyEncryptionAlgorithm', KeyEncryptionAlgorithmIdentifier),
							TYPE('encryptedKey', EncryptedKey))
						
# OtherRecipientInfo ::= SEQUENCE {
#   oriType OBJECT IDENTIFIER,
#   oriValue ANY DEFINED BY oriType }
OtherRecipientInfo = SEQ(TYPE('oriType', univ.ObjectIdentifier),
						 TYPE('oriValue', univ.Any))

# RecipientInfo ::= CHOICE {
#   ktri KeyTransRecipientInfo,
#   kari [1] KeyAgreeRecipientInfo,
#   kekri [2] KEKRecipientInfo,
#   pwri [3] PasswordRecipientInfo,
#   ori [4] OtherRecipientInfo }
RecipientInfo = CHOICE(TYPE('ktri', KeyTransRecipientInfo),
					   TYPE('kari', KeyAgreeRecipientInfo, DEFAULT_TAG, 1),
					   TYPE('kekri', KEKRecipientInfo, DEFAULT_TAG, 2),
					   TYPE('pwri', PasswordRecipientInfo, DEFAULT_TAG, 3),
					   TYPE('ori', OtherRecipientInfo, DEFAULT_TAG, 4))

# RecipientInfos ::= SET SIZE (1..MAX) OF RecipientInfo
class RecipientInfos(univ.SetOf):
	componentType = RecipientInfo()
	subtypeSpec = constraint.ValueSizeConstraint(1, MAX)














# Data types

# DigestedData ::= SEQUENCE {
#   version CMSVersion,
#   digestAlgorithm DigestAlgorithmIdentifier,
#   encapContentInfo EncapsulatedContentInfo,
#   digest Digest }
DigestedData = SEQ(TYPE('version', CMSVersion),
				   TYPE('digestAlgorithm', DigestAlgorithmIdentifier),
				   TYPE('encapContentInfo', EncapsulatedContentInfo),
				   TYPE('digest', Digest))

# EncryptedData ::= SEQUENCE {
#   version CMSVersion,
#   encryptedContentInfo EncryptedContentInfo,
#   unprotectedAttrs [1] IMPLICIT UnprotectedAttributes OPTIONAL }
EncryptedData = SEQ(TYPE('version', CMSVersion),
					TYPE('encryptedContentInfo', EncryptedContentInfo),
					TYPE('unprotectedAttrs', UnprotectedAttributes, False, 1, optional=True))

# AuthenticatedData ::= SEQUENCE {
#   version CMSVersion,
#   originatorInfo [0] IMPLICIT OriginatorInfo OPTIONAL,
#   recipientInfos RecipientInfos,
#   macAlgorithm MessageAuthenticationCodeAlgorithm,
#   digestAlgorithm [1] DigestAlgorithmIdentifier OPTIONAL,
#   encapContentInfo EncapsulatedContentInfo,
#   authAttrs [2] IMPLICIT AuthAttributes OPTIONAL,
#   mac MessageAuthenticationCode,
#   unauthAttrs [3] IMPLICIT UnauthAttributes OPTIONAL }
AuthenticatedData = SEQ(TYPE('version', CMSVersion),
						TYPE('originatorInfo', OriginatorInfo, False, optional=True),
						TYPE('recipientInfos', RecipientInfos),
						TYPE('macAlgorithm', MessageAuthenticationCodeAlgorithm),
						TYPE('digestAlgorithm', DigestAlgorithmIdentifier, DEFAULT_TAG, 1, optional=True),
						TYPE('encapContentInfo', EncapsulatedContentInfo),
						TYPE('authAttrs', AuthAttributes, False, 2, optional=True),
						TYPE('mac', MessageAuthenticationCode),
						TYPE('unauthAttrs', UnauthAttributes, False, 3, optional=True))

# SignedData ::= SEQUENCE {
#   version CMSVersion,
#   digestAlgorithms DigestAlgorithmIdentifiers,
#   encapContentInfo EncapsulatedContentInfo,
#   certificates [0] IMPLICIT CertificateSet OPTIONAL,
#   crls [1] IMPLICIT RevocationInfoChoices OPTIONAL,
#   signerInfos SignerInfos }
SignedData = SEQ(TYPE('version', CMSVersion),
				 TYPE('digestAlgorithms', DigestAlgorithmIdentifiers),
				 TYPE('encapContentInfo', EncapsulatedContentInfo),
				 TYPE('certificates', CertificateSet, False, optional=True),
				 TYPE('crls', RevocationInfoChoices, False, 1, optional=True),
				 TYPE('signerInfos', SignerInfos))

# EnvelopedData ::= SEQUENCE {
#   version CMSVersion,
#   originatorInfo [0] IMPLICIT OriginatorInfo OPTIONAL,
#   recipientInfos RecipientInfos,
#   encryptedContentInfo EncryptedContentInfo,
#   unprotectedAttrs [1] IMPLICIT UnprotectedAttributes OPTIONAL }
EnvelopedData = SEQ(TYPE('version', CMSVersion),
					TYPE('originatorInfo', OriginatorInfo, False, optional=True),
					TYPE('recipientInfos', RecipientInfos),
					TYPE('encryptedContentInfo', EncryptedContentInfo),
					TYPE('unprotectedAttrs', UnprotectedAttributes, False, 1, optional=True))








# -- Content Type Object Identifiers

# id-ct-contentInfo OBJECT IDENTIFIER ::= { iso(1) member-body(2)
#     us(840) rsadsi(113549) pkcs(1) pkcs-9(9) smime(16) ct(1) 6 }
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
#     us(840) rsadsi(113549) pkcs(1) pkcs-9(9) smime(16) ct(1) 2 }
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


# END -- of CryptographicMessageSyntax2004

