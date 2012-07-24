from shorthand import MAX, TYPE, SEQ, SET, SEQOF, SETOF, CHOICE, ID, TUP

from pyasn1.type import tag, namedtype, namedval, univ, constraint, char, useful


"""PKIXCRMF-2005 {iso(1) identified-organization(3) dod(6) internet(1)
security(5) mechanisms(5) pkix(7) id-mod(0) id-mod-crmf2005(36)}

DEFINITIONS IMPLICIT TAGS ::=
BEGIN

IMPORTS
  -- Directory Authentication Framework (X.509)
     Version, AlgorithmIdentifier, Name, Time,
     SubjectPublicKeyInfo, Extensions, UniqueIdentifier, Attribute
        FROM PKIX1Explicit88 {iso(1) identified-organization(3) dod(6)
            internet(1) security(5) mechanisms(5) pkix(7) id-mod(0)
            id-pkix1-explicit(18)} -- found in [PROFILE]

  -- Certificate Extensions (X.509)
     GeneralName
        FROM PKIX1Implicit88 {iso(1) identified-organization(3) dod(6)
               internet(1) security(5) mechanisms(5) pkix(7) id-mod(0)
               id-pkix1-implicit(19)}  -- found in [PROFILE]

  -- Cryptographic Message Syntax
     EnvelopedData
        FROM CryptographicMessageSyntax2004 { iso(1) member-body(2)
             us(840) rsadsi(113549) pkcs(1) pkcs-9(9) smime(16)
             modules(0) cms-2004(24) };  -- found in [CMS]

-- The following definition may be uncommented for use with
-- ASN.1 compilers that do not understand UTF8String.

-- UTF8String ::= [UNIVERSAL 12] IMPLICIT OCTET STRING
       -- The contents of this type correspond to RFC 2279."""

from rfc5280_explicit import ( Version, AlgorithmIdentifier,
							   Name, Time, SubjectPublicKeyInfo,
							   Extensions, UniqueIdentifier, Attribute )

from rfc5280_implicit import GeneralName

from rfc5652_cms_2004 import EnvelopedData

DEFAULT_TAG = False


# id-pkix  OBJECT IDENTIFIER  ::= { iso(1) identified-organization(3)
# dod(6) internet(1) security(5) mechanisms(5) 7 }
id_pkix = ID(1, 3, 6, 1, 5, 5, 7)


# -- arc for Internet X.509 PKI protocols and their components

# id-pkip  OBJECT IDENTIFIER ::= { id-pkix 5 }
id_pkip = ID(*TUP(id_pkix, 5))

# id-smime OBJECT IDENTIFIER ::= { iso(1) member-body(2)
#              us(840) rsadsi(113549) pkcs(1) pkcs9(9) 16 }
id_smime = ID(1, 2, 840, 113549, 1, 9, 19)

# id-ct   OBJECT IDENTIFIER ::= { id-smime  1 }  -- content types
id_ct = ID(*TUP(id_smime, 1))


# -- Core definitions for this module

# OptionalValidity ::= SEQUENCE {
#   notBefore  [0] Time OPTIONAL,
#   notAfter   [1] Time OPTIONAL } -- at least one MUST be present
OptionalValidity = SEQ(TYPE('notBefore', Time, DEFAULT_TAG, optional=True),
					   TYPE('notAfter', Time, DEFAULT_TAG, 1, optional=True))

# CertTemplate ::= SEQUENCE {
#   version      [0] Version               OPTIONAL,
#   serialNumber [1] INTEGER               OPTIONAL,
#   signingAlg   [2] AlgorithmIdentifier   OPTIONAL,
#   issuer       [3] Name                  OPTIONAL,
#   validity     [4] OptionalValidity      OPTIONAL,
#   subject      [5] Name                  OPTIONAL,
#   publicKey    [6] SubjectPublicKeyInfo  OPTIONAL,
#   issuerUID    [7] UniqueIdentifier      OPTIONAL,
#   subjectUID   [8] UniqueIdentifier      OPTIONAL,
#   extensions   [9] Extensions            OPTIONAL }
CertTemplate = SEQ(TYPE('version', Version, DEFAULT_TAG, optional=True),
				   TYPE('serialNumber', univ.Integer, DEFAULT_TAG, 1, optional=True),
				   TYPE('signingAlg', AlgorithmIdentifier, DEFAULT_TAG, 2, optional=True),
				   TYPE('issuer', Name, DEFAULT_TAG, 3, optional=True),
				   TYPE('validity', OptionalValidity, DEFAULT_TAG, 4, optional=True),
				   TYPE('subject', Name, DEFAULT_TAG, 5, optional=True),
				   TYPE('publicKey', SubjectPublicKeyInfo, DEFAULT_TAG, 6, optional=True),
				   TYPE('issuerUID', UniqueIdentifier, DEFAULT_TAG, 7, optional=True),
				   TYPE('subjectUID', UniqueIdentifier, DEFAULT_TAG, 8, optional=True),
				   TYPE('extensions', Extensions, DEFAULT_TAG, 9, optional=True))

# AttributeTypeAndValue ::= SEQUENCE {
#   type         OBJECT IDENTIFIER,
#   value        ANY DEFINED BY type }
AttributeTypeAndValue = SEQ(TYPE('type', univ.ObjectIdentifier),
							TYPE('value', univ.Any))

# Controls  ::= SEQUENCE SIZE(1..MAX) OF AttributeTypeAndValue
class Controls(univ.SequenceOf):
	componentType = AttributeTypeAndValue()
	subtypeSpec = univ.SequenceOf.subtypeSpec + constraint.ValueSizeConstraint(1, MAX)

# CertRequest ::= SEQUENCE {
#   certReqId     INTEGER,          -- ID for matching request and reply
#   certTemplate  CertTemplate,  -- Selected fields of cert to be issued
#   controls      Controls OPTIONAL }   -- Attributes affecting issuance
CertRequest = SEQ(TYPE('certReqId', univ.Integer),
				  TYPE('certTemplate', CertTemplate),
				  TYPE('controls', Controls, optional=True))

# PKMACValue ::= SEQUENCE {
#   algId  AlgorithmIdentifier,
#   -- algorithm value shall be PasswordBasedMac {1 2 840 113533 7 66 13}
#   -- parameter value is PBMParameter
#   value  BIT STRING }
PKMACValue = SEQ(TYPE('algId', AlgorithmIdentifier),
				 TYPE('value', univ.BitString))

# POPOSigningKeyInput ::= SEQUENCE {
#   authInfo            CHOICE {
#       sender              [0] GeneralName,
#       -- used only if an authenticated identity has been
#       -- established for the sender (e.g., a DN from a
#       -- previously-issued and currently-valid certificate)
#       publicKeyMAC        PKMACValue },
#       -- used if no authenticated GeneralName currently exists for
#       -- the sender; publicKeyMAC contains a password-based MAC
#       -- on the DER-encoded value of publicKey
#   publicKey           SubjectPublicKeyInfo }  -- from CertTemplate
POPOSigningKeyInput = SEQ(TYPE('authInfo', CHOICE(TYPE('sender', GeneralName, DEFAULT_TAG),
												  TYPE('publicKeyMAX', PKMACValue))),
						  TYPE('publicKey', SubjectPublicKeyInfo))

# -- The signature (using "algorithmIdentifier") is on the
# -- DER-encoded value of poposkInput.  NOTE: If the CertReqMsg
# -- certReq CertTemplate contains the subject and publicKey values,
# -- then poposkInput MUST be omitted and the signature MUST be
# -- computed over the DER-encoded value of CertReqMsg certReq.  If
# -- the CertReqMsg certReq CertTemplate does not contain both the
# -- public key and subject values (i.e., if it contains only one
# -- of these, or neither), then poposkInput MUST be present and
# -- MUST be signed.

# POPOSigningKey ::= SEQUENCE {
#   poposkInput           [0] POPOSigningKeyInput OPTIONAL,
#   algorithmIdentifier   AlgorithmIdentifier,
#   signature             BIT STRING }
POPOSigningKey = SEQ(TYPE('poposkInput', POPOSigningKeyInput, DEFAULT_TAG, optional=True),
					 TYPE('algorithmIdentifier', AlgorithmIdentifier),
					 TYPE('signature', univ.BitString))

# -- for keyAgreement (only), possession is proven in this message
# -- (which contains a MAC (over the DER-encoded value of the
# -- certReq parameter in CertReqMsg, which MUST include both subject
# -- and publicKey) based on a key derived from the end entity's
# -- private DH key and the CA's public DH key);

# SubsequentMessage ::= INTEGER {
#   encrCert (0),
#   -- requests that resulting certificate be encrypted for the
#   -- end entity (following which, POP will be proven in a
#   -- confirmation message)
#   challengeResp (1) }
#   -- requests that CA engage in challenge-response exchange with
#   -- end entity in order to prove private key possession
class SubsequentMessage(univ.Integer):
	namedValues = namedval.NamedValues(('encrCert', 0), ('challengeResp', 1))

# POPOPrivKey ::= CHOICE {
#   thisMessage       [0] BIT STRING,         -- Deprecated
#   -- possession is proven in this message (which contains the private
#   -- key itself (encrypted for the CA))
#   subsequentMessage [1] SubsequentMessage,
#   -- possession will be proven in a subsequent message
#   dhMAC             [2] BIT STRING,         -- Deprecated
#   agreeMAC          [3] PKMACValue,
#   encryptedKey      [4] EnvelopedData }
POPOPrivKey = CHOICE(TYPE('thisMessage', univ.BitString, DEFAULT_TAG),
					 TYPE('subsequentMessage', SubsequentMessage, DEFAULT_TAG, 1),
					 TYPE('dhMAC', univ.BitString, DEFAULT_TAG, 2),
					 TYPE('agreeMAC', PKMACValue, DEFAULT_TAG, 3),
					 TYPE('encryptedKey', EnvelopedData, DEFAULT_TAG, 4))

# ProofOfPossession ::= CHOICE {
#   raVerified        [0] NULL,
#   -- used if the RA has already verified that the requester is in
#   -- possession of the private key
#   signature         [1] POPOSigningKey,
#   keyEncipherment   [2] POPOPrivKey,
#   keyAgreement      [3] POPOPrivKey }
ProofOfPossession = CHOICE(TYPE('rAVerifier', univ.Null, DEFAULT_TAG),
						   TYPE('signature', POPOSigningKey, DEFAULT_TAG, 1),
						   TYPE('keyEncipherment', POPOPrivKey, DEFAULT_TAG, 2),
						   TYPE('keyAgreement', POPOPrivKey, DEFAULT_TAG, 3))

# CertReqMsg ::= SEQUENCE {
#   certReq   CertRequest,
#   popo       ProofOfPossession  OPTIONAL,
#   -- content depends upon key type
#   regInfo   SEQUENCE SIZE(1..MAX) OF AttributeTypeAndValue OPTIONAL }
CertReqMsg = SEQ(TYPE('certReq', CertRequest),
				 TYPE('popo', ProofOfPossession, optional=True),
				 TYPE('regInfo', SEQOF(AttributeTypeAndValue), optional=True,
					  constraint=constraint.ValueSizeConstraint(1, MAX)))

# CertReqMessages ::= SEQUENCE SIZE (1..MAX) OF CertReqMsg
class CertReqMessages(univ.SequenceOf):
	componentType = CertReqMsg()
	subtypeSpec = univ.SequenceOf.subtypeSpec + constraint.ValueSizeConstraint(1, MAX)

# PBMParameter ::= SEQUENCE {
#   salt                OCTET STRING,
#   owf                 AlgorithmIdentifier,
#   -- AlgId for a One-Way Function (SHA-1 recommended)
#   iterationCount      INTEGER,
#   -- number of times the OWF is applied
#   mac                 AlgorithmIdentifier
#   -- the MAC AlgId (e.g., DES-MAC, Triple-DES-MAC [PKCS11],
# }   -- or HMAC [HMAC, RFC2202])
PBMParameter = SEQ(TYPE('salt', univ.OctetString),
				   TYPE('owf', AlgorithmIdentifier),
				   TYPE('iterationCount', univ.Integer),
				   TYPE('mac', AlgorithmIdentifier))

# -- Object identifier assignments --

# -- Registration Controls in CRMF

# id-regCtrl OBJECT IDENTIFIER ::= { id-pkip 1 }
id_regCtrl = ID(*TUP(id_pkip, 1))

# id-regCtrl-regToken OBJECT IDENTIFIER ::= { id-regCtrl 1 }
id_regCtrl_regToken = ID(*TUP(id_regCtrl, 1))

# RegToken ::= UTF8String
class RegToken(char.UTF8String): pass

# id-regCtrl-authenticator OBJECT IDENTIFIER ::= { id-regCtrl 2 }
id_regCtrl_authenticator = ID(*TUP(id_regCtrl, 2))

# Authenticator ::= UTF8String
class Authenticator(char.UTF8String): pass

# id-regCtrl-pkiPublicationInfo OBJECT IDENTIFIER ::= { id-regCtrl 3 }
id_regCtrl_pkiPublicationInfo = ID(*TUP(id_regCtrl, 3))

# SinglePubInfo ::= SEQUENCE {
#   pubMethod    INTEGER {
#       dontCare    (0),
#       x500        (1),
#       web         (2),
#       ldap        (3) },
#   pubLocation  GeneralName OPTIONAL }
SinglePubInfo = SEQ(TYPE('pubMethod', univ.Integer, named=namedval.NamedValues(('dontCare', 0), ('x500', 1),
																			   ('web', 2), ('ldap', 3))),
					TYPE('pubLocation', GeneralName, optional=True))

# PKIPublicationInfo ::= SEQUENCE {
#   action     INTEGER {
#                dontPublish (0),
#                pleasePublish (1) },
#   pubInfos  SEQUENCE SIZE (1..MAX) OF SinglePubInfo OPTIONAL }
#     -- pubInfos MUST NOT be present if action is "dontPublish"
#     -- (if action is "pleasePublish" and pubInfos is omitted,
#     -- "dontCare" is assumed)
PKIPublicationInfo = SEQ(TYPE('action', univ.Integer, named=namedval.NamedValues(('dontPublish', 0),
																				 ('pleasePublish', 1))),
						 TYPE('pubInfos', SEQOF(SinglePubInfo), optional=True,
							  constraint=constraint.ValueSizeConstraint(1, MAX)))

# id-regCtrl-pkiArchiveOptions     OBJECT IDENTIFIER ::= { id-regCtrl 4 }
id_regCtrl_pkiArchiveOptions = ID(*TUP(id_regCtrl, 4))

# EncryptedValue ::= SEQUENCE {
#   intendedAlg   [0] AlgorithmIdentifier  OPTIONAL,
#   -- the intended algorithm for which the value will be used
#   symmAlg       [1] AlgorithmIdentifier  OPTIONAL,
#   -- the symmetric algorithm used to encrypt the value
#   encSymmKey    [2] BIT STRING           OPTIONAL,
#   -- the (encrypted) symmetric key used to encrypt the value
#   keyAlg        [3] AlgorithmIdentifier  OPTIONAL,
#   -- algorithm used to encrypt the symmetric key
#   valueHint     [4] OCTET STRING         OPTIONAL,
#   -- a brief description or identifier of the encValue content
#   -- (may be meaningful only to the sending entity, and used only
#   -- if EncryptedValue might be re-examined by the sending entity
#   -- in the future)
#   encValue       BIT STRING }
#   -- the encrypted value itself
# -- When EncryptedValue is used to carry a private key (as opposed to
# -- a certificate), implementations MUST support the encValue field
# -- containing an encrypted PrivateKeyInfo as defined in [PKCS11],
# -- section 12.11.  If encValue contains some other format/encoding
# -- for the private key, the first octet of valueHint MAY be used
# -- to indicate the format/encoding (but note that the possible values
# -- of this octet are not specified at this time).  In all cases, the
# -- intendedAlg field MUST be used to indicate at least the OID of
# -- the intended algorithm of the private key, unless this information
# -- is known a priori to both sender and receiver by some other means.
EncryptedValue = SEQ(TYPE('intendedAlg', AlgorithmIdentifier, DEFAULT_TAG, optional=True),
					 TYPE('symmAlg', AlgorithmIdentifier, DEFAULT_TAG, 1, optional=True),
					 TYPE('encSymmKey', univ.BitString, DEFAULT_TAG, 2, optional=True),
					 TYPE('keyAlg', AlgorithmIdentifier, DEFAULT_TAG, 3, optional=True),
					 TYPE('valueHint', univ.OctetString, DEFAULT_TAG, 4, optional=True),
					 TYPE('encValue', univ.BitString))

# EncryptedKey ::= CHOICE {
#   encryptedValue        EncryptedValue,   -- Deprecated
#   envelopedData     [0] EnvelopedData }
#   -- The encrypted private key MUST be placed in the envelopedData
#   -- encryptedContentInfo encryptedContent OCTET STRING.
EncryptedKey = CHOICE(TYPE('encryptedValue', EncryptedValue),
					  TYPE('envelopedData', EnvelopedData, DEFAULT_TAG))

# KeyGenParameters ::= OCTET STRING
class KeyGenParameters(univ.OctetString): pass

# PKIArchiveOptions ::= CHOICE {
#   encryptedPrivKey     [0] EncryptedKey,
#   -- the actual value of the private key
#   keyGenParameters     [1] KeyGenParameters,
#   -- parameters that allow the private key to be re-generated
#   archiveRemGenPrivKey [2] BOOLEAN }
#   -- set to TRUE if sender wishes receiver to archive the private
#   -- key of a key pair that the receiver generates in response to
#   -- this request; set to FALSE if no archival is desired.
PKIArchiveOptions = CHOICE(TYPE('encryptedPrivKey', EncryptedKey, DEFAULT_TAG),
						   TYPE('keyGenParameters', KeyGenParameters, DEFAULT_TAG, 1),
						   TYPE('archiveRemGenPrivKey', univ.Boolean, DEFAULT_TAG, 2))

# CertId ::= SEQUENCE {
#   issuer           GeneralName,
#   serialNumber     INTEGER }
CertId = SEQ(TYPE('issuer', GeneralName),
			 TYPE('serialNumber', univ.Integer))

# id-regCtrl-oldCertID          OBJECT IDENTIFIER ::= { id-regCtrl 5 }
id_regCtrl_oldCertID = ID(*TUP(id_regCtrl, 5))

# OldCertId ::= CertId
class OldCertId(CertId): pass

# id-regCtrl-protocolEncrKey    OBJECT IDENTIFIER ::= { id-regCtrl 6 }
id_regCtrl_protocolEncrKey = ID(*TUP(id_regCtrl, 6))

# ProtocolEncrKey ::= SubjectPublicKeyInfo
class ProtocolEncrKey(SubjectPublicKeyInfo): pass


# -- Registration Info in CRMF

# id-regInfo OBJECT IDENTIFIER ::= { id-pkip 2 }
id_regInfo = ID(*TUP(id_pkip, 2))

# id-regInfo-utf8Pairs    OBJECT IDENTIFIER ::= { id-regInfo 1 }
id_regInfo_utf8Pairs = ID(*TUP(id_regInfo, 1))

# UTF8Pairs ::= UTF8String
class UTF8Pairs(char.UTF8String): pass

# id-regInfo-certReq       OBJECT IDENTIFIER ::= { id-regInfo 2 }
id_regInfo_certReq = ID(*TUP(id_regInfo, 2))

# CertReq ::= CertRequest
class CertReq(CertRequest): pass

# -- id-ct-encKeyWithID is a new content type used for CMS objects.
# -- it contains both a private key and an identifier for key escrow
# -- agents to check against recovery requestors.

# Attributes ::= SET OF Attribute
Attributes = SETOF(Attribute)

# PrivateKeyInfo ::= SEQUENCE {
#   version                   INTEGER,
#   privateKeyAlgorithm       AlgorithmIdentifier,
#   privateKey                OCTET STRING,
#   attributes                [0] IMPLICIT Attributes OPTIONAL
# }
PrivateKeyInfo = SEQ(TYPE('version', univ.Integer),
					 TYPE('privateKeyAlgorithm', AlgorithmIdentifier),
					 TYPE('privateKey', univ.OctetString),
					 TYPE('attributes', Attributes, False, optional=True))

# id-ct-encKeyWithID OBJECT IDENTIFIER ::= {id-ct 21}
id_ct_encKeyWithID = ID(*TUP(id_ct, 21))

# EncKeyWithID ::= SEQUENCE {
#   privateKey           PrivateKeyInfo,
#   identifier CHOICE {
#     string             UTF8String,
#     generalName        GeneralName
#   } OPTIONAL
# }
EncKeyWithID = SEQ(TYPE('privateKey', PrivateKeyInfo),
				   TYPE('identifier', CHOICE(TYPE('string', char.UTF8String),
											 TYPE('generalName', GeneralName)),
						optional=True))

# END
