from shorthand import MAX, TYPE, SEQ, SET, SEQOF, SETOF, CHOICE, ID, TUP

from pyasn1.type import tag, namedtype, namedval, univ, constraint, char, useful


"""EnrollmentMessageSyntax
 { iso(1) identified-organization(3) dod(4) internet(1)
 security(5) mechansims(5) pkix(7) id-mod(0) id-mod-cmc2002(23) }

 DEFINITIONS IMPLICIT TAGS ::=
 BEGIN

 -- EXPORTS All --
 -- The types and values defined in this module are exported for use
 -- in the other ASN.1 modules.  Other applications may use them for
 -- their own purposes.

 IMPORTS

   -- PKIX Part 1 - Implicit    From [PKIXCERT]
      GeneralName, CRLReason, ReasonFlags
      FROM PKIX1Implicit88 {iso(1) identified-organization(3) dod(6)
              internet(1) security(5) mechanisms(5) pkix(7) id-mod(0)
              id-pkix1-implicit(19)}

   -- PKIX Part 1 - Explicit    From [PKIXCERT]
      AlgorithmIdentifier, Extension, Name, CertificateSerialNumber
      FROM PKIX1Explicit88 {iso(1) identified-organization(3) dod(6)
              internet(1) security(5) mechanisms(5) pkix(7) id-mod(0)
              id-pkix1-explicit(18)}

   -- Cryptographic Message Syntax   FROM [CMS]
      ContentInfo, Attribute, IssuerAndSerialNumber
        FROM CryptographicMessageSyntax2004 { iso(1) member-body(2)
             us(840) rsadsi(113549) pkcs(1) pkcs-9(9) smime(16)
             modules(0) cms-2004(24)}

 -- CRMF                         FROM [CRMF]
    CertReqMsg, PKIPublicationInfo, CertTemplate
    FROM PKIXCRMF-2005 {iso(1) identified-organization(3) dod(6)
           internet(1) security(5) mechanisms(5) pkix(7) id-mod(0)
           id-mod-crmf2005(36)};

   -- Global Types
      UTF8String ::= [UNIVERSAL 12] IMPLICIT OCTET STRING
        -- The content of this type conforms to RFC 2279."""

from rfc5280_implicit import GeneralName, CRLReason, ReasonFlags

from rfc5280_explicit import AlgorithmIdentifier, Extension, Name, CertificateSerialNumber

from rfc5652_cms_2004 import ContentInfo, Attribute, IssuerAndSerialNumber

from rfc4211_crmf import CertReqMsg, PKIPublicationInfo, CertTemplate

DEFAULT_TAG = False


# id-pkix OBJECT IDENTIFIER  ::= { iso(1) identified-organization(3)
#      dod(6) internet(1) security(5) mechanisms(5) pkix(7) }
id_pkix = ID(1, 3, 6, 1, 5, 5, 7)

# id-cmc OBJECT IDENTIFIER ::= {id-pkix 7}   -- CMC controls
id_cmc = ID(*TUP(id_pkix, 7))

# id-cct OBJECT IDENTIFIER ::= {id-pkix 12}  -- CMC content types
id_cct = ID(*TUP(id_pkix, 12))


# -- The following controls have the type OCTET STRING

# id-cmc-identityProof OBJECT IDENTIFIER ::= {id-cmc 3}
id_cmc_identityProof = ID(*TUP(id_cmc, 3))
# id-cmc-dataReturn OBJECT IDENTIFIER ::= {id-cmc 4}
id_cmc_dataReturn = ID(*TUP(id_cmc, 4))
# id-cmc-regInfo OBJECT IDENTIFIER ::= {id-cmc 18}
id_cmc_regInfo = ID(*TUP(id_cmc, 18))
# id-cmc-responseInfo OBJECT IDENTIFIER ::= {id-cmc 19}
id_cmc_responseInfo = ID(*TUP(id_cmc, 19))
# id-cmc-queryPending OBJECT IDENTIFIER ::= {id-cmc 21}
id_cmc_queryPending = ID(*TUP(id_cmc, 21))
# id-cmc-popLinkRandom OBJECT IDENTIFIER ::= {id-cmc 22}
id_cmc_popLinkRandom = ID(*TUP(id_cmc, 22))
# id-cmc-popLinkWitness OBJECT IDENTIFIER ::= {id-cmc 23}
id_cmc_popLinkWitness = ID(*TUP(id_cmc, 23))


# -- The following controls have the type UTF8String

# id-cmc-identification OBJECT IDENTIFIER ::= {id-cmc 2}
id_cmc_identification = ID(*TUP(id_cmc, 2))

# -- The following controls have the type INTEGER

# id-cmc-transactionId OBJECT IDENTIFIER ::= {id-cmc 5}
id_cmc_transactionId = ID(*TUP(id_cmc, 5))

# -- The following controls have the type OCTET STRING

# id-cmc-senderNonce OBJECT IDENTIFIER ::= {id-cmc 6}
id_cmc_senderNonce = ID(*TUP(id_cmc, 6))
# id-cmc-recipientNonce OBJECT IDENTIFIER ::= {id-cmc 7}
id_cmc_recipientNonce = ID(*TUP(id_cmc, 7))


# bodyIdMax INTEGER ::= 4294967295
bodyIdMax = univ.Integer(4294967295)

# BodyPartID ::= INTEGER(0..bodyIdMax)
class BodyPartID(univ.Integer):
	subtypeSpec = univ.Integer.subtypeSpec + constraint.ValueRangeConstraint(0, bodyIdMax)

# BodyPartPath ::= SEQUENCE SIZE (1..MAX) OF BodyPartID
class BodyPartPath(univ.SequenceOf):
	componentType = BodyPartID()
	subtypeSpec = univ.SequenceOf.subtypeSpec + constraint.ValueSizeConstraint(1, MAX)

# BodyPartReference ::= CHOICE {
#   bodyPartID           BodyPartID,
#   bodyPartPath         BodyPartPath
# }
BodyPartReference = CHOICE(TYPE('bodyPartID', BodyPartID),
						   TYPE('bodyPartPath', BodyPartPath))


# AttributeValue ::= ANY
class AttributeValue(univ.Any): pass

# TaggedAttribute ::= SEQUENCE {
#     bodyPartID         BodyPartID,
#     attrType           OBJECT IDENTIFIER,
#     attrValues         SET OF AttributeValue
# }
TaggedAttribute = SEQ(TYPE('bodyPartId', BodyPartID),
					  TYPE('attrType', univ.ObjectIdentifier),
					  TYPE('attrValues', SETOF(AttributeValue)))

# CertificationRequest ::= SEQUENCE {
#   certificationRequestInfo  SEQUENCE {
#     version                   INTEGER,
#     subject                   Name,
#     subjectPublicKeyInfo      SEQUENCE {
#       algorithm                 AlgorithmIdentifier,
#       subjectPublicKey          BIT STRING },
#     attributes                [0] IMPLICIT SET OF Attribute },
#   signatureAlgorithm        AlgorithmIdentifier,
#   signature                 BIT STRING
# }
class _SubjectPublicKeyInfo(univ.Sequence):
	componentType = namedtype.NamedTypes(
		namedtype.NamedType('algorithm', AlgorithmIdentifier()),
		namedtype.NamedType('subjectPublicKey', univ.BitString())
	)
class _Attributes(univ.SetOf):
	componentType = Attribute()
	tagSet = univ.SetOf.tagSet.tagImplicitly(tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0))
class _CertificationRequestInfo(univ.Sequence):
	componentType = namedtype.NamedTypes(
		namedtype.NamedType('version', univ.Integer()),
		namedtype.NamedType('subject', Name()),
		namedtype.NamedType('subjectPublicKeyInfo', _SubjectPublicKeyInfo()),
		namedtype.NamedType('attributes', _Attributes())
	)
class _CertificationRequest(univ.Sequence):
	componentType = namedtype.NamedTypes(
		namedtype.NamedType('certificationRequestInfo', _CertificationRequestInfo()),
		namedtype.NamedType('signatureAlgorithm', AlgorithmIdentifier()),
		namedtype.NamedType('signature', univ.BitString())
	)
	
CertificationRequest = SEQ(TYPE('certificationRequestInfo', 
								SEQ(TYPE('version', univ.Integer),
									TYPE('subject', Name),
									TYPE('subjectPublicKeyInfo', SEQ(TYPE('algorithm', AlgorithmIdentifier),
																	 TYPE('subjectPublicKey', univ.BitString))),
									TYPE('attributes', SETOF(Attribute), False))),
						   TYPE('signatureAlgorithm', AlgorithmIdentifier),
						   TYPE('signature', univ.BitString))

# TaggedCertificationRequest ::= SEQUENCE {
#     bodyPartID            BodyPartID,
#     certificationRequest  CertificationRequest
# }
TaggedCertificationRequest = SEQ(TYPE('bodyPartID', BodyPartID),
								 TYPE('certificationRequest', CertificationRequest))

# TaggedRequest ::= CHOICE {
#     tcr               [0] TaggedCertificationRequest,
#     crm               [1] CertReqMsg,
#     orm               [2] SEQUENCE {
#         bodyPartID            BodyPartID,
#         requestMessageType    OBJECT IDENTIFIER,
#         requestMessageValue   ANY DEFINED BY requestMessageType
#     }
# }
TaggedRequest = CHOICE(TYPE('tcr', TaggedCertificationRequest, DEFAULT_TAG),
					   TYPE('crm', CertReqMsg, DEFAULT_TAG, 1),
					   TYPE('orm', SEQ(TYPE('bodyPartID', BodyPartID),
									   TYPE('requestMessageType', univ.ObjectIdentifier),
									   TYPE('requestMessageValue', univ.Any))))

# TaggedContentInfo ::= SEQUENCE {
#     bodyPartID              BodyPartID,
#     contentInfo             ContentInfo
# }
TaggedContentInfo = SEQ(TYPE('bodyPartID', BodyPartID),
						TYPE('contentInfo', ContentInfo))

# OtherMsg ::= SEQUENCE {
#     bodyPartID        BodyPartID,
#     otherMsgType      OBJECT IDENTIFIER,
#     otherMsgValue     ANY DEFINED BY otherMsgType }
OtherMsg = SEQ(TYPE('bodyPartID', BodyPartID),
			   TYPE('otherMsgType', univ.ObjectIdentifier),
			   TYPE('otherMsgValue', univ.Any))


# -- This is the content type used for a request message in the protocol

# id-cct-PKIData OBJECT IDENTIFIER ::= { id-cct 2 }
id_cct_PKIData = ID(*TUP(id_cct, 2))

# PKIData ::= SEQUENCE {
#     controlSequence    SEQUENCE SIZE(0..MAX) OF TaggedAttribute,
#     reqSequence        SEQUENCE SIZE(0..MAX) OF TaggedRequest,
#     cmsSequence        SEQUENCE SIZE(0..MAX) OF TaggedContentInfo,
#     otherMsgSequence   SEQUENCE SIZE(0..MAX) OF OtherMsg
# }
_PKIDataConstraint = constraint.ValueSizeConstraint(0, MAX)
PKIData = SEQ(TYPE('controlSequence', SEQOF(TaggedAttribute), constraint=_PKIDataConstraint),
			  TYPE('reqSequence', SEQOF(TaggedRequest), constraint=_PKIDataConstraint),
			  TYPE('cmsSequence', SEQOF(TaggedContentInfo), constraint=_PKIDataConstraint),
			  TYPE('otherMsgSequence', SEQOF(OtherMsg), constraint=_PKIDataConstraint))


# --  This defines the response message in the protocol

# PKIResponse ::= SEQUENCE {
#     controlSequence   SEQUENCE SIZE(0..MAX) OF TaggedAttribute,
#     cmsSequence       SEQUENCE SIZE(0..MAX) OF TaggedContentInfo,
#     otherMsgSequence  SEQUENCE SIZE(0..MAX) OF OtherMsg
# }
_PKIResponseConstraint = constraint.ValueSizeConstraint(0, MAX)
PKIResponse = SEQ(TYPE('controlSequence', SEQOF(TaggedAttribute), constraint=_PKIResponseConstraint),
				  TYPE('cmsSequence', SEQOF(TaggedContentInfo), constraint=_PKIResponseConstraint),
				  TYPE('otherMsgSequence', SEQOF(OtherMsg), constraint=_PKIResponseConstraint))

# id-cct-PKIResponse OBJECT IDENTIFIER ::= { id-cct 3 }
id_cct_PKIResponse = ID(*TUP(id_cct, 3))

# ResponseBody ::= PKIResponse
class ResponseBody(PKIResponse): pass


# -- Used to return status state in a response

# CMCStatus ::= INTEGER {
#     success         (0),
#     failed          (2),
#     pending         (3),
#     noSupport       (4),
#     confirmRequired (5),
#     popRequired     (6),
#     partial                (7)
# }
class CMCStatus(univ.Integer):
	namedValues = namedval.NamedValues(('success', 0), ('failed', 2),
									   ('pending', 3), ('noSupport', 4),
									   ('confirmRequired', 5), ('popRequired', 6),
									   ('partial', 7))

# -- Note:
# -- The spelling of unsupportedExt is corrected in this version.
# -- In RFC 2797, it was unsuportedExt.

# CMCFailInfo ::= INTEGER {
#     badAlg          (0),
#     badMessageCheck (1),
#     badRequest      (2),
#     badTime         (3),
#     badCertId       (4),
#     unsupportedExt  (5),
#     mustArchiveKeys (6),
#     badIdentity     (7),
#     popRequired     (8),
#     popFailed       (9),
#     noKeyReuse      (10),
#     internalCAError (11),
#     tryLater        (12),
#     authDataFail    (13)
# }
class CMCFailInfo(univ.Integer):
	namedValues = namedval.NamedValues(('badAlg', 0), ('badMessageCheck', 1),
									   ('badRequest', 2), ('badTime', 3),
									   ('badCertId', 4), ('unsupportedExt', 5),
									   ('mustArchiveKeys', 6), ('badIdentity', 7),
									   ('popRequired', 8), ('popFailed', 9),
									   ('noKeyReuse', 10), ('internalCAError', 11),
									   ('tryLater', 12), ('authDataFail', 13))

# PendInfo ::= SEQUENCE {
#     pendToken        OCTET STRING,
#     pendTime         GeneralizedTime
# }
PendInfo = SEQ(TYPE('pendToken', univ.OctetString),
			   TYPE('pendTime', useful.GeneralizedTime))

# id-cmc-statusInfo OBJECT IDENTIFIER ::= {id-cmc 1}
id_cmc_statusInfo = ID(*TUP(id_cmc, 1))

# CMCStatusInfo ::= SEQUENCE {
#     cMCStatus       CMCStatus,
#     bodyList        SEQUENCE SIZE (1..MAX) OF BodyPartID,
#     statusString    UTF8String OPTIONAL,
#     otherInfo        CHOICE {
#       failInfo         CMCFailInfo,
#       pendInfo         PendInfo } OPTIONAL
# }
CMCStatusInfo = SEQ(TYPE('cMCStatus', CMCStatus),
					TYPE('bodyList', SEQOF(BodyPartID), constraint=constraint.ValueSizeConstraint(1, MAX)),
					TYPE('statusString', char.UTF8String, optional=True),
					TYPE('otherInfo', CHOICE(TYPE('failInfo', CMCFailInfo),
											 TYPE('pendInfo', PendInfo)),
						 optional=True))


# -- Used for RAs to add extensions to certification requests
# id-cmc-addExtensions OBJECT IDENTIFIER ::= {id-cmc 8}

# AddExtensions ::= SEQUENCE {
#     pkiDataReference    BodyPartID,
#     certReferences      SEQUENCE OF BodyPartID,
#     extensions          SEQUENCE OF Extension
# }
AddExtensions = SEQ(TYPE('pkiDataReference', BodyPartID),
					TYPE('certReferences', SEQOF(BodyPartID)),
					TYPE('extensions', SEQOF(Extension)))

# id-cmc-encryptedPOP OBJECT IDENTIFIER ::= {id-cmc 9}
id_cmc_encryptedPOP = ID(*TUP(id_cmc, 9))

# EncryptedPOP ::= SEQUENCE {
#     request       TaggedRequest,
#     cms             ContentInfo,
#     thePOPAlgID     AlgorithmIdentifier,
#     witnessAlgID    AlgorithmIdentifier,
#     witness         OCTET STRING
# }
EncryptedPOP = SEQ(TYPE('request', TaggedRequest),
				   TYPE('cms', ContentInfo),
				   TYPE('thePOPAlgID', AlgorithmIdentifier),
				   TYPE('witnessAlgID', AlgorithmIdentifier),
				   TYPE('witness', univ.BitString))

# id-cmc-decryptedPOP OBJECT IDENTIFIER ::= {id-cmc 10}
id_cmc_decryptedPOP = ID(*TUP(id_cmc, 10))

# DecryptedPOP ::= SEQUENCE {
#     bodyPartID      BodyPartID,
#     thePOPAlgID     AlgorithmIdentifier,
#     thePOP          OCTET STRING
# }
DecryptedPOP = SEQ(TYPE('bodyPartID', BodyPartID),
				   TYPE('thePOPAlgID', AlgorithmIdentifier),
				   TYPE('thePOP', univ.OctetString))

# id-cmc-lraPOPWitness OBJECT IDENTIFIER ::= {id-cmc 11}
id_cmc_lraPOPWitness = ID(*TUP(id_cmc, 11))

# LraPopWitness ::= SEQUENCE {
#     pkiDataBodyid   BodyPartID,
#     bodyIds         SEQUENCE OF BodyPartID
# }
LraPopWitness = SEQ(TYPE('pkiDataBodyid', BodyPartID),
					TYPE('bodyIds', SEQOF(BodyPartID)))

# id-cmc-getCert OBJECT IDENTIFIER ::= {id-cmc 15}
id_cmc_getCert = ID(*TUP(id_cmc, 15))

# GetCert ::= SEQUENCE {
#     issuerName      GeneralName,
#     serialNumber    INTEGER }
GetCert = SEQ(TYPE('issuerName', GeneralName),
			  TYPE('serialNumber', univ.Integer))

# id-cmc-getCRL OBJECT IDENTIFIER ::= {id-cmc 16}

# GetCRL ::= SEQUENCE {
#     issuerName    Name,
#     cRLName       GeneralName OPTIONAL,
#     time          GeneralizedTime OPTIONAL,
#     reasons       ReasonFlags OPTIONAL }
GetCRL = SEQ(TYPE('issuerName', Name),
			 TYPE('cRLName', GeneralName, optional=True),
			 TYPE('time', useful.GeneralizedTime, optional=True),
			 TYPE('reasons', ReasonFlags, optional=True))

# id-cmc-revokeRequest OBJECT IDENTIFIER ::= {id-cmc 17}
id_cmc_revokeRequest = ID(*TUP(id_cmc, 17))

# RevokeRequest ::= SEQUENCE {
#     issuerName            Name,
#     serialNumber          INTEGER,
#     reason                CRLReason,
#     invalidityDate         GeneralizedTime OPTIONAL,
#     passphrase            OCTET STRING OPTIONAL,
#     comment               UTF8String OPTIONAL }
RevokeRequest = SEQ(TYPE('issuerName', Name),
					TYPE('serialNumber', univ.Integer),
					TYPE('reason', CRLReason),
					TYPE('invalidityDate', useful.GeneralizedTime, optional=True),
					TYPE('passphrase', univ.OctetString, optional=True),
					TYPE('comment', char.UTF8String, optional=True))

# id-cmc-confirmCertAcceptance OBJECT IDENTIFIER ::= {id-cmc 24}
id_cmc_confirmCertAcceptance = ID(*TUP(id_cmc, 24))

# CMCCertId ::= IssuerAndSerialNumber
class CMCCertId(IssuerAndSerialNumber): pass


# -- The following is used to request V3 extensions be added to a
# -- certificate

# id-ExtensionReq OBJECT IDENTIFIER ::= {iso(1) member-body(2) us(840)
#     rsadsi(113549) pkcs(1) pkcs-9(9) 14}
id_ExtensionReq = ID(1, 2, 840, 113549, 1, 9, 14)

# ExtensionReq ::= SEQUENCE SIZE (1..MAX) OF Extension
class ExtensionReq(univ.SequenceOf):
	componentType = Extension()
	subtypeSpec = univ.SequenceOf.subtypeSpec + constraint.ValueSizeConstraint(1, MAX)

# -- The following exists to allow Diffie-Hellman Certification Requests
# -- Messages to be well-formed

# id-alg-noSignature OBJECT IDENTIFIER ::= {id-pkix id-alg(6) 2}
id_alg_noSignature = ID(*TUP(id_pkix, 6, 2))

# NoSignatureValue ::= OCTET STRING
class NoSignatureValue(univ.OctetString): pass


# --  Unauthenticated attribute to carry removable data.
# --    This could be used in an update of "CMC Extensions: Server Side
# --    Key Generation and Key Escrow" (February 2005) and in other
# --    documents.

# id-aa OBJECT IDENTIFIER ::= { iso(1) member-body(2) us(840)
#       rsadsi(113549) pkcs(1) pkcs-9(9) smime(16) id-aa(2)}
id_aa = ID(1, 2, 840, 113549, 1, 9, 16, 2)

# id-aa-cmc-unsignedData OBJECT IDENTIFIER ::= {id-aa 34}
id_aa_cmc_unsignedData = ID(*TUP(id_aa, 34))

# CMCUnsignedData ::= SEQUENCE {
#     bodyPartPath        BodyPartPath,
#     identifier          OBJECT IDENTIFIER,
#     content             ANY DEFINED BY identifier
# }
CMCUnsignedData = SEQ(TYPE('bodyPartPath', BodyPartPath),
					  TYPE('identifier', univ.ObjectIdentifier),
					  TYPE('content', univ.Any))


# --  Replaces CMC Status Info
# --

# id-cmc-statusInfoV2 OBJECT IDENTIFIER ::= {id-cmc 25}
id_cmc_statusInfoV2 = ID(*TUP(id_cmc, 25))

# CMCStatusInfoV2 ::= SEQUENCE {
#   cMCStatus             CMCStatus,
#   bodyList              SEQUENCE SIZE (1..MAX) OF
#                                  BodyPartReference,
#   statusString          UTF8String OPTIONAL,
#   otherInfo             CHOICE {
#     failInfo               CMCFailInfo,
#     pendInfo               PendInfo,
#     extendedFailInfo       SEQUENCE {
#        failInfoOID            OBJECT IDENTIFIER,
#        failInfoValue          AttributeValue
#     }
#   } OPTIONAL
# }
CMCStatusInfoV2 = SEQ(TYPE('cMCStatus', CMCStatus),
					  TYPE('bodyList', SEQOF(BodyPartReference), constraint=constraint.ValueSizeConstraint(1, MAX)),
					  TYPE('statusString', char.UTF8String, optional=True),
					  TYPE('otherInfo', CHOICE(TYPE('failInfo', CMCFailInfo),
											   TYPE('pendInfo', PendInfo),
											   TYPE('extendedFailInfo', SEQ(TYPE('failInfoOID', univ.ObjectIdentifier),
																			TYPE('failInfoValue', AttributeValue)))),
						   optional=True))


# --  Allow for distribution of trust anchors

# id-cmc-trustedAnchors OBJECT IDENTIFIER ::= {id-cmc 26}
id_cmc_trustedAnchors = ID(*TUP(id_cmc, 26))

# PublishTrustAnchors ::= SEQUENCE {
#     seqNumber      INTEGER,
#     hashAlgorithm  AlgorithmIdentifier,
#     anchorHashes     SEQUENCE OF OCTET STRING
# }
PublishTrustAnchors = SEQ(TYPE('seqNumber', univ.Integer),
						  TYPE('hashAlgorithm', AlgorithmIdentifier),
						  TYPE('anchorHashes', SEQOF(univ.OctetString)))

# id-cmc-authData OBJECT IDENTIFIER ::= {id-cmc 27}
id_cmc_authData = ID(*TUP(id_cmc, 27))

# AuthPublish ::= BodyPartID
class AuthPublish(BodyPartID): pass


# --   These two items use BodyPartList

# id-cmc-batchRequests OBJECT IDENTIFIER ::= {id-cmc 28}
id_cmc_batchRequests = ID(*TUP(id_cmc, 28))

# id-cmc-batchResponses OBJECT IDENTIFIER ::= {id-cmc 29}
id_cmc_batchResponses = ID(*TUP(id_cmc, 29))


# BodyPartList ::= SEQUENCE SIZE (1..MAX) OF BodyPartID
class BodyPartList(univ.SequenceOf):
	componentType = BodyPartID()
	subtypeSpec = univ.SequenceOf.subtypeSpec + constraint.ValueSizeConstraint(1, MAX)

# id-cmc-publishCert OBJECT IDENTIFIER ::= {id-cmc 30}
id_cmc_publishCert = ID(*TUP(id_cmc, 30))

# CMCPublicationInfo ::= SEQUENCE {
#     hashAlg                      AlgorithmIdentifier,
#     certHashes                   SEQUENCE OF OCTET STRING,
#     pubInfo                          PKIPublicationInfo
# }
CMCPublicationInfo = SEQ(TYPE('hashAlg', AlgorithmIdentifier),
						 TYPE('certHashes', SEQOF(univ.OctetString)),
						 TYPE('pubInfo', PKIPublicationInfo))

# id-cmc-modCertTemplate OBJECT IDENTIFIER ::= {id-cmc 31}
id_cmc_modCertTemplate = ID(*TUP(id_cmc, 31))

# ModCertTemplate ::= SEQUENCE {
#     pkiDataReference             BodyPartPath,
#     certReferences               BodyPartList,
#     replace                      BOOLEAN DEFAULT TRUE,
#     certTemplate                 CertTemplate
# }
ModCertTemplate = SEQ(TYPE('pkiDataReference', BodyPartPath),
					  TYPE('certReferences', BodyPartList),
					  TYPE('replace', univ.Boolean, default=True),
					  TYPE('certTemplate', CertTemplate))


# -- Inform follow on servers that one or more controls have already been
# -- processed

# id-cmc-controlProcessed OBJECT IDENTIFIER ::= {id-cmc 32}
id_cmc_controlProcesses = ID(*TUP(id_cmc, 32))

# ControlsProcessed ::= SEQUENCE {
#     bodyList              SEQUENCE SIZE(1..MAX) OF BodyPartReference
# }
ControlsProcesses = SEQ(TYPE('bodyList', SEQOF(BodyPartReference), constraint=constraint.ValueSizeConstraint(1, MAX)))


# --  Identity Proof control w/ algorithm agility

# id-cmc-identityProofV2 OBJECT IDENTIFIER ::= { id-cmc 34 }
id_cmc_identityProofV2 = ID(*TUP(id_cmc, 34))

# IdentifyProofV2 ::= SEQUENCE {
#     proofAlgID       AlgorithmIdentifier,
#     macAlgId         AlgorithmIdentifier,
#     witness          OCTET STRING
# }
IdentityProofV2 = SEQ(TYPE('proofAlgID', AlgorithmIdentifier),
					  TYPE('macAlgId', AlgorithmIdentifier),
					  TYPE('witness', univ.OctetString))

# id-cmc-popLinkWitnessV2 OBJECT IDENTIFIER ::= { id-cmc 33 }
id_cmc_popLinkWitnessV2 = ID(*TUP(id_cmc, 33))

# PopLinkWitnessV2 ::= SEQUENCE {
#     keyGenAlgorithm   AlgorithmIdentifier,
#     macAlgorithm      AlgorithmIdentifier,
#     witness           OCTET STRING
# }
PopLinkWitnessV2 = SEQ(TYPE('keyGenAlgorithm', AlgorithmIdentifier),
					   TYPE('macAlgorithm', AlgorithmIdentifier),
					   TYPE('witness', univ.OctetString))

# END

