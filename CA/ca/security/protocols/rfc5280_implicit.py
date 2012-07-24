from shorthand import TYPE, SEQ, SET, SEQOF, SETOF, CHOICE, ID, TUP

from pyasn1.type import tag, namedtype, namedval, univ, constraint, char, useful


"""PKIX1Implicit88 { iso(1) identified-organization(3) dod(6) internet(1)
     security(5) mechanisms(5) pkix(7) id-mod(0) id-pkix1-implicit(19) }

DEFINITIONS IMPLICIT TAGS ::=

BEGIN

-- EXPORTS ALL --

IMPORTS
      id-pe, id-kp, id-qt-unotice, id-qt-cps,
      -- delete following line if "new" types are supported --
      BMPString, UTF8String,  -- end "new" types --
      ORAddress, Name, RelativeDistinguishedName,
      CertificateSerialNumber, Attribute, DirectoryString
      FROM PKIX1Explicit88 { iso(1) identified-organization(3)
            dod(6) internet(1) security(5) mechanisms(5) pkix(7)
            id-mod(0) id-pkix1-explicit(18) };"""

from rfc5280_explicit import ( id_pe, id_kp, id_qt_unotice, id_qt_cps,
							   ORAddress, Name, RelativeDistinguishedName,
							   CertificateSerialNumber, Attribute, DirectoryString )

DEFAULT_TAG = True
MAX = 2147483647 # FIXME: Is this right?


# -- ISO arc for standard certificate and CRL extensions

# id-ce OBJECT IDENTIFIER  ::=  {joint-iso-ccitt(2) ds(5) 29}
id_ce = ID(2, 5, 29)


# -- AnotherName replaces OTHER-NAME ::= TYPE-IDENTIFIER, as
# -- TYPE-IDENTIFIER is not supported in the '88 ASN.1 syntax

# AnotherName ::= SEQUENCE {
#      type-id    OBJECT IDENTIFIER,
#      value      [0] EXPLICIT ANY DEFINED BY type-id }
AnotherName = SEQ(TYPE('type-id', univ.ObjectIdentifier),
				  TYPE('value', univ.Any, True))

# EDIPartyName ::= SEQUENCE {
#      nameAssigner              [0]  DirectoryString OPTIONAL,
#      partyName                 [1]  DirectoryString }
EDIPartyName = SEQ(TYPE('nameAssigner', DirectoryString, DEFAULT_TAG, optional=True),
				   TYPE('partyName', DirectoryString, DEFAULT_TAG, 1))

# GeneralName ::= CHOICE {
#      otherName                 [0]  AnotherName,
#      rfc822Name                [1]  IA5String,
#      dNSName                   [2]  IA5String,
#      x400Address               [3]  ORAddress,
#      directoryName             [4]  Name,
#      ediPartyName              [5]  EDIPartyName,
#      uniformResourceIdentifier [6]  IA5String,
#      iPAddress                 [7]  OCTET STRING,
#      registeredID              [8]  OBJECT IDENTIFIER }
GeneralName = CHOICE(TYPE('otherName', AnotherName, DEFAULT_TAG),
					 TYPE('rfc822Name', char.IA5String, DEFAULT_TAG, 1),
					 TYPE('dNSName', char.IA5String, DEFAULT_TAG, 2),
					 TYPE('x400Address', ORAddress, DEFAULT_TAG, 3),
					 TYPE('directoryName', Name, DEFAULT_TAG, 4),
					 TYPE('ediPartyName', EDIPartyName, DEFAULT_TAG, 5),
					 TYPE('uniformResourceIdentifier', char.IA5String, DEFAULT_TAG, 6),
					 TYPE('iPAddress', univ.OctetString, DEFAULT_TAG, 7),
					 TYPE('registeredID', univ.ObjectIdentifier, DEFAULT_TAG, 8))

# GeneralNames ::= SEQUENCE SIZE (1..MAX) OF GeneralName
class GeneralNames(univ.SequenceOf):
	componentType = GeneralName()
	subtypeSpec = univ.SequenceOf.subtypeSpec + constraint.ValueSizeConstraint(1, MAX)


# -- authority key identifier OID and syntax

# id-ce-authorityKeyIdentifier OBJECT IDENTIFIER ::=  { id-ce 35 }
id_ce_authorityKeyIdentifier = ID(*TUP(id_ce, 35))

# KeyIdentifier ::= OCTET STRING
class KeyIdentifier(univ.BitString): pass

# AuthorityKeyIdentifier ::= SEQUENCE {
#     keyIdentifier             [0] KeyIdentifier            OPTIONAL,
#     authorityCertIssuer       [1] GeneralNames             OPTIONAL,
#     authorityCertSerialNumber [2] CertificateSerialNumber  OPTIONAL }
#     -- authorityCertIssuer and authorityCertSerialNumber MUST both
#     -- be present or both be absent
AuthorityKeyIdentifier = SEQ(TYPE('keyIdentifier', KeyIdentifier, DEFAULT_TAG, optional=True),
							 TYPE('authorityCertIssuer', GeneralNames, DEFAULT_TAG, 1, optional=True),
							 TYPE('authorityCertSerialNumber', CertificateSerialNumber, DEFAULT_TAG, 2, optional=True))


# -- subject key identifier OID and syntax

# id-ce-subjectKeyIdentifier OBJECT IDENTIFIER ::=  { id-ce 14 }
id_ce_subjectKeyIdentifier = ID(*TUP(id_ce, 14))

# SubjectKeyIdentifier ::= KeyIdentifier
class SubjectKeyIdentifier(KeyIdentifier): pass


# -- key usage extension OID and syntax

# id-ce-keyUsage OBJECT IDENTIFIER ::=  { id-ce 15 }
id_ce_keyUsage = ID(*TUP(id_ce, 15))

# KeyUsage ::= BIT STRING {
#      digitalSignature        (0),
#      nonRepudiation          (1),  -- recent editions of X.509 have
#                                 -- renamed this bit to contentCommitment
#      keyEncipherment         (2),
#      dataEncipherment        (3),
#      keyAgreement            (4),
#      keyCertSign             (5),
#      cRLSign                 (6),
#      encipherOnly            (7),
#      decipherOnly            (8) }
class KeyUsage(univ.BitString):
	namedValues = namedval.NamedValues(('digitalSignature', 0), ('nonRepudiation', 1),
									   ('keyEncipherment', 2), ('dataEncipherment', 3),
									   ('keyAgreement', 4), ('keyCertSign', 5),
									   ('cRLSign', 6), ('encipherOnly', 7),
									   ('decipherOnly', 8))


# -- private key usage period extension OID and syntax

# id-ce-privateKeyUsagePeriod OBJECT IDENTIFIER ::=  { id-ce 16 }
id_ce_privateKeyUsagePeriod = ID(*TUP(id_ce, 16))

# PrivateKeyUsagePeriod ::= SEQUENCE {
#      notBefore       [0]     GeneralizedTime OPTIONAL,
#      notAfter        [1]     GeneralizedTime OPTIONAL }
#      -- either notBefore or notAfter MUST be present
PrivateKeyUsagePeriod = SEQ(TYPE('notBefore', useful.GeneralizedTime, DEFAULT_TAG, optional=True),
							TYPE('notAfter', useful.GeneralizedTime, DEFAULT_TAG, 1, optional=True))


# -- certificate policies extension OID and syntax

# id-ce-certificatePolicies OBJECT IDENTIFIER ::=  { id-ce 32 }
id_ce_certificatePolicies = ID(*TUP(id_ce, 32))

# anyPolicy OBJECT IDENTIFIER ::= { id-ce-certificatePolicies 0 }
anyPolicy = ID(*TUP(id_ce_certificatePolicies, 0))

# CertPolicyId ::= OBJECT IDENTIFIER
class CertPolicyId(univ.ObjectIdentifier): pass

# -- Implementations that recognize additional policy qualifiers MUST
# -- augment the following definition for PolicyQualifierId

# PolicyQualifierId ::= OBJECT IDENTIFIER ( id-qt-cps | id-qt-unotice )
class PolicyQualifierId(univ.ObjectIdentifier):
	subtypeSpec = univ.ObjectIdentifier.subtypeSpec + constraint.SingleValueConstraint(id_qt_cps, id_qt_unotice)

# PolicyQualifierInfo ::= SEQUENCE {
#      policyQualifierId  PolicyQualifierId,
#      qualifier          ANY DEFINED BY policyQualifierId }
PolicyQualifierInfo = SEQ(TYPE('policyQualifierId', PolicyQualifierId),
						  TYPE('qualifier', univ.Any))

# PolicyInformation ::= SEQUENCE {
#      policyIdentifier   CertPolicyId,
#      policyQualifiers   SEQUENCE SIZE (1..MAX) OF
#              PolicyQualifierInfo OPTIONAL }
PolicyInformation = SEQ(TYPE('policyIdentifier', CertPolicyId),
						TYPE('policyQualifiers', SEQOF(PolicyQualifierInfo), optional=True,
							 constraint=constraint.ValueSizeConstraint(1, MAX)))

# CertificatePolicies ::= SEQUENCE SIZE (1..MAX) OF PolicyInformation
class CertificatePolicies(univ.SequenceOf):
	componentType = PolicyInformation()
	subtypeSpec = univ.SequenceOf.subtypeSpec + constraint.ValueSizeConstraint(1, MAX)


# -- CPS pointer qualifier

# CPSuri ::= IA5String
class CPSuri(char.IA5String): pass


# -- user notice qualifier

# DisplayText ::= CHOICE {
#      ia5String        IA5String      (SIZE (1..200)),
#      visibleString    VisibleString  (SIZE (1..200)),
#      bmpString        BMPString      (SIZE (1..200)),
#      utf8String       UTF8String     (SIZE (1..200)) }
_DisplayTextConstraint = constraint.ValueSizeConstraint(1, 200)
DisplayText = CHOICE(TYPE('ia5String', char.IA5String, constraint=_DisplayTextConstraint),
					 TYPE('visibleString', char.VisibleString, constraint=_DisplayTextConstraint),
					 TYPE('bmp5String', char.BMPString, constraint=_DisplayTextConstraint),
					 TYPE('utf8String', char.UTF8String, constraint=_DisplayTextConstraint))

# NoticeReference ::= SEQUENCE {
#      organization     DisplayText,
#      noticeNumbers    SEQUENCE OF INTEGER }
NoticeReference = SEQ(TYPE('organization', DisplayText),
					  TYPE('noticeNumbers', SEQOF(univ.Integer)))

# UserNotice ::= SEQUENCE {
#      noticeRef        NoticeReference OPTIONAL,
#      explicitText     DisplayText OPTIONAL }
UserNotice = SEQ(TYPE('noticeRef', NoticeReference, optional=True),
				 TYPE('explicitText', DisplayText, optional=True))


# -- policy mapping extension OID and syntax

# id-ce-policyMappings OBJECT IDENTIFIER ::=  { id-ce 33 }
id_ce_policyMappings = ID(*TUP(id_ce, 33))

# PolicyMappings ::= SEQUENCE SIZE (1..MAX) OF SEQUENCE {
#      issuerDomainPolicy      CertPolicyId,
#      subjectDomainPolicy     CertPolicyId }
class PolicyMappings(univ.SequenceOf):
	componentType = SEQ(TYPE('issuerDomainPolicy', CertPolicyId),
						TYPE('subjectDomainPolicy', CertPolicyId))
	subtypeSpec = univ.SequenceOf.subtypeSpec + constraint.ValueSizeConstraint(1, MAX)


# -- subject alternative name extension OID and syntax

# id-ce-subjectAltName OBJECT IDENTIFIER ::=  { id-ce 17 }
id_ce_subjectAltName = ID(*TUP(id_ce, 17))

# SubjectAltName ::= GeneralNames
class SubjectAltName(GeneralNames): pass


# -- issuer alternative name extension OID and syntax

# id-ce-issuerAltName OBJECT IDENTIFIER ::=  { id-ce 18 }
id_ce_issuerAltName = ID(*TUP(id_ce, 18))

# IssuerAltName ::= GeneralNames
class IssuerAltNames(GeneralNames): pass

# id-ce-subjectDirectoryAttributes OBJECT IDENTIFIER ::=  { id-ce 9 }
id_ce_subjectDirectoryAttributes = ID(*TUP(id_ce, 9))

# SubjectDirectoryAttributes ::= SEQUENCE SIZE (1..MAX) OF Attribute
class SubjectDirectoryAttributes(univ.SequenceOf):
	componentType = Attribute()
	subtypeSpec = univ.SequenceOf.subtypeSpec + constraint.ValueSizeConstraint(1, MAX)


# -- basic constraints extension OID and syntax

# id-ce-basicConstraints OBJECT IDENTIFIER ::=  { id-ce 19 }
id_ce_basicConstraints = ID(*TUP(id_ce, 19))

# BasicConstraints ::= SEQUENCE {
#      cA                      BOOLEAN DEFAULT FALSE,
#      pathLenConstraint       INTEGER (0..MAX) OPTIONAL }
BasicConstraints = SEQ(TYPE('cA', univ.Boolean, default=False),
					   TYPE('pathLenConstraint', univ.Integer, optional=True,
							constraint=constraint.ValueRangeConstraint(1, MAX)))


# -- name constraints extension OID and syntax

# BaseDistance ::= INTEGER (0..MAX)
class BaseDistance(univ.Integer):
	subtypeSpec = univ.Integer.subtypeSpec + constraint.ValueRangeConstraint(0, MAX)

# GeneralSubtree ::= SEQUENCE {
#      base                    GeneralName,
#      minimum         [0]     BaseDistance DEFAULT 0,
#      maximum         [1]     BaseDistance OPTIONAL }
GeneralSubtree = SEQ(TYPE('base', GeneralName),
					 TYPE('minimum', BaseDistance, DEFAULT_TAG, default=0),
					 TYPE('maximum', BaseDistance, DEFAULT_TAG, 1, optional=True))

# GeneralSubtrees ::= SEQUENCE SIZE (1..MAX) OF GeneralSubtree
class GeneralSubtrees(univ.SequenceOf):
	componentType = GeneralSubtree()
	subtypeSpec = univ.SequenceOf.subtypeSpec + constraint.ValueSizeConstraint(1, MAX)

# id-ce-nameConstraints OBJECT IDENTIFIER ::=  { id-ce 30 }
id_ce_nameConstraints = ID(*TUP(id_ce, 30))

# NameConstraints ::= SEQUENCE {
#      permittedSubtrees       [0]     GeneralSubtrees OPTIONAL,
#      excludedSubtrees        [1]     GeneralSubtrees OPTIONAL }
NameConstraints = SEQ(TYPE('permittedSubtrees', GeneralSubtrees, DEFAULT_TAG, optional=True),
					  TYPE('excludedSubtrees', GeneralSubtrees, DEFAULT_TAG, 1, optional=True))


# -- policy constraints extension OID and syntax

# SkipCerts ::= INTEGER (0..MAX)
class SkipCerts(univ.Integer):
	subtypeSpec = univ.Integer.subtypeSpec + constraint.ValueRangeConstraint(0, MAX)

# id-ce-policyConstraints OBJECT IDENTIFIER ::=  { id-ce 36 }
id_ce_policyConstraints = ID(*TUP(id_ce, 36))

# PolicyConstraints ::= SEQUENCE {
#      requireExplicitPolicy   [0]     SkipCerts OPTIONAL,
#      inhibitPolicyMapping    [1]     SkipCerts OPTIONAL }
PolicyConstraints = SEQ(TYPE('requireExplicitPolicy', SkipCerts, DEFAULT_TAG, optional=True),
						TYPE('inhibitPolicyMapping', SkipCerts, DEFAULT_TAG, 1, optional=True))


# -- CRL distribution points extension OID and syntax

# DistributionPointName ::= CHOICE {
#      fullName                [0]     GeneralNames,
#      nameRelativeToCRLIssuer [1]     RelativeDistinguishedName }
DistributionPointName = CHOICE(TYPE('fullName', GeneralNames, DEFAULT_TAG),
							   TYPE('nameRelativeToCRLIssuer', RelativeDistinguishedName, DEFAULT_TAG, 1))


# ReasonFlags ::= BIT STRING {
#      unused                  (0),
#      keyCompromise           (1),
#      cACompromise            (2),
#      affiliationChanged      (3),
#      superseded              (4),
#      cessationOfOperation    (5),
#      certificateHold         (6),
#      privilegeWithdrawn      (7),
#      aACompromise            (8) }
class ReasonFlags(univ.BitString):
	namedValues = namedval.NamedValues(('unused', 0), ('keyCompromise', 1),
									   ('cACompromise', 2), ('affiliationChanges', 3),
									   ('superseded', 4), ('cessationOfOperation', 5),
									   ('certificateHold', 6), ('privilegeWithdrawn', 7),
									   ('aACompromise', 8))

# DistributionPoint ::= SEQUENCE {
#      distributionPoint       [0]     DistributionPointName OPTIONAL,
#      reasons                 [1]     ReasonFlags OPTIONAL,
#      cRLIssuer               [2]     GeneralNames OPTIONAL }
DistributionPoint = SEQ(TYPE('distributionPoint', DistributionPointName, DEFAULT_TAG, optional=True),
						TYPE('reasons', ReasonFlags, DEFAULT_TAG, 1, optional=True),
						TYPE('cRLIssuer', GeneralNames, DEFAULT_TAG, 2, optional=True))

# id-ce-cRLDistributionPoints     OBJECT IDENTIFIER  ::=  {id-ce 31}
id_ce_cRLDistributionPoints = ID(*TUP(id_ce, 31))

# CRLDistributionPoints ::= SEQUENCE SIZE (1..MAX) OF DistributionPoint
class CRLDistributionPoints(univ.SequenceOf):
	componentType = DistributionPoint()
	subtypeSpec = univ.SequenceOf.subtypeSpec + constraint.ValueSizeConstraint(1, MAX)


# -- extended key usage extension OID and syntax

# KeyPurposeId ::= OBJECT IDENTIFIER
class KeyPurposeId(univ.ObjectIdentifier): pass

# id-ce-extKeyUsage OBJECT IDENTIFIER ::= {id-ce 37}
id_ce_extKeyUsage = ID(*TUP(id_ce, 37))

# ExtKeyUsageSyntax ::= SEQUENCE SIZE (1..MAX) OF KeyPurposeId
class ExtKeyUsageSyntax(univ.SequenceOf):
	componentType = KeyPurposeId()
	subtypeSpec = univ.SequenceOf.subtypeSpec + constraint.ValueSizeConstraint(1, MAX)


# -- permit unspecified key uses

# anyExtendedKeyUsage OBJECT IDENTIFIER ::= { id-ce-extKeyUsage 0 }
anyExtendedKeyUsage = ID(*TUP(id_ce_extKeyUsage, 0))


# -- extended key purpose OIDs

# id-kp-serverAuth             OBJECT IDENTIFIER ::= { id-kp 1 }
id_kp_serverAuth = ID(*TUP(id_kp, 1))
# id-kp-clientAuth             OBJECT IDENTIFIER ::= { id-kp 2 }
id_kp_clientAuth = ID(*TUP(id_kp, 2))
# id-kp-codeSigning            OBJECT IDENTIFIER ::= { id-kp 3 }
id_kp_codeSigning = ID(*TUP(id_kp, 3))
# id-kp-emailProtection        OBJECT IDENTIFIER ::= { id-kp 4 }
id_kp_emailProtection = ID(*TUP(id_kp, 4))
# id-kp-timeStamping           OBJECT IDENTIFIER ::= { id-kp 8 }
id_kp_timeStamping = ID(*TUP(id_kp, 8))
# id-kp-OCSPSigning            OBJECT IDENTIFIER ::= { id-kp 9 }
id_kp_OCSPSigning = ID(*TUP(id_kp, 9))


# -- inhibit any policy OID and syntax

# id-ce-inhibitAnyPolicy OBJECT IDENTIFIER ::=  { id-ce 54 }
id_ce_inhibitAnyPolicy = ID(*TUP(id_ce, 54))

# InhibitAnyPolicy ::= SkipCerts
class InhibitAnyPolicy(SkipCerts): pass


# -- freshest (delta)CRL extension OID and syntax

# id-ce-freshestCRL OBJECT IDENTIFIER ::=  { id-ce 46 }
id_ce_freshestCRL = ID(*TUP(id_ce, 46))

# FreshestCRL ::= CRLDistributionPoints
class FreshestCRL(CRLDistributionPoints): pass


# -- authority info access

# AccessDescription  ::=  SEQUENCE {
#         accessMethod          OBJECT IDENTIFIER,
#         accessLocation        GeneralName  }
AccessDescription = SEQ(TYPE('accessMethod', univ.ObjectIdentifier),
						TYPE('accessLocation', GeneralName))

# id-pe-authorityInfoAccess OBJECT IDENTIFIER ::= { id-pe 1 }
id_pe_authorityInfoAccess = ID(*TUP(id_pe, 1))

# AuthorityInfoAccessSyntax  ::=
#         SEQUENCE SIZE (1..MAX) OF AccessDescription
class AuthorityInfoAccessSyntax(univ.SequenceOf):
	componentType = AccessDescription()
	subtypeSpec = univ.SequenceOf.subtypeSpec + constraint.ValueSizeConstraint(1, MAX)


# -- subject info access

# id-pe-subjectInfoAccess OBJECT IDENTIFIER ::= { id-pe 11 }
id_pe_subjectInfoAccess = ID(*TUP(id_pe, 11))

# SubjectInfoAccessSyntax  ::=
#         SEQUENCE SIZE (1..MAX) OF AccessDescription
class SubjectInfoAccessSyntax(univ.SequenceOf):
	componentType = AccessDescription()
	subtypeSpec = univ.SequenceOf.subtypeSpec + constraint.ValueSizeConstraint(1, MAX)


# -- CRL number extension OID and syntax

# id-ce-cRLNumber OBJECT IDENTIFIER ::= { id-ce 20 }
id_ce_cRLNumber = ID(*TUP(id_ce, 20))

# CRLNumber ::= INTEGER (0..MAX)
class CRLNumber(univ.Integer):
	subtypeSpec = univ.Integer.subtypeSpec + constraint.ValueRangeConstraint(1, MAX)


# -- issuing distribution point extension OID and syntax

# id-ce-issuingDistributionPoint OBJECT IDENTIFIER ::= { id-ce 28 }
id_ce_issuingDistributionPoint = ID(*TUP(id_ce, 28))

# IssuingDistributionPoint ::= SEQUENCE {
#      distributionPoint          [0] DistributionPointName OPTIONAL,
#      onlyContainsUserCerts      [1] BOOLEAN DEFAULT FALSE,
#      onlyContainsCACerts        [2] BOOLEAN DEFAULT FALSE,
#      onlySomeReasons            [3] ReasonFlags OPTIONAL,
#      indirectCRL                [4] BOOLEAN DEFAULT FALSE,
#      onlyContainsAttributeCerts [5] BOOLEAN DEFAULT FALSE }
#      -- at most one of onlyContainsUserCerts, onlyContainsCACerts,
#      -- and onlyContainsAttributeCerts may be set to TRUE.
IssuingDistributionPoint = SEQ(TYPE('distributionPoint', DistributionPointName, DEFAULT_TAG, optional=True),
							   TYPE('onlyContainsUserCerts', univ.Boolean, DEFAULT_TAG, 1, default=False),
							   TYPE('onlyContainsCACerts', univ.Boolean, DEFAULT_TAG, 2, default=False),
							   TYPE('onlySomeReasons', ReasonFlags, DEFAULT_TAG, 3, optional=True),
							   TYPE('indirectCRL', univ.Boolean, DEFAULT_TAG, 4, default=False),
							   TYPE('onlyContainsAttributeCerts', univ.Boolean, DEFAULT_TAG, 5, default=False))

# id-ce-deltaCRLIndicator OBJECT IDENTIFIER ::= { id-ce 27 }
id_ce_deltaCRLIndicator = ID(*TUP(id_ce, 27))

# BaseCRLNumber ::= CRLNumber
class BaseCRLNumber(CRLNumber): pass


# -- reason code extension OID and syntax

# id-ce-cRLReasons OBJECT IDENTIFIER ::= { id-ce 21 }
id_ce_cRLReasons = ID(*TUP(id_ce, 21))

# CRLReason ::= ENUMERATED {
#      unspecified             (0),
#      keyCompromise           (1),
#      cACompromise            (2),
#      affiliationChanged      (3),
#      superseded              (4),
#      cessationOfOperation    (5),
#      certificateHold         (6),
#      removeFromCRL           (8),
#      privilegeWithdrawn      (9),
#      aACompromise           (10) }
class CRLReason(univ.Enumerated):
	namedValues = namedval.NamedValues(('unspecified', 0), ('keyCompromise', 1),
									   ('cACompromise', 2), ('affiliationChanged', 3),
									   ('superseded', 4), ('cessationOfOperation', 5),
									   ('certificateHold', 6), ('removeFromCRL', 8),
									   ('privilegeWithdrawn', 9), ('aACompromise', 10))


# -- certificate issuer CRL entry extension OID and syntax

# id-ce-certificateIssuer OBJECT IDENTIFIER ::= { id-ce 29 }
id_ce_certificateIssuer = ID(*TUP(id_ce, 29))

# CertificateIssuer ::= GeneralNames
class CertificateIssuer(GeneralNames): pass


# -- hold instruction extension OID and syntax

# id-ce-holdInstructionCode OBJECT IDENTIFIER ::= { id-ce 23 }
id_ce_holdInstructionCode = ID(*TUP(id_ce, 23))

# HoldInstructionCode ::= OBJECT IDENTIFIER
class HoldInstructionCode(univ.ObjectIdentifier): pass


# -- ANSI x9 arc holdinstruction arc

# holdInstruction OBJECT IDENTIFIER ::=
#           {joint-iso-itu-t(2) member-body(2) us(840) x9cm(10040) 2}
holdInstruction = ID(2, 2, 840, 10040, 2)


# -- ANSI X9 holdinstructions

# id-holdinstruction-none OBJECT IDENTIFIER  ::=
#                                       {holdInstruction 1} -- deprecated
id_holdInstruction_none = ID(*TUP(holdInstruction, 1))

# id-holdinstruction-callissuer OBJECT IDENTIFIER ::= {holdInstruction 2}
id_holdInstruction_callissuer = ID(*TUP(holdInstruction, 2))

# id-holdinstruction-reject OBJECT IDENTIFIER ::= {holdInstruction 3}
id_holdInstruction_reject = ID(*TUP(holdInstruction, 3))


# -- invalidity date CRL entry extension OID and syntax

# id-ce-invalidityDate OBJECT IDENTIFIER ::= { id-ce 24 }
id_ce_invalidityDate = ID(*TUP(id_ce, 24))

# InvalidityDate ::=  GeneralizedTime
class InvalidityDate(useful.GeneralizedTime): pass

# END

