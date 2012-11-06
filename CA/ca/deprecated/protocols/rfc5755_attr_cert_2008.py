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

from shorthand import MAX, TYPE, SEQ, SET, ENUM, SEQOF, SETOF, CHOICE, ID, TUP

from pyasn1.type import tag, namedtype, namedval, univ, constraint, char, useful


"""PKIXAttributeCertificate-2008 { iso(1) identified-organization(3)
     dod(6) internet(1) security(5) mechanisms(5) pkix(7) id-mod(0)
     id-mod-attribute-cert-v2(61) }

   DEFINITIONS IMPLICIT TAGS ::=

   BEGIN

   -- EXPORTS ALL --

   IMPORTS

   -- IMPORTed module OIDs MAY change if [PKIXPROF] changes
   -- PKIX Certificate Extensions

   Attribute, AlgorithmIdentifier, CertificateSerialNumber,
   Extensions, UniqueIdentifier, id-pkix, id-pe, id-kp, id-ad, id-at
     FROM PKIX1Explicit88
       { iso(1) identified-organization(3) dod(6) internet(1)
         security(5) mechanisms(5) pkix(7) id-mod(0)
         id-pkix1-explicit-88(18) }

   GeneralName, GeneralNames, id-ce, AuthorityKeyIdentifier,
   AuthorityInfoAccessSyntax, CRLDistributionPoint
     FROM PKIX1Implicit88
       { iso(1) identified-organization(3) dod(6) internet(1)
         security(5) mechanisms(5) pkix(7) id-mod(0)
         id-pkix1-implicit-88(19) }

   ContentInfo
     FROM CryptographicMessageSyntax2004
       { iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs-9(9)
         smime(16) modules(0) cms-2004(24) }

   ;"""

from rfc5280_explicit import ( Attribute, AlgorithmIdentifier,
							   CertificateSerialNumber, Extensions,
							   UniqueIdentifier, id_pkix,
							   id_pe, id_kp, id_ad, id_at )

from rfc5280_implicit import ( GeneralName, GeneralNames,
							   id_ce, AuthorityKeyIdentifier,
							   AuthorityInfoAccessSyntax ) #, CRLDistributionPoint ) FIXME: This isn't used, and doesn't exist

# Circular import
# import rfc5652_cms_2004 as rfc5652
# FIXME: ContentInfo is never used

DEFAULT_TAG = False


# id-pe-ac-auditIdentity       OBJECT IDENTIFIER ::= { id-pe 4 }
id_pe_ac_auditIdentity = ID(*TUP(id_pe, 4))

# id-pe-aaControls             OBJECT IDENTIFIER ::= { id-pe 6 }
id_pe_ac_aaControls = ID(*TUP(id_pe, 6))

# id-pe-ac-proxying            OBJECT IDENTIFIER ::= { id-pe 10 }
id_pe_ac_proxying = ID(*TUP(id_pe, 10))

# id-ce-targetInformation      OBJECT IDENTIFIER ::= { id-ce 55 }
id_ce_targetInformation = ID(*TUP(id_ce, 55))

# id-aca                       OBJECT IDENTIFIER ::= { id-pkix 10 }
id_aca = ID(*TUP(id_pkix, 10))

# id-aca-authenticationInfo    OBJECT IDENTIFIER ::= { id-aca 1 }
id_aca_authenticationInfo = ID(*TUP(id_aca, 1))

# id-aca-accessIdentity        OBJECT IDENTIFIER ::= { id-aca 2 }
id_aca_accessIdentity = ID(*TUP(id_aca, 2))

# id-aca-chargingIdentity      OBJECT IDENTIFIER ::= { id-aca 3 }
id_aca_chargingIdentity = ID(*TUP(id_aca, 3))

# id-aca-group                 OBJECT IDENTIFIER ::= { id-aca 4 }
id_aca_group = ID(*TUP(id_aca, 4))

# -- { id-aca 5 } is reserved

# id-aca-encAttrs              OBJECT IDENTIFIER ::= { id-aca 6 }
id_aca_encAttrs = ID(*TUP(id_aca, 6))

# id-at-role                   OBJECT IDENTIFIER ::= { id-at 72}
id_at_role = ID(*TUP(id_at, 72))

# id-at-clearance              OBJECT IDENTIFIER ::= {
#  joint-iso-ccitt(2) ds(5) attributeType(4) clearance (55) }
id_at_clearance = ID(2, 5, 4, 55)

#FIXME: Which of these should be used?
# -- Uncomment the following declaration and comment the above line if
# -- using the id-at-clearance attribute as defined in [RFC3281]

# --  id-at-clearance              OBJECT IDENTIFIER ::= {
# --    joint-iso-ccitt(2) ds(5) module(1) selected-attribute-types(5)
# --    clearance (55) }

# -- Uncomment this if using a 1988 level ASN.1 compiler

# -- UTF8String ::= [UNIVERSAL 12] IMPLICIT OCTET STRING


# AttCertVersion ::= INTEGER { v2(1) }
class AttCertVersion(univ.Integer):
	namedValues = namedval.NamedValues(('v2', 1))

# IssuerSerial ::= SEQUENCE {
#   issuer     GeneralNames,
#   serial     CertificateSerialNumber,
#   issuerUID  UniqueIdentifier OPTIONAL
# }
IssuerSerial = SEQ(TYPE('issuer', GeneralNames),
				   TYPE('serial', CertificateSerialNumber),
				   TYPE('issuerUID', UniqueIdentifier, optional=True))

# ObjectDigestInfo ::= SEQUENCE {
#   digestedObjectType  ENUMERATED {
#                        publicKey         (0),
#                        publicKeyCert     (1),
#                        otherObjectTypes  (2) },
#          -- otherObjectTypes MUST NOT
#          -- MUST NOT be used in this profile
#   otherObjectTypeID   OBJECT IDENTIFIER  OPTIONAL,
#   digestAlgorithm     AlgorithmIdentifier,
#   objectDigest        BIT STRING
# }
ObjectDigestInfo = SEQ(TYPE('digestedObjectType', ENUM(('publicKey', 0), ('publicKeyCert', 1), ('otherObjectTypes', 2))),
					   TYPE('otherObjectTypeID', univ.ObjectIdentifier, optional=True),
					   TYPE('digestAlgorithm', AlgorithmIdentifier),
					   TYPE('objectDigest', univ.BitString))

# Holder ::= SEQUENCE {
#   baseCertificateID   [0] IssuerSerial OPTIONAL,
#          -- the issuer and serial number of
#          -- the holder's Public Key Certificate
#   entityName          [1] GeneralNames OPTIONAL,
#          -- the name of the claimant or role
#   objectDigestInfo    [2] ObjectDigestInfo OPTIONAL
#          -- used to directly authenticate the
#          -- holder, for example, an executable
# }
Holder = SEQ(TYPE('baseCertificateID', IssuerSerial, DEFAULT_TAG, optional=True),
			 TYPE('entityName', GeneralNames, DEFAULT_TAG, 1, optional=True),
			 TYPE('objectDigestInfo', ObjectDigestInfo, DEFAULT_TAG, 2, optional=True))

# V2Form ::= SEQUENCE {
#   issuerName             GeneralNames  OPTIONAL,
#   baseCertificateID  [0] IssuerSerial  OPTIONAL,
#   objectDigestInfo   [1] ObjectDigestInfo  OPTIONAL
#          -- issuerName MUST be present in this profile
#          -- baseCertificateID and objectDigestInfo MUST
#          -- NOT be present in this profile
# }
V2Form = SEQ(TYPE('issuerName', GeneralNames, optional=True),
			 TYPE('baseCertificateID', IssuerSerial, DEFAULT_TAG, optional=True),
			 TYPE('bobjectDigestInfo', ObjectDigestInfo, DEFAULT_TAG, 1, optional=True))

# AttCertIssuer ::= CHOICE {
#   v1Form      GeneralNames,  -- MUST NOT be used in this
#                              -- profile
#   v2Form  [0] V2Form         -- v2 only
# }
AttCertIssuer = CHOICE(TYPE('v1Form', GeneralNames),
					   TYPE('v2Form', V2Form, DEFAULT_TAG))

# AttCertValidityPeriod  ::= SEQUENCE {
#   notBeforeTime  GeneralizedTime,
#   notAfterTime   GeneralizedTime
# }
AttCertValidityPeriod = SEQ(TYPE('notBeforeTime', useful.GeneralizedTime),
							TYPE('notAfterTime', useful.GeneralizedTime))

# AttributeCertificateInfo ::= SEQUENCE {
#   version                 AttCertVersion,  -- version is v2
#   holder                  Holder,
#   issuer                  AttCertIssuer,
#   signature               AlgorithmIdentifier,
#   serialNumber            CertificateSerialNumber,
#   attrCertValidityPeriod  AttCertValidityPeriod,
#   attributes              SEQUENCE OF Attribute,
#   issuerUniqueID          UniqueIdentifier OPTIONAL,
#   extensions              Extensions OPTIONAL
# }
AttributeCertificateInfo = SEQ(TYPE('version', AttCertVersion),
							   TYPE('holder', Holder),
							   TYPE('issuer', AttCertIssuer),
							   TYPE('signature', AlgorithmIdentifier),
							   TYPE('serialNumber', CertificateSerialNumber),
							   TYPE('attrCertValidityPeriod', AttCertValidityPeriod),
							   TYPE('attributes', SEQOF(Attribute)),
							   TYPE('issuerUniqueID', UniqueIdentifier, optional=True),
							   TYPE('extensions', Extensions, optional=True))

# AttributeCertificate ::= SEQUENCE {
#   acinfo              AttributeCertificateInfo,
#   signatureAlgorithm  AlgorithmIdentifier,
#   signatureValue      BIT STRING
# }
AttributeCertificate = SEQ(TYPE('acinfo', AttributeCertificateInfo),
						   TYPE('signatureAlgorithm', AlgorithmIdentifier),
						   TYPE('signatureValue', univ.BitString))

# TargetCert ::= SEQUENCE {
#   targetCertificate  IssuerSerial,
#   targetName         GeneralName OPTIONAL,
#   certDigestInfo     ObjectDigestInfo OPTIONAL
# }
TargetCert = SEQ(TYPE('targetCertificate', IssuerSerial),
				 TYPE('targetName', GeneralName, optional=True),
				 TYPE('certDigestInfo', ObjectDigestInfo, optional=True))

# Target ::= CHOICE {
#   targetName   [0] GeneralName,
#   targetGroup  [1] GeneralName,
#   targetCert   [2] TargetCert
# }
Target = CHOICE(TYPE('targetName', GeneralName, DEFAULT_TAG),
				TYPE('targetGroup', GeneralName, DEFAULT_TAG, 1),
				TYPE('targetCert', TargetCert, DEFAULT_TAG, 2))

# Targets ::= SEQUENCE OF Target
Targets = SEQOF(Target)

# IetfAttrSyntax ::= SEQUENCE {
#   policyAuthority [0] GeneralNames OPTIONAL,
#   values          SEQUENCE OF CHOICE {
#                     octets  OCTET STRING,
#                     oid     OBJECT IDENTIFIER,
#                     string  UTF8String
#   }
# }
IetfAttrSyntax = SEQ(TYPE('policyAuthority', GeneralNames, DEFAULT_TAG, optional=True),
					 TYPE('values', SEQOF(CHOICE(TYPE('octets', univ.OctetString),
												 TYPE('oid', univ.ObjectIdentifier),
												 TYPE('string', char.UTF8String)))))

# SvceAuthInfo ::= SEQUENCE {
#   service   GeneralName,
#   ident     GeneralName,
#   authInfo  OCTET STRING OPTIONAL
# }
SvceAuthInfo = SEQ(TYPE('service', GeneralName),
				   TYPE('ident', GeneralName),
				   TYPE('authInfo', univ.OctetString, optional=True))

# RoleSyntax ::= SEQUENCE {
#   roleAuthority  [0] GeneralNames OPTIONAL,
#   roleName       [1] GeneralName
# }
RoleSyntax = SEQ(TYPE('roleAuthority', GeneralNames, DEFAULT_TAG, optional=True),
				 TYPE('roleName', GeneralName, DEFAULT_TAG, 1))

# ClassList ::= BIT STRING {
#   unmarked      (0),
#   unclassified  (1),
#   restricted    (2),
#   confidential  (3),
#   secret        (4),
#   topSecret     (5)
# }
class ClassList(univ.BitString):
	namedValues = namedval.NamedValues(('unmarked', 0), ('unclassified', 1),
									   ('restricted', 2), ('confidential', 3),
									   ('secret', 4), ('topSecret', 5))

# SecurityCategory ::= SEQUENCE {
#   type   [0] OBJECT IDENTIFIER,
#   value  [1] EXPLICIT ANY DEFINED BY type
# }
SecurityCategory = SEQ(TYPE('type', univ.ObjectIdentifier, DEFAULT_TAG),
					   TYPE('value', univ.Any, True, 1))

# -- Note that in [RFC3281] the syntax for SecurityCategory was
# -- as follows:
# --
# --  SecurityCategory ::= SEQUENCE {
# --    type   [0] IMPLICIT OBJECT IDENTIFIER,
# --    value  [1] ANY DEFINED BY type
# -- }
# --
# -- The removal of the IMPLICIT from the type line and the
# -- addition of the EXPLICIT to the value line result in
# -- no changes to the encoding.

# Clearance ::= SEQUENCE {
#   policyId            OBJECT IDENTIFIER,
#   classList           ClassList DEFAULT {unclassified},
#   securityCategories  SET OF SecurityCategory  OPTIONAL
# }
Clearance = SEQ(TYPE('policyId', univ.ObjectIdentifier),
				TYPE('classList', ClassList, default='unclassified'),
				TYPE('securityCategories', SETOF(SecurityCategory), optional=True))

#FIXME: Which should be used?
# -- Uncomment the following lines to support deprecated clearance
# -- syntax and comment out previous Clearance.

# -- Clearance ::= SEQUENCE {
# --   policyId            [0] OBJECT IDENTIFIER,
# --   classList           [1] ClassList DEFAULT {unclassified},
# --   securityCategories  [2] SET OF SecurityCategory  OPTIONAL
# -- }

# AttrSpec ::= SEQUENCE OF OBJECT IDENTIFIER
AttrSpec = SEQOF(univ.ObjectIdentifier)

# AAControls ::= SEQUENCE {
#   pathLenConstraint      INTEGER (0..MAX) OPTIONAL,
#   permittedAttrs     [0] AttrSpec OPTIONAL,
#   excludedAttrs      [1] AttrSpec OPTIONAL,
#   permitUnSpecified      BOOLEAN DEFAULT TRUE
# }
AAControls = SEQ(TYPE('pathLenConstraint', univ.Integer, optional=True, constraint=constraint.ValueRangeConstraint(1, MAX)),
				 TYPE('permittedAttrs', AttrSpec, DEFAULT_TAG, optional=True),
				 TYPE('excludedAttrs', AttrSpec, DEFAULT_TAG, 1, optional=True),
				 TYPE('permitUnSpecified', univ.Boolean, default=True))

# ACClearAttrs ::= SEQUENCE {
#   acIssuer  GeneralName,
#   acSerial  INTEGER,
#   attrs     SEQUENCE OF Attribute
# }
ACClearAttrs = SEQ(TYPE('acIssuer', GeneralName),
				   TYPE('acSerial', univ.Integer),
				   TYPE('attrs', SEQOF(Attribute)))

# ProxyInfo ::= SEQUENCE OF Targets
ProxyInfo = SEQOF(Targets)

# END
