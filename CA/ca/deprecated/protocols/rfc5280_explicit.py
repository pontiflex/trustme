from shorthand import MAX, TYPE, SEQ, SET, SEQOF, SETOF, CHOICE, ID, TUP

from pyasn1.type import tag, namedtype, namedval, univ, constraint, char, useful


"""PKIX1Explicit88 { iso(1) identified-organization(3) dod(6) internet(1)
  security(5) mechanisms(5) pkix(7) id-mod(0) id-pkix1-explicit(18) }

DEFINITIONS EXPLICIT TAGS ::=

BEGIN

-- EXPORTS ALL --

-- IMPORTS NONE --

-- UNIVERSAL Types defined in 1993 and 1998 ASN.1
-- and required by this specification

UniversalString ::= [UNIVERSAL 28] IMPLICIT OCTET STRING
        -- UniversalString is defined in ASN.1:1993

BMPString ::= [UNIVERSAL 30] IMPLICIT OCTET STRING
      -- BMPString is the subtype of UniversalString and models
      -- the Basic Multilingual Plane of ISO/IEC 10646

UTF8String ::= [UNIVERSAL 12] IMPLICIT OCTET STRING
      -- The content of this type conforms to RFC 3629."""

DEFAULT_TAG = True

def TAG(tagSet):
	return tagSet.tagExplicitly if DEFAULT_TAG else tagSet.tagImplicitly

def DIRSTR(lower, upper):
	cons = constraint.ValueSizeConstraint(lower, upper)
	return CHOICE(TYPE('teletexString', char.TeletexString, constraint=cons),
				  TYPE('printableString', char.PrintableString, constraint=cons),
				  TYPE('universalString', char.UniversalString, constraint=cons),
				  TYPE('utf8String', char.UTF8String, constraint=cons),
				  TYPE('bmpString', char.BMPString, constraint=cons))

	


# -- PKIX specific OIDs

# id-pkix  OBJECT IDENTIFIER  ::=
#   { iso(1) identified-organization(3) dod(6) internet(1)
#   security(5) mechanisms(5) pkix(7) }
id_pkix = ID(1, 3, 6, 1, 5, 5, 7)


# -- PKIX arcs

# id-pe OBJECT IDENTIFIER ::= { id-pkix 1 }
#   -- arc for private certificate extensions
id_pe = ID(*TUP(id_pkix, 1))

# id-qt OBJECT IDENTIFIER ::= { id-pkix 2 }
#   -- arc for policy qualifier types
id_qt = ID(*TUP(id_pkix, 2))

# id-kp OBJECT IDENTIFIER ::= { id-pkix 3 }
#   -- arc for extended key purpose OIDS
id_kp = ID(*TUP(id_pkix, 3))

# id-ad OBJECT IDENTIFIER ::= { id-pkix 48 }
#   -- arc for access descriptors
id_ad = ID(*TUP(id_pkix, 48))


# -- policyQualifierIds for Internet policy qualifiers

# id-qt-cps      OBJECT IDENTIFIER ::=  { id-qt 1 }
#   -- OID for CPS qualifier
id_qt_cps = ID(*TUP(id_qt, 1))

# id-qt-unotice  OBJECT IDENTIFIER ::=  { id-qt 2 }
#   -- OID for user notice qualifier
id_qt_unotice = ID(*TUP(id_qt, 2))


# -- access descriptor definitions

# id-ad-ocsp         OBJECT IDENTIFIER ::= { id-ad 1 }
id_ad_ocsp = ID(*TUP(id_ad, 1))

# id-ad-caIssuers    OBJECT IDENTIFIER ::= { id-ad 2 }
id_ad_caIssuers = ID(*TUP(id_ad, 2))

# id-ad-timeStamping OBJECT IDENTIFIER ::= { id-ad 3 }
id_ad_timeStamping = ID(*TUP(id_ad, 3))

# id-ad-caRepository OBJECT IDENTIFIER ::= { id-ad 5 }
id_ad_caRepository = ID(*TUP(id_ad, 5))


# --  specifications of Upper Bounds MUST be regarded as mandatory
# --  from Annex B of ITU-T X.411 Reference Definition of MTS Parameter
# --  Upper Bounds

# -- Upper Bounds
# ub-name INTEGER ::= 32768
ub_name = univ.Integer(32768)
# ub-common-name INTEGER ::= 64
ub_common_name = univ.Integer(64)
# ub-locality-name INTEGER ::= 128
ub_locality_name = univ.Integer(128)
# ub-state-name INTEGER ::= 128
ub_state_name = univ.Integer(128)
# ub-organization-name INTEGER ::= 64
ub_organization_name = univ.Integer(64)
# ub-organizational-unit-name INTEGER ::= 64
ub_organizational_unit_name = univ.Integer(64)
# ub-title INTEGER ::= 64
ub_title = univ.Integer(64)
# ub-serial-number INTEGER ::= 64
ub_serial_number = univ.Integer(64)
# ub-match INTEGER ::= 128
ub_match = univ.Integer(128)
# ub-emailaddress-length INTEGER ::= 255
ub_emailaddress_length = univ.Integer(255)
# ub-common-name-length INTEGER ::= 64
ub_common_name_length = univ.Integer(64)
# ub-country-name-alpha-length INTEGER ::= 2
ub_country_name_alpha_length = univ.Integer(2)
# ub-country-name-numeric-length INTEGER ::= 3
ub_country_name_numeric_length = univ.Integer(3)
# ub-domain-defined-attributes INTEGER ::= 4
ub_domain_defined_attributes = univ.Integer(4)
# ub-domain-defined-attribute-type-length INTEGER ::= 8
ub_domain_defined_attribute_type_length = univ.Integer(8)
# ub-domain-defined-attribute-value-length INTEGER ::= 128
ub_domain_defined_attribute_value_length = univ.Integer(128)
# ub-domain-name-length INTEGER ::= 16
ub_domain_name_length = univ.Integer(16)
# ub-extension-attributes INTEGER ::= 256
ub_extension_attributes = univ.Integer(256)
# ub-e163-4-number-length INTEGER ::= 15
ub_e163_4_number_length = univ.Integer(15)
# ub-e163-4-sub-address-length INTEGER ::= 40
ub_e163_4_sub_address_length = univ.Integer(40)
# ub-generation-qualifier-length INTEGER ::= 3
ub_generation_qualifier_length = univ.Integer(3)
# ub-given-name-length INTEGER ::= 16
ub_given_name_length = univ.Integer(16)
# ub-initials-length INTEGER ::= 5
ub_initials_length = univ.Integer(5)
# ub-integer-options INTEGER ::= 256
ub_integer_options = univ.Integer(256)
# ub-numeric-user-id-length INTEGER ::= 32
ub_numeric_user_id_length = univ.Integer(32)
# ub-organization-name-length INTEGER ::= 64
ub_organization_name_length = univ.Integer(64)
# ub-organizational-unit-name-length INTEGER ::= 32
ub_organizational_unit_name_length = univ.Integer(32)
# ub-organizational-units INTEGER ::= 4
ub_organizational_units = univ.Integer(4)
# ub-pds-name-length INTEGER ::= 16
ub_pds_name_length = univ.Integer(16)
# ub-pds-parameter-length INTEGER ::= 30
ub_pds_parameter_length = univ.Integer(30)
# ub-pds-physical-address-lines INTEGER ::= 6
ub_pds_physical_address_lines = univ.Integer(6)
# ub-postal-code-length INTEGER ::= 16
ub_postal_code_length = univ.Integer(16)
# ub-pseudonym INTEGER ::= 128
ub_pseudonym = univ.Integer(128)
# ub-surname-length INTEGER ::= 40
ub_surname_length = univ.Integer(40)
# ub-terminal-id-length INTEGER ::= 24
ub_terminal_id_length = univ.Integer(24)
# ub-unformatted-address-length INTEGER ::= 180
ub_unformatted_address_length = univ.Integer(180)
# ub-x121-address-length INTEGER ::= 16
ub_x121_address_length = univ.Integer(16)

# -- Note - upper bounds on string types, such as TeletexString, are
# -- measured in characters.  Excepting PrintableString or IA5String, a
# -- significantly greater number of octets will be required to hold
# -- such a value.  As a minimum, 16 octets, or twice the specified
# -- upper bound, whichever is the larger, should be allowed for
# -- TeletexString.  For UTF8String or UniversalString at least four
# -- times the upper bound should be allowed.


# -- attribute data types

# AttributeType ::= OBJECT IDENTIFIER
class AttributeType(univ.ObjectIdentifier): pass

# AttributeValue ::= ANY -- DEFINED BY AttributeType
class AttributeValue(univ.Any): pass

# Attribute ::= SEQUENCE
#   { type AttributeType,
#   values SET OF AttributeValue }
#   -- at least one value is required
Attribute = SEQ(TYPE('type', AttributeType),
				TYPE('values', SETOF(AttributeValue)))

# AttributeTypeAndValue   ::= SEQUENCE
#   { type    AttributeType,
#   value   AttributeValue }
AttributeTypeAndValue = SEQ(TYPE('type', AttributeType),
							TYPE('value', AttributeValue))

# -- suggested naming attributes: Definition of the following
# --   information object set may be augmented to meet local
# --   requirements.  Note that deleting members of the set may
# --   prevent interoperability with conforming implementations.
# --   presented in pairs: the AttributeType followed by the
# --   type definition for the corresponding AttributeValue


# -- Arc for standard naming attributes

# id-at OBJECT IDENTIFIER ::= { joint-iso-ccitt(2) ds(5) 4 }
id_at = ID(2, 5, 4)


# -- Naming attributes of type X520name

# id-at-name                AttributeType ::= { id-at 41 }
id_at_name = AttributeType(TUP(id_at, 41))

# id-at-surname             AttributeType ::= { id-at  4 }
id_at_surname = AttributeType(TUP(id_at, 4))

# id-at-givenName           AttributeType ::= { id-at 42 }
id_at_givenName = AttributeType(TUP(id_at, 42))

# id-at-initials            AttributeType ::= { id-at 43 }
id_at_initials = AttributeType(TUP(id_at, 43))

# id-at-generationQualifier AttributeType ::= { id-at 44 }
id_at_generationQualifier = AttributeType(TUP(id_at, 44))

# -- Naming attributes of type X520Name:
# --   X520name ::= DirectoryString (SIZE (1..ub-name))
# --
# -- Expanded to avoid parameterized type:
# X520name ::= CHOICE {
#       teletexString     TeletexString   (SIZE (1..ub-name)),
#       printableString   PrintableString (SIZE (1..ub-name)),
#       universalString   UniversalString (SIZE (1..ub-name)),
#       utf8String        UTF8String      (SIZE (1..ub-name)),
#       bmpString         BMPString       (SIZE (1..ub-name)) }
X520Name = DIRSTR(1, ub_name)


# -- Naming attributes of type X520CommonName

# id-at-commonName        AttributeType ::= { id-at 3 }
id_at_commonName = AttributeType(TUP(id_at, 3))

# -- Naming attributes of type X520CommonName:
# --   X520CommonName ::= DirectoryName (SIZE (1..ub-common-name))
# --
# -- Expanded to avoid parameterized type:
# X520CommonName ::= CHOICE {
#       teletexString     TeletexString   (SIZE (1..ub-common-name)),
#       printableString   PrintableString (SIZE (1..ub-common-name)),
#       universalString   UniversalString (SIZE (1..ub-common-name)),
#       utf8String        UTF8String      (SIZE (1..ub-common-name)),
#       bmpString         BMPString       (SIZE (1..ub-common-name)) }
X520CommonName = DIRSTR(1, ub_common_name)


# -- Naming attributes of type X520LocalityName

# id-at-localityName      AttributeType ::= { id-at 7 }
id_at_localityName = AttributeType(TUP(id_at, 7))

# -- Naming attributes of type X520LocalityName:
# --   X520LocalityName ::= DirectoryName (SIZE (1..ub-locality-name))
# --
# -- Expanded to avoid parameterized type:
# X520LocalityName ::= CHOICE {
#       teletexString     TeletexString   (SIZE (1..ub-locality-name)),
#       printableString   PrintableString (SIZE (1..ub-locality-name)),
#       universalString   UniversalString (SIZE (1..ub-locality-name)),
#       utf8String        UTF8String      (SIZE (1..ub-locality-name)),
#       bmpString         BMPString       (SIZE (1..ub-locality-name)) }
X520LocalityName = DIRSTR(1, ub_locality_name)


# -- Naming attributes of type X520StateOrProvinceName

# id-at-stateOrProvinceName AttributeType ::= { id-at 8 }
id_at_stateOrProvinceName = AttributeType(TUP(id_at, 8))

# -- Naming attributes of type X520StateOrProvinceName:
# --   X520StateOrProvinceName ::= DirectoryName (SIZE (1..ub-state-name))
# --
# -- Expanded to avoid parameterized type:
# X520StateOrProvinceName ::= CHOICE {
#       teletexString     TeletexString   (SIZE (1..ub-state-name)),
#       printableString   PrintableString (SIZE (1..ub-state-name)),
#       universalString   UniversalString (SIZE (1..ub-state-name)),
#       utf8String        UTF8String      (SIZE (1..ub-state-name)),
#       bmpString         BMPString       (SIZE (1..ub-state-name)) }
X520StateOrProvinceName = DIRSTR(1, ub_state_name)


#-- Naming attributes of type X520OrganizationName

# id-at-organizationName  AttributeType ::= { id-at 10 }
id_at_organizationName = AttributeType(TUP(id_at, 10))

# -- Naming attributes of type X520OrganizationName:
# --   X520OrganizationName ::=
# --          DirectoryName (SIZE (1..ub-organization-name))
# --
# -- Expanded to avoid parameterized type:
# X520OrganizationName ::= CHOICE {
#       teletexString     TeletexString   (SIZE (1..ub-organization-name)),
#       printableString   PrintableString (SIZE (1..ub-organization-name)),
#       universalString   UniversalString (SIZE (1..ub-organization-name)),
#       utf8String        UTF8String      (SIZE (1..ub-organization-name)),
#       bmpString         BMPString       (SIZE (1..ub-organization-name))  }
X520OrganizationName = DIRSTR(1, ub_organization_name)


# -- Naming attributes of type X520OrganizationalUnitName

# id-at-organizationalUnitName AttributeType ::= { id-at 11 }
id_at_organizationalUnitName = AttributeType(TUP(id_at, 11))

# -- Naming attributes of type X520OrganizationalUnitName:
# --   X520OrganizationalUnitName ::=
# --          DirectoryName (SIZE (1..ub-organizational-unit-name))
# --
# -- Expanded to avoid parameterized type:
# X520OrganizationalUnitName ::= CHOICE {
#       teletexString     TeletexString   (SIZE (1..ub-organizational-unit-name)),
#       printableString   PrintableString (SIZE (1..ub-organizational-unit-name)),
#       universalString   UniversalString (SIZE (1..ub-organizational-unit-name)),
#       utf8String        UTF8String      (SIZE (1..ub-organizational-unit-name)),
#       bmpString         BMPString       (SIZE (1..ub-organizational-unit-name)) }
X520OrganizationalUnitName = DIRSTR(1, ub_organizational_unit_name)


# -- Naming attributes of type X520Title

# id-at-title             AttributeType ::= { id-at 12 }
id_at_title = AttributeType(TUP(id_at, 12))

# -- Naming attributes of type X520Title:
# --   X520Title ::= DirectoryName (SIZE (1..ub-title))
# --
# -- Expanded to avoid parameterized type:
# X520Title ::= CHOICE {
#       teletexString     TeletexString   (SIZE (1..ub-title)),
#       printableString   PrintableString (SIZE (1..ub-title)),
#       universalString   UniversalString (SIZE (1..ub-title)),
#       utf8String        UTF8String      (SIZE (1..ub-title)),
#       bmpString         BMPString       (SIZE (1..ub-title)) }
X520Title = DIRSTR(1, ub_title)


# -- Naming attributes of type X520dnQualifier

# id-at-dnQualifier       AttributeType ::= { id-at 46 }
id_at_dnQualifier = AttributeType(TUP(id_at, 46))

# X520dnQualifier ::=     PrintableString
class X520dnQualifier(char.PrintableString): pass


# -- Naming attributes of type X520countryName (digraph from IS 3166)

# id-at-countryName       AttributeType ::= { id-at 6 }
id_at_countryName = AttributeType(TUP(id_at, 6))

# X520countryName ::=     PrintableString (SIZE (2))
class X520countryName(char.PrintableString):
	subtypeSpec = char.PrintableString.subtypeSpec + constraint.ValueSizeConstraint(2, 2)


# -- Naming attributes of type X520SerialNumber

# id-at-serialNumber      AttributeType ::= { id-at 5 }
id_at_serialNumber = AttributeType(TUP(id_at, 5))

# X520SerialNumber ::=    PrintableString (SIZE (1..ub-serial-number))
class X520SerialNumber(char.PrintableString):
	subtypeSpec = char.PrintableString.subtypeSpec + constraint.ValueSizeConstraint(1, ub_serial_number)


# -- Naming attributes of type X520Pseudonym

# id-at-pseudonym         AttributeType ::= { id-at 65 }
id_at_pseudonym = AttributeType(TUP(id_at, 65))

# -- Naming attributes of type X520Pseudonym:
# --   X520Pseudonym ::= DirectoryName (SIZE (1..ub-pseudonym))
# --
# -- Expanded to avoid parameterized type:
# X520Pseudonym ::= CHOICE {
#    teletexString     TeletexString   (SIZE (1..ub-pseudonym)),
#    printableString   PrintableString (SIZE (1..ub-pseudonym)),
#    universalString   UniversalString (SIZE (1..ub-pseudonym)),
#    utf8String        UTF8String      (SIZE (1..ub-pseudonym)),
#    bmpString         BMPString       (SIZE (1..ub-pseudonym)) }
X520Pseudonym = DIRSTR(1, ub_pseudonym)


# -- Naming attributes of type DomainComponent (from RFC 4519)

# id-domainComponent   AttributeType ::= { 0 9 2342 19200300 100 1 25 }
id_domainComponent = AttributeType((0, 9, 2342, 19200300, 100, 1, 25))

# DomainComponent ::=  IA5String
class DomainComponent(char.IA5String): pass


# -- Legacy attributes

# pkcs-9 OBJECT IDENTIFIER ::=
#        { iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) 9 }
pkcs9 = ID(1, 2, 840, 113549, 1, 9)

# id-emailAddress      AttributeType ::= { pkcs-9 1 }
id_emailAddress = AttributeType(TUP(pkcs9, 1))

# EmailAddress ::=     IA5String (SIZE (1..ub-emailaddress-length))
class EmailAddress(char.IA5String):
	subtypeSpec = char.IA5String.subtypeSpec + constraint.ValueSizeConstraint(1, ub_emailaddress_length)


# -- naming data types --

# RelativeDistinguishedName ::= SET SIZE (1..MAX) OF AttributeTypeAndValue
class RelativeDistinguishedName(univ.SetOf):
	componentType = AttributeTypeAndValue()
	subtypeSpec = univ.SetOf.subtypeSpec + constraint.ValueSizeConstraint(1, MAX)

# RDNSequence ::= SEQUENCE OF RelativeDistinguishedName
RDNSequence = SEQOF(RelativeDistinguishedName)

# Name ::= CHOICE { -- only one possibility for now --
#       rdnSequence  RDNSequence }
Name = CHOICE(TYPE('rdnSequence', RDNSequence))

# DistinguishedName ::=   RDNSequence
class DistinguishedName(RDNSequence): pass


# -- Directory string type --

# DirectoryString ::= CHOICE {
#       teletexString       TeletexString   (SIZE (1..MAX)),
#       printableString     PrintableString (SIZE (1..MAX)),
#       universalString     UniversalString (SIZE (1..MAX)),
#       utf8String          UTF8String      (SIZE (1..MAX)),
#       bmpString           BMPString       (SIZE (1..MAX)) }
DirectoryString = DIRSTR(1, MAX)


# -- Algorithm identifier type --

# AlgorithmIdentifier  ::=  SEQUENCE  {
#      algorithm               OBJECT IDENTIFIER,
#      parameters              ANY DEFINED BY algorithm OPTIONAL  }
#                                 -- contains a value of the type
#                                 -- registered for use with the
#                                 -- algorithm object identifier value
AlgorithmIdentifier = SEQ(TYPE('algorithm', univ.ObjectIdentifier),
						  TYPE('parameters', univ.Any, optional=True))


# -- certificate and CRL specific structures begin here

# Version  ::=  INTEGER  {  v1(0), v2(1), v3(2)  }
class Version(univ.Integer):
	namedValues = namedval.NamedValues(('v1', 0), ('v2', 1), ('v3', 2))

# CertificateSerialNumber  ::=  INTEGER
class CertificateSerialNumber(univ.Integer): pass

# Time ::= CHOICE {
#      utcTime        UTCTime,
#      generalTime    GeneralizedTime }
Time = CHOICE(TYPE('utcTime', useful.UTCTime),
			  TYPE('generalTime', useful.GeneralizedTime))

# Validity ::= SEQUENCE {
#      notBefore      Time,
#      notAfter       Time  }
Validity = SEQ(TYPE('notBefore', Time),
			   TYPE('notAfter', Time))

# UniqueIdentifier  ::=  BIT STRING
class UniqueIdentifier(univ.BitString): pass

# SubjectPublicKeyInfo  ::=  SEQUENCE  {
#      algorithm            AlgorithmIdentifier,
#      subjectPublicKey     BIT STRING  }
SubjectPublicKeyInfo = SEQ(TYPE('algorithm', AlgorithmIdentifier),
						   TYPE('subjectPublicKey', univ.BitString))

# Extension  ::=  SEQUENCE  {
#      extnID      OBJECT IDENTIFIER,
#      critical    BOOLEAN DEFAULT FALSE,
#      extnValue   OCTET STRING
#                  -- contains the DER encoding of an ASN.1 value
#                  -- corresponding to the extension type identified
#                  -- by extnID
#      }
Extension = SEQ(TYPE('extnId', univ.ObjectIdentifier),
				TYPE('critical', univ.Boolean, default=False),
				TYPE('extnValue', univ.OctetString))

# Extensions  ::=  SEQUENCE SIZE (1..MAX) OF Extension
Extensions = SEQOF(Extension)

# TBSCertificate  ::=  SEQUENCE  {
#      version         [0]  Version DEFAULT v1,
#      serialNumber         CertificateSerialNumber,
#      signature            AlgorithmIdentifier,
#      issuer               Name,
#      validity             Validity,
#      subject              Name,
#      subjectPublicKeyInfo SubjectPublicKeyInfo,
#      issuerUniqueID  [1]  IMPLICIT UniqueIdentifier OPTIONAL,
#                           -- If present, version MUST be v2 or v3
#      subjectUniqueID [2]  IMPLICIT UniqueIdentifier OPTIONAL,
#                           -- If present, version MUST be v2 or v3
#      extensions      [3]  Extensions OPTIONAL
#                           -- If present, version MUST be v3 --  }
TBSCertificate = SEQ(TYPE('version', Version, DEFAULT_TAG, default='v1'),
					 TYPE('serialNumber', CertificateSerialNumber),
					 TYPE('signature', AlgorithmIdentifier),
					 TYPE('issuer', Name),
					 TYPE('validity', Validity),
					 TYPE('subject', Name),
					 TYPE('subjectPublicKeyInfo', SubjectPublicKeyInfo),
					 TYPE('issuerUniqueID', UniqueIdentifier, False, 1, optional=True),
					 TYPE('subjectUniqueID', UniqueIdentifier, False, 2, optional=True),
					 TYPE('extensions', Extensions, False, 3))

# Certificate  ::=  SEQUENCE  {
#      tbsCertificate       TBSCertificate,
#      signatureAlgorithm   AlgorithmIdentifier,
#      signature            BIT STRING  }
Certificate = SEQ(TYPE('tbsCertificate', TBSCertificate),
				  TYPE('signatureAlgorithm', AlgorithmIdentifier),
				  TYPE('signature', univ.BitString))


# -- CRL structures

# TBSCertList  ::=  SEQUENCE  {
#      version                 Version OPTIONAL,
#                                    -- if present, MUST be v2
#      signature               AlgorithmIdentifier,
#      issuer                  Name,
#      thisUpdate              Time,
#      nextUpdate              Time OPTIONAL,
#      revokedCertificates     SEQUENCE OF SEQUENCE  {
#           userCertificate         CertificateSerialNumber,
#           revocationDate          Time,
#           crlEntryExtensions      Extensions OPTIONAL
#                                    -- if present, version MUST be v2
#                                }  OPTIONAL,
#      crlExtensions           [0] Extensions OPTIONAL }
#                                    -- if present, version MUST be v2
# 
# -- Version, Time, CertificateSerialNumber, and Extensions were
# -- defined earlier for use in the certificate structure
TBSCertList = SEQ(TYPE('version', Version, optional=True),
				  TYPE('signature', AlgorithmIdentifier),
				  TYPE('issuer', Name),
				  TYPE('thisUpdate', Time),
				  TYPE('nextUpdate', Time, optional=True),
				  TYPE('revokedCertificates', SEQOF(SEQ(TYPE('userCertificate', CertificateSerialNumber),
														TYPE('revocationDate', Time),
														TYPE('crlEntryExtensions', Extensions, optional=True))),
											  optional=True),
				  TYPE('crlExtensions', Extensions, DEFAULT_TAG, optional=True))

# CertificateList  ::=  SEQUENCE  {
#      tbsCertList          TBSCertList,
#      signatureAlgorithm   AlgorithmIdentifier,
#      signature            BIT STRING  }
CertificateList = SEQ(TYPE('tbsCertList', TBSCertList),
					  TYPE('signatureAlgorithm', AlgorithmIdentifier),
					  TYPE('signature', univ.BitString))


# -- X.400 address syntax starts here

# -- Built-in Standard Attributes

# CountryName ::= [APPLICATION 1] CHOICE {
#    x121-dcc-code         NumericString
#                            (SIZE (ub-country-name-numeric-length)),
#    iso-3166-alpha2-code  PrintableString
#                            (SIZE (ub-country-name-alpha-length)) }
class CountryName(univ.Choice):
	tagSet = TAG(univ.Choice.tagSet)(tag.Tag(tag.tagClassApplication, tag.tagFormatConstructed, 1))
	componentType = namedtype.NamedTypes(TYPE('x121-dcc-code', char.NumericString,
											  constraint=constraint.ValueSizeConstraint(ub_country_name_numeric_length,
																						 ub_country_name_numeric_length)),
										 TYPE('iso-3166-alpha2-code', char.PrintableString,
											  constraint=constraint.ValueSizeConstraint(ub_country_name_alpha_length,
																						 ub_country_name_alpha_length)))

# AdministrationDomainName ::= [APPLICATION 2] CHOICE {
#    numeric   NumericString   (SIZE (0..ub-domain-name-length)),
#    printable PrintableString (SIZE (0..ub-domain-name-length)) }
_AdminDomainConstraint = constraint.ValueSizeConstraint(0, ub_domain_name_length)
class AdministrationDomainName(univ.Choice):
	tagSet = TAG(univ.Choice.tagSet)(tag.Tag(tag.tagClassApplication, tag.tagFormatConstructed, 2))
	componentType = namedtype.NamedTypes(TYPE('numeric', char.NumericString, constraint=_AdminDomainConstraint),
										 TYPE('printable', char.PrintableString,  constraint=_AdminDomainConstraint))

# X121Address ::= NumericString (SIZE (1..ub-x121-address-length))
class X121Address(char.NumericString):
	subtypeSpec = char.NumericString.subtypeSpec + constraint.ValueSizeConstraint(1, ub_x121_address_length)

# NetworkAddress ::= X121Address  -- see also extended-network-address
class NetworkAddress(X121Address): pass

# TerminalIdentifier ::= PrintableString (SIZE (1..ub-terminal-id-length))
class TerminalIdentifier(char.PrintableString):
	subtypeSpec = char.PrintableString.subtypeSpec + constraint.ValueSizeConstraint(1, ub_terminal_id_length)

# PrivateDomainName ::= CHOICE {
#    numeric   NumericString   (SIZE (1..ub-domain-name-length)),
#    printable PrintableString (SIZE (1..ub-domain-name-length)) }
_PrivateDomainConstraint = constraint.ValueSizeConstraint(1, ub_domain_name_length)
PrivateDomainName = CHOICE(TYPE('numeric', char.NumericString, constraint=_PrivateDomainConstraint),
						   TYPE('printable', char.PrintableString,  constraint=_PrivateDomainConstraint))

# OrganizationName ::= PrintableString
#                             (SIZE (1..ub-organization-name-length))
#   -- see also teletex-organization-name
class OrganizationName(char.PrintableString):
	subtypeSpec = char.PrintableString.subtypeSpec + constraint.ValueSizeConstraint(1, ub_organization_name_length)

# NumericUserIdentifier ::= NumericString
#                             (SIZE (1..ub-numeric-user-id-length))
class NumericUserIdentifier(char.NumericString):
	subtypeSpec = char.NumericString.subtypeSpec + constraint.ValueSizeConstraint(1, ub_numeric_user_id_length)

# PersonalName ::= SET {
#    surname     [0] IMPLICIT PrintableString
#                     (SIZE (1..ub-surname-length)),
#    given-name  [1] IMPLICIT PrintableString
#                     (SIZE (1..ub-given-name-length)) OPTIONAL,
#    initials    [2] IMPLICIT PrintableString
#                     (SIZE (1..ub-initials-length)) OPTIONAL,
#    generation-qualifier [3] IMPLICIT PrintableString
#                     (SIZE (1..ub-generation-qualifier-length))
#                     OPTIONAL }
#   -- see also teletex-personal-name
PersonalName = SET(TYPE('surname', char.PrintableString, False,
						constraint=constraint.ValueSizeConstraint(1, ub_surname_length)),
				   TYPE('given-name', char.PrintableString, False, 1, optional=True,
						constraint=constraint.ValueSizeConstraint(1, ub_given_name_length)),
				   TYPE('initials', char.PrintableString, False, 2, optional=True,
						constraint=constraint.ValueSizeConstraint(1, ub_initials_length)),
				   TYPE('generation-qualifier', char.PrintableString, False, 3, optional=True,
						constraint=constraint.ValueSizeConstraint(1, ub_generation_qualifier_length)))

# OrganizationalUnitName ::= PrintableString (SIZE
#                     (1..ub-organizational-unit-name-length))
class OrganizationalUnitName(char.PrintableString):
	subtypeSpec = char.PrintableString.subtypeSpec + constraint.ValueSizeConstraint(1, ub_organizational_unit_name_length)

# OrganizationalUnitNames ::= SEQUENCE SIZE (1..ub-organizational-units)
#                              OF OrganizationalUnitName
#   -- see also teletex-organizational-unit-names
class OrganizationalUnitNames(univ.SequenceOf):
	componentType = OrganizationalUnitName()
	subtypeSpec = univ.SequenceOf.subtypeSpec + constraint.ValueSizeConstraint(1, ub_organizational_units)

# BuiltInStandardAttributes ::= SEQUENCE {
#    country-name                  CountryName OPTIONAL,
#    administration-domain-name    AdministrationDomainName OPTIONAL,
#    network-address           [0] IMPLICIT NetworkAddress OPTIONAL,
#      -- see also extended-network-address
#    terminal-identifier       [1] IMPLICIT TerminalIdentifier OPTIONAL,
#    private-domain-name       [2] PrivateDomainName OPTIONAL,
#    organization-name         [3] IMPLICIT OrganizationName OPTIONAL,
#      -- see also teletex-organization-name
#    numeric-user-identifier   [4] IMPLICIT NumericUserIdentifier
#                                  OPTIONAL,
#    personal-name             [5] IMPLICIT PersonalName OPTIONAL,
#      -- see also teletex-personal-name
#    organizational-unit-names [6] IMPLICIT OrganizationalUnitNames
#                                  OPTIONAL }
#      -- see also teletex-organizational-unit-names
BuiltInStandardAttributes = SEQ(TYPE('country-name', CountryName, optional=True),
								TYPE('administration-domain-name', AdministrationDomainName, optional=True),
								TYPE('network-address', NetworkAddress, False, optional=True),
								TYPE('terminal-identifier', TerminalIdentifier, False, 1, optional=True),
								TYPE('private-domain-name', PrivateDomainName, False, 2, optional=True),
								TYPE('organization-name', OrganizationName, False, 3, optional=True),
								TYPE('numeric-use-identifier', NumericUserIdentifier, False, 4, optional=True),
								TYPE('personal-name', PersonalName, False, 5, optional=True),
								TYPE('organizational-unit-names', OrganizationalUnitNames, False, 6, optional=True))


# -- Built-in Domain-defined Attributes

# BuiltInDomainDefinedAttribute ::= SEQUENCE {
#    type PrintableString (SIZE
#                    (1..ub-domain-defined-attribute-type-length)),
#    value PrintableString (SIZE
#                    (1..ub-domain-defined-attribute-value-length)) }
BuiltInDomainDefinedAttribute = SEQ(TYPE('type', char.PrintableString,
										 constraint=constraint.ValueSizeConstraint(1, ub_domain_defined_attribute_type_length)),
									TYPE('value', char.PrintableString,
										 constraint=constraint.ValueSizeConstraint(1, ub_domain_defined_attribute_value_length)))

# BuiltInDomainDefinedAttributes ::= SEQUENCE SIZE
#                     (1..ub-domain-defined-attributes) OF
#                     BuiltInDomainDefinedAttribute
class BuiltInDomainDefinedAttributes(univ.SequenceOf):
	componentType = BuiltInDomainDefinedAttribute()
	subtypeSpec = univ.SequenceOf.subtypeSpec + constraint.ValueSizeConstraint(1, ub_domain_defined_attributes)


# -- Extension Attributes

# ExtensionAttribute ::=  SEQUENCE {
#    extension-attribute-type [0] IMPLICIT INTEGER
#                    (0..ub-extension-attributes),
#    extension-attribute-value [1]
#                    ANY DEFINED BY extension-attribute-type }
ExtensionAttribute = SEQ(TYPE('extension-attribute-type', univ.Integer, False,
							  constraint=constraint.ValueSizeConstraint(0, ub_extension_attributes)),
						 TYPE('extension-attribute-value', univ.Any, DEFAULT_TAG, 1))

# ExtensionAttributes ::= SET SIZE (1..ub-extension-attributes) OF
#                ExtensionAttribute
class ExtensionAttributes(univ.SetOf):
	componentType = ExtensionAttribute()
	subtypeSpec = univ.SetOf.subtypeSpec + constraint.ValueSizeConstraint(1, ub_extension_attributes)


# -- ORAddress type --

# ORAddress ::= SEQUENCE {
#    built-in-standard-attributes BuiltInStandardAttributes,
#    built-in-domain-defined-attributes
#                    BuiltInDomainDefinedAttributes OPTIONAL,
#    -- see also teletex-domain-defined-attributes
#    extension-attributes ExtensionAttributes OPTIONAL }
ORAddress = SEQ(TYPE('built-in-standard-attributes', BuiltInStandardAttributes),
				TYPE('build-in-domain-defined-attributes', BuiltInDomainDefinedAttributes, optional=True),
				TYPE('extension-attributes', ExtensionAttributes, optional=True))


# -- Extension types and attribute values

# common-name INTEGER ::= 1
common_name = univ.Integer(1)

# CommonName ::= PrintableString (SIZE (1..ub-common-name-length))
class CommonName(char.PrintableString):
	subtypeSpec = char.PrintableString.subtypeSpec + constraint.ValueSizeConstraint(1, ub_common_name_length)

# teletex-common-name INTEGER ::= 2
teletex_common_name = univ.Integer(2)

# TeletexCommonName ::= TeletexString (SIZE (1..ub-common-name-length))
class TeletexCommonName(char.TeletexString):
	subtypeSpec = char.TeletexString.subtypeSpec + constraint.ValueSizeConstraint(1, ub_common_name_length)

# teletex-organization-name INTEGER ::= 3
teletex_organization_name = univ.Integer(3)

# TeletexOrganizationName ::=
#                 TeletexString (SIZE (1..ub-organization-name-length))
class TeletexOrganizationName(char.TeletexString):
	subtypeSpec = char.TeletexString.subtypeSpec + constraint.ValueSizeConstraint(1, ub_organization_name_length)

# teletex-personal-name INTEGER ::= 4
teletex_personal_name = univ.Integer(4)

# TeletexPersonalName ::= SET {
#    surname     [0] IMPLICIT TeletexString
#                     (SIZE (1..ub-surname-length)),
#    given-name  [1] IMPLICIT TeletexString
#                     (SIZE (1..ub-given-name-length)) OPTIONAL,
#    initials    [2] IMPLICIT TeletexString
#                     (SIZE (1..ub-initials-length)) OPTIONAL,
#    generation-qualifier [3] IMPLICIT TeletexString
#                     (SIZE (1..ub-generation-qualifier-length))
#                     OPTIONAL }
TeletexPersonalName = SET(TYPE('surname', char.TeletexString, False,
							   constraint=constraint.ValueSizeConstraint(1, ub_surname_length)),
						  TYPE('given-name', char.TeletexString, False, 1, optional=True,
							   constraint=constraint.ValueSizeConstraint(1, ub_given_name_length)),
				 		  TYPE('initials', char.TeletexString, False, 2, optional=True,
							   constraint=constraint.ValueSizeConstraint(1, ub_initials_length)),
						  TYPE('generation-qualifier', char.TeletexString, False, 3, optional=True,
							   constraint=constraint.ValueSizeConstraint(1, ub_generation_qualifier_length)))

# teletex-organizational-unit-names INTEGER ::= 5
teletex_organizational_unit_names = univ.Integer(5)

# TeletexOrganizationalUnitName ::= TeletexString
#                   (SIZE (1..ub-organizational-unit-name-length))
class TeletexOrganizationalUnitName(char.TeletexString):
	subtypeSpec = char.TeletexString.subtypeSpec + constraint.ValueSizeConstraint(1, ub_organizational_unit_name_length)

# TeletexOrganizationalUnitNames ::= SEQUENCE SIZE
#       (1..ub-organizational-units) OF TeletexOrganizationalUnitName
class TeletexOrganizationUnitNames(univ.SequenceOf):
	componentType = TeletexOrganizationalUnitName()
	subtypeSpec = univ.SequenceOf.subtypeSpec + constraint.ValueSizeConstraint(1, ub_organizational_units)

# pds-name INTEGER ::= 7
pds_name = univ.Integer(7)

# PDSName ::= PrintableString (SIZE (1..ub-pds-name-length))
class PDSName(char.PrintableString):
	subtypeSpec = char.PrintableString.subtypeSpec + constraint.ValueSizeConstraint(1, ub_pds_name_length)

# physical-delivery-country-name INTEGER ::= 8
physical_delivery_country_name = univ.Integer(8)

# PhysicalDeliveryCountryName ::= CHOICE {
#    x121-dcc-code NumericString (SIZE (ub-country-name-numeric-length)),
#    iso-3166-alpha2-code PrintableString
#                                (SIZE (ub-country-name-alpha-length)) }
PhysicalDeliveryCountryName = CHOICE(TYPE('x121-dcc-code', char.NumericString,
											  constraint=constraint.ValueSizeConstraint(ub_country_name_numeric_length,
																						 ub_country_name_numeric_length)),
									 TYPE('iso-3166-alpha2-code', char.PrintableString,
											  constraint=constraint.ValueSizeConstraint(ub_country_name_alpha_length,
																						 ub_country_name_alpha_length)))

# postal-code INTEGER ::= 9
postal_code = univ.Integer(9)

# PostalCode ::= CHOICE {
#    numeric-code   NumericString (SIZE (1..ub-postal-code-length)),
#    printable-code PrintableString (SIZE (1..ub-postal-code-length)) }
_PostalCodeConstraint = constraint.ValueSizeConstraint(1, ub_postal_code_length)
PostalCode = CHOICE(TYPE('numeric-code', char.NumericString, constraint=_PostalCodeConstraint),
					TYPE('printable-code', char.PrintableString, constraint=_PostalCodeConstraint))

# PDSParameter ::= SET {
#    printable-string PrintableString
#                 (SIZE(1..ub-pds-parameter-length)) OPTIONAL,
#    teletex-string TeletexString
#                 (SIZE(1..ub-pds-parameter-length)) OPTIONAL }
_PDSParameterConstraint = constraint.ValueSizeConstraint(1, ub_pds_parameter_length)
PDSParameter = SET(TYPE('printable-string', char.PrintableString, optional=True, constraint=_PDSParameterConstraint),
				   TYPE('teletex-string', char.TeletexString, optional=True, constraint=_PDSParameterConstraint))

# physical-delivery-office-name INTEGER ::= 10
physical_delivery_office_name = univ.Integer(10)

# PhysicalDeliveryOfficeName ::= PDSParameter
class PhysicalDeliveryOfficeName(PDSParameter): pass

# physical-delivery-office-number INTEGER ::= 11
physical_delivery_office_number = univ.Integer(11)

# PhysicalDeliveryOfficeNumber ::= PDSParameter
class PhysicalDeliveryOfficeNumber(PDSParameter): pass

# extension-OR-address-components INTEGER ::= 12
extension_OR_address_components = univ.Integer(12)

# ExtensionORAddressComponents ::= PDSParameter
class ExtensionORAddressComponents(PDSParameter): pass

# physical-delivery-personal-name INTEGER ::= 13
physical_delivery_personal_name = univ.Integer(13)

# PhysicalDeliveryPersonalName ::= PDSParameter
class PhysicalDeliveryPersonalName(PDSParameter): pass

# physical-delivery-organization-name INTEGER ::= 14
physical_delivery_organization_name = univ.Integer(14)

# PhysicalDeliveryOrganizationName ::= PDSParameter
class PhysicalDeliveryOrganizationName(PDSParameter): pass

# extension-physical-delivery-address-components INTEGER ::= 15
extension_physical_delivery_address_components = univ.Integer(15)

# ExtensionPhysicalDeliveryAddressComponents ::= PDSParameter
class ExtensionPhysicalDeliveryAddressComponents(PDSParameter): pass

# unformatted-postal-address INTEGER ::= 16
unformatted_postal_address = univ.Integer(16)

# UnformattedPostalAddress ::= SET {
#    printable-address SEQUENCE SIZE (1..ub-pds-physical-address-lines)
#         OF PrintableString (SIZE (1..ub-pds-parameter-length)) OPTIONAL,
#    teletex-string TeletexString
#         (SIZE (1..ub-unformatted-address-length)) OPTIONAL }
UnformattedPostalAddress = SET(TYPE('printable-address',
									SEQOF(char.PrintableString,
										  constraint.ValueSizeConstraint(1, ub_pds_parameter_length)),
									optional=True,
									constraint=constraint.ValueSizeConstraint(1, ub_pds_physical_address_lines)),
							   TYPE('teletex-string', char.TeletexString, optional=True,
									constraint=constraint.ValueSizeConstraint(1, ub_unformatted_address_length)))

# street-address INTEGER ::= 17
street_address = univ.Integer(17)

# StreetAddress ::= PDSParameter
class StreetAddress(PDSParameter): pass

# post-office-box-address INTEGER ::= 18
post_office_box_address = univ.Integer(18)

# PostOfficeBoxAddress ::= PDSParameter
class PostOfficeBoxAddress(PDSParameter): pass

# poste-restante-address INTEGER ::= 19
poste_restante_address = univ.Integer(19)

# PosteRestanteAddress ::= PDSParameter
class PosteRestanteAddress(PDSParameter): pass

# unique-postal-name INTEGER ::= 20
unique_postal_name = univ.Integer(20)

# UniquePostalName ::= PDSParameter
class UniquePostalName(PDSParameter): pass

# local-postal-attributes INTEGER ::= 21
local_post_attributes = univ.Integer(21)

# LocalPostalAttributes ::= PDSParameter
class LocalPostAttributes(PDSParameter): pass

# PresentationAddress ::= SEQUENCE {
#     pSelector     [0] EXPLICIT OCTET STRING OPTIONAL,
#     sSelector     [1] EXPLICIT OCTET STRING OPTIONAL,
#     tSelector     [2] EXPLICIT OCTET STRING OPTIONAL,
#     nAddresses    [3] EXPLICIT SET SIZE (1..MAX) OF OCTET STRING }
PresentationAddress = SEQ(TYPE('pSelector', univ.OctetString, True, optional=True),
						  TYPE('sSelector', univ.OctetString, True, 1, optional=True),
						  TYPE('tSelector', univ.OctetString, True, 2, optional=True),
						  TYPE('nAddresses', SETOF(univ.OctetString, constraint.ValueSizeConstraint(1, MAX)), False, 3))

# extended-network-address INTEGER ::= 22
extended_network_address = univ.Integer(22)

# ExtendedNetworkAddress ::= CHOICE {
#    e163-4-address SEQUENCE {
#       number      [0] IMPLICIT NumericString
#                        (SIZE (1..ub-e163-4-number-length)),
#       sub-address [1] IMPLICIT NumericString
#                        (SIZE (1..ub-e163-4-sub-address-length))
#                        OPTIONAL },
#    psap-address   [0] IMPLICIT PresentationAddress }
ExtendedNetworkAddress = CHOICE(TYPE('e163-4-address', SEQ(TYPE('number', char.NumericString, False, 0,
																constraint=constraint.ValueSizeConstraint(
																				1, ub_e163_4_number_length)),
														   TYPE('sub-address', char.NumericString, False, 1, optional=True,
																constraint=constraint.ValueSizeConstraint(
																				1, ub_e163_4_sub_address_length)))),
								TYPE('psap-address', PresentationAddress, False, 0))

# terminal-type  INTEGER ::= 23
terminal_type = univ.Integer(23)

# TerminalType ::= INTEGER {
#    telex        (3),
#    teletex      (4),
#    g3-facsimile (5),
#    g4-facsimile (6),
#    ia5-terminal (7),
#    videotex     (8) } (0..ub-integer-options)
class TerminalType(univ.Integer):
	namedValues = namedval.NamedValues(('telex', 3), ('teletex', 4), ('g3-facsimile', 5),
									   ('g4-facsimile', 6), ('ia5-terminal', 7), ('videotex', 8))
	subtypeSpec = univ.Integer.subtypeSpec + constraint.ValueRangeConstraint(0, ub_integer_options)


# -- Extension Domain-defined Attributes

# teletex-domain-defined-attributes INTEGER ::= 6
teletex_domain_defined_attributes = univ.Integer(6)

# TeletexDomainDefinedAttribute ::= SEQUENCE {
#         type TeletexString
#                (SIZE (1..ub-domain-defined-attribute-type-length)),
#         value TeletexString
#                (SIZE (1..ub-domain-defined-attribute-value-length)) }
TeletexDomainDefinedAttribute = SEQ(TYPE('type', char.TeletexString,
										 constraint=constraint.ValueSizeConstraint(1, ub_domain_defined_attribute_type_length)),
									TYPE('value', char.TeletexString,
										 constraint=constraint.ValueSizeConstraint(1, ub_domain_defined_attribute_value_length)))

# TeletexDomainDefinedAttributes ::= SEQUENCE SIZE
#    (1..ub-domain-defined-attributes) OF TeletexDomainDefinedAttribute
class TeletexDomainDefinedAttributes(univ.SequenceOf):
	componentType = TeletexDomainDefinedAttribute()
	subtypeSpec = univ.SequenceOf.subtypeSpec + constraint.ValueSizeConstraint(1, ub_domain_defined_attributes)

# END

