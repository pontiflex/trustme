from shorthand import MAX, TYPE, SEQ, SET, SEQOF, SETOF, CHOICE

from pyasn1.type import univ, namedval


# FROM RFC 5652 (http://tools.ietf.org/html/rfc5652)

"""AttributeCertificateVersion1
     { iso(1) member-body(2) us(840) rsadsi(113549)
       pkcs(1) pkcs-9(9) smime(16) modules(0) v1AttrCert(15) }

   DEFINITIONS EXPLICIT TAGS ::=
   BEGIN

   -- EXPORTS All

   IMPORTS

     -- Imports from RFC 5280 [PROFILE], Appendix A.1
           AlgorithmIdentifier, Attribute, CertificateSerialNumber,
           Extensions, UniqueIdentifier
              FROM PKIX1Explicit88
                   { iso(1) identified-organization(3) dod(6)
                     internet(1) security(5) mechanisms(5) pkix(7)
                     mod(0) pkix1-explicit(18) }

     -- Imports from RFC 5280 [PROFILE], Appendix A.2
           GeneralNames
              FROM PKIX1Implicit88
                   { iso(1) identified-organization(3) dod(6)
                     internet(1) security(5) mechanisms(5) pkix(7)
                     mod(0) pkix1-implicit(19) }

     -- Imports from RFC 3281 [ACPROFILE], Appendix B
           AttCertValidityPeriod, IssuerSerial
              FROM PKIXAttributeCertificate
                   { iso(1) identified-organization(3) dod(6)
                     internet(1) security(5) mechanisms(5) pkix(7)
                     mod(0) attribute-cert(12) } ;

   -- Definition extracted from X.509-1997 [X.509-97], but
   -- different type names are used to avoid collisions."""

from rfc5280_explicit import ( AlgorithmIdentifier, Attribute, 
							   CertificateSerialNumber, Extensions,
							   UniqueIdentifier )

from rfc5280_implicit import GeneralNames

# Resolve circular import (use RFC5755, which obsoletes RFC3281)
import rfc5755_attr_cert_2008
AttCertValidityPeriod = rfc5755_attr_cert_2008.AttCertValidityPeriod
IssuerSerial = rfc5755_attr_cert_2008.IssuerSerial

DEFAULT_TAG = True


# AttCertVersionV1 ::= INTEGER { v1(0) }
class AttCertVersionV1(univ.Integer):
	namedValues = namedval.NamedValues(('v1', 0))

# AttributeCertificateInfoV1 ::= SEQUENCE {
#   version AttCertVersionV1 DEFAULT v1,
#   subject CHOICE {
#     baseCertificateID [0] IssuerSerial,
#       -- associated with a Public Key Certificate
#     subjectName [1] GeneralNames },
#       -- associated with a name
#   issuer GeneralNames,
#   signature AlgorithmIdentifier,
#   serialNumber CertificateSerialNumber,
#   attCertValidityPeriod AttCertValidityPeriod,
#   attributes SEQUENCE OF Attribute,
#   issuerUniqueID UniqueIdentifier OPTIONAL,
#   extensions Extensions OPTIONAL }
AttributeCertificateInfoV1 = SEQ(TYPE('version', AttCertVersionV1('v1')),
								 TYPE('subject', CHOICE(TYPE('baseCertificateID', IssuerSerial, DEFAULT_TAG),
														TYPE('subjectName', GeneralNames, DEFAULT_TAG, 1))),
								 TYPE('issuer', GeneralNames),
								 TYPE('signature', AlgorithmIdentifier),
								 TYPE('serialNumber', CertificateSerialNumber),
								 TYPE('attCertValidityPeriod', AttCertValidityPeriod),
								 TYPE('attributes', SEQOF(Attribute)),
								 TYPE('issuerUniqueID', UniqueIdentifier, optional=True),
								 TYPE('extensions', Extensions, optional=True))

# AttributeCertificateV1 ::= SEQUENCE {
#   acInfo AttributeCertificateInfoV1,
#   signatureAlgorithm AlgorithmIdentifier,
#   signature BIT STRING }
AttributeCertificateV1 = SEQ(TYPE('acInfo', AttributeCertificateInfoV1),
							 TYPE('signatureAlgorithm', AlgorithmIdentifier),
							 TYPE('signature', univ.BitString))

# END -- of AttributeCertificateVersion1
