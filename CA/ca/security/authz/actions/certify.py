from ca.security.authz.access import Access
from ca.security.authz.action import Action
from ca.security.authz.policy import offer_creds

from ca.security.authority.openssl import invoke, RawInput, OpenSSLError
from ca.security.authority.secrets import Secrets
from ca.security.authority.pkcs10_req import PKCS10Request

from ca.security.ui.check import check_page
from ca.security.ui.review import review_page

from ca.models import DBSession

from pyramid.httpexceptions import HTTPBadRequest, HTTPNotFound
from pyramid.response import Response
from pyramid.view import view_config

from sqlalchemy import Column, ForeignKey, Integer, Text
from sqlalchemy import not_

from base64 import b64decode


REQUEST_TEMPLATE = 'ca:templates/security/ui/request/certify.pt'
CHECK_TEMPLATE = 'ca:templates/security/ui/check/default.pt'
REVIEW_TEMPLATE = 'ca:templates/security/ui/review/default.pt'
MATCH = 'type=%s' % 'certify'


class Certify(Action):
	__tablename__ = 'certification_requests'
	__mapper_args__ = {'polymorphic_identity':'certify'}
	id = Column(Integer, ForeignKey(Action.id), primary_key=True)
	csr = Column(Text, nullable=False)
	cert = Column(Text)

	def __init__(self, data, *args, **kwargs):
		super(Certify, self).__init__()
		self.csr = data
		self.cert = None

		with RawInput(data) as path:
			req = PKCS10Request(path, *args, **kwargs)
			if not req.valid:
				raise ValueError('Error parsing CSR')

		"""self.fields.append(IntField(self, 'version', req.version))
		self.fields.extend((StrField(self, 'name.%s' % n, v)
							for n,v in req.name.iteritems()))
		self.fields.append(StrField(self, 'keyAlgorithm', req.key_alg))
		self.fields.append(StrField(self, 'signatureAlgorithm', req.sig_alg))"""

	@classmethod
	def readable(cls):
		return 'certification'

	def perform(self, request):
		print request.registry.settings
		secrets = Secrets.from_request(request)
		serial = b64decode(self.serial).encode('hex')
		with RawInput(self.csr) as inFile:
			with RawInput(serial) as sFile:				
				with RawInput(secrets.cert) as certFile:
					with RawInput(secrets.key) as keyFile:
						with invoke('x509', inFile, 'req', days=365,
									CAserial=sFile, CA=certFile, CAkey=keyFile) as (out, err):
							self.cert = out.read().replace('\r', '\n').replace('\n\n', '\n')
		return self.cert


@view_config(route_name='check', match_param=MATCH, renderer=CHECK_TEMPLATE)
def check_csr(request):
	return check_page(request, Certify, type='Certification')

@view_config(route_name='review', match_param=MATCH, renderer=REVIEW_TEMPLATE)
def approve_csr(request):
	return review_page(request, Certify, type='Certification')


@view_config(route_name='request', match_param=MATCH, renderer=REQUEST_TEMPLATE)
def certify(request):
	csr_field = 'csr'
	submitted = 'csr.submitted'
	csr_text, message = '', ''
	if csr_field in request.POST:
		try:
			csr_text = request.POST[csr_field]
			csr = Certify(csr_text)
		except ValueError as e:
			if submitted not in request.POST:
				raise HTTPBadRequest(e.args[0])
			message = e.args[0]
		if not message:
			return Response(Access(request).perform(csr))

	return dict(
				csr_field=csr_field,
				csr=csr_text,
				submitted=submitted,
				message=message,
				credentials=offer_creds(request),
			)

