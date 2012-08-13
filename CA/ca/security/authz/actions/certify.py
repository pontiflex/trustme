from ca.security.authz.access import Access
from ca.security.authz.action import Action
from ca.security.authz.policy import offer_creds

from ca.security.parsers.openssl import invoke, RawInput
from ca.security.parsers.pkcs10_req import PKCS10Request

from ca.security.ui.check import check_page
from ca.security.ui.review import review_page

from ca.models import DBSession

from pyramid.httpexceptions import HTTPBadRequest, HTTPNotFound
from pyramid.response import Response
from pyramid.view import view_config

from sqlalchemy import Column, ForeignKey, Integer, Text
from sqlalchemy import not_


REQUEST_TEMPLATE = 'ca:templates/security/authz/actions/certify.pt'
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

	def perform(self):
		self.cert = 'TODO: Sign cert<br>%s' % self.serial
		return Response(self.cert)


@view_config(route_name='check', match_param=MATCH, renderer=CHECK_TEMPLATE)
def check_csr(request):
	return check_page(request, Certify, type='Certification')

@view_config(route_name='review', match_param=MATCH, renderer=REVIEW_TEMPLATE)
def approve_csr(request):
	return review_page(request, Certify, type='Certification')


@view_config(route_name='request', match_param=MATCH, renderer=REQUEST_TEMPLATE)
def certify(request):
	csr_field = 'csr'
	csr_text = ''
	if csr_field in request.POST:
		try:
			csr_text = request.POST[csr_field]
			csr = Certify(csr_text)
		except ValueError as e:
			raise HTTPBadRequest(e.args[0])
		return Access(request).perform(csr)

	return dict(csr_field=csr_field, csr=csr_text, credentials=offer_creds(request))

