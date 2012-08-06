from ca.security.algorithms import size64, rand64
from ca.security.authz.access import Access
from ca.security.authz.action import Action

from ca.security.authz.fields.int_ import IntField
from ca.security.authz.fields.str_ import StrField

from ca.security.parsers.openssl import RawInput
from ca.security.parsers.pkcs10_req import PKCS10Request

from ca.models import DBSession

from pyramid.httpexceptions import HTTPBadRequest, HTTPNotFound
from pyramid.response import Response
from pyramid.view import view_config

from sqlalchemy import Column, ForeignKey, Integer, Text
from sqlalchemy import not_


POLY_ID = 'certify'


@view_config(route_name='check_cert')
def check_cert(request):
	if 'serial' in request.POST:
		serial = request.POST['serial'].replace(' ', '+')
		req = (DBSession.query(Certify)
				.filter(Certify.serial == serial)
				.first())
		if req is None:
			raise HTTPNotFound('Invalid serial number')
		if Access.processed(req):
			return Response(req.cert)
		if Access.processed(req, False):
			return Response('Denied')
		if Access.filtered(req):
			return Response('Pending')
		return Response('Rejected')
	return Response('<html><head></head><body><form method="post"><input type="text" name="serial"></input><input type="submit" value="Check" /></form></body></html>')

@view_config(route_name='certify', renderer='ca:templates/security/authz/actions/certify.pt')
def certify(request):
	csr_field = 'csr'
	if csr_field in request.POST:
		try:
			csr = Certify(request.POST[csr_field])
		except ValueError as e:
			raise HTTPBadRequest(e.args[0])
		return Access(request).perform(csr)

	caps, actions = Access.allowable(request, POLY_ID)
	return dict(csr_field=csr_field)

class Certify(Action):
	__tablename__ = 'certification_requests'
	__mapper_args__ = {'polymorphic_identity':POLY_ID}
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

		self.fields.append(IntField(self, 'version', req.version))
		self.fields.extend((StrField(self, 'name.%s' % n, v)
							for n,v in req.name.iteritems()))
		self.fields.append(StrField(self, 'keyAlgorithm', req.key_alg))
		self.fields.append(StrField(self, 'signatureAlgorithm', req.sig_alg))

	def perform(self):
		self.cert = 'TODO: Sign cert<br>%s' % self.serial
		return Response(self.cert)

	

