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

@view_config(route_name='certify')
def certify(request):		
	if 'csr' in request.POST:
		csr = Certify(request.POST['csr'])
		try:
			return Response(str(Access(request).perform(csr)))
		except ValueError as e:
			raise HTTPBadRequest(e.args[0])
	return Response('<html><head></head><body><form method="post"><textarea name="csr"></textarea><input type="submit" value="Request" /></form></body></html>')

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
			req = PKCS10Request(path)
			if not req.valid:
				raise ValueError('Error parsing CSR')

		self.fields.append(IntField(self, 'version', req.version))
		self.fields.extend((StrField(self, 'name.%s' % n, v)
							for n,v in req.name.iteritems()))
		self.fields.append(StrField(self, 'keyAlgorithm', req.key_alg))
		self.fields.append(StrField(self, 'signatureAlgorithm', req.sig_alg))

	def perform(self):
		self.cert = 'TODO: Sign cert<br>%s' % self.serial
		return self.cert

	

