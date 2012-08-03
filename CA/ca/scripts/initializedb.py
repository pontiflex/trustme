from ca.models import DBSession, Base

from ca.security.authn import user
from ca.security.authz import access, action, capability, constraint
from ca.security.authz.fields import *
from ca.security.authz.actions import *

from sqlalchemy import engine_from_config

from pyramid.paster import get_appsettings, setup_logging

import os
import sys
import transaction


def usage(argv):
	cmd = os.path.basename(argv[0])
	print('usage: %s <config_uri>\n'
		  '(example: "%s development.ini")' % (cmd, cmd)) 
	sys.exit(1)

def main(argv=sys.argv):
	if len(argv) != 2:
		usage(argv)
	config_uri = argv[1]
	setup_logging(config_uri)
	settings = get_appsettings(config_uri)
	engine = engine_from_config(settings, 'sqlalchemy.')
	DBSession.configure(bind=engine)
	Base.metadata.create_all(engine)
	with transaction.manager:
		pass

