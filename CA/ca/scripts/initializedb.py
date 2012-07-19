from ..models import DBSession, Base

from ..security.user import User
from ..security.capability import AccessCapability
from ..security import access, action, constraint
from ..security.fields import int_, str_

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
		user = User('root', 'test@example.com', 'thispasswordsucks')
		DBSession.add(user)
		DBSession.add(AccessCapability(user, 'foo', 'request'))
		DBSession.add(AccessCapability(user, 'foo', 'accept'))
