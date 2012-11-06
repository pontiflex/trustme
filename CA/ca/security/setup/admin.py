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

from ca.security.authz.capability import (
		AdminCapability,
		GrantCapability,
	)
from ca.security.authz.actions.newuser import NewUser
from ca.security.authz.constraint import AndBaseConstraint
from ca.security.authz.access import FILTER as FILTER_ACCESS, EXIT as PROCESS_ACCESS

from ca.security.authn.user import User
from ca.security.authn.credentials import (
		validate_username,
		validate_email,
		validate_passwords,
	)

from ca.models import DBSession

from pyramid.security import remember
from pyramid.httpexceptions import HTTPFound
from pyramid.view import view_config


"""This file defines a view on the 'home' route which is displayed when TrustMe hasn't
been configured yet. It allows the first user to set the administrative email and
account passwords."""


# The template for the admin setup page
TEMPLATE = 'ca:templates/security/setup/admin.pt'


def _needs_admin(info, request):
	"""Custom predicate which checks if an admin needs to be created"""
	return DBSession.query(User).count() == 0


@view_config(route_name='home', renderer=TEMPLATE, custom_predicates=(_needs_admin,))
def setup_admin(request):
	"""Provide a form view for configuring initial admin account settings"""
	# Name and maxLength of the email field
	mail_field = 'email', User.email.property.columns[0].type.length
	# Names of the password/confirmation fields
	pass_fields = 'pass1', 'pass2', 'pass3', 'pass4'
	# Name of the submitted field
	submitted = 'newuser.submitted'

	# Set the inputs and error message to empty strings
	email, passwords, message = '', ('', '', '', ''), ''
	# FIXME: Set defaults for easy testing
	email = 'douglasm@pontiflex.com'
	passwords = ('password', 'password', 'password1', 'password1')

	# If the form was submitted, process the input
	if submitted in request.params:
		# Retrieve the input values
		email = request.POST[mail_field[0]]
		passwords = (request.POST[pass_fields[0]].encode('utf-8'),
					 request.POST[pass_fields[1]].encode('utf-8'),
					 request.POST[pass_fields[2]].encode('utf-8'),
					 request.POST[pass_fields[3]].encode('utf-8'),)
		# Validate the email, and passwords
		message = validate_email(email)
		if not message:	message = validate_passwords((passwords[0], passwords[1]))
		if not message:	message = validate_passwords((passwords[2], passwords[3]))
		if not message and passwords[0] == passwords[2]:
			message = 'ROOT and USERS passwords must be different'
		# If no error occurred, create the configured accounts
		if not message:
			# Create the ROOT user
			priv_root = User('ROOT', email, passwords[0])
			DBSession.add(priv_root)
			# Give it an admin capability (can grant any capability)
			DBSession.add(AdminCapability(priv_root))

			# Create the USERS user
			user_root = User('USERS', email, passwords[2])
			DBSession.add(user_root)
			# Give it every capability related to NewUser requests
			for access_type in FILTER_ACCESS + PROCESS_ACCESS:
				grant = GrantCapability(user_root, NewUser, access_type)
				DBSession.add(grant)
				access = grant.grant(user_root)
				DBSession.add(access)

			# Redirect to the home page, logged in as USERS
			return HTTPFound(location=request.route_url('home'),
							 headers=remember(request, 'USERS'))

	# Return the render dictionary
	return dict(
		mail_field = mail_field,
		pass_fields = pass_fields,
		message = message,
		email = email,
		passwords = passwords,
		submitted = submitted,
		)

