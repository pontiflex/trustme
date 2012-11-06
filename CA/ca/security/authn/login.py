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

from ca.security.algorithms import sha256
from ca.security.authn.user import User

from pyramid.security import remember, forget

from pyramid.httpexceptions import HTTPFound
from pyramid.view import view_config


"""This file contains views for logging in and out of the TrustMe system. Logging in
requires the user agent to solve a cryptographic puzzle, which prevents online attacks without requiring the server to keep any state about repeat guessers."""


# The log of the number of puzzle solutions that must be checked in the worst case
PUZZLE_DIFFICULTY = 10
# The TrustMe hashing algorithm to be used by the puzzle
PUZZLE_ALG = sha256
# The CryptoJS code to compute a hash of the appropriate type
PUZZLE_ALG_JS = 'CryptoJS.SHA256(%s).toString(CryptoJS.enc.Hex)'
# FIXME: The CryptoJS URL from which to import the implementation (should be changed to a locally hosted source!)
PUZZLE_ALG_LOC = 'http://crypto-js.googlecode.com/svn/tags/3.0.2/build/rollups/sha256.js'


# TODO: Move this to a central location if puzzles are implemented more widely
def verify_puzzle(url, login, password, solution):
	"""Take a page url, login, password, and puzzle solution, and return whether or
	not the solution is valid"""
	# Hash the inputs individually and encode in hex
	url = PUZZLE_ALG(url).encode('hex')
	login = PUZZLE_ALG(login).encode('hex')
	password = PUZZLE_ALG(password).encode('hex')
	# Concatenate the results into a puzzle
	puzzle = url + login + password
	# Hash the solution and encode in hex
	solution = PUZZLE_ALG(solution).encode('hex')
	# Hash the concatenation of the puzzle and solution hashes into a final result
	check = PUZZLE_ALG(puzzle + solution)
	# Make sure the hash ends in at least PUZZLE_DIFFICULTY zero bits
	for i in xrange(PUZZLE_DIFFICULTY):
		if (ord(check[-(i+1)//8])>>(i%8)) & 1:
			return False
	return True







@view_config(route_name='login', renderer='ca:templates/security/authn/login.pt')
def login(request):
	"""Provide a form for logging into the TrustMe system"""
	# Compute the URL of the login page
	login_url = request.route_url('login')
	# Make sure the referrer is set and isn't this page
	referrer = request.referrer
	if not referrer or referrer == login_url:
		referrer = request.route_url('home')
	# Set the redirect target to the original referrer, or the current one if this
	# is the first page view
	came_from = request.params.get('came_from', referrer)
	# If there is already an authenticated user, redirect immediately
	if User.authenticated(request):
		return HTTPFound(location = came_from)

	# Set the input values and error message to empty strings
	login, password, message = '', '', ''

	# If the form is submitted, process the input
	if 'form.submitted' in request.params:
		# Retrieve and parse the input
		login = request.POST['login']
		password = request.POST['password'].encode('utf-8')
		solution = request.POST['solution'].encode('utf-8')
		# If the puzzle solution is correct, check the actual input
		if verify_puzzle(request.url, login, password, solution):
			# Get the User with the given credentials, if any
			user = User.verify(login, password)
			if user:
				# Reset the CSRF token
				request.session.new_csrf_token()
				# Remember the User
				headers = remember(request, login)
				# Redirect to the target page
				return HTTPFound(location=came_from,
					headers=headers)
			else:
				message = 'Failed login'
		else:
			message = 'Failed DOS check'

	# Return the render dictionary
	return dict(
		message = message,
		puzzle_diff = PUZZLE_DIFFICULTY,
		puzzle_alg = PUZZLE_ALG_JS,
		puzzle_alg_loc = PUZZLE_ALG_LOC,
		url = login_url,
		came_from = came_from,
		login = login,
		password = password,
		)

@view_config(route_name='logout')
def logout(request):
	"""Take a Pyramid request object and log out the current user, if any"""
	# Reset the CSRF token
	request.session.new_csrf_token()
	# Forget the user
	headers = forget(request)
	# Redirect to the homepage
	return HTTPFound(location=request.route_url('home'), headers=headers)

