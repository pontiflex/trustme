from algorithms import sha256
from user import User

from pyramid.security import remember, forget

from pyramid.httpexceptions import HTTPFound
from pyramid.response import Response
from pyramid.view import view_config


PUZZLE_DIFFICULTY = 10
PUZZLE_ALG = sha256
PUZZLE_ALG_JS = 'CryptoJS.SHA256(%s).toString(CryptoJS.enc.Hex)'
PUZZLE_ALG_LOC = 'http://crypto-js.googlecode.com/svn/tags/3.0.2/build/rollups/sha256.js'


def verify_puzzle(url, login, password, solution):
	url = PUZZLE_ALG(url).encode('hex')
	login = PUZZLE_ALG(login).encode('hex')
	password = PUZZLE_ALG(password).encode('hex')
	puzzle = url + login + password
	solution = PUZZLE_ALG(solution).encode('hex')
	check = PUZZLE_ALG(puzzle + solution)
	for i in xrange(PUZZLE_DIFFICULTY):
		if (ord(check[-(i+1)//8])>>(i%8)) & 1:
			return False
	return True







@view_config(route_name='login', renderer='ca:security/login.pt')
def login(request):
	login_url = request.route_url('login')
	referrer = request.referrer
	if not referrer or referrer == login_url:
		referrer = request.route_url('home')
	came_from = request.params.get('came_from', referrer)	
	if User.authenticated(request):
		return HTTPFound(location = came_from)

	login = ''
	password = ''
	message = ''

	if 'form.submitted' in request.params:
		login = request.POST['login']
		password = request.POST['password'].encode('utf-8')
		solution = request.POST['solution'].encode('utf-8')
		user = User.verify(login, password)
		if user:
			if verify_puzzle(request.url, login, password, solution):
				headers = remember(request, login)
				return HTTPFound(location=came_from,
					headers=headers)
			message = 'Failed DOS check'
		else:
			message = 'Failed login'	

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
	headers = forget(request)
	return HTTPFound(location=request.route_url('home'), headers=headers)

