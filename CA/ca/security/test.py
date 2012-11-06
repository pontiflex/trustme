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

from algorithms import slow_equals, pbkdf2_hmac_sha1

import random
import timeit


"""This file provides a framework for testing the cryptographic wrappers, and currently
implements an automatic test of the PBKDF2 function (SHA1 only) against standard test
vectors and a visual test of slow_equals as compared to =="""


_tests = 0
_failures = 0
def run_tests(*args):
	global _failures, _tests
	_tests = _failures = 0
	for f in args:
		f()
	if _failures == 0:
		print 'All tests passed! (%i tests run)' % _tests
	else:
		print '%i tests failed... (%i tests run)' % _failures, _tests

def test(func, expect, *args):
	global _tests, _failures
	_tests += 1
	res = func(*args)
	if res != expect:
		print ('FAILURE: Expected', expect, 'from', func,
				'with arguments', args, 'but got', res)
		_failures += 1
		return False
	return True

def slice_res(func, index):
	def new_func(*args):
		return func(*args)[index]
	return new_func

def percent(chance):
	return random.uniform(0, 100) < chance

def test_slow_equals():
	length = lambda: random.randint(1, 100)
	same = lambda: percent(50)
	samelength = lambda: percent(50)
	char = lambda: chr(random.randint(0, 255))
	for i in xrange(500):
		string = ''.join(char() for j in xrange(length()))
		if same():
			other = string[:]
		else:
			l = len(string) if samelength() else length()
			other = ''.join(char() for j in xrange(l))
		test(slow_equals, string==other, string, other)

"""Pulled from https://github.com/mitsuhiko/python-pbkdf2/blob/master/pbkdf2.py,
   verified for correct transcription from RFC 6070."""
def test_pbkdf2():
	def check(password, salt, rounds, key_bytes, hex_result):
		func = slice_res(pbkdf2_hmac_sha1, slice(0, key_bytes))
		result = hex_result.decode('hex')
		test(func, result, password, salt, rounds)

	# From RFC 6070
	check('password', 'salt', 1, 20,
			'0c60c80f961f0e71f3a9b524af6012062fe037a6')
	check('password', 'salt', 2, 20,
			'ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957')
	check('password', 'salt', 4096, 20,
			'4b007901b765489abead49d926f721d065a429c1')
	check('passwordPASSWORDpassword', 'saltSALTsaltSALTsaltSALTsaltSALTsalt',
			4096, 25, '3d2eec4fe41c849b80c8d83662c0e44a8b291a964cf2f07038')
	check('pass\x00word', 'sa\x00lt', 4096, 16,
			'56fa6aa75548099dcc37d7f03425e0c3')

	# From Crypt-PBKDF2 ???
	check('password', 'ATHENA.MIT.EDUraeburn', 1, 16,
			'cdedb5281bb2f801565a1122b2563515')
	check('password', 'ATHENA.MIT.EDUraeburn', 1, 32,
			'cdedb5281bb2f801565a1122b25635150ad1f7a04bb9f3a333ecc0e2e1f70837')
	check('password', 'ATHENA.MIT.EDUraeburn', 2, 16,
			'01dbee7f4a9e243e988b62c73cda935d')
	check('password', 'ATHENA.MIT.EDUraeburn', 2, 32,
			'01dbee7f4a9e243e988b62c73cda935da05378b93244ec8f48a99e61ad799d86')
	check('password', 'ATHENA.MIT.EDUraeburn', 1200, 32,
			'5c08eb61fdf71e4e4ec3cf6ba1f5512ba7e52ddbc5e5142f708a31e2e62b1e13')
	check('X' * 64, 'pass phrase equals block size', 1200, 32,
			'139c30c0966bc32ba55fdbf212530ac9c5ec59f1a452f5cc9ad940fea0598ed1')
	check('X' * 65, 'pass phrase exceeds block size', 1200, 32,
			'9ccad6d468770cd51b10e6a68721be611a8b4d282601db3b36be9246915ec82a')

def test_timing():
	iters = 1000
	repeats = 3
	setup = 'from algorithms import slow_equals'
	length = 10000
	char = 'x'
	dif_char = 'y'

	string = "'%s' * %i" % (char, length)
	dif_string = "'%s' + '%s' * %i" % (dif_char, char, length-1)
	short_string = "'%s' * %i" % (char, length-1)
	slow = lambda(s): 'slow_equals(%s, %s)' % (string, s)
	fast = lambda(s): '%s == %s' % (string, s)
	t = lambda(stmt): timeit.repeat(stmt, setup, repeat=repeats, number=iters)	

	timer_slow_same = t(slow(string))
	print 'Slow, same:', timer_slow_same
	timer_fast_same = t(fast(string))
	print 'Fast, same:', timer_fast_same	
	timer_slow_dif = t(slow(dif_string))
	print 'Slow, different:', timer_slow_dif	
	timer_fast_dif = t(fast(dif_string))
	print 'Fast, different:', timer_fast_dif	
	timer_slow_short = t(slow(short_string))
	print 'Slow, short:', timer_slow_short	
	timer_fast_short = t(fast(short_string))	
	print 'Fast, short:', timer_fast_short

if __name__ == '__main__':
	run_tests(test_slow_equals, test_pbkdf2)
	test_timing()

	
