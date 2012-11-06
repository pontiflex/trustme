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

from ca.models import Base, DBSession


__predicates__ = set()

def predicate(fun):
	__predicates__.add(fun.__func__)
	return fun

def get_predicate(obj, name):
	pred = getattr(obj, name, None)
	if pred is None or pred.__func__ not in __predicates__:
		return _Throw()
	return pred


class _Throw:
	def __call__(self, *args, **kwargs):
		raise PredicateError()

class PredicateError(AttributeError): pass

