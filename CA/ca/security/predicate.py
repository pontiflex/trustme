from ..models import Base, DBSession


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

