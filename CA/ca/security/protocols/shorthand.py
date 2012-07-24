from pyasn1.type import tag, univ, namedtype, namedval, constraint

from inspect import isclass

MAX = 2147483647 # FIXME: Is this right?

def TYPE(name, type_, explicit=None, tagnum=0, tagcons=True, tagclass=tag.tagClassContext,
		 optional=False, default=None, constraint=None):
	if not isclass(type_): type_ = type_.__class__
	class Type(type_): pass
	if explicit is not None:
		form = tag.tagFormatConstructed if tagcons else tag.tagFormatSimple
		tag_ = tag.Tag(tagclass, form, tagnum)
		if explicit: Type.tagSet = Type.tagSet.tagExplicitly(tag_)
		else:		 Type.tagSet = Type.tagSet.tagImplicitly(tag_)
	if constraint is not None:
		Type.subtypeSpec += constraint
	T = Type() if default is None else Type(default)
	if optional:
		return namedtype.OptionalNamedType(name, Type)
	return namedtype.NamedType(name, Type)

def SEQ(*types):
	class Seq(univ.Sequence):
		componentType = namedtype.NamedTypes(*types)
	return Seq

def SET(*types):
	class Set(univ.Set):
		componentType = namedtype.NamedTypes(*types)
	return Set

def ENUM(*values):
	class Enum(univ.Enumerated):
		namedValues = namedval.NamedValues(*values)
		subtypeSpec = univ.Enumerated.subtypeSpec + constraint.SingleValueConstraint(*(v[1] for v in values))
	return Enum		

def SEQOF(type_, constraint=None):
	class In(type_): pass
	if constraint is not None:
		In.subtypeSpec += constraint
	class Of(univ.SequenceOf):
		componentType = In
	return Of

def SETOF(type_, constraint=None):
	class In(type_): pass
	if constraint is not None:
		In.subtypeSpec += constraint
	class Of(univ.SetOf):
		componentType = In
	return Of

def CHOICE(*types):
	class Choice(univ.Choice):
		componentType = namedtype.NamedTypes(*types)
	return Choice

def ID(*nums):
	return univ.ObjectIdentifier(tuple(nums))

def TUP(base, num):
	ls = list(base)
	ls.append(num)
	return tuple(ls)

