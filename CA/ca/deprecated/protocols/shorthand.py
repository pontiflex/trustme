from pyasn1.type import tag, univ, namedtype, namedval, constraint

from inspect import isclass

MAX = 2147483647 # FIXME: Is this right?

def TYPE(name, type_, explicit=None, tagnum=0, tagcons=True, tagclass=tag.tagClassContext,
		 optional=False, default=None, constraint=None, named=None):
	type_ = type_() if default is None else type_(default)
	subArgs = {}
	if explicit is not None:
		form = tag.tagFormatConstructed if tagcons else tag.tagFormatSimple
		tag_ = tag.Tag(tagclass, form, tagnum)
		if explicit: subArgs['explicitTag'] = tag_
		else:		 subArgs['implicitTag'] = tag_
	if constraint is not None:
		subArgs['subtypeSpec'] = constraint
	if named is not None:
		subArgs['namedValues'] = named

	if subArgs:
		type_ = type_.subtype(**subArgs)
	if name is None:
		return type_

	if default is not None:
		return namedtype.DefaultedNamedType(name, type_)
	elif optional:
		return namedtype.OptionalNamedType(name, type_)
	return namedtype.NamedType(name, type_)

def SEQ(*types):
	class Seq(univ.Sequence):
		componentType = namedtype.NamedTypes(*types)
	return Seq

def SET(*types):
	class Set(univ.Set):
		componentType = namedtype.NamedTypes(*types)
	return Set

def CHOICE(*types):
	class Choice(univ.Choice):
		componentType = namedtype.NamedTypes(*types)
	return Choice

def ENUM(*values):
	class Enum(univ.Enumerated):
		namedValues = namedval.NamedValues(*values)
		subtypeSpec = univ.Enumerated.subtypeSpec + constraint.SingleValueConstraint(*(v[1] for v in values))
	return Enum

def SEQOF(type_, constraint=None):
	type_ = type_()
	if constraint is not None:
		type_ = type_.subtype(subtypeSpec=constraint)
	class SeqOf(univ.SequenceOf):
		componentType = type_
	return SeqOf

def SETOF(type_, constraint=None):
	type_ = type_()
	if constraint is not None:
		type_ = type_.subtype(subtypeSpec=constraint)
	class SetOf(univ.SetOf):
		componentType = type_
	return SetOf

def ID(*nums):
	return univ.ObjectIdentifier(tuple(nums))

def TUP(base, *nums):
	ls = list(base)
	ls.extend(nums)
	return tuple(ls)

