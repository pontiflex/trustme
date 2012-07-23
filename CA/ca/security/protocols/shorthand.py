from pyasn1.type import tag, univ, namedtype

from inspect import isclass

"""def TYPE(name, type, explicit=None, tagnum=0, tagcons=True, tagclass=tag.tagClassContext, optional=False, **kwargs):
	tag_ = None
	if explicit is not None:
		form = tag.tagFormatConstructed if tagcons else tag.tagFormatSimple
		tag_ = tag.Tag(tagclass, form, tagnum)
		if explicit: kwargs['explicitTag'] = tag_
		else:		 kwargs['implicitTag'] = tag_
	if kwargs: type = type.subtype(**kwargs)
	if optional:
		return namedtype.OptionalNamedType(name, type)
	return namedtype.NamedType(name, type)"""

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

def SEQOF(type_, constraint=None):
	if constraint is not None:
		type_ = type_.subtype(subtypeSpec=type_.subtypeSpec + constraint)
	else:
		type_ = type_()
	class Of(univ.SequenceOf):
		componentType = type_
	if constraint is not None:
		Of.subtypeSpec += constraint
	return Of

def SETOF(type_, constraint=None):
	if constraint is not None:
		type_ = type_.subtype(subtypeSpec=type_.subtypeSpec + constraint)
	else:
		type_ = type_()
	class Of(univ.SetOf):
		componentType = type_
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

