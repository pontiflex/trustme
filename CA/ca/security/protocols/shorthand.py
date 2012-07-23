from pyasn1.type import tag, univ, namedtype

def TYPE(name, type, explicit=None, tagnum=0, tagcons=True, tagclass=tag.tagClassContext, optional=False, **kwargs):
	tag = None
	if explicit is not None:
		form = tag.tagFormatConstructed if tagcons else tag.tagFormatSimple
		tag = tag.Tag(tagclass, form, tagnum)
		if explicit: kwargs['explicitTag'] = tag
		else:		 kwargs['implicitTag'] = tag
	if kwargs: type = type.subtype(**kwargs)
	if optional:
		return namedtype.OptionalNamedType(name, type)
	return namedtype.NamedType(name, type)

def SEQ(*types):
	class seq(univ.Sequence):
		componentType = namedtype.NamedTypes(*types)
	return seq

def SET(*types):
	class set_(univ.Set):
		componentType = namedtype.NamedTypes(*types)
	return set_

def SEQOF(type):
	class of(univ.SequenceOf):
		componentType = type
	return of()

def SETOF(type):
	class of(univ.SetOf):
		componentType = type
	return of()

def CHOICE(*types):
	class choice(univ.Choice):
		componentType = namedtype.NamedTypes(*types)
	return choice

def ID(*nums):
	return univ.ObjectIdentifier(*nums)
