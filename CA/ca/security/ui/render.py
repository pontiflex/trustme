from pyramid.renderers import render as render_


def render(renderer_name, value, request=None, package=None):
	if request is not None:
		content_type = request.response.content_type
	try:
		return render_(renderer_name, value, request, package)
	finally:
		if request is not None:
			request.response.content_type = content_type
