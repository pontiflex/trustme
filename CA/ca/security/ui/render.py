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

from pyramid.renderers import render as render_


def render(renderer_name, value, request=None, package=None):
	if request is not None:
		content_type = request.response.content_type
	try:
		return render_(renderer_name, value, request, package)
	finally:
		if request is not None:
			request.response.content_type = content_type
