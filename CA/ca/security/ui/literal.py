
class HTML(object):
	def __init__(self, html):
		self.html = html
	def __html__(self):
		return self.html
	def __repr__(self):
		return 'Safe HTML: %s' % self.html
