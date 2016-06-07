
import re

from errbot import BotPlugin, botcmd, cmdfilter

class HashMatch(BotPlugin):
	'''
	'''
	def __init__(self, bot):
		super().__init__(bot)

		self.pattern = re.compile('([a-zA-Z0-9]{64}|[a-zA-Z0-9]{40}|[a-zA-Z0-9]{32})')


	def callback_message(self, msg):
		'''Check the messages if they contain a hash.'''

		for match in self.pattern.finditer(msg.body):
			self.send(msg.frm, match.group(0))
			self.send(msg.frm, str(msg))
			self.log('Seems like a match: %s' % (match.group(0)))
		return