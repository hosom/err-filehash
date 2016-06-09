import re

import dns.resolver
from errbot import BotPlugin, botcmd, cmdfilter

_MHR_API = 'malware.hash.cymru.com'

def mhr(ahash):
	'''Lookup a file in the malware hash registry.'''
	try:
		answers = dns.resolver.query('%s.%s' % (ahash, _MHR_API), 'TXT')
	except dns.resolver.NXDOMAIN:
		return 'File not found in MHR.'

	answer = answers[0].to_text().strip('"')
	answer = MHRReply(*[field for field in answer.split(' ')])

	ts = datetime.datetime.fromtimestamp(int(answer.ts))

	return 'Malicious file %s last seen %s with a detection rate of %s' % (
									args,
									ts,
									answer.detection_rate
									)

class HashMatch(BotPlugin):
	'''Plugin that finds file hashes inside of messages and then performs
	lookups and actions based on the presence of a file hash.
	'''
	def __init__(self, bot):
		super().__init__(bot)

		# Compile the pattern on the bot load and reuse it over and over again
		# for better performance.
		self.pattern = re.compile('([a-fA-F0-9]{64}|[a-fA-F0-9]{40}|[a-fA-F0-9]{32})')


	def callback_message(self, msg):
		'''Check the messages if they contain a hash.'''

		# Prevent a message loop by ignoring all messages sent by the bot
		user = "@%s"  % (msg.frm.username)
		if user == str(self.bot_identifier):
			return

		# Match for hash patterns inside of the message to determine if
		# lookups should be performed.
		for match in self.pattern.finditer(msg.body):
			self.send(msg.to, 'Found a file hash: %s' % (match.group(0)))
			self.send(msg.to, mhr(match.group(0)))
		return
