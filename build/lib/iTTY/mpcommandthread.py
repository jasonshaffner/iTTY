from threading import Thread
from .iTTY import iTTY
from .command import Command_parser

#Subclass of Thread, used for concurrent logins across multiple devices
class Mpcommand(Thread):
	def __init__(self, username, password, host, commanddelay, **kwargs):
		Thread.__init__(self)
		self.username = username
		self.password = password
		self.host = host
		self.commanddelay = commanddelay
		self.alucommands = kwargs.get('alucommands', None)
		self.asacommands = kwargs.get('asacommands', None)
		self.ioscommands = kwargs.get('ioscommands', None)
		self.junoscommands = kwargs.get('junoscommands', None)
		self.xrcommands = kwargs.get('xrcommands', None)
		self.commandheader = kwargs.get('commandheader', 1)
		self.pool = kwargs.get('pool', None)
		self.tty = iTTY(username=username, password=password, host=host)

	def run(self):
		if self.pool: self.pool.acquire()
		try:
			with self.tty:
				if self.tty.os == 1:self.tty.setcommands(self.alucommands)
				elif self.tty.os == 2:self.tty.setcommands(self.xrcommands)
				elif self.tty.os == 3:self.tty.setcommands(self.ioscommands)
				elif self.tty.os == 4:self.tty.setcommands(self.junoscommands)
				elif self.tty.os == 5:self.tty.setcommands(self.asacommands)
				else: return
				output = self.tty.runcommands(self.commanddelay, commandheader=self.commandheader)
		except:
			print("Could not log in to: " + self.tty.host)
			if self.pool: self.pool.release()
			return
		self.tty.setoutput(self.tty.siftoutput(self.username, self.password, self.tty.prompt))
		if self.pool: self.pool.release()

class Mpinteractivecommand(Mpcommand):

	def run(self):
		if self.pool: self.pool.acquire()
		if self.tty.login():
			if self.tty.os == 1: commands = self.alucommands
			elif self.tty.os == 2: commands = self.xrcommands
			elif self.tty.os == 3: commands = self.ioscommands
			elif self.tty.os == 4: commands = self.junoscommands
			elif self.tty.os == 5: commands = self.asacommands
			else: return
			self.tty.setcommands(commands[0])
			output = self.tty.runcommands(self.commanddelay, commandheader=self.commandheader)
			for command in commands[1]:
				if command.commanddelay: self.commanddelay = command.commanddelay
				self.tty.setcommands(Command_parser.generate_commands(command, output))
				output = self.tty.runcommands(self.commanddelay, commandheader=self.commandheader)
		else:
			print("Could not log in to " + self.host.strip())
			self.tty.logout()
			if self.pool: self.pool.release()
			return
		output = self.tty.getoutput()
		self.tty.setoutput(self.tty.siftoutput(self.username, self.password, self.tty.prompt))
		self.tty.logout()
		if self.pool: self.pool.release()
