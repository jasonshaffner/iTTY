from threading import Thread
from iTTY import iTTY
from format import Format

#Subclass of Thread, used for concurrent logins across multiple devices
class Mpcommand(Thread):
	def __init__(self, username, password, host, commanddelay, **kwargs):
		Thread.__init__(self)
		self.username = username
		self.password = password
		self.host = host
		self.commanddelay = commanddelay
		self.pool = kwargs.get('pool', None)
		self.alucommands = kwargs.get('alucommands', None)
		self.asacommands = kwargs.get('asacommands', None)
		self.ioscommands = kwargs.get('ioscommands', None)
		self.junoscommands = kwargs.get('junoscommands', None)
		self.xrcommands = kwargs.get('xrcommands', None)
		self.commandheader = kwargs.get('commandheader', 1)
		self.tty = iTTY(username=username, password=password, host=host)

	def run(self):
		self.pool.acquire()
		if self.tty.securelogin(): 
			if self.tty.os == 1:self.tty.setcommands(self.alucommands)
			elif self.tty.os == 2:self.tty.setcommands(self.xrcommands)
			elif self.tty.os == 3:self.tty.setcommands(self.ioscommands)
			elif self.tty.os == 4:self.tty.setcommands(self.junoscommands)
			elif self.tty.os == 5:self.tty.setcommands(self.asacommands)
			else: 
				self.pool.release()
				return 0
			output = self.tty.runseccommands(self.commanddelay, commandheader=self.commandheader)
		elif self.tty.unsecurelogin():
			if self.tty.os == 1: self.tty.setcommands(self.alucommands)
			elif self.tty.os == 2: self.tty.setcommands(self.xrcommands)
			elif self.tty.os == 3: self.tty.setcommands(self.ioscommands)
			elif self.tty.os == 4: self.tty.setcommands(self.junoscommands)
			elif self.tty.os == 5: self.tty.setcommands(self.asacommands)
			else: 
				self.pool.release()
				return 0
			output = self.tty.rununseccommands(self.commanddelay, commandheader=self.commandheader)
		else:
			print "Could not log in to " + self.host
			exit()
		self.tty.setoutput(Format.siftoutput(output, siftout=[self.tty.username, self.tty.prompt]))
		self.pool.release()
		return

	def join(self):
		Thread.join(self)
		return self.tty.getoutput()
