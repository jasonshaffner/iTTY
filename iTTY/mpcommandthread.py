from threading import Thread
from iTTY import iTTY

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
		self.tty = iTTY(username=username, password=password, host=host)

	def run(self):
		self.pool.acquire()
		self.tty.addtooutput(['\n\n*************** ' + self.host.strip("\n") + ' ***************\n', ])
		if self.tty.securelogin(): 
			if self.tty.os == 1:self.tty.setcommands(self.alucommands)
			elif self.tty.os == 2:self.tty.setcommands(self.xrcommands)
			elif self.tty.os == 3:self.tty.setcommands(self.ioscommands)
			elif self.tty.os == 4:self.tty.setcommands(self.junoscommands)
			elif self.tty.os == 5:self.tty.setcommands(self.asacommands)
			else: 
				self.pool.release()
				return 0
			self.tty.runseccommands(self.commanddelay)
		elif self.tty.unsecurelogin():
			if self.tty.os == 1: self.tty.setcommands(self.alucommands)
			elif self.tty.os == 2: self.tty.setcommands(self.xrcommands)
			elif self.tty.os == 3: self.tty.setcommands(self.ioscommands)
			elif self.tty.os == 4: self.tty.setcommands(self.junoscommands)
			elif self.tty.os == 5: self.tty.setcommands(self.asacommands)
			else: 
				self.pool.release()
				return 0
			self.tty.rununseccommands(self.commanddelay)
		self.pool.release()
		return self.tty.getoutput()

	def join(self):
		Thread.join(self)
		return self.tty.getoutput()
