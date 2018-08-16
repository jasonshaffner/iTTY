import getpass, telnetlib, time, re, paramiko
paramiko.util.log_to_file('/dev/null')

class iTTY:
	#Factory, optional keyword args: host, username, password
	def __init__(self, **kwargs):
		self.host = kwargs.get('host', None)
		self.username = kwargs.get('username', None)
		self.password = kwargs.get('password', None)
		self.os = None
		self.session = None
		self.shell = None
		self.prompt = None
		self.commands = []
		self.output = []

	def __enter__(self):
		self.login()

	def __exit__(self, *args):
		self.logout()

	#Sets which host to login and run commands
	def sethost(self, host):
		self.host = host

	#Returns host (if none set, default is None)
	def gethost(self):
		return self.host

	def clearhost(self):
		self.host = None

	#Sets username and password used for login
	def setlogin(self, **kwargs):
		self.username = kwargs.get('username', None)
		if not self.username: self.username = input("Username: ")
		self.password = kwargs.get('password', None)
		if not self.password: self.password = getpass.getpass()

	#Returns username (if none set, default is None)
	def getusername(self):
		return self.username

	def clearlogin(self):
		self.username = None
		self.password = None

	#Verifies that all necessary login parameters are set, returns 0 if one is missing
	def verifyloginparameters(self):
		flag = 1
		if not self.username:
			print("No username specified")
			flag = 0
		if not self.password:
			print("No password specified")
			flag = 0
		if not self.host:
			print("No host specified")
			flag = 0
		return flag

	#Takes prompt as arg, returns digit signifying type of OS
	def setos(self, prompt):
		if re.search('[A-B]:.*#', prompt): self.os = 1 #ALU
		elif re.search('CPU.*#', prompt): self.os = 2  #XR
		elif re.search('.*#', prompt): self.os = 3     #IOS
		elif re.search(self.username + '@.*>', prompt): self.os = 4  #JUNOS
		elif re.search('.*>', prompt): 
			self.os = 5  #ASA
			self.prompt = self.prompt.strip()[0:-1] + '#'
		return self.os

	#Returns digit signifying type of OS
	def getos(self):
		return self.os

	def clearos(self):
		self.os = 0

	#Takes a list of commands as arg, sets commands to that list
	def setcommands(self, commands):
		self.commands = commands

	#Takes a file with list of commands as arg, sets commands to that list
	def setcommandsfromfile(self, file):
		self.commands = list(open(file, 'r'))

	#Takes a single command as arg, appends command to list of commands
	def addcommand(self, command):
		self.commands.append(command)

	#Returns list of commands to run
	def getcommands(self):
		return self.commands

	def clearcommands(self):
		self.commands = []

	#Sets the output of commands run, overwriting any previous entries
	def setoutput(self, output):
		self.output = output

	#Adds to output of commands run
	def addtooutput(self, output):
		self.output.append(output)

	#Returns the output
	def getoutput(self):
		return self.output

	def clearoutput(self):
		self.output = []

	def login(self, **kwargs):
		if kwargs:
			self.host = kwargs.get('host', None)
			self.username = kwargs.get('username', None)
			self.password = kwargs.get('password', None)
		if not self.verifyloginparameters(): return
		if self.securelogin() or self.unsecurelogin(): return self.os

	#Attempts to login to devices via SSH, returns OS type if successful, if not returns 0
	def securelogin(self, **kwargs):
		if kwargs:
			self.host = kwargs.get('host', None)
			self.username = kwargs.get('username', None)
			self.password = kwargs.get('password', None)
		if not self.verifyloginparameters(): return
		try:
			self.session = paramiko.SSHClient() # Create instance of SSHClient object
			self.session.set_missing_host_key_policy(paramiko.AutoAddPolicy())
			self.session.connect(self.host.strip('\n'), username=self.username, password=self.password, look_for_keys=False, allow_agent=False)
			self.shell = self.session.invoke_shell()
			time.sleep(3)  #Allow time to log in and strip MOTD
			self.prompt = self.shell.recv(1000).decode().split('\n')[-1].strip()
			self.setos(str(self.prompt))
			return self.os
		except: return

	#Attempts fo login to devices via Telnet, returns OS type if successful, if not returns 0
	def unsecurelogin(self, **kwargs):
		if kwargs:
			self.host = kwargs.get('host', None)
			self.username = kwargs.get('username', None)
			self.password = kwargs.get('password', None)
		if not self.verifyloginparameters(): return
		try:
			self.session = telnetlib.Telnet(self.host.strip('\n'),23,3)
			self.session.expect(['sername:','ogin'],5)
			self.session.write(self.username + '\r')
			self.session.read_until('assword:')
			self.session.write(self.password + '\r')
			software, match, previous_text = self.session.expect(['[A-B]:.*#' ,'CPU.*#' , '.*#' , self.username + '@.*>'], 7)
			self.prompt = previous_text.split('\n')[-1].decode().strip()
			self.setos(self.prompt)
			return self.os
		except: return

	def runcommands(self, command_delay, commandheader=0, done=False):
		if self.shell: return self.runseccommands(command_delay, commandheader=commandheader, done=done)
		elif self.session: return self.rununseccommands(command_delay, commandheader=commandheader, done=done)

	#Runs commands when logged in via SSH, returns output
	def runseccommands(self, command_delay, commandheader=0, done=False):
		for command in self.getcommands():
			self.shell.send(command.strip() + '\r')
			time.sleep(command_delay)
			if commandheader:
				self.addtooutput(['\n' + _underline(command), ])
			self.addtooutput(self.shell.recv(500000).decode().split('\n')[1:])
		if done: self.logout()
		return self.getoutput()

	#Runs commands when logged in via Telnet, returns output
	def rununseccommands(self, command_delay, commandheader=0, done=False):
		for command in self.commands:
			self.session.write(command.strip() + '\r')
			n, m, output = self.session.expect([self.prompt, ], command_delay)
			time.sleep(command_delay)
			if commandheader:
				self.addtooutput(['\n' + _underline(command), ])
			self.addtooutput(output.split('\n')[1:])
		if done: self.logout()
		return self.getoutput()

	def logout(self):
		if self.shell: self.shell.close()
		elif self.session: self.session.close()
		return

	def siftoutput(self, *siftout):
		dontprint = ['enable', 'Password:', 'terminal length', 'screen-length', 'Screen length', \
			'terminal pager', 'environment no more', '{master', 'Building config', \
			'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun',] + list(siftout)
		output= []
		for entry in self.output:
			for line in entry:
				if not line.strip() or any(str(n) in line for n in dontprint): continue
				output.append(line)
		return output

	def _underline(input, linechar="-"):
		return input.strip() + '\n' + _makeline(len(input.strip()), linechar)

	def _makeline(count, linechar="-"):
		return linechar * int(count)
