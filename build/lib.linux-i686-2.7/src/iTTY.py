#!/usr/bin/env python
#Fully importable class to log in and run commands on multiple OS
#This has been tested to work on IOS-XR, IOS, JUNOS, ALU, ASA
#Optionally runs as a multithreaded script, will attempt login via SSH first, if unsuccessful will try Telnet

import getpass, telnetlib, os, sys, re, time, threading, paramiko
from multiprocessing import Manager

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
		return

	#Sets which host to login and run commands
	def sethost(self, host):
		self.host = host
		return

	#Returns host (if none set, default is None)
	def gethost(self):
		return self.host

	def clearhost(self):
		self.host = None
		return

	#Sets username and password used for login
	def setlogin(self, **kwargs):
		self.username = kwargs.get('username', None)
		if not self.username: self.username = raw_input("Username: ")
		self.password = kwargs.get('password', None)
		if not self.password: self.password = getpass.getpass()
		return

	#Returns username (if none set, default is None)
	def getusername(self):
		return self.username

	def clearlogin(self):
		self.username = None
		self.password = None
		return

	#Verifies that all necessary login parameters are set, returns 0 if one is missing
	def verifyloginparameters(self):
		flag = 1
		if not self.username:
			print "No username specified"
			flag = 0
		if not self.password:
			print "No password specified"
			flag = 0
		if not self.host:
			print "No host specified"
			flag = 0
		return flag

	#Takes prompt as arg, returns digit signifying type of OS
	def setos(self, prompt):
		if re.search('[A-B]:.*#', prompt): self.os = 1 #ALU
		elif re.search('CPU.*#', prompt): self.os = 2  #XR
		elif re.search('.*#', prompt): self.os = 3     #IOS
		elif re.search(self.username + '@.*>', prompt): self.os = 4  #JUNOS
		elif re.search('.*>', prompt): self.os = 5  #ASA
		return

	#Returns digit signifying type of OS
	def getos(self):
		return self.os

	def clearos(self):
		self.os = 0
		return

	#Takes a list of commands as arg, sets commands to that list
	def setcommands(self, commands):
		self.commands = commands
		return

	#Takes a file with list of commands as arg, sets commands to that list
	def setcommandsfromfile(self, file):
		self.commands = list(open(file, 'r'))
		return

	#Takes a single command as arg, appends command to list of commands
	def addcommand(self, command):
		self.commands.append(command)
		return

	#Returns list of commands to run
	def getcommands(self):
		return self.commands

	def clearcommands(self):
		self.commands = []
		return

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
		return

	#Cleans up and formats output
	def siftoutput(self): 
		dontprint = ['enable', 'Password:', 'terminal', 'screen-length', 'Screen length','environment no more', '{master', 'Building config', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun', self.username, self.prompt]
		temp = []
		for entry in self.output:
			for line in entry:
				if any(n in line for n in dontprint): continue
				temp.append(line)
			temp.append('\n\n')
		self.setoutput(temp) 
		return

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
			self.prompt = self.shell.recv(1000)
			self.setos(self.prompt)
			self.addtooutput(['\n\n*************** ' + self.host + ' ***************\n\n', ])
			return self.os
		except: 
			return 0

	#Attempts fo login to devices via Telnet, returns OS type if successful, if not returns 0
	def unsecurelogin(self, **kwargs):   #Telnet specific login and processing
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
			self.prompt = previous_text.split('\n')[-1].strip()
			self.setos(self.prompt)
		except: 
			return 0
		self.addtooutput(['\n\n*************** ' + self.host + ' ***************\n\n', ])
		return self.os

	#Runs commands when logged in via SSH, returns output
	def runseccommands(self, command_delay):
		flag = 1 
		if self.os == 5: flag = 3
		for command in self.getcommands():
			self.shell.send(command.strip() + '\r')
			time.sleep(command_delay)
			if flag > 0:
				flag -= 1
				continue
			self.addtooutput(['\n\n' + command + '_________________________________________\n', ])
			self.addtooutput(self.shell.recv(500000).split('\n'))
		self.siftoutput()
		return self.getoutput()

	#Runs commands when logged in via Telnet, returns output
	def rununseccommands(self, command_delay):
		flag = 0 
		for command in self.commands:
			self.session.write(command.strip() + '\r')
			n, m, output = self.session.expect([self.prompt, ], command_delay)
			time.sleep(command_delay)
			if flag == 0:
				flag = 1
				continue
			self.addtooutput([command + '_________________________________________\n', ])
			self.addtooutput(output.split('\n')[1:-1])
			#self.addtooutput(self.session.read_very_eager().split('\n'))
		self.siftoutput()
		self.session.write('exit\r')
		self.session.close()
		return self.getoutput()

#Subclass of Thread, used for concurrent logins across multiple devices, only used when running as script
class runthread(threading.Thread):
	def __init__(self, pool, host, username, password):
		threading.Thread.__init__(self)
		self.pool = pool
		self.host= host
		self.username = username
		self.password = password

	def run(self):
		self.pool.acquire()
		tty = iTTY(host=self.host.split('.', 1)[0], username=self.username, password=self.password)
		if tty.securelogin(): 
			if tty.os == 1: tty.setcommands(alucommands)
			elif tty.os == 2: tty.setcommands(xrcommands)
			elif tty.os == 3: tty.setcommands(ioscommands)
			elif tty.os == 4: tty.setcommands(junoscommands)
			elif tty.os == 5: tty.setcommands(asacommands)
			else: 
				pool.release()
				return 0
			tty.runseccommands(commanddelay)
			report.append(tty.getoutput())
		elif tty.unsecurelogin():
			if tty.os == 1: tty.setcommands(alucommands)
			elif tty.os == 2: tty.setcommands(xrcommands)
			elif tty.os == 3: tty.setcommands(ioscommands)
			elif tty.os == 4: tty.setcommands(junoscommands)
			elif tty.os == 5: tty.setcommands(asacommands)
			else: 
				pool.release()
				return 0
			tty.rununseccommands(commanddelay)
			report.append(tty.getoutput())
		pool.release()

#Main method, used when running as script
if __name__ == "__main__":
	if len(sys.argv) < 5:
		username = raw_input("Username: ")
		password = getpass.getpass()
		devicelist = raw_input("Device list file: ")
		configs = raw_input("Are you making config changes? [y/n] ")
	else:
		username = sys.argv[1]
		password = sys.argv[2]
		devicelist = sys.argv[3]
		configs = sys.argv[4]
	hostnames = open(devicelist, 'r')
	if "y" in configs: command_delay = 1
	else: commanddelay = 5 #Seconds to wait for each command to finish
	manager = Manager()
	report = manager.list([])
	threadcount = 1000
	commandfiles = 0
	try:
		junoscommands = list(open('JUNOS', 'r'))
		junoscommands.insert(0, 'set cli screen-length 0')
	except: commandfiles += 1
	try:
		ioscommands = list(open('IOS', 'r'))
		ioscommands.insert(0, 'terminal length 0')
	except: commandfiles += 1
	try:
		xrcommands = list(open('XR', 'r'))
		xrcommands.insert(0, 'terminal length 0')
	except: commandfiles += 1
	try:
		alucommands = list(open('ALU', 'r'))
		alucommands.insert(0, "environment no more")
	except: commandfiles += 1
	try:
		asacommands = list(open('ASA', 'r'))
		asacommands.insert(0, 'enable')
		asacommands.insert(1, password)
		asacommands.insert(2, 'terminal pager 0')
	except: commandfiles += 1
	if commandfiles == 5:
		print "Couldn't find command files\r"
		exit()
	pool = threading.Semaphore(threadcount)
	threads = []
	for host in hostnames:
		with pool:
			thread = runthread(pool, host, username, password)
			threads.append(thread)
			thread.start()
	for t in threads: t.join()
	hostnames.close()
	###### Print output of commands and post thread processing ######
	report = sorted(report, key=lambda hostname: hostname[0])
	for y in report:
		for x in y: print x
