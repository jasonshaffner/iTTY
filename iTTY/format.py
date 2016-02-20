import re, sys

class Format(object):
	#Cleans up and provides basic formatting for output
	@staticmethod
	def siftoutput(input, **kwargs): 
		siftout = kwargs.get('siftout', [])
		dontprint = ['enable', 'Password:', 'terminal length', 'screen-length', 'Screen length',\
			'environment no more', '{master', 'Building config', 'Mon', 'Tue', 'Wed', \
			'Thu', 'Fri', 'Sat', 'Sun',] + siftout
		temp = []
		for entry in input:
			for line in entry:
				if not line.strip(): continue
				if any(n in line for n in dontprint): continue
				temp.append(line)
		return temp

	@staticmethod
	def underline(input, linechar="-"):
		line = ""
		for i in range(len(input)):
			line = line + linechar	
		return input.strip() + '\n' + line + '\n'

	@staticmethod
	def makeline(count, linechar="-"):
		line = ""
		for i in range(count):
			line = line + linechar
		return input.strip() + '\n' + line + '\n'

	@staticmethod
	def starpad(input, count):
		input = " " + input.strip() + " "
		for i in range(count):
			input = "*" + input + "*"
		return input

	@staticmethod
	def spacepad(input, count):
		input = " " + input.strip() + " "
		for i in range(count):
			input = " " + input + " "
		return input

