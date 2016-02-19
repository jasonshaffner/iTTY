import re, sys

class Format(object):
	#Cleans up and provides basic formatting for output
	@staticmethod
	def siftoutput(input, **kwargs): 
		siftout = kwargs.get('siftout', [])
		dontprint = ['enable', 'Password:', 'terminal length', 'screen-length', 'Screen length',\
			'environment no more', '{master', 'Building config', 'Mon', 'Tue', 'Wed', \
			'Thu', 'Fri', 'Sat', 'Sun'] + siftout
		temp = []
		for entry in input:
			for line in entry:
				if any(n in line for n in dontprint): continue
				temp.append(line)
			temp.append('\n')
		return temp

	@staticmethod
	def underline(input):
		line = ""
		for i in range(len(input)):
			line = line + "_"	
		return input.strip() + '\n' + line + '\n'

	@staticmethod
	def starpad(input, count):
		input = " " + input.strip() + " "
		for i in range(count):
			input = "*" + input + "*"
		return input

