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
		for i in range(len(input.strip())):
			line = line + linechar
		return input.strip() + '\n' + line

	@staticmethod
	def makeline(count, linechar="-"):
		line = ""
		for i in range(count):
			line = line + linechar
		return line

	@staticmethod
	def pad(input, count, padchar=" "):
		input = " " + input.strip() + " "
		for i in range(count):
			input = padchar + input + padchar
		return input

	@staticmethod
	def padleft(input, count, padchar=" "):
		for i in range(count): input = padchar + input
		return input

	@staticmethod
	def padright(input, count, padchar=" "):
		for i in range(count): input += padchar
		return input

	@staticmethod
	def columnize(input, bars=0, width=0):
		maxlen = []
		for i in input:
			n = 0
			for j in i:
				if len(maxlen) < len(i): maxlen.append(len(j))
				else: maxlen[n] = max(maxlen[n], len(j))	
				n += 1
		for i in range(len(input)):
			n = 0
			for j in range(len(input[i])):
				padding = maxlen[n] - len(input[i][j]) 
				if bars: 
					input[i][j] = Format.padright(Format.padright(input[i][j], padding + width/2) + '|', width/2)
					if j == 0: input[i][j] = '| ' + input[i][j]
				else: input[i][j] = Format.padright(input[i][j], padding + width) 
				n += 1
		return input
