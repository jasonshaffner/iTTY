import re, sys

class Format(object):
	#Cleans up and provides basic formatting for output
	@staticmethod
	def siftoutput(input, **kwargs): 
		siftout = kwargs.get('siftout', [])
		dontprint = ['enable', 'Password:', 'terminal length', 'screen-length', 'Screen length',\
			'environment no more', '{master', 'Building config', 'Mon', 'Tue', 'Wed', \
			'Thu', 'Fri', 'Sat', 'Sun', 'terminal pager'] + siftout
		output = []
		for entry in input:
			for line in entry:
				if not line.strip() or any(n in line for n in dontprint): continue
				output.append(line)
		return output

	@staticmethod
	def makeline(count, linechar="-"):
		return linechar * count

	@staticmethod
	def underline(input, linechar="-"):
		return input.strip() + '\n' + Format.makeline(input.strip(), linechar)

	@staticmethod
	def padleft(input, count, padchar=" "):
		return Format.makeline(count, padchar) + " " + input

	@staticmethod
	def padright(input, count, padchar=" "):
		return input + " " + Format.makeline(count, padchar)

	@staticmethod
	def pad(input, count, padchar=" "):
		return Format.padleft(Format.padright(input, count, padchar), count, padchar)

	@staticmethod
	def columnize(input, bars=0, width=0):
		maxlen = []
		for line in input:
			n = 0
			for entry in line:
				if len(maxlen) < len(line): maxlen.append(len(entry))
				else: maxlen[n] = max(maxlen[n], len(entry))
				n += 1
		output = '\n'
		for line in input:
			n = 0
			if bars: tmp = '| '
			else: tmp = ""
			for entry in line:
				padding = maxlen[n] - len(entry)
				if bars: tmp += Format.padright(Format.padright(entry, padding + width/2) + '|', width/2)
				else: tmp += Format.padright(entry, padding + width) 
				n += 1
			if bars and (line == input[0] or line == input[-1]): tmp = Format.underline(tmp) 
			output += tmp + '\n'
		return output
