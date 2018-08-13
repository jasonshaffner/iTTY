from iTTY import iTTY
from iTTY.format import Format

user = open('/home/jasonshaffner/authenticity/.user', 'r')
for un in user:
	username = un.strip()
hashes = open('/home/jasonshaffner/authenticity/.hash', 'r')
for pw in hashes:
	passwrd = pw.strip()
	password = passwrd.decode('base64')

command = ['terminal length 0', "admin sh install active summary | in CSC | utility wc -l"]
tty = iTTY(username=username, password=password, host='hstqtxl301r.texas.rr.com')
tty.setcommands(command)
print tty.login()
tty.runcommands(10)
print Format.siftoutput(tty.getoutput(), siftout=[username, password, tty.prompt])
print tty.getoutput()
