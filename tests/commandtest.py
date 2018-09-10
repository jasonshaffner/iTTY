from iTTY import iTTY
from format import Format
from authenticity import Authenticity

usernamesAndPassword = Authenticity.get_usernames_and_passwords()
username = usernamesAndPassword['twc_user']
password = usernamesAndPassword['twc_password']

tty = iTTY(username=username, password=password, host='hstqtxl301r.texas.rr.com')

with tty:
	command = ['terminal length 0', "admin sh install active summary | in CSC | utility wc -l"]
	tty.setcommands(command)
	tty.runcommands(10)
	print(Format.siftoutput(tty.getoutput(), siftout=[username, password, tty.prompt]))
	print(tty.getoutput())
