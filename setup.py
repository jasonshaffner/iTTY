from distutils.core import setup

setup(name='iTTY',
	version='0.3',
	description='Intelligent TTY Utilities for Network Administration',
	author='Jason Shaffner, Patrick Lawless',
	url='https://git.netops.charter.com/jasonshaffner/iTTY',
	packages=['iTTY'],
	scripts=['scripts/intflaplist', 'scripts/ipspace', 'scripts/runcommands', \
		'scripts/checklight', 'scripts/checkversion', 'scripts/checkowner',\
		'scripts/ipv6intbrief'],
	requires=['paramiko', 'netaddr', 'format'],
	)
