from distutils.core import setup
setup(name='iTTY', 
	version='0.2', 
	description='Intelligent TTY Utilities for Network Administration',
	author='Jason Shaffner, Patrick Lawless',
	url='https://github.com/jasonshaffner/iTTY',
	packages=['iTTY'], 
	scripts=['scripts/intflaplist', 'scripts/ipspace', 'scripts/runcommands', \
		'scripts/checklight', 'scripts/checkversion'],
	requires=['paramiko', 'netaddr'],
	)
