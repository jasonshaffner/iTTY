from distutils.core import setup
setup(name='iTTY', 
	version='0.1', 
	description='Intelligent TTY Utilities for Network Administration',
	author='Jason Shaffner, Patrick Lawless',
	packages=['iTTY'], 
	scripts=['scripts/intflaplist', 'scripts/ipspace', 'scripts/runcommands'],
	requires=['paramiko', 'netaddr'],
	)
