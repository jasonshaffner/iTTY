from distutils.core import setup

setup(
    name='iTTY',
	version='0.4',
	description='Intelligent TTY Utilities for Network Administration',
	author='Jason Shaffner, Patrick Lawless',
	url='https://git.netops.charter.com/jasonshaffner/iTTY',
	packages=['iTTY'],
    license="LGPL",
	scripts=[
        'scripts/intflaplist',
		'scripts/ipspace',
		'scripts/runcommands',
		'scripts/checklight',
		'scripts/checkversion',
		'scripts/checkowner',
		'scripts/ipv6intbrief',
        'scripts/verify_login',
    ],
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Programming Language :: Python",
        "Programming Language :: Python :: 3.5",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
    ],
	requires=[
        'paramiko',
		'netaddr',
    ]
	)
