from distutils.core import setup

setup(
    name='iTTY',
    version='0.9',
    description='Intelligent TTY Utilities for Network Administration',
    author='Jason Shaffner, Patrick Lawless',
    packages=['iTTY', 'iTTY.utils'],
    license="LGPL",
	scripts=[
		'scripts/run_commands',
		'scripts/check_version',
                'scripts/check_contact',
		'scripts/check_hostname',
		'scripts/check_location',
		'scripts/check_syslog',
		'scripts/check_trap_collectors',
                'scripts/verify_login',
                'scripts/can_i_login',
                'scripts/can_i_run_commands',
        ],
        classifiers=[
            "Development Status :: 4 - Beta",
            "Intended Audience :: Developers",
            "Programming Language :: Python",
            "Programming Language :: Python :: 3.7",
        ],
        requires=[
            'paramiko',
        ]
)
