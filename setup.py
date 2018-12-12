from distutils.core import setup

setup(
    name='iTTY',
    version='0.8',
    description='Intelligent TTY Utilities for Network Administration',
    author='Jason Shaffner, Patrick Lawless',
    packages=['iTTY'],
    license="LGPL",
	scripts=[
		'scripts/run_commands',
		'scripts/run_commands_with_variables',
		'scripts/check_version',
                'scripts/check_contact',
		'scripts/check_location',
		'scripts/check_syslog',
		'scripts/check_trap_collectors',
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
