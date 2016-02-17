iTTY
====

A small suite of tools designed to simplify network maintenance and administration.

The base module, iTTY.py, was created to provide a template to log in and run commands on multiple OS.

This has been tested to work with Cisco IOS-XR, Cisco IOS, Cisco ASA, Juniper JUNOS, and Alcatel TiMOS.

*SSH functionality is dependent on paramiko (https://github.com/paramiko/paramiko).

*There are also a number of scripts based on the module in development. Check the _scripts_ folder and documentation for more details.

iTTY.py can be run as a standalone multithreaded script. It will attempt login via SSH first, if unsuccessful will try Telnet.

It requires that commands be located in files titled: IOS, XR, ALU, ASA, and/or JUNOS

It requires that you have a file with a list of devices, one per line


Runs with optional args (recommended for use as part of another script)


`$ iTTY username password devicelistfilename [configmode y or n]`


or can be run using prompts (recommended for running manually)


`$ iTTY`

`Username: john.doe`

`Password: `

`Device list file: routers.txt`

`Are you making config changes? [y/n] y`

