Created to provide a template to log in and run commands on multiple OS, primarily for network maintenance and administration.
This has been tested to work with Cisco IOS-XR, Cisco IOS, Cisco ASA, Juniper JUNOS, and Alcatel TiMOS.

*SSH functionality is dependent on paramiko (https://github.com/paramiko/paramiko).

iTTY.py can be run as a standalone multithreaded script. It will attempt login via SSH first, if unsuccessful will try Telnet.

run with optional args (recommended for use as part of another script)

$ python iTTY.py username password devicelistfilename [configmode y or n]

or can be run using prompts (recommended for running manually)

$ python iTTY.py
Username: john.doe
Password: 
Device list file: routers.txt
Are you making config changes? [y/n] y
