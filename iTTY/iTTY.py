"""
Telnet and SSH Client
"""

import getpass
import telnetlib
import time
import asyncio
import re
from functools import partial
import paramiko

paramiko.util.log_to_file('/dev/null')

class iTTY:
    """
    iTTY is a class to ensure easy logging in and running of commands on multiple platforms.
    This is developed by network engineers specifically for logging in to network devices (routers, switches, firewalls, etc.)
    but could be extended for other systems should the need arise. We build off the standard built-in telnetlib and paramiko so
    we have multiple ways to log in. We first attempt secure (ssh) logins, then use telnet as a backup.
    This has been tested to work with Cisco IOS-XR, Cisco IOS, Cisco ASA, Juniper JUNOS, and Alcatel/Nokia TiMOS.
    """


    def __init__(self, **kwargs):
        """
        Factory, optional keyword args: host, username, password
        """
        self.host = kwargs.get('host', None)
        self.username = kwargs.get('username', None)
        self.password = kwargs.get('password', None)
        self.timeout = kwargs.get('timeout', 5)
        self.os = None
        self.session = None
        self.shell = None
        self.prompt = None
        self.commands = []
        self.output = []


    def __enter__(self):
        """
        Support for "with" statements
        """
        self.login()


    def __exit__(self, *args):
        """
        Support for "with" statements
        """
        self.logout()


    async def __aenter__(self):
        """
        Support for "async with" statements
        """
        await self.async_login()


    async def __aexit__(self, *args):
        """
        Support for "async with" statements
        """
        self.logout()


    def set_host(self, host):
        """
        Sets which host to login and run_ commands
        """
        self.host = host


    def get_host(self):
        """
        Returns host (if none set, default is None)
        """
        return self.host


    def clear_host(self):
        self.host = None


    def set_login(self, **kwargs):
        """
        Sets username and password used for login
        """
        self.username = kwargs.get('username', None)
        if not self.username:
            self.username = input("Username: ")
        self.password = kwargs.get('password', None)
        if not self.password:
            self.password = getpass.getpass()


    def get_username(self):
        """
        Returns username (if none set, default is None)
        """
        return self.username


    def clear_login(self):
        self.username = None
        self.password = None


    def verify_login_parameters(self):
        """
        Verifies that all necessary login parameters are set, returns 0 if one is missing
        """
        flag = 1
        if not self.username:
            print("No username specified")
            flag = 0
        if not self.password:
            print("No password specified")
            flag = 0
        if not self.host:
            print("No host specified")
            flag = 0
        return flag


    def set_os(self, prompt):
        """
        Takes prompt as arg, returns digit signifying type of OS
        """
        if re.search('[A-B]:.*#', str(prompt)):
            self.os = 1 #ALU
        elif re.search('CPU.*#', str(prompt)):
            self.os = 2  #XR
        elif re.search('.*#', str(prompt)):
            self.os = 3    #IOS
        elif re.search(self.username + '@.*>', str(prompt)):
            self.os = 4  #JUNOS
        elif re.search('.*>', str(prompt)):
            self.os = 5  #ASA
            if self.shell:
                self.prompt = "".join(self.prompt.strip()[0:-1], '#')
            elif self.session:
                self.prompt = "".join(self.prompt.strip()[0:-1], b'#')
        return self.os


    def get_os(self):
        """
        Returns digit signifying type of OS
        """
        return self.os


    def clear_os(self):
        self.os = 0


    def set_commands(self, commands):
        """
        Takes a list of commands as arg, set_s commands to that list
        """
        self.commands = commands


    def set_commandsfromfile(self, file):
        """
        Takes a file with list of commands as arg, set_s commands to that list
        """
        self.commands = list(open(file, 'r'))


    def add_command(self, command):
        """
        Takes a single command as arg, appends command to list of commands
        """
        self.commands.append(command)


    def get_commands(self):
        """
        Returns list of commands to run_
        """
        return self.commands


    def clear_commands(self):
        self.commands = []


    def set_output(self, output):
        """
        Sets the output of commands run, overwriting any previous entries
        """
        self.output = output


    def add_to_output(self, output):
        """
        Adds to output of commands run
        """
        self.output.append(output)


    def get_output(self):
        """
        Returns output from client
        """
        return self.output


    def clear_output(self):
        self.output = []


    def login(self, **kwargs):
        if kwargs:
            self.host = kwargs.get('host', None)
            self.username = kwargs.get('username', None)
            self.password = kwargs.get('password', None)
        if not self.verify_login_parameters():
            return
        if self.secure_login() or self.unsecure_login():
            return self.os


    async def async_login(self, **kwargs):
        if kwargs:
            self.host = kwargs.get('host', None)
            self.username = kwargs.get('username', None)
            self.password = kwargs.get('password', None)
        if not self.verify_login_parameters():
            return
        try:
            if await self.async_secure_login() or await self.async_unsecure_login():
                return self.os
        except:
            return None


    def secure_login(self, **kwargs):
        """
        Attempts to login to devices via SSH, returns OS type if successful, if not returns 0
        """
        if kwargs:
            self.host = kwargs.get('host', None)
            self.username = kwargs.get('username', None)
            self.password = kwargs.get('password', None)
        if not self.verify_login_parameters():
            return
        try:
            self.session = paramiko.SSHClient() #Create instance of SSHClient object
            self.session.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            self.session.connect(self.host.strip('\n'),\
                                    username=self.username,\
                                    password=self.password,\
                                    look_for_keys=False,\
                                    allow_agent=False,\
                                    timeout=self.timeout)
            self.shell = self.session.invoke_shell()
            time.sleep(3)  #Allow time to log in and strip MOTD
            self.prompt = self.shell.recv(1000).decode().split('\n')[-1].strip()
            self.set_os(self.prompt)
            return self.os
        except:
            return

    @asyncio.coroutine
    def async_secure_login(self, **kwargs):
        if kwargs:
            self.host = kwargs.get('host', None)
            self.username = kwargs.get('username', None)
            self.password = kwargs.get('password', None)
        loop = asyncio.get_event_loop()
        if not self.verify_login_parameters():
            return
        try:
            self.session = paramiko.SSHClient() #Create instance of SSHClient object
            self.session.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            _ = yield from loop.run_in_executor(None, partial(self.session.connect,\
                                    self.host.strip('\n'),\
                                    username=self.username,\
                                    password=self.password,\
                                    look_for_keys=False,\
                                    allow_agent=False,\
                                    timeout=self.timeout))
            self.shell = yield from loop.run_in_executor(None, self.session.invoke_shell)
            time.sleep(3)  #Allow time to log in and strip MOTD
            self.prompt = self.shell.recv(1000).decode().split('\n')[-1].strip()
            self.set_os(self.prompt)
            return self.os
        except:
            return


    def unsecure_login(self, **kwargs):
        """
        Attempts fo login to devices via Telnet, returns OS type if successful, if not returns 0
        """
        if kwargs:
            self.host = kwargs.get('host', None)
            self.username = kwargs.get('username', None)
            self.password = kwargs.get('password', None)
        if not self.verify_login_parameters():
            return
        if type(self.password) != bytes:
            self.password = self.password.encode()
        try:
            login_regex = re.compile(b"|".join([b'[Uu]sername', b'[Ll]ogin']))
            prompt_regex = re.compile(b"|".join([b'[AB]:.*#', b'CPU.*#', b'.*#', b'@.*>']))
            self.session = telnetlib.Telnet(self.host.strip('\n').encode(), 23, self.timeout)
            self.session.expect([login_regex, ], 5)
            self.session.write(self.username.encode() + b'\r')
            self.session.read_until(b'assword')
            self.session.write(self.password + b'\r')
            _, _, previous_text = self.session.expect([prompt_regex,], 7)
            self.prompt = previous_text.split(b'\n')[-1].strip().decode()
            self.set_os(self.prompt)
            return self.os
        except:
            return


    @asyncio.coroutine
    def async_unsecure_login(self, **kwargs):
        if kwargs:
            self.host = kwargs.get('host', None)
            self.username = kwargs.get('username', None)
            self.password = kwargs.get('password', None)
        loop = asyncio.get_event_loop()
        if not self.verify_login_parameters():
            return
        if type(self.password) != bytes:
            self.password = self.password.encode()
        login_regex = re.compile(b"|".join([b'[Uu]sername', b'[Ll]ogin']))
        prompt_regex = re.compile(b"|".join([b'[AB]:.*#', b'CPU.*#', b'.*#', b'@.*>']))
        try:
            self.session = yield from loop.run_in_executor(None, partial(telnetlib.Telnet, self.host.strip('\n').encode(), 23, self.timeout))
            _ = yield from loop.run_in_executor(None, partial(self.session.expect, [login_regex, ], 5))
            self.session.write(self.username.encode() + b'\r')
            _ = yield from loop.run_in_executor(None, partial(self.session.read_until, b'assword'))
            self.session.write(self.password + b'\r')
            _, _, previous_text = yield from loop.run_in_executor(None, partial(self.session.expect, [prompt_regex,], 7))
            self.prompt = previous_text.split(b'\n')[-1].strip().decode()
            self.set_os(self.prompt)
            return self.os
        except:
            return


    def run_commands(self, command_delay, command_header=0, done=False):
        if self.shell:
            return self.run_sec_commands(command_delay, command_header=command_header, done=done)
        elif self.session:
            return self.run_unsec_commands(command_delay, command_header=command_header, done=done)


    async def async_run_commands(self, command_delay, command_header=0, done=False):
        if self.shell:
            return await self.async_run_sec_commands(command_delay, command_header=command_header, done=done)
        elif self.session:
            return await self.async_run_unsec_commands(command_delay, command_header=command_header, done=done)


    def run_sec_commands(self, command_delay, command_header=0, done=False):
        """
        Runs commands when logged in via SSH, returns output
        """
        for command in self.get_commands():
            reattempts = 0
            while not self.shell.get_transport().is_active():
                reattempts += 1
                self.secure_login()
                if reattempts > 2 and not self.shell.get_transport().is_active():
                    return
            self.shell.send(command.strip() + '\r')
            time.sleep(command_delay)
            if command_header:
                self.add_to_output(['\n' + _underline(command), ])
            self.add_to_output(self.shell.recv(500000).decode().split('\n')[1:])
        if done:
            self.logout()
        return self.get_output()

    async def async_run_sec_commands(self, command_delay, command_header=0, done=False):
        for command in self.get_commands():
            reattempts = 0
            while not self.shell.get_transport().is_active():
                reattempts += 1
                await self.async_secure_login()
                if reattempts > 2 and not self.shell.get_transport().is_active():
                    return
            self.shell.send(command.strip() + '\r')
            await asyncio.sleep(command_delay)
            if command_header:
                self.add_to_output(['\n' + _underline(command), ])
            self.add_to_output(self.shell.recv(500000).decode().split('\n')[1:])
        if done:
            self.logout()
        return self.get_output()


    def run_unsec_commands(self, command_delay, command_header=0, done=False):
        """
        Runs commands when logged in via Telnet, returns output
        """
        for command in self.commands:
            self.session.write((command.strip() + '\r').encode())
            try:
                _, _, output = self.session.expect([re.compile(self.prompt.encode()), ], command_delay)
            except EOFError:
                self.unsecure_login()
                self.session.write((command.strip() + '\r').encode())
                try:
                    _, _, output = self.session.expect([re.compile(self.prompt.encode()), ], command_delay)
                except Exception:
                    return
            time.sleep(command_delay)
            if command_header:
                self.add_to_output(['\n' + _underline(command), ])
            self.add_to_output(output.decode().split('\n')[1:])
        if done:
            self.logout()
        return self.get_output()

    @asyncio.coroutine
    def async_run_unsec_commands(self, command_delay, command_header=0, done=False):
        loop = asyncio.get_event_loop()
        for command in self.commands:
            self.session.write((command.strip() + '\r').encode())
            try:
                _, _, output = yield from loop.run_in_executor(None, partial(self.session.expect, [re.compile(self.prompt.encode()), ], command_delay))
            except EOFError:
                _ = yield from self.async_unsecure_login()
                self.session.write((command.strip() + '\r').encode())
                try:
                    _, _, output = yield from loop.run_in_executor(None, partial(self.session.expect, [re.compile(self.prompt.encode()), ], command_delay))
                except Exception:
                    return
            #time.sleep(command_delay)
            if command_header:
                self.add_to_output(['\n' + _underline(command), ])
            self.add_to_output(output.decode().split('\n')[1:])
        if done:
            self.logout()
        return self.get_output()


    def logout(self):
        if self.shell:
            self.shell.close()
        elif self.session:
            self.session.close()
        return


    def sift_output(self, *sift_out):
        dont_print = ['enable', 'Password:', 'terminal length', 'screen-length', 'Screen length', \
            'terminal pager', 'environment no more', '{master', 'Building config', \
            'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun',] + list(sift_out)
        output= []
        for entry in self.output:
            for line in entry:
                if not line.strip() or any(str(n) in line for n in dont_print):
                    continue
                output.append(line)
        return output


def _underline(input, line_char="-"):
    return input.strip() + '\n' + _make_line(len(input.strip()), line_char)


def _make_line(count, line_char="-"):
    return line_char * int(count)
