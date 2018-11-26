"""
Telnet and SSH Client
"""

import getpass
import telnetlib
import time
import asyncio
import re
import socket
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
        self.timeout = kwargs.get('timeout', 10)
        self.os = None
        self.session = None
        self.shell = None
        self.prompt = None
        self.commands = []
        self.output = []


    def __enter__(self, **kwargs):
        """
        Support for "with" statements
        """
        self.__init__(kwargs)
        self.login()
        return self




    def __exit__(self, *args):
        """
        Support for "with" statements
        """
        self.logout()


    async def __aenter__(self, **kwargs):
        """
        Support for "async with" statements
        """
        self.__init__
        await self.async_login()
        return self


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
        if not self.username or not self.password or not self.host:
            raise LoginParametersNotSpecifiedError
        return True


    def set_os(self, prompt):
        """
        Takes prompt as arg, returns digit signifying type of OS
        """
        if re.search('[A-B]:.*#', str(prompt)):
            self.os = 1 #ALU
        elif re.search('CPU.*#', str(prompt)):
            self.os = 2  #XR
        elif re.search('.*#', str(prompt)) and not re.search('@', str(prompt)):
            self.set_commands(['show version', '.'])
            try:
                output = self.run_commands(3)
            except:
                return
            finally:
                self.clear_output()
            if re.search('A10', str(output)):
                self.os = 8 #A10
            elif re.search('Arista', str(output)):
                self.os = 7
            elif re.search('Invalid', str(output)):
                self.os = 10 #Niagara
            else:
                self.os = 3    #IOS
        elif re.search(''.join((self.username, '@.*>')), str(prompt)) and not re.search('@\(', str(prompt)):
            self.os = 4  #JUNOS
        elif re.search('.*>', str(prompt)) and not re.search(self.username, str(prompt)) and not re.search('cli', str(prompt)):
            self.set_commands(['show version', '.'])
            try:
                output = self.run_commands(3)
            except:
                return
            finally:
                self.clear_output()
            if re.search('Arista', str(output)):
                self.os = 7 #Arista
            elif re.search('A10', str(output)):
                self.os = 8
            else:
                self.os = 5  #ASA
                if self.shell:
                    self.prompt = "".join((self.prompt.strip()[0:-1], '#'))
                elif self.session:
                    self.prompt = "".join((self.prompt.strip()[0:-1], b'#'))
        elif re.search(''.join((self.username, '@\(')), str(prompt)):
            self.os = 6 #Big IP Load balancer
        elif re.search('refresh \:', str(prompt)) or re.search('--:- / cli->', str(prompt)):
            self.os = 9 #Avocent
        return self.os

    async def async_set_os(self, prompt):
        """
        Takes prompt as arg, returns digit signifying type of OS
        """
        if re.search('[A-B]:.*#', str(prompt)):
            self.os = 1 #ALU
        elif re.search('CPU.*#', str(prompt)):
            self.os = 2  #XR
        elif re.search('.*#', str(prompt)) and not re.search('@', str(prompt)):
            self.set_commands(['show version', 'q'])
            try:
                output = await self.async_run_commands(3)
            except:
                return
            finally:
                self.clear_output()
            if re.search('A10', str(output)):
                self.os = 8 #A10
            elif re.search('Arista', str(output)):
                self.os = 7 #Arista
            elif re.search('Invalid', str(output)):
                self.os = 10 #Niagara
            else:
                self.os = 3    #IOS
        elif re.search(''.join((self.username, '@.*>')), str(prompt)) and not re.search('@\(', str(prompt)):
            self.os = 4  #JUNOS
        elif re.search('.*>', str(prompt)) and not re.search(self.username, str(prompt)) and not re.search('cli', str(prompt)):
            self.set_commands(['show version', 'q'])
            try:
                output = await self.async_run_commands(3)
            except:
                return
            finally:
                self.clear_output()
            if re.search('Arista', str(output)):
                self.os = 7 #Arista
            elif re.search('A10', str(output)):
                self.os = 8
            else:
                self.os = 5  #ASA
                if self.shell:
                    self.prompt = "".join((self.prompt.strip()[0:-1], '#'))
                elif self.session:
                    self.prompt = "".join((self.prompt.strip()[0:-1], b'#'))
        elif re.search(''.join((self.username, '@\(')), str(prompt)):
            self.os = 6 #Big IP Load balancer
        elif re.search('refresh \:', str(prompt)) or re.search('--:- / cli->', str(prompt)):
            self.os = 9 #Avocent
        return self.os


    def get_os(self):
        """
        Returns integer signifying type of OS
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
            return await self.async_secure_login()
        except CouldNotConnectError:
            return await self.async_unsecure_login()


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
            connection = self.session.connect(self.host.strip('\n'),\
                                    username=self.username,\
                                    password=self.password,\
                                    look_for_keys=False,\
                                    allow_agent=False,\
                                    timeout=self.timeout)
            self.shell = self.session.invoke_shell()
            time.sleep(self.timeout)  #Allow time to log in and strip MOTD
            self.prompt = self.shell.recv(10000).decode().split('\n')[-1].strip().lstrip('*')
            self.set_os(self.prompt)
            return self.os
        except:
            return

    async def async_secure_login(self, **kwargs):
        if kwargs:
            self.host = kwargs.get('host', None)
            self.username = kwargs.get('username', None)
            self.password = kwargs.get('password', None)
        if not self.verify_login_parameters():
            return
        self.session = paramiko.SSHClient() #Create instance of SSHClient object
        self.session.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        await self.async_connect()
        await asyncio.sleep(self.timeout)  #Allow time to log in and strip MOTD
        self.prompt = await self.async_get_prompt()
        await self.async_set_os(self.prompt)
        return self.os

    @asyncio.coroutine
    def async_connect(self):
        loop = asyncio.get_event_loop()
        try:
            yield from loop.run_in_executor(None, partial(self.session.connect,\
                                    self.host.strip('\n'),\
                                    username=self.username,\
                                    password=self.password,\
                                    look_for_keys=False,\
                                    allow_agent=False,\
                                    timeout=self.timeout))
            self.shell = yield from loop.run_in_executor(None, self.session.invoke_shell)
        except Exception:
            self.session = None
            self.shell = None
            raise CouldNotConnectError(self.host)
            return


    @asyncio.coroutine
    def async_get_prompt(self):
        loop = asyncio.get_event_loop()
        raw_prompt = yield from loop.run_in_executor(None, partial(self.shell.recv, 10000))
        return raw_prompt.decode().split('\n')[-1].split('*')[-1].strip().lstrip('*')


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
        if not isinstance(self.password, bytes):
            self.password = self.password.encode()
        try:
            login_regex = re.compile(b"|".join([b'[Uu]sername', b'[Ll]ogin']))
            prompt_regex = re.compile(b"|".join([b'[AB]:.*#', b'CPU.*#', b'.*#', b'@.*>']))
            self.session = telnetlib.Telnet(self.host.strip('\n').encode(), 23, self.timeout)
            _, match, _ = self.session.expect([login_regex, ], timeout=self.timeout)
            if not match:
                return
            self.session.write(self.username.encode() + b'\r')
            _, match, _ = self.session.expect([b'assword'], timeout=self.timeout)
            if not match:
                return
            self.session.write(self.password + b'\r')
            _, _, previous_text = self.session.expect([prompt_regex,], timeout=self.timeout)
            self.prompt = previous_text.split(b'\n')[-1].strip().decode().lstrip('*')
            self.set_os(self.prompt)
            return self.os
        except:
            raise CouldNotConnectError(self.host)
            return


    async def async_unsecure_login(self, **kwargs):
        if kwargs:
            self.host = kwargs.get('host', None)
            self.username = kwargs.get('username', None)
            self.password = kwargs.get('password', None)
        loop = asyncio.get_event_loop()
        if not self.verify_login_parameters():
            return
        if not isinstance(self.password, bytes):
            self.password = self.password.encode()
        login_regex = re.compile(b"|".join([b'[Uu]sername', b'[Ll]ogin']))
        prompt_regex = re.compile(b"|".join([b'[AB]:.*#', b'CPU.*#', b'.*#', b'@.*>']))
        try:
            await self.async_telnet_login()
            if not self.session:
                return
            if not await self.async_expect(login_regex, self.timeout):
                self.session = None
                return
            self.session.write(self.username.encode() + b'\r')
            if not self.async_expect(b'assword', self.timeout):
                self.session = None
                return
            self.session.write(self.password + b'\r')
            match = await self.async_expect(prompt_regex, self.timeout)
            if match:
                self.prompt = match.split(b'\n')[-1].strip().decode().lstrip('*')
            else:
                raise CouldNotConnectError(self.host)
                return
            await self.async_set_os(self.prompt)
            return self.os
        except (ConnectionResetError, CouldNotConnectError):
            self.session = None
            raise CouldNotConnectError(self.host)
            return

    @asyncio.coroutine
    def async_telnet_login(self):
        loop = asyncio.get_event_loop()
        try:
            self.session = yield from loop.run_in_executor(None, partial(telnetlib.Telnet, self.host.strip('\n').encode(), 23, self.timeout))
        except (ConnectionRefusedError, OSError, socket.timeout):
            raise CouldNotConnectError(self.host)
            return

    def telnet_or_ssh(self):
        if isinstance(self.session, paramiko.SSHClient):
            return 'SSH'
        elif isinstance(self.session, telnetlib.Telnet):
            return 'Telnet'

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


    def run_sec_commands(self, command_delay=1, command_header=0, done=False):
        """
        Runs commands when logged in via SSH, returns output
        """
        for command in self.get_commands():
            if not isinstance(command, bytes):
                command = command.encode()
            reattempts = 0
            while not self.shell.get_transport().is_active():
                reattempts += 1
                self.secure_login()
                if reattempts > 2 and not self.shell.get_transport().is_active():
                    return
            self.shell.send(command.strip() + b'\r')
            time.sleep(command_delay)
            if command_header:
                self.add_to_output(['\n' + _underline(command), ])
            self.add_to_output(self.shell.recv(500000).decode().split('\n')[1:])
        if done:
            self.logout()
        return self.get_output()

    async def async_run_sec_commands(self, command_delay=1, command_header=0, done=False):
        for command in self.commands:
            if not isinstance(command, bytes):
                command = command.encode()
            try:
                if not self.shell.get_transport().is_active():
                    try:
                        await self.async_secure_login()
                    except CouldNotConnectError:
                        return
            except OSError:
                try:
                    await self.async_secure_login()
                except CouldNotConnectError:
                    return
            try:
                self.shell.send(command.strip() + b'\r')
            except OSError:
                return
            await asyncio.sleep(command_delay)
            if command.decode() != self.password.decode():
                if command_header:
                    self.add_to_output(['\n' + _underline(command.decode()), ])
                self.add_to_output(self.shell.recv(500000).decode().split('\n')[1:])
        if done:
            self.logout()
        return self.get_output()


    def run_unsec_commands(self, command_delay=1, command_header=0, done=False):
        """
        Runs commands when logged in via Telnet, returns output
        """
        for command in self.commands:
            if not isinstance(command, bytes):
                command = command.encode()
            self.session.write((command.strip() + b'\r'))
            try:
                _, _, output = self.session.expect([re.compile(self.prompt.encode()), ], command_delay)
            except (EOFError, ConnectionResetError):
                self.unsecure_login()
                self.session.write((command.strip() + b'\r'))
                try:
                    _, _, output = self.session.expect([re.compile(self.prompt.encode()), ], command_delay)
                except Exception:
                    return
            except Exception:
                return
            time.sleep(command_delay)
            if output and (str(command) != str(self.password) and str(command) != str(self.username)):
                if command_header:
                    self.add_to_output(['\n' + _underline(command.decode()), ])
                self.add_to_output(output.decode().split('\n')[1:])
        if done:
            self.logout()
        return self.get_output()


    async def async_run_unsec_commands(self, command_delay=1, command_header=0, done=False):
        for command in self.commands:
            output = await self.async_run_unsec_command(command, command_delay)
            if output and (str(command) != str(self.password) and str(command) != str(self.username)):
                if command_header:
                    self.add_to_output([''.join(('\n', _underline(command))), ])
                self.add_to_output(output.decode().split('\n')[1:])
        if done:
            self.logout()
        return self.output

    async def async_run_unsec_command(self, command, command_delay):
        try:
            await self.async_expect(command_delay=command_delay)
            self.session.write(command.strip().encode() + b'\r')
            return await self.async_expect(command_delay=command_delay)
        except (BrokenPipeError, ConnectionResetError):
            return


    @asyncio.coroutine
    def async_expect(self, expectation=None, command_delay=1):
        loop = asyncio.get_event_loop()
        if not expectation:
            expectation = re.compile(self.prompt.encode())
        if not isinstance(expectation, re.Pattern):
            if not isinstance(expectation, bytes):
                expectation = expectation.encode()
            expectation = re.compile(expectation)
        try:
            _, match, output = yield from loop.run_in_executor(None, partial(self.session.expect, [expectation], timeout=command_delay))
            if match:
                return output
        except (EOFError, ConnectionResetError):
            return

    def logout(self):
        try:
            if self.shell:
                self.shell.close()
            elif self.session:
                self.session.close()
            return
        except EOFError:
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

class CouldNotConnectError(Exception):
    pass

class LoginParametersNotSpecifiedError(Exception):
    pass
