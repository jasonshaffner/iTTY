"""
Telnet and SSH Client
"""

import getpass
import telnetlib
import time
import asyncio
import re
import socket
import warnings
from functools import partial
import paramiko
from paramiko.ssh_exception import SSHException, NoValidConnectionsError, AuthenticationException

paramiko.util.log_to_file('/dev/null')
warnings.simplefilter("ignore")
ansi_escape = re.compile("|".join([r'\x1B\[[0-?]*[ -/]*[@-~]', r'0xf2']))

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
        Context Manager
        """
        self.__init__
        self.login()
        return self


    def __exit__(self, *args):
        """
        Context Manager
        """
        self.logout()


    async def __aenter__(self, **kwargs):
        """
        Asynchronous Context Manager
        """
        self.__init__
        await self.async_login()
        return self


    async def __aexit__(self, *args):
        """
        Asynchronous Context Manager
        """
        self.logout()


    def set_host(self, host):
        """
        Sets host variable
        """
        self.host = host


    def get_host(self):
        """
        Returns host (if none set, default is None)
        """
        return self.host


    def clear_host(self):
        """
        Sets host variable = None
        """
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
        """
        Sets username and password variables = None
        """
        self.username = None
        self.password = None


    def verify_login_parameters(self):
        """
        Verifies that all necessary login parameters are set, raises LoginParametersNotSpecifiedError if not
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
            if re.search(' A10 ', str(output)):
                self.os = 8 #A10
            elif re.search('Arista', str(output)):
                self.os = 7
            elif re.search('Invalid', str(output)):
                self.os = 10 #Niagara
            elif re.search('ACSW', str(output)):
                self.os = 5
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
            if re.search('Arista', str(output)):
                self.os = 7 #Arista
            elif re.search(' A10 ', str(output)):
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
            self.set_commands(['show version'])
            try:
                output = await self.async_run_commands(3)
            except:
                return
            if re.search(' A10 ', str(output)):
                self.os = 8 #A10
            elif re.search('Arista', str(output)):
                self.os = 7 #Arista
            elif re.search('Invalid', str(output)):
                self.os = 10 #Niagara
            elif re.search('ACSW', str(output)):
                self.os = 5
            else:
                self.os = 3    #IOS
        elif re.search(''.join((self.username, '@.*>')), str(prompt)) and not re.search('@\(', str(prompt)):
            self.os = 4  #JUNOS
        elif re.search('.*>', str(prompt)) and not re.search(self.username, str(prompt)) and not re.search('cli', str(prompt)):
            self.set_commands(['show version'])
            try:
                output = await self.async_run_commands(3)
            except:
                return
            if re.search('Arista', str(output)):
                self.os = 7 #Arista
            elif re.search(' A10 ', str(output)):
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
        """
        Sets os variable = 0
        """
        self.os = 0


    def set_commands(self, commands):
        """
        Takes a list of commands as arg, sets commands to that list
        """
        self.commands = commands


    def set_commands_from_file(self, file):
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
        """
        Sets commands variable = []
        """
        self.commands = []


    def login(self, **kwargs):
        """
        Attempts to login to self.host using self.username and self.password to authenticate
        """
        if kwargs:
            self.host = kwargs.get('host', None)
            self.username = kwargs.get('username', None)
            self.password = kwargs.get('password', None)
        self.verify_login_parameters()
        try:
            return self.secure_login()
        except CouldNotConnectError:
            return self.unsecure_login()


    async def async_login(self, **kwargs):
        """
        Attempts to login to self.host using self.username and self.password to authenticate
        """
        if kwargs:
            self.host = kwargs.get('host', None)
            self.username = kwargs.get('username', None)
            self.password = kwargs.get('password', None)
        self.verify_login_parameters()
        try:
            return await self.async_secure_login()
        except CouldNotConnectError as e:
            try:
                return await self.async_unsecure_login()
            except CouldNotConnectError as e2:
                raise CouldNotConnectError(e, e2, host=self.host)


    def secure_login(self, **kwargs):
        """
        Attempts to login to devices via SSH, returns OS type if successful, if not returns 0
        """
        if kwargs:
            self.host = kwargs.get('host', None)
            self.username = kwargs.get('username', None)
            self.password = kwargs.get('password', None)
        self.verify_login_parameters()
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
        except (SSHException, NoValidConnectionsError, AuthenticationException, ValueError, EOFError, socket.error, socket.timeout) as e:
            self.session = None
            self.shell = None
            raise CouldNotConnectError({'ssh': str(e)})

    async def async_secure_login(self, **kwargs):
        """
        Attempts to login to devices via SSH asyncrhonously, returns OS type if successful, if not returns 0
        """
        if kwargs:
            self.host = kwargs.get('host', None)
            self.username = kwargs.get('username', None)
            self.password = kwargs.get('password', None)
        if not isinstance(self.password, bytes):
            self.password = self.password.encode()
        self.verify_login_parameters()
        self.session = paramiko.SSHClient() #Create instance of SSHClient object
        self.session.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        await self._async_connect()
        await asyncio.sleep(self.timeout)  #Allow time to log in and strip MOTD
        self.prompt = await self._async_get_prompt()
        await self.async_set_os(self.prompt)
        return self.os

    @asyncio.coroutine
    def _async_connect(self):
        """
        Helper to async_secure_login, performs the login via SSH
        """
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
        except (SSHException, NoValidConnectionsError, AuthenticationException, EOFError, ValueError, socket.error, socket.timeout) as e:
            self.session = None
            self.shell = None
            raise CouldNotConnectError({'ssh': str(e)})


    @asyncio.coroutine
    def _async_get_prompt(self):
        """
        Helper to async_secure_login, finds the prompt for the device
        """
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
        self.verify_login_parameters()
        if not isinstance(self.password, bytes):
            self.password = self.password.encode()
        try:
            login_regex = re.compile(b"|".join([b'[Uu]sername', b'[Ll]ogin']))
            prompt_regex = re.compile(b"|".join([b'[AB]:.*#', b'CPU.*#', b'.*#', b'@.*>']))
            self.session = telnetlib.Telnet(self.host.strip('\n').encode(), 23, self.timeout)
            _, match, _ = self.session.expect([login_regex, ], timeout=self.timeout)
            if not match:
                raise CouldNotConnectError(self.host)
            self.session.write(self.username.encode() + b'\r')
            _, match, _ = self.session.expect([b'assword'], timeout=self.timeout)
            if not match:
                raise CouldNotConnectError(self.host)
            self.session.write(self.password + b'\r')
            _, match, previous_text = self.session.expect([prompt_regex,], timeout=self.timeout)
            if not match:
                raise CouldNotConnectError(self.host)
            self.prompt = previous_text.split(b'\n')[-1].strip().decode().lstrip('*')
            self.set_os(self.prompt)
            return self.os
        except (CouldNotConnectError, ConnectionResetError, BrokenPipeError, ConnectionRefusedError, EOFError, OSError, socket.timeout) as e:
            self.session = None
            raise CouldNotConnectError({'telnet': str(e)})


    async def async_unsecure_login(self, **kwargs):
        """
        Attempts fo login to devices via Telnet asynchronously, returns OS type if successful, if not returns 0
        """
        if kwargs:
            self.host = kwargs.get('host', None)
            self.username = kwargs.get('username', None)
            self.password = kwargs.get('password', None)
        loop = asyncio.get_event_loop()
        self.verify_login_parameters()
        if not isinstance(self.password, bytes):
            self.password = self.password.encode()
        login_regex = re.compile(b"|".join([b'[Uu]sername', b'[Ll]ogin']))
        prompt_regex = re.compile(b"|".join([b'[AB]:.*#', b'CPU.*#', b'.*#', b'@.*>']))
        try:
            await self._async_telnet_login()
            if not await self._async_expect(login_regex, self.timeout):
                raise CouldNotConnectError({'telnet': 'host did not prompt for username'})
            self.session.write(self.username.encode() + b'\r')
            if not self._async_expect(b'assword', self.timeout):
                raise CouldNotConnectError({'telnet': 'host did not prompt for password'})
            self.session.write(self.password + b'\r')
            match = await self._async_expect(prompt_regex, self.timeout)
            if match:
                self.prompt = match.split('\n')[-1].strip().lstrip('*')
            else:
                raise CouldNotConnectError({'telnet': 'Authentication failed'})
            await self.async_set_os(self.prompt)
            return self.os
        except (ConnectionResetError, BrokenPipeError, socket.timeout, BrokenConnectionError) as e:
            self.session = None
            raise CouldNotConnectError({'telnet': str(e)})

    @asyncio.coroutine
    def _async_telnet_login(self):
        """
        Helper to async_unsecure_login, performs login
        """
        loop = asyncio.get_event_loop()
        try:
            self.session = yield from loop.run_in_executor(None, partial(telnetlib.Telnet, self.host.strip('\n').encode(), 23, self.timeout))
        except (ConnectionRefusedError, OSError, socket.timeout, BrokenPipeError, EOFError, BrokenConnectionError) as e:
            raise CouldNotConnectError({'telnet': str(e)})

    def telnet_or_ssh(self):
        """
        Returns 'SSH' if login via SSH, else Telnet if login via Telnet
        """
        if isinstance(self.session, paramiko.SSHClient):
            return 'SSH'
        elif isinstance(self.session, telnetlib.Telnet):
            return 'Telnet'

    def run_commands(self, command_delay, command_header=0, done=False):
        """
        Runs commands stored in self.commands on remote device
        """
        if self.shell:
            return self.run_sec_commands(command_delay, command_header=command_header, done=done)
        elif self.session:
            return self.run_unsec_commands(command_delay, command_header=command_header, done=done)


    async def async_run_commands(self, command_delay, command_header=0, done=False):
        """
        Runs commands stored in self.commands asynchronously on remote device
        """
        if self.shell:
            return await self.async_run_sec_commands(command_delay, command_header=command_header, done=done)
        elif self.session:
            return await self.async_run_unsec_commands(command_delay, command_header=command_header, done=done)


    def run_sec_commands(self, command_delay=1, command_header=0, done=False):
        """
        Runs commands when logged in via SSH, returns output
        """
        output = []
        for command in self.get_commands():
            if not isinstance(command, bytes):
                command = command.encode()
            try:
                if not self.shell.get_transport().is_active():
                    try:
                        self.secure_login()
                    except CouldNotConnectError:
                        return
            except OSError:
                try:
                    self.secure_login()
                except CouldNotConnectError:
                    return
            try:
                self.shell.send(command.strip() + b'\r')
            except OSError:
                return
            time.sleep(command_delay)
            if command_header:
                output.append('\n' + _underline(command))
            output.append(self.shell.recv(500000).strip().decode(errors="ignore").split('\n')[1:])
        if done:
            self.logout()
        return output

    async def async_run_sec_commands(self, command_delay=1, command_header=0, done=False):
        """
        Runs commands asynchronously when logged in via SSH, returns output
        """
        output = []
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
            except OSError as e:
                raise BrokenConnectionError(self.host, e)
            await asyncio.sleep(command_delay)
            if command != self.password:
                if command_header:
                    output.append(['\n' + _underline(command.decode()), ])
                raw = self.shell.recv(500000).strip().decode(errors="ignore").split('\n')[1:]
                output.append([ansi_escape.sub('', line) for line in raw])
                if raw and not (self.prompt.strip('#>') in raw[-1] or 'sername' in raw[-1] or 'assword' in raw[-1]):
                    try:
                        self.shell.send('q'.encode() + b'\r')
                    except OSError:
                        pass
                    await asyncio.sleep(3)
        if done:
            self.logout()
        return output


    def run_unsec_commands(self, command_delay=1, command_header=0, done=False):
        """
        Runs commands when logged in via Telnet, returns output
        """
        output = []
        for command in self.commands:
            if not isinstance(command, bytes):
                command = command.encode()
            self.session.write((command.strip() + b'\r'))
            try:
                _, _, out = self.session.expect([re.compile(self.prompt.encode()), ], command_delay)
            except (EOFError, BrokenPipeError, ConnectionResetError):
                self.unsecure_login()
                self.session.write((command.strip() + b'\r'))
                try:
                    _, _, out = self.session.expect([re.compile(self.prompt.encode()), ], command_delay)
                except (EOFError, BrokenPipeError, ConnectionResetError):
                    return
            time.sleep(command_delay)
            if out and (str(command) != str(self.password) and str(command) != str(self.username)):
                if command_header:
                    output.append(['\n' + _underline(command.decode()), ])
                output.append(out.decode().split('\n')[1:])
        if done:
            self.logout()
        return output


    async def async_run_unsec_commands(self, command_delay=1, command_header=0, done=False):
        """
        Runs commands asynchronously when logged in via Telnet, returns output
        """
        output = []
        for command in self.commands:
            out = await self._async_run_unsec_command(command, command_delay)
            if out and (str(command) != str(self.password) and str(command) != str(self.username)):
                if command_header:
                    output.append([''.join(('\n', _underline(command))), ])
                output.append(out.split('\n')[1:])
        if done:
            self.logout()
        return output

    async def _async_run_unsec_command(self, command, command_delay):
        """
        Helper to async_run_unsec_commands, writes are returns output of commands
        """
        try:
            await self._async_expect(command_delay=command_delay)
            self.session.write(command.strip().encode() + b'\r')
            return await self._async_expect(command_delay=command_delay)
        except (BrokenPipeError, ConnectionResetError) as e:
            raise BrokenConnectionError(self.host, e)


    @asyncio.coroutine
    def _async_expect(self, expectation=None, command_delay=1):
        """
        Helper to async_run_unsec_commands, performs "expect"
        """
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
                return ansi_escape.sub('', output.decode())
        except (EOFError, ConnectionResetError) as e:
            raise BrokenConnectionError(self.host, e)

    def logout(self):
        """
        Performs logout of SSH and Telnet logins
        """
        try:
            if self.shell:
                self.shell.close()
            if self.session:
                self.session.close()
            return
        except EOFError:
            return


    def sift_output(self, output, *sift_out):
        """
        Helper command that sifts unwanted output from output
        """
        dont_print = ['enable', 'Password:', 'terminal length', 'screen-length', 'Screen length', \
            'terminal pager', 'environment no more', '{master', '{primary', '{secondary', 'Building config', \
            'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun',] + list(sift_out)
        filtered_output= []
        for entry in output:
            for line in entry:
                if not line.strip() or any(str(n) in line for n in dont_print):
                    continue
                filtered_output.append(line)
        return filtered_output



class CouldNotConnectError(Exception):
    """
    Exception that is raised when unable to connect to a remote device
    """
    def __init__(self, *source_exceptions, **kwargs):
        self.host = kwargs.get('host')
        if len(source_exceptions) == 1:
            source_exceptions = source_exceptions[0]
        if isinstance(source_exceptions, dict):
            self.message = source_exceptions
            self.exceptions = source_exceptions
        else:
            if isinstance(source_exceptions, (list, tuple, set)):
                self.exceptions = dict()
                exc = None
                try:
                    for exception in source_exceptions:
                        exc = exception
                        self.exceptions.update(exception.exceptions)
                except TypeError as e:
                    print('TypeError:', e, exc.exceptions)
                except ValueError as e:
                    print('ValueError:', e, exc.exceptions)
            else:
                self.exceptions = str(source_exceptions)
            self.message = str(self.exceptions)\
                    if not isinstance(self.exceptions, (list, tuple, set))\
                    else ', '.join([str(exception.exceptions) for exception in self.exceptions])
        super().__init__(self.message)

    def __str__(self):
        return str(self.as_dict())

    def as_dict(self):
        if self.host:
            return {'CouldNotConnectError': {'host': self.host, 'exceptions': self.exceptions}}
        else:
            return {'CouldNotConnectError': {'exceptions': self.exceptions}}


    def __repr__(self):
        return f'CouldNotConnectError({self.message})'


class BrokenConnectionError(Exception):
    """
    Exception that is raised when an established connection fails
    """
    def __init__(self, host, source_exception):
        self.host = host
        self.source_exception = source_exception
        self.message = " ".join(('{ host:', host, '} {', str(source_exception), '}'))
        super().__init__(self.message)

    def __str__(self):
        return self.message

    def __repr__(self):
        return f'BrokenConnectionError({self.host}, {self.source_exception})'


class LoginParametersNotSpecifiedError(Exception):
    """
    Exception that is rasied when either username or password is not specified before login
    """
    pass


def _underline(input, line_char="-"):
    """
    Format helper, makes lines under a string
    """
    return input.strip() + '\n' + _make_line(len(input.strip()), line_char)


def _make_line(count, line_char="-"):
    """
    Format helper, makes lines
    """
    return line_char * int(count)
