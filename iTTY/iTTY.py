"""
Telnet and SSH Client
"""

import telnetlib
import time
import asyncio
import re
import socket
import warnings
import traceback
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

    ALU = 1
    XR = 2
    IOS = 3
    JUNOS = 4
    ASA = 5
    F5 = 6
    EOS = 7
    A10 = 8
    AVOCENT = 9
    NIAGARA = 10
    NXOS = 11
    IOSXE = 12


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


    def verify_login_parameters(self):
        """
        Verifies that all necessary login parameters are set, raises LoginParametersNotSpecifiedError if not
        """
        if not self.username or not self.password or not self.host:
            raise LoginParametersNotSpecifiedError
        return True


    def set_os(self, prompt):
        """
        Takes prompt as arg, returns integer signifying type of OS
        """
        if re.search('[A-B]:.*#', str(prompt)):
            self.os = self.ALU
        elif re.search('CPU.*#', str(prompt)):
            self.os = self.XR
        elif re.search('.*#', str(prompt)) and not re.search('@', str(prompt)):
            try:
                output = self.run_commands('show version', 3)
            except BrokenConnectionError:
                raise
            if re.search(' A10 ', str(output)):
                self.os = self.A10
            elif re.search('Arista', str(output)):
                self.os = self.EOS
            elif re.search('Invalid', str(output)):
                self.os = self.NIAGARA
            elif re.search('ACSW', str(output)):
                self.os = self.ASA
            elif re.search('NX-OS', str(output)):
                self.os = self.NXOS
            elif re.search('IOS-XE', str(output)):
                self.os = self.IOSXE
            else:
                self.os = self.IOS
        elif re.search(''.join((self.username, '@.*>')), str(prompt)) and not re.search('@\(', str(prompt)):
            self.os = self.JUNOS
        elif re.search('.*>', str(prompt)) and not re.search(self.username, str(prompt)) and not re.search('->', str(prompt)):
            try:
                output = self.run_commands('show version', 3)
            except:
                return
            if re.search('Arista', str(output)):
                self.os = self.EOS
            elif re.search(' A10 ', str(output)):
                self.os = self.A10
            else:
                try:
                    self.run_commands(['enable', self.password], 3)
                except BrokenConnectionError:
                    raise
                if re.search('NX-OS', str(output)):
                    self.os = self.NXOS
                elif re.search('IOS-XE', str(output)):
                    self.os = self.IOSXE
                elif re.search(r'(?:^| |\t)IOS(?:$| |\t)', str(output)):
                    self.os = self.IOS
                else:
                    self.os = self.ASA
                    self.prompt = "".join((self.prompt.strip()[0:-1], '#'))
        elif re.search(''.join((self.username, '@\(')), str(prompt)):
            self.os = self.F5
        elif re.search('refresh \:', str(prompt)) or re.search('--:- / cli->', str(prompt)):
            self.os = self.AVOCENT
            if re.search('refresh \:', str(prompt)):
                self.prompt = '--:- / cli->'
                self.run_commands('q', 3)
        return self.os

    async def async_set_os(self, prompt):
        """
        Takes prompt as arg, returns digit signifying type of OS
        """
        if re.search('[A-B]:.*#', str(prompt)):
            self.os = self.ALU
        elif re.search('CPU.*#', str(prompt)):
            self.os = self.XR
        elif re.search('.*#', str(prompt)) and not re.search('@', str(prompt)):
            try:
                output = await self.async_run_commands('show version', 10)
            except Exception as e:
                return
            if re.search(' A10 ', str(output)):
                self.os = self.A10
            elif re.search('Arista', str(output)):
                self.os = self.EOS
            elif re.search('Invalid', str(output)):
                self.os = self.NIAGARA
            elif re.search('ACSW', str(output)) and not re.search('Admin', prompt):
                self.os = self.ASA
            elif re.search('NX-OS', str(output)):
                self.os = self.NXOS
            elif re.search('IOS-XE', str(output)):
                self.os = self.IOSXE
            else:
                self.os = self.IOS
        elif re.search(''.join((self.username, '@.*>')), str(prompt)) and not re.search('@\(', str(prompt)):
            self.os = self.JUNOS
        elif re.search('.*>', str(prompt)) and not re.search(self.username, str(prompt)) and not re.search('->', str(prompt)):
            try:
                output = await self.async_run_commands('show version', 10)
            except:
                return
            if re.search('Arista', str(output)):
                self.os = self.EOS
                try:
                    await self.async_enable()
                except:
                    return
            elif re.search(' A10 ', str(output)):
                self.os = self.A10
            else:
                try:
                    await self.async_enable()
                except:
                    return
                if re.search('NX-OS', str(output)):
                    self.os = self.NXOS
                elif re.search('IOS-XE', str(output)):
                    self.os = self.IOSXE
                elif re.search(r'(?:^| |\t)IOS(?:$| |\t)', str(output)):
                    self.os = self.IOS
                else:
                    self.os = self.ASA
                    self.prompt = "".join((self.prompt.strip()[0:-1], '#'))
        elif re.search(''.join((self.username, '@\(')), str(prompt)):
            self.os = self.F5
        elif re.search('refresh \:', str(prompt)) or re.search('--:- / cli->', str(prompt)):
            self.os = self.AVOCENT
            if re.search('refresh \:', str(prompt)):
                self.prompt = '--:- / cli->'
                await self.async_run_commands('q', 3)
        return self.os

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
        except CouldNotConnectError as e:
            try:
                return self.unsecure_login()
            except CouldNotConnectError as e2:
                raise CouldNotConnectError(e, e2, host=self.host)

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
        if not isinstance(self.password, bytes):
            self.password = self.password.encode()
        self.session = paramiko.SSHClient() #Create instance of SSHClient object
        self.session.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            connection = self.session.connect(self.host.strip('\n'),\
                                    username=self.username,\
                                    password=self.password,\
                                    look_for_keys=False,\
                                    allow_agent=False,\
                                    timeout=self.timeout)
            self.shell = self.session.invoke_shell()
        except (SSHException, NoValidConnectionsError, AuthenticationException, ValueError, EOFError, socket.error, socket.timeout) as e:
            self.session = None
            self.shell = None
            raise CouldNotConnectError({'ssh': str(e)})
        time.sleep(self.timeout)  #Allow time to log in and strip MOTD
        self.prompt = self.shell.recv(10000).decode().split('\n')[-1].strip().lstrip('*')
        self.set_os(self.prompt)
        return self.os

    async def async_secure_login(self, **kwargs):
        """
        Attempts to login to devices via SSH asyncrhonously, returns OS type if successful, if not returns 0
        """
        if kwargs:
            self.host = kwargs.get('host', None)
            self.username = kwargs.get('username', None)
            self.password = kwargs.get('password', None)
        self.verify_login_parameters()
        if not isinstance(self.password, bytes):
            self.password = self.password.encode()
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
            self.shell = yield from loop.run_in_executor(None, partial(self.session.invoke_shell, width=200, height=200))
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
        return raw_prompt.decode(errors="ignore").split('\n')[-1].split('*')[-1].strip().lstrip('*')


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
        login_regex = re.compile(b"|".join([b'[Uu]sername', b'[Ll]ogin']))
        prompt_regex = re.compile(b"|".join([b'[AB]:.*#', b'CPU.*#', b'.*#', b'@.*>']))
        try:
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
            self.prompt = previous_text.split(b'\n')[-1].strip().decode(errors="ignore").lstrip('*')
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
        self.verify_login_parameters()
        if not isinstance(self.password, bytes):
            self.password = self.password.encode()
        login_regex = re.compile(b"|".join([b'[Uu]sername', b'[Ll]ogin']))
        password_regex = re.compile(b'[Pp]assword')
        prompt_regex = re.compile(b"|".join([b'[AB]:.*#', b'CPU.*#', b'.*#', b'@.*>']))
        try:
            await self._async_telnet_login()
            _, user_prompt = await self._async_recv_unsec_output(expectation=login_regex, timeout=self.timeout)
            if not user_prompt:
                raise CouldNotConnectError({'telnet': 'host did not prompt for username'})
            await self._async_send_unsec_command(self.username.encode() + b'\r')
            _, password_prompt = await self._async_recv_unsec_output(expectation=password_regex, timeout=self.timeout)
            if not password_prompt:
                raise CouldNotConnectError({'telnet': 'host did not prompt for password'})
            await self._async_send_unsec_command(self.password + b'\r')
            _prompt, match = await self._async_recv_unsec_output(expectation=prompt_regex, timeout=self.timeout)
            if match:
                self.prompt = match.group(0).decode(errors="ignore")
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

    async def async_enable(self):
        if self.shell:
            await self._async_secure_enable()
        elif self.session:
            await self._async_unsec_enable()

    async def _async_secure_enable(self):
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
            raw = await self.async_run_sec_commands('enable')
        except OSError as e:
            raise BrokenConnectionError(self.host, e)
        if re.search('[Pp]assword', str(raw)):
            try:
                raw = await self.async_run_sec_commands(self.password)
            except OSError as e:
                raise BrokenConnectionError(self.host, e)
            return
        raise CouldNotConnectError({'ssh': raw})

    async def _async_unsec_enable(self):
        pass_regex = re.compile('[Pp]assword:')
        raw, send_pass = self._async_run_unsec_command('enable', expectation=pass_regex)
        if send_pass:
            raw, success = self._async_run_unsec_command(self.password)
            if success:
                return
        raise CouldNotConnectError({'telnet': raw})




    def telnet_or_ssh(self):
        """
        Returns 'SSH' if login via SSH, else Telnet if login via Telnet
        """
        if isinstance(self.session, paramiko.SSHClient):
            return 'SSH'
        elif isinstance(self.session, telnetlib.Telnet):
            return 'Telnet'

    def run_commands(self, commands, timeout=1, command_header=0, done=False):
        """
        Runs commands stored in commands on remote device
        """
        if self.shell:
            return self.run_sec_commands(commands, timeout, command_header=command_header, done=done)
        elif self.session:
            return self.run_unsec_commands(commands, timeout, command_header=command_header, done=done)


    async def async_run_commands(self, commands, timeout=1, command_header=0, done=False):
        """
        Runs commands stored in commands asynchronously on remote device
        """
        if self.shell:
            return await self.async_run_sec_commands(commands, timeout, command_header=command_header, done=done)
        elif self.session:
            return await self.async_run_unsec_commands(commands, timeout, command_header=command_header, done=done)


    def run_sec_commands(self, commands, timeout=1, command_header=0, done=False):
        """
        Runs commands when logged in via SSH, returns output
        """
        output = []
        if isinstance(commands, (str, bytes)):
            commands = [commands]
        for command in commands:
            raw = ''
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
            if command != self.password:
                raw = self._receive_sec_output(timeout)
                raw = re.sub(command.decode(errors="ignore"), '', raw).strip()
                if command_header:
                    raw = '\n'.join((_underline(command.strip().decode(errors="ignore")), raw))
                else:
                    raw = "\n".join((" ".join((self.prompt, command.strip().decode(errors="ignore"))), raw))
                if not done:
                    raw += '\n'
                output.append([ansi_escape.sub('', line) for line in raw.splitlines()])
        if done:
            self.logout()
        return output

    def _receive_sec_output(self, timeout):
        raw = ''
        complete = re.compile('|'.join((self.prompt.strip('#>'), '[Uu]sername', '[Pp]assword')))
        more = re.compile(r'-(?: |\()?(?:more|less \d+\%)(?:\(| )?|Press any key', flags=re.IGNORECASE)
        while not raw or not complete.match(str(raw.splitlines()[1:])):
            while not self.shell.recv_ready() and timeout > 0:
                time.sleep(0.1)
                timeout -= 0.1
            out = self.shell.recv(50000).decode(errors='ignore')
            raw += out
            if timeout <= 0:
                self.shell.send('\x03')
                break
            if more.search(out):
                self.shell.send(b' ')
            time.sleep(0.1)
        return "\n".join([line for line in raw.splitlines() if not re.match(self.prompt, line)])

    async def async_run_sec_commands(self, commands, timeout=120, command_header=0, done=False):
        """
        Runs commands asynchronously when logged in via SSH, returns output
        """
        output = []
        if isinstance(commands, (str, bytes)):
            commands = [commands]
        for command in commands:
            raw = ''
            if not isinstance(command, bytes):
                command = command.encode()
            try:
                if not self.shell.get_transport().is_active():
                    try:
                        await self.async_secure_login()
                    except CouldNotConnectError as e:
                        raise BrokenConnectionError(self.host, e)
            except OSError as e:
                try:
                    await self.async_secure_login()
                except CouldNotConnectError:
                    raise BrokenConnectionError(self.host, e)
            try:
                await self._async_send_sec_command(command.strip() + b'\r')
            except OSError as e:
                print(self.host, e)
                raise BrokenConnectionError(self.host, e)
            if command != self.password:
                try:
                    raw = await self._async_receive_sec_output(timeout)
                except socket.error as e:
                    raise BrokenConnectionError(self.host, e)
                while len(raw) > 1 and not raw[0]:
                    raw = raw[1:]
                if command_header:
                    raw.insert(0, '\n' + _underline(command.strip().decode(errors="ignore")))
                else:
                    raw.insert(0, " ".join((self.prompt, command.strip().decode(errors="ignore"))))
                if not done:
                    raw.append('\n')
                output.append(raw)
        if done:
            self.logout()
        return output

    @asyncio.coroutine
    def _async_send_sec_command(self, command):
        loop = asyncio.get_event_loop()
        if not isinstance(command, bytes):
            command = command.encode()
        yield from loop.run_in_executor(None, partial(self.shell.send, command))

    async def _async_receive_sec_output(self, timeout):
        raw = ''
        prompt = "".join((self.prompt.strip('#>'), '([\(>]config.*(\))?)?', '(?:#|>|$| )'))
        complete = re.compile('|'.join((prompt, '[Uu]sername', '[Pp]assword')))
        more = re.compile(r'-(?: |\()?(?:more|less \d+\%)(?:\( )?|Press any key', flags=re.IGNORECASE)
        while not raw or not complete.search(str(raw.splitlines()[1:])):
            while not self.shell.recv_ready() and timeout > 0:
                await asyncio.sleep(0.1)
                timeout -= 0.1
            if timeout <= 0:
                await self._async_send_sec_command('\x03')
                break
            out = await self._async_recv_sec_output()
            raw += out
            if more.search(out):
                await self._async_send_sec_command(' ')
            await asyncio.sleep(0.1)
        return [line for line in raw.splitlines()][1:]

    @asyncio.coroutine
    def _async_recv_sec_output(self):
        loop = asyncio.get_event_loop()
        raw = yield from loop.run_in_executor(None, partial(self.shell.recv, 50000))
        return ansi_escape.sub('', raw.decode(errors='ignore'))



    def run_unsec_commands(self, commands, timeout=1, command_header=0, done=False):
        """
        Runs commands when logged in via Telnet, returns output
        """
        output = []
        if isinstance(commands, (str, bytes)):
            commands = [commands]
        while commands:
            out = None
            command = commands.pop(0)
            if not isinstance(command, bytes):
                command = command.encode()
            try:
                self.session.read_very_eager()
            except (EOFError, BrokenPipeError, ConnectionResetError):
                self.unsecure_login()
            self.session.write((command.strip() + b'\r'))
            try:
                _, match, out = self.session.expect([re.compile(self.prompt.encode()), ], timeout)
            except (EOFError, BrokenPipeError, ConnectionResetError):
                self.unsecure_login()
                self.session.write((command.strip() + b'\r'))
                try:
                    _, match, out = self.session.expect([re.compile(self.prompt.encode()), ], timeout)
                except (EOFError, BrokenPipeError, ConnectionResetError) as e:
                    raise BrokenConnectionError(self.host, e)
            if out:
                out = re.sub(command.decode(errors="ignore"), '', out).strip()
            if not match:
                self.session.write((b'q\r'))
                time.sleep(1)
                try:
                    self.session.read_very_eager()
                except (EOFError, BrokenPipeError, ConnectionResetError) as e:
                    pass
            if out and (str(command) != str(self.password) and str(command) != str(self.username)):
                if command_header:
                    out = "\n".join((_underline(command.strip().decode(errors="ignore")), raw))
                else:
                    out = "\n".join((" ".join((self.prompt, command.strip().decode(errors="ignore"))), out))
                if not done:
                    out += '\n'
                output.append([ansi_escape.sub('', line) for line in out.splitlines()])
        if done:
            self.logout()
        return output


    async def async_run_unsec_commands(self, commands, timeout=120, command_header=0, done=False):
        """
        Runs commands asynchronously when logged in via Telnet, returns output
        """
        output = []
        if isinstance(commands, (str, bytes)):
            commands = [commands]
        while commands:
            command = commands.pop(0)
            if not isinstance(command, bytes):
                command = command.encode(errors="ignore")
            raw = await self._async_run_unsec_command(command + b'\r', timeout=timeout)
            if (str(command) != str(self.password) and str(command) != str(self.username)):
                while len(raw) > 1 and not raw[0]:
                    raw = raw[1:]
                if command_header:
                    raw.insert(0, "\n" + _underline(command.strip().decode(errors="ignore")))
                else:
                    raw.insert(0, ' '.join((self.prompt, command.strip().decode(errors="ignore"))))
                if not done:
                    raw.append('\n')
                output.append(raw)
        if done:
            self.logout()
        return output

    async def _async_run_unsec_command(self, command, timeout=120):
        """
        Helper to async_run_unsec_commands, writes and returns output of commands
        """
        try:
            self.session.read_very_eager()
        except EOFError:
            return ''
        await self._async_send_unsec_command(command)
        output = await self._async_receive_unsec_output(timeout=timeout)
        return output

    @asyncio.coroutine
    def _async_send_unsec_command(self, command):
        loop = asyncio.get_event_loop()
        if not isinstance(command, bytes):
            command = command.encode()
        try:
            yield from loop.run_in_executor(None, partial(self.session.write, command))
        except AttributeError as err:
            raise BrokenConnectionError(self.host, err)

    @asyncio.coroutine
    def _async_recv_unsec_output(self, expectation=None, timeout=1):
        loop = asyncio.get_event_loop()
        if not expectation:
            try:
                expectation = re.compile(b"".join((self.prompt.strip('#>'), '(\(config.*\)#)?', '(?:#|>|$| )')).encode())
            except re.error as err:
                print(err, self.prompt)
                raise BrokenConnectionError(self.host, err)
        if not isinstance(expectation, re.Pattern):
            if not isinstance(expectation, bytes):
                expectation = expectation.encode()
            expectation = re.compile(expectation)
        _, match, raw = yield from loop.run_in_executor(None, partial(self.session.expect, [expectation], timeout=timeout))
        return ansi_escape.sub('', raw.decode(errors='ignore')), match

    async def _async_receive_unsec_output(self, expectation=None, timeout=10):
        """
        Helper to async_run_unsec_commands, performs "expect"
        """
        prompt = "".join((self.prompt.strip('#>'), '([\(>]config.*(\))?)?', '(?:#|>|$| )')).encode()
        if not expectation:
            expectation = re.compile(b'|'.join((prompt, b'[Uu]sername', b'[Pp]assword')))
        more = re.compile(r'-(?: |\()?(?:more|less \d+\%)(?:\( )?|Press any key', flags=re.IGNORECASE)
        out = ''
        raw = ''
        match = False
        try:
            while not out or not match and timeout > 0:
                out, match = await self._async_recv_unsec_output(expectation=expectation)
                if out:
                    raw += out
                    if not match and more.search(out):
                        self.session.write(b' \r')
                if timeout <= 0:
                    await self._async_send_unsec_command('\x03')
                    break
                await asyncio.sleep(1)
                timeout -= 1
            return [line for line in raw.splitlines()][1:]
        except (BrokenPipeError, ConnectionResetError, EOFError, AttributeError) as e:
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
    if isinstance(input, bytes):
        input = input.decode(errors="ignore")
    return input.strip() + '\n' + _make_line(len(input.strip()), line_char)


def _make_line(count, line_char="-"):
    """
    Format helper, makes lines
    """
    return line_char * int(count)
