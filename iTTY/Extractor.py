import re
import traceback
from . import iTTY

ip_regex = re.compile(r'(?:^|\s)(?P<address>((?:[1-9]?\d|1\d{2}|2[0-4]\d|25[0-5])\.){3}(?:[1-9]?\d|1\d{2}|2[0-4]\d|25[0-5]))(?P<slash>/)?(?(slash)(?P<cidr>\d|[12]\d|3[0-2]))(?:$|\s|:)')

def extract_func(commands):
    """
    Basic closure, runs commands on iTTY instance
    """
    async def func(tty):
        output = await tty.async_run_commands(commands)
        return output
    return func

async def extract_make(tty):
    """
    Extracts "make" of remote device
    """
    if tty.os == 1:
        return 'alcatel'
    elif tty.os in (2, 3, 5, 11, 12):
        return 'cisco'
    elif tty.os == 4:
        return 'juniper'
    elif tty.os == 6:
        return 'f5'
    elif tty.os == 7:
        return 'arista'
    elif tty.os == 8:
        return 'a10'
    elif tty.os == 9:
        return 'avocent'
    elif tty.os == 10:
        return 'niagara'
    elif tty.os == 13:
        return 'raritan'

async def extract_hostname(tty):
    """
    Extracts "hostname" of remote device
    """
    if tty.os == 1:
        return await extract_alu_hostname(tty)
    elif tty.os in (2, 3, 5, 7, 11, 12):
        return await extract_cisco_hostname(tty)
    elif tty.os == 4:
        return await extract_junos_hostname(tty)
    elif tty.os == 6:
        return await extract_f5_hostname(tty)
    elif tty.os == 8:
        return await extract_a10_hostname(tty)
    elif tty.os == 9:
        return await extract_avocent_hostname(tty)
    elif tty.os == 13:
        return await extract_raritan_hostname(tty)

async def extract_contact(tty):
    """
    Extracts "contact" of remote device
    """
    if tty.os == 1:
        return await extract_alu_contact(tty)
    elif tty.os in (2, 3, 5, 7, 11, 12):
        return await extract_cisco_contact(tty)
    elif tty.os == 4:
        return await extract_junos_contact(tty)
    elif tty.os == 6:
        return await extract_f5_contact(tty)
    elif tty.os == 8:
        return await extract_a10_contact(tty)

async def extract_location(tty):
    """
    Extracts "location" of remote device
    """
    if tty.os == 1:
        return await extract_alu_location(tty)
    elif tty.os in (2, 3, 5, 7, 11, 12):
        return await extract_cisco_location(tty)
    elif tty.os == 4:
        return await extract_junos_location(tty)
    elif tty.os == 6:
        return await extract_f5_location(tty)
    elif tty.os == 8:
        return await extract_a10_location(tty)

async def extract_version(tty):
    """
    Extracts "version" of remote device
    """
    if tty.os == 1:
        return await extract_alu_version(tty)
    elif tty.os == 2:
        return await extract_xr_version(tty)
    elif tty.os in (3, 11, 12):
        return await extract_ios_version(tty)
    elif tty.os == 4:
        return await extract_junos_version(tty)
    elif tty.os == 5:
        return await extract_asa_version(tty)
    elif tty.os == 6:
        return await extract_f5_version(tty)
    elif tty.os == 7:
        return await extract_arista_version(tty)
    elif tty.os == 8:
        return await extract_a10_version(tty)
    elif tty.os == 9:
        return await extract_avocent_version(tty)
    elif tty.os == 13:
        return await extract_raritan_version(tty)

async def extract_model(tty):
    """
    Extracts "model" of remote device
    """
    if tty.os == 1:
        return await extract_alu_model(tty)
    elif tty.os == 2:
        return await extract_xr_model(tty)
    elif tty.os in (3, 12):
        return await extract_ios_model(tty)
    elif tty.os == 4:
        return await extract_junos_model(tty)
    elif tty.os == 5:
        return await extract_asa_model(tty)
    elif tty.os == 6:
        return await extract_f5_model(tty)
    elif tty.os == 7:
        return await extract_arista_model(tty)
    elif tty.os == 8:
        return await extract_a10_model(tty)
    elif tty.os == 9:
        return await extract_avocent_model(tty)
    elif tty.os == 11:
        return await extract_nxos_model(tty)

async def extract_series(tty):
    """
    Extracts "series" of remote device
    """
    if tty.os == 1:
        return await extract_alu_series(tty)
    elif tty.os == 2:
        return await extract_xr_series(tty)
    elif tty.os in (3, 11, 12):
        return await extract_ios_series(tty)
    elif tty.os == 4:
        return await extract_junos_series(tty)
    elif tty.os == 5:
        return await extract_asa_series(tty)
    #elif tty.os == 6:
    #    return await extract_f5_series(tty)
    elif tty.os == 7:
        return await extract_arista_series(tty)
    #elif tty.os == 8:
    #    return await extract_a10_series(tty)

async def extract_syslog_server(tty):
    """
    Extracts "syslog server" of remote device
    """
    if tty.os == 1:
        return await extract_alu_syslog_server(tty)
    elif tty.os == 2:
        return await extract_xr_syslog_server(tty)
    elif tty.os in (3, 11, 12):
        return await extract_ios_syslog_server(tty)
    elif tty.os == 4:
        return await extract_junos_syslog_server(tty)
    elif tty.os == 5:
        return await extract_asa_syslog_server(tty)
    elif tty.os == 6:
        return await extract_f5_syslog_server(tty)
    elif tty.os == 7:
        return await extract_arista_syslog_server(tty)
    elif tty.os == 8:
        return await extract_a10_syslog_server(tty)
    elif tty.os == 13:
        return await extract_raritan_syslog_server(tty)

async def extract_trap_collector(tty):
    """
    Extracts "trap collector" of remote device
    """
    if tty.os == 1:
        return await extract_alu_trap_collector(tty)
    elif tty.os == 2:
        return await extract_xr_trap_collector(tty)
    elif tty.os in (3, 11, 12):
        return await extract_ios_trap_collector(tty)
    elif tty.os == 4:
        return await extract_junos_trap_collector(tty)
    elif tty.os == 5:
        return await extract_asa_trap_collector(tty)
    elif tty.os == 6:
        return await extract_f5_trap_collector(tty)
    elif tty.os == 7:
        return await extract_arista_trap_collector(tty)
    elif tty.os == 8:
        return await extract_a10_trap_collector(tty)
    elif tty.os == 13:
        return await extract_raritan_trap_collector(tty)

async def extract_tacacs_server(tty):
    """
    Extracts "tacacs servers" of remote device
    """
    if tty.os == 1:
        return await extract_alu_tacacs_server(tty)
    elif tty.os == 2:
        return await extract_xr_tacacs_server(tty)
    elif tty.os in (3, 12):
        return await extract_ios_tacacs_server(tty)
    elif tty.os == 4:
        return await extract_junos_tacacs_server(tty)
    #elif tty.os == 5:
    #    return await extract_asa_tacacs_server(tty)
    elif tty.os == 6:
        return await extract_f5_tacacs_server(tty)
    elif tty.os == 7:
        return await extract_arista_tacacs_server(tty)
    elif tty.os == 8:
        return await extract_a10_tacacs_server(tty)
    elif tty.os == 11:
        return await extract_nxos_tacacs_server(tty)

async def extract_acl(tty, acl_name):
    """
    Extracts "trap collector" of remote device
    """
    if tty.os == 1:
        return await extract_alu_acl(tty, acl_name)
    elif tty.os == 2:
        return await extract_xr_acl(tty, acl_name)
    elif tty.os in (3, 11, 12):
        return await extract_ios_acl(tty, acl_name)
    elif tty.os == 4:
        return await extract_junos_acl(tty, acl_name)
    #elif tty.os == 5:
    #    return await extract_asa_acl(tty, acl_name)
    #elif tty.os == 6:
    #    return await extract_f5_acl(tty, acl_name)
    elif tty.os == 7:
        return await extract_arista_acl(tty, acl_name)
    #elif tty.os == 8:
    #    return await extract_a10_acl(tty, acl_name)

async def extract_interface_v4_addresses(tty, interface=None):
    """
    Extracts interface v4 addresses of remote device
    """
    if tty.os == 1:
        return await extract_alu_interface_v4_addresses(tty, interface)
    elif tty.os in (2, 3, 7, 11, 12):
        return await extract_cisco_interface_v4_addresses(tty, interface)
    elif tty.os == 4:
        return await extract_junos_interface_v4_addresses(tty, interface)
    elif tty.os == 5:
        return await extract_asa_interface_v4_addresses(tty, interface)


async def extract_alu_version(tty):
    """
    Extracts software version of remote alcatel/nokia device
    """
    output = await tty.async_run_commands('show version', 10)
    output = '\n'.join(output[0]) if output else output
    if output:
        match = re.search(r'(?:^TiMOS[-a-zA-Z]+)([\w\.]+)', output, re.M)
        return match.group(1) if match else None

async def extract_xr_version(tty):
    """
    Extracts software version of remote cisco IOS-XR device
    """
    version = ''
    sp = ''
    output = await tty.async_run_commands('show version | in IOS XR', 20)
    if output:
        for out in output:
            for line in out:
                if re.search('XR', line) and not re.search('show', line):
                    try:
                        version = line.split('Version')[1].strip()
                        if '[' in version:
                            version = version.split('[')[0].strip()
                    except IndexError:
                        print('IndexError async_extract_xr_version', line)
                    break
    if not version:
        return
    output = await tty.async_run_commands('show version | in memory', 20)
    if output:
        dev_type = str(output)
    else:
        return version
    if re.search('ASR9K', dev_type):
        output = await tty.async_run_commands('admin show install active summary | in sp', 20)
        if output:
            for out in output:
                for line in out:
                    if not re.search(tty.prompt, line) and not re.search('show', line):
                        try:
                            sp = line.split('-')[-2].split('.')[-1]
                            if re.search('sp', sp):
                                break
                        except:
                            sp = None
                            continue
            if sp:
                return version + '-' + sp
            else:
                return version
    else:
        if re.match('CRS', dev_type):
            count = 'utility wc -l'
        else:
            count = 'count'
        output = await tty.async_run_commands(f'admin show install active summary | in CSC | {count}', 20)
        if output:
            ansi_escape = re.compile(r'\x1B\[[0-?]*[ -/]*[@-~]')
            for out in output:
                for line in out:
                    if re.search(r'\d', line) and not re.search('show', line) and not re.search(tty.prompt, line):
                        try:
                            smu = int(ansi_escape.sub('', line).strip()) if not count == 'count' else int(ansi_escape.sub('', line).strip().split()[1])
                        except ValueError:
                            smu = None
                            continue
                        except IndexError:
                            print(line, traceback.format_exc())
                            smu = None
                            continue
                        if smu:
                            return version + '-smu' + str(smu)
            return version

async def extract_ios_version(tty):
    """
    Extracts software version of remote cisco IOS device
    """
    output = await tty.async_run_commands(['show version'], 10)
    if output:
        for out in output:
            for line in out:
                if re.search('Version', line) and not re.search('show|LGPL|ID|SW Image|Uptime', line):
                    try:
                        version = line.split('Version')[1].split(',')[0].split()[0].strip()
                        return version
                    except IndexError:
                        print('extract_ios_verion: INDEXERROR: ', tty.host, line)
                elif re.search('system.*version', line):
                    return line.split('version')[1].strip()
                elif re.match(r'1\s+\w+\s+\w+\.', line):
                    return line.split()[2]

async def extract_junos_version(tty):
    """
    Extracts software version of remote juniper device
    """
    output = await tty.async_run_commands('show version', 10)
    if output:
        output = "\n".join(output[0])
        version = re.search(r'(?i:^junos)(?::\s)?(?:[^\n]+\[)?([^\n^\]]+)(?:[\]\n])', output, re.M)
        if version:
            return version.group(1)

async def extract_asa_version(tty):
    """
    Extracts software version of remote cisco asa device
    """
    output = await tty.async_run_commands('show version', 10)
    if output:
        output = "\n".join(output[0])
        version = re.search('^Cisco Adaptive Security Appliance Software Version ([^\n]+)\n', output, re.M)
        if version:
            return version.group(1)

async def extract_f5_version(tty):
    """
    Extracts software version of remote f5 device
    """
    output = await tty.async_run_commands('show sys version | grep Version | grep -v Sys', 10)
    if output:
        for out in output:
            for line in out:
                if re.search('Version', line) and not re.search('show', line):
                    return line.split()[1]

async def extract_arista_version(tty):
    """
    Extracts software version of remote arista device
    """
    output = await tty.async_run_commands('show version | in Software', 10)
    if output:
        output = "\n".join(output[0])
        version = re.search('^Software image version: ([^\n]+)\n', output, re.M)
        if version:
            return version.group(1)

async def extract_a10_version(tty):
    """
    Extracts software version of remote a10 device
    """
    output = await tty.async_run_commands('show version | in Advanced', 10)
    if output:
        for out in output:
            for line in out:
                if not re.search('show', line) and re.search('ersion', line):
                    return line.split('ersion')[1].split()[0].strip(',')

async def extract_avocent_version(tty):
    """
    Extracts software version of remote avocent device
    """
    output = await tty.async_run_commands('show /system/information/', 10)
    if output:
        for out in output:
            for line in out:
                if not re.search('show', line) and re.search('firmware', line):
                    return line.split()[1]

async def extract_raritan_version(tty):
    """
    Extracts software version of remote avocent device
    """
    output = await tty.async_run_commands('show version', 30)
    if output:
        for out in output:
            for line in out:
                if re.match('Firmware', line):
                    return line.split()[-1]


async def extract_alu_model(tty):
    """
    Extracts model of remote alcatel/nokia device
    """
    output = await tty.async_run_commands('show chassis | match Type', 10)
    if output:
        for out in output:
            for line in out:
                if re.search('Type', line) and not re.search('show', line):
                    return "".join(line.split(':')[1].split()).strip()

async def extract_xr_model(tty):
    """
    Extracts model of remote cisco IOS-XR device
    """
    output = await tty.async_run_commands(['show version | in "processor|hassis"'], 30)
    if output:
        output = "\n".join(output[0])
        match = re.search(r'(^ASR[-\s]\d+|IOS-XRv\s\w+|CRS[-\w/]+)', output, re.M)
        if match:
            return re.sub(r'[\s]', '-', match.group(0)) if re.search(r'ASR|CRS', output) else re.sub(r'[-\s]', '', match.group(0)).upper()
    output = await tty.async_run_commands('admin show inventory', 30)
    if output:
        output = '\n'.join(output[0])
        match = re.search(r'(?:Name[^\n]*Chassis[^\n]*\n\s+PID:\s)([-\w]+)', output)
        return match.group(1) if match else None

async def extract_ios_model(tty):
    """
    Extracts model of remote cisco IOS device
    """
    output = await tty.async_run_commands(['show version'], 20)
    if output:
        output = '\n'.join(output[0])
        match = re.search(r'^[Cc]isco\s([-\w]+)[^\n]*(?!ermission|reload)[^\n]*memory\.\n', output, re.M)
        if match:
            return match.group(1)

async def extract_nxos_model(tty):
    """
    Extracts model of remote cisco NXOS device
    """
    output = await tty.async_run_commands(['show version'], 10)
    if output:
        output = '\n'.join(output[0])
        match = re.search(r'^\s*[Cc]isco (Nexus\s?\d{1,4})[^\n]+(?=Chassis)', output, re.M)
        return re.sub(' ', '', match.group(1)) if match else None

async def extract_junos_model(tty):
    """
    Extracts model of remote juniper device
    """
    output = await tty.async_run_commands(['show version | match Model'], 10)
    if output:
        output = '\n'.join(output[0])
        if re.search('^Model', output, re.M):
            return re.search(r'(?:^Model: )(.*)(?:$)', output, re.M).group(1)

async def extract_asa_model(tty):
    """
    Extracts model of remote cisco ASA device
    """
    output = await tty.async_run_commands(['terminal pager 0', 'show version | in Hardware', 'show inventory | in PID'], 10)
    if re.search('Hardware:', str(output)):
        for out in output:
            for line in out:
                if re.match('Hardware', line):
                    try:
                        return line.split()[1].strip(',')
                    except IndexError:
                        print('extract_asa_model: INDEXERROR: ', tty.host, line)
                        return
    elif re.search('PID', str(output)):
        for out in output:
            for line in out:
                if re.search('PID', line) and not re.search('show', line):
                    try:
                        return line.split()[1].strip(',')
                    except IndexError:
                        print('extract_asa_model: INDEXERROR: ', tty.host, line)
                        return


async def extract_f5_model(tty):
    """
    Extracts model of remote f5 device
    """
    output = await tty.async_run_commands('show sys hardware field-fmt | grep marketing-name', 10)
    if output:
        for out in output:
            for line in out:
                if not re.search('show', line) and re.search('marketing', line) and not re.match('Edition', line.split()[-1]):
                    return line.split()[-1]
    output = await tty.async_run_commands('show sys hardware field-fmt | grep platform', 10)
    if output:
        for out in output:
            for line in out:
                if not re.search('show|hardware', line) and re.search('platform', line):
                    return line.split()[-1]

async def extract_arista_model(tty):
    """
    Extracts model of remote arista device
    """
    output = await tty.async_run_commands('show version | in Arista', 10)
    if output:
        output = "\n".join(output[0])
        model = re.search(r'^Arista ([^\n]+)\n', output, re.M)
        if model:
            return model.group(1)

async def extract_a10_model(tty):
    """
    Extracts model of remote a10 device
    """
    output = await tty.async_run_commands('show version | include Series', 10)
    if output:
        for out in output:
            for line in out:
                if not re.search('show', line) and re.search('Series', line):
                    return line.split()[-1]

async def extract_avocent_model(tty):
    """
    Extracts model of remote avocent device
    """
    output = await tty.async_run_commands('show /system/information/', 10)
    if output:
        for out in output:
            for line in out:
                if not re.search('show', line) and re.search('type', line):
                    return line.split()[1]

async def extract_alu_hostname(tty):
    """
    Extracts hostname of remote alcatel/nokia device
    """
    return tty.prompt.split(":")[1].strip("#")

async def extract_cisco_hostname(tty):
    """
    Extracts hostname of remote cisco (and arista EOS) device
    """
    output = await tty.async_run_commands('show run | in name', 10)
    if output:
        output = "\n".join(output[0])
        hostname = re.search(r'^hostname ([^\n]+)\n', output, re.M)
        if not hostname:
            return
        domain = re.search(r'^(?:ip )?domain.name ([^\n]+)\n', output, re.M)
        if domain:
            return ".".join((hostname.group(1), domain.group(1)))
        return hostname.group(1)

async def extract_junos_hostname(tty):
    """
    Extracts hostname of remote juniper device
    """
    output = await tty.async_run_commands('show configuration | display set | match name', 10)
    if output:
        output = "\n".join(output[0])
        snmp_name = re.search(r'^set snmp name ([^\n]+)\n', output, re.M)
        if snmp_name:
            return snmp_name.group(1)
        hostname = re.search(r'^set (?:groups node0 )?system host.name ([^\n]+)\n', output, re.M)
        if not hostname:
            return
        domain = re.search(r'^set system domain-name ([^\n]+)\n', output, re.M)
        if domain:
            return '.'.join((hostname.group(1), domain.group(1)))
        return hostname.group(1)

async def extract_f5_hostname(tty):
    """
    Extracts hostname of remote f5 device
    """
    output = await tty.async_run_commands('list cm device | grep hostname', 10)
    if output:
        output = "\n".join(output[0])
        hostname = re.search(r'^\s+hostname ([^\n])\n', output, re.M)
        if hostname:
            return hostname.group(1)

async def extract_a10_hostname(tty):
    """
    Extracts hostname of remote a10 device
    """
    output = await tty.async_run_commands(r'show run | in hostname\|suffix', 10)
    if output:
        output = "\n".join(output[0])
        hostname = re.search(r'^hostname ([^\n]+)(?: device \d+)?\n', output, re.M)
        if not hostname:
            return
        domain = re.search(r'^ip dns suffix ([^\n]+)\n', output, re.M)
        if domain:
            return '.'.join((hostname.group(1), domain.group(1)))
        return hostname.group(1)


async def extract_avocent_hostname(tty):
    """
    Extracts hostname of remote avocent device
    """
    output = await tty.async_run_commands('ls access/', 10)
    if output:
        for out in output:
            for line in out:
                if not re.search('cli->', line):
                    return line.split('/')[0]

async def extract_niagara_hostname(tty):
    """
    Extracts hostname of remote niagara device
    """
    return tty.prompt.strip('#')

async def extract_raritan_hostname(tty):
    """
    Extracts hostname of remote raritan device
    """
    hostname = None
    domain = None
    output = await tty.async_run_commands('show network', 10)
    if output:
        for out in output:
            for line in out:
                if re.match('Name', line.strip()):
                    hostname = line.split()[-1]
                elif re.match('Domain', line.strip()):
                    domain = line.split()[-1]
        if hostname:
            if domain:
                return ".".join((hostname, domain))
            return hostname

async def extract_alu_contact(tty):
    """
    Extracts contact of remote alcatel/nokia device
    """
    output = await tty.async_run_commands('admin display-config | match contact', 10)
    if output:
        for out in output:
            for line in out:
                if not re.search('display', line) and re.search('contact', line):
                    return line.split('contact')[-1].strip().strip('"')

async def extract_cisco_contact(tty):
    """
    Extracts contact of remote cisco (and arista EOS) device
    """
    output = await tty.async_run_commands('show run | in contact', 10)
    if output:
        for out in output:
            for line in out:
                if not re.search('show|banner|sending|description', line) and re.search('contact', line):
                    return line.split('contact')[-1].strip().strip('"')

async def extract_junos_contact(tty):
    """
    Extracts contact of remote juniper device
    """
    output = await tty.async_run_commands(['set cli screen-length 0', 'show configuration | display set | match contact'], 10)
    if output:
        for out in output:
            for line in out:
                if not re.search('show', line) and re.search('contact', line):
                    return line.split('contact')[-1].strip().strip('"')

async def extract_f5_contact(tty):
    """
    Extracts contact of remote f5 device
    """
    output = await tty.async_run_commands('list sys snmp sys-contact', 10)
    if output:
        for out in output:
            for line in out:
                if not re.search('list', line) and re.search('contact', line):
                    try:
                        if re.search('"', line):
                            return line.split('"')[1]
                        else:
                            return line.split()[-1]
                    except IndexError:
                        print('extract_f5_contact: INDEXERROR: ', tty.host, line)

async def extract_a10_contact(tty):
    """
    Extracts contact of remote a10 device
    """
    output = await tty.async_run_commands('show run | in snmp-server contact', 10)
    if output:
        for out in output:
            for line in out:
                if not re.search('show', line) and re.search('contact', line):
                    try:
                        if re.search('"', line):
                            return line.split('"')[1]
                        else:
                            return line.split()[-1]
                    except IndexError:
                        print('extract_a10_contact: INDEXERROR: ', tty.host, line)


async def extract_alu_location(tty):
    """
    Extracts location of remote alcatel/nokia device
    """
    output = await tty.async_run_commands('admin display-config | match location', 10)
    if output:
        for out in output:
            for line in out:
                if not re.search(r'display|cf\d:', line) and re.search('location', line):
                    return line.split('location')[-1].strip().strip('"')

async def extract_cisco_location(tty):
    """
    Extracts location of remote cisco (and arista EOS) device
    """
    output = await tty.async_run_commands(['terminal length 0', 'show run | in location'], 10)
    if output:
        for out in output:
            for line in out:
                if not re.search('show|vlan|modem|banner|cpu0|description|note', line, flags=re.IGNORECASE) and re.search('location', line):
                    return line.split('location')[-1].strip().strip('"')

async def extract_junos_location(tty):
    """
    Extracts location of remote juniper device
    """
    output = await tty.async_run_commands(['set cli screen-length 0', 'show configuration | display set | match location'], 10)
    if output:
        for out in output:
            for line in out:
                if not re.search(r'show|\-code', line) and re.search('location', line):
                    return line.split('location')[-1].strip().strip('"')

async def extract_f5_location(tty):
    """
    Extracts location of remote f5 device
    """
    output = await tty.async_run_commands('list sys snmp sys-location', 10)
    if output:
        for out in output:
            for line in out:
                if not re.search('list', line) and re.search('location', line):
                    try:
                        if re.search('"', line):
                            return line.split('"')[1]
                        elif re.search('sys-location', line):
                            return line.split()[1]
                        return line.split()[10]
                    except IndexError:
                        print('extract_f5_location: INDEXERROR: ', tty.host, line)

async def extract_a10_location(tty):
    """
    Extracts location of remote a10 device
    """
    output = await tty.async_run_commands('show run | in snmp-server location', 10)
    if output:
        for out in output:
            for line in out:
                if not re.search('show', line) and re.search('location', line):
                    try:
                        return line.split('"')[1]
                    except IndexError:
                        print('extract_a10_location: INDEXERROR: ', tty.host, line)

async def extract_alu_syslog_server(tty):
    """
    Extracts configured syslog servers of remote alcatel/nokia device
    """
    output = await tty.async_run_commands('admin display-config | match syslog context children | match address', 10)
    if output:
        syslog_servers = set([ip_regex.search(line).group('address') for out in output for line in out if ip_regex.search(line)])
        if syslog_servers:
            return syslog_servers
    print(f'Could not extract ALU syslog server data from {tty.host}: {output}')

async def extract_xr_syslog_server(tty):
    """
    Extracts configured syslog servers of remote cisco IOS-XR device
    """
    output = await tty.async_run_commands(r"show run formal | utility egrep '^logging [0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}'", 20)
    if output:
        syslog_servers = set([ip_regex.search(line).group('address') for out in output for line in out if ip_regex.search(line)])
        if syslog_servers:
            return syslog_servers
    print(f'Could not extract XR syslog server data from {tty.host}: {output}')

async def extract_ios_syslog_server(tty):
    """
    Extracts configured syslog servers of remote cisco IOS device
    """
    output = await tty.async_run_commands(["terminal length 0", "show run | in logging.*[0-9]"], 20)
    if output:
        syslog_servers =  set([ip_regex.search(line).group('address') for out in output for line in out if re.search('logging', line) and ip_regex.search(line)])
        if syslog_servers:
            return syslog_servers
    print(f'Could not extract IOS syslog server data from {tty.host}: {output}')

async def extract_junos_syslog_server(tty):
    """
    Extracts configured syslog servers of remote juniper device
    """
    output = await tty.async_run_commands(['set cli screen-length 0', r"show configuration | display set | match syslog\ host"], 20)
    if output:
        syslog_servers = set([ip_regex.search(line).group('address') for out in output for line in out if ip_regex.search(line)])
        if syslog_servers:
            return syslog_servers
    print(f'Could not extract JUNOS syslog server data from {tty.host}: {output}')

async def extract_asa_syslog_server(tty):
    """
    Extracts configured syslog servers of remote cisco asa device
    """
    output = await tty.async_run_commands(['terminal pager 0', 'show run | in logging host'], 20)
    if output:
        syslog_servers = set([ip_regex.search(line).group('address') for out in output for line in out if ip_regex.search(line)])
        if syslog_servers:
            return syslog_servers
    print(f'Could not extract ASA syslog server data from {tty.host}: {output}')

async def extract_f5_syslog_server(tty):
    """
    Extracts configured syslog servers of remote f5 device
    """
    output = await tty.async_run_commands('show running-config sys syslog', 10)
    if output:
        syslog_servers = set([ip_regex.search(line).group('address') for out in output for line in out if ip_regex.search(line)])
        if syslog_servers:
            return syslog_servers
    print(f'Could not extract f5 syslog server data from {tty.host}: {output}')

async def extract_arista_syslog_server(tty):
    """
    Extracts configured syslog servers of remote arista device
    """
    output = await tty.async_run_commands("show run | in logging host", 10)
    if output:
        syslog_servers = set([ip_regex.search(line).group('address') for out in output for line in out if ip_regex.search(line)])
        if syslog_servers:
            return syslog_servers
    print(f'Could not extract EOS syslog server data from {tty.host}: {output}')

async def extract_a10_syslog_server(tty):
    """
    Extracts configured syslog servers of remote a10 device
    """
    output = await tty.async_run_commands("show run | in logging host", 10)
    if output:
        syslog_servers = set([ip_regex.search(line).group('address') for out in output for line in out if ip_regex.search(line)])
        if syslog_servers:
            return syslog_servers
    print(f'Could not extract A10 syslog server data from {tty.host}: {output}')

async def extract_raritan_syslog_server(tty):
    """
    Extracts configured syslog servers of remote raritan device
    """
    output = await tty.async_run_commands("show syslog", 30)
    if output:
        syslog_servers = set([ip_regex.search(line).group('address') for out in output for line in out if ip_regex.search(line)])
        if syslog_servers:
            return syslog_servers
    print(f'Could not extract raritan syslog server data from {tty.host}: {output}')

async def extract_junos_series(tty):
    output = await tty.async_run_commands(['set cli screen-length 0', 'show version local | match Model'], 10)
    if output:
        for out in output:
            for line in out:
                if re.search('Model', line) and not re.search('show', line):
                    return line.split()[-1].split('-')[0]

async def extract_ios_series(tty):
    output = await tty.async_run_commands(['terminal length 0', 'show version'], 10)
    if output:
        if re.search('c7600', str(output)):
            return 'c7600'
        elif re.search(r's\d+_rp', str(output)):
            match = re.search(r's\d+_rp', str(output))
            out = await tty.async_run_commands(['terminal length 0', 'show inventory'], 10)
            if out:
                series_line = next((line for o in out for line in o if re.search('Chassis', line)), None)
                if series_line:
                    if re.search('6500', series_line):
                        return 'c6500'
        elif re.search('CAT3K', str(output)):
            return 'CAT3K'
        for out in output:
            for line in out:
                if re.search('Software', line)\
                    and not re.search('Nexus', line)\
                    and not re.search('Internetwork', line)\
                    and not re.search(r' XE ', line)\
                    and len(line.strip().split()) > 1:
                    try:
                        if re.search('Catalyst', line):
                            return line.split('Catalyst')[1].split()[0]
                        elif re.match('IOS', line):
                            return line.split(')')[1].split()[0]
                        return line.split(',')[1].split()[0]
                    except IndexError:
                        print('extract_ios_series: IndexError:', tty.host, line)
                elif re.search(r'bootflash.*n\d{1,4}', line):
                    return re.search(r'n\d{1,4}', line).group(0)
                elif re.search(r'Nexus\ ?\d{1,4}', line):
                    return ''.join(('n', line.split('Nexus')[1].split()[0]))

async def extract_alu_series(tty):
    output = await tty.async_run_commands('show chassis | Type', 10)
    if output:
        for out in output:
            for line in out:
                if re.search('Type', line.strip()):
                    return "".join((line.split()[-1].split('-')[0], line.split()[-2])).lower()

async def extract_xr_series(tty):
    output = await tty.async_run_commands("show version | in processor", 10)
    if output:
        if re.search(r'CRS|IOS-XRv|ASR\w+', str(output)):
            return re.search(r'CRS|IOS-XRv|ASR\w+', str(output)).group(0)

async def extract_asa_series(tty):
    output = await tty.async_run_commands(['show version | in hardware', 'show inventory | in DESCR:'], 10)
    if output:
        for out in output:
            for line in out:
                try:
                    if re.search('Encryption hardware device', str(line)):
                        return line.split(':')[1].split()[1]
                    elif re.search('DESCR:', line) and not re.search('show', line):
                        return line.split('DESCR:')[1].split()[0].strip('"')
                except IndexError:
                    print(f'extract_asa_series: IndexError: {line}')

async def extract_arista_series(tty):
    output = await tty.async_run_commands('show version | in Arista', 10)
    if output:
        for out in output:
            for line in out:
                if re.search('Arista', line) and not re.search('show', line):
                    return line.split('Arista')[1].split('-')[1].strip()

async def extract_alu_trap_collector(tty):
    output = await tty.async_run_commands('admin display config | match trap-target', 10)
    if output:
        return set([ip_regex.search(line).group('address') for out in output for line in out if ip_regex.search(line)])

async def extract_xr_trap_collector(tty):
    output = await tty.async_run_commands('show run formal | in host.*traps', 10)
    if output:
        return set([ip_regex.search(line).group('address') for out in output for line in out if ip_regex.search(line)])

async def extract_ios_trap_collector(tty):
    output = await tty.async_run_commands('show run | in snmp-server.*host', 10)
    if output:
        return set([ip_regex.search(line).group('address') for out in output for line in out if ip_regex.search(line)])

async def extract_junos_trap_collector(tty):
    output = await tty.async_run_commands('show configuration | display set | match trap.*targets', 10)
    if output:
        return set([ip_regex.search(line).group('address') for out in output for line in out if ip_regex.search(line)])

async def extract_asa_trap_collector(tty):
    output = await tty.async_run_commands('show run | in snmp.*host', 10)
    if output:
        return set([ip_regex.search(line).group('address') for out in output for line in out if ip_regex.search(line) and not re.search('poll', line)])

async def extract_f5_trap_collector(tty):
    output = await tty.async_run_commands('show running-config sys snmp traps | grep host', 10)
    if output:
        return set([ip_regex.search(line).group('address') for out in output for line in out if ip_regex.search(line)])

async def extract_arista_trap_collector(tty):
    output = await tty.async_run_commands('show run | in snmp-server.*host', 10)
    if output:
        return set([ip_regex.search(line).group('address') for out in output for line in out if ip_regex.search(line)])

async def extract_a10_trap_collector(tty):
    output = await tty.async_run_commands('show run | in snmp-server.*host', 10)
    if output:
        return set([ip_regex.search(line).group('address') for out in output for line in out if ip_regex.search(line)])

async def extract_raritan_trap_collector(tty):
    """
    Extracts configured syslog servers of remote raritan device
    """
    output = await tty.async_run_commands("show snmp", 30)
    if output:
        trap_collectors = set([ip_regex.search(line).group('address') for out in output for line in out if ip_regex.search(line)])
        if trap_collectors:
            return trap_collectors
    print(f'Could not extract raritan trap collector data from {tty.host}: {output}')

async def extract_alu_acl(tty, acl_name):
    output = await tty.async_run_commands(rf'admin display-config | match "prefix-list \"{acl_name}\"" context all', 10)
    if output:
        return tty.sift_output(output, tty.username, tty.password, tty.prompt)

async def extract_xr_acl(tty, acl_name):
    output = await tty.async_run_commands(f'show access-list {acl-name}', 10)
    if output:
        return tty.sift_output(output, tty.username, tty.password, tty.prompt)

async def extract_ios_acl(tty, acl_name):
    output = await tty.async_run_commands(f'show ip access-list {acl-name}', 10)
    if output:
        return tty.sift_output(output, tty.username, tty.password, tty.prompt)

async def extract_junos_acl(tty, acl_name):
    output = await tty.async_run_commands(f'show configuration firewall | display set | match {acl-name}', 10)
    if output:
        return tty.sift_output(output, tty.username, tty.password, tty.prompt)

async def extract_arista_acl(tty, acl_name):
    output = await tty.async_run_commands(f'show ip access-list {acl-name}', 10)
    if output:
        return tty.sift_output(output, tty.username, tty.password, tty.prompt)


async def extract_alu_interface_v4_addresses(tty, interface):
    command = 'show router interface ipv4'
    if interface:
        command = " ".join([command, interface])
    output = await tty.async_run_commands(['environment no more', command], 10)
    interfaces = {}
    if output:
        if interface:
            return {interface: ip_regex.search(out[index + 1]).group('address') for out in output for index, line in enumerate(out) if re.match(interface, line)}
        else:
            return {out[index - 1].split()[0]: ip_regex.search(line).group('address') for out in output for index, line in enumerate(out) if ip_regex.search(line)}

async def extract_cisco_interface_v4_addresses(tty, interface):
    command = 'show ipv4 interface brief' if tty.os == 2 else 'show ip interface brief'
    if interface:
        command = " ".join([command, interface])
    output = await tty.async_run_commands(['terminal length 0', command], 10)
    if output:
        if interface:
            return {interface: ip_regex.search(line).group('address') for out in output for line in out if ip_regex.search(line) and re.match(interface, line)}
        else:
            return {line.split()[0]: ip_regex.search(line).group('address') for out in output for line in out if ip_regex.search(line)}

async def extract_junos_interface_v4_addresses(tty, interface):
    command = 'show interfaces terse | match "inet * [0-9]" | except "^em|^bme|^jsrv"'
    if interface:
        command = " ".join((command.split('|')[0], interface, "|", command.split('|')[1:]))
    output = await tty.async_run_commands(['set cli screen-length 0', command], 10)
    if output:
        if interface:
            return {interface: ip_regex.search(line).group('address') for out in output for line in out if ip_regex.search(line) and re.match(interface, line)}
        else:
            return {line.split()[0]: ip_regex.search(line).group('address') for out in output for line in out if ip_regex.search(line)}

async def extract_asa_interface_v4_addresses(tty, interface):
    command = 'show interface ip brief'
    if interface:
        command = " ".join((command, 'include |', interface))
    output = await tty.async_run_commands(['terminal pager 0', command], 10)
    phys_interfaces = {}
    if output:
        if interface:
            return {interface: ip_regex.search(line).group('address') for out in output for line in out if ip_regex.search(line) and re.match(interface, line)}
        else:
            phys_interfaces = {line.split()[0]: ip_regex.search(line).group('address') for out in output for line in out if ip_regex.search(line)}
    commands = []
    if phys_interfaces:
        commands = (f'show interface {interface} | include {interface}' for interface, _ in phys_interfaces.items())
    if commands:
        output = await tty.async_run_commands(commands, 5)
        if output:
            return {line.split('"')[1]: phys_interfaces.get(line.split()[1]) for out in output for line in out if '"' in line and line.split()[1] in phys_interfaces.keys()}


async def extract_f5_interface_v4_addresses(tty, interface):
    raise NotImplementedError

async def extract_a10_interface_v4_addresses(tty, interface):
    raise NotImplementedError

async def extract_xr_chassis_configuration(tty):
    output = await tty.async_run_commands('admin show controllers fabric plane all detail | in UP', 10)
    output = '\n'.join(output[0]) if output else output
    if output:
        match = re.search(r'MC|SC|BSB', output)
        return match.group(0) if match else None

async def extract_alu_tacacs_server(tty):
    output = await tty.async_run_commands('admin display-config | match tacplus context children | match server')
    if output:
        tacacs_servers = set([ip_regex.search(line).group('address') for out in output for line in out if ip_regex.search(line)])
        if tacacs_servers:
            return tacacs_servers

async def extract_ios_tacacs_server(tty):
    output = await tty.async_run_commands('show tacacs | include address')
    if output:
        tacacs_servers = set([ip_regex.search(line).group('address') for out in output for line in out if ip_regex.search(line)])
        if tacacs_servers:
            return tacacs_servers

async def extract_xr_tacacs_server(tty):
    output = await tty.async_run_commands('show tacacs | include server')
    if output:
        tacacs_servers = set([ip_regex.search(line.split('/')[0]).group('address') for out in output for line in out if ip_regex.search(line.split('/')[0])])
        if tacacs_servers:
            return tacacs_servers

async def extract_junos_tacacs_server(tty):
    output = await tty.async_run_commands('show configuration | display set | match tacplus')
    if output:
        tacacs_servers = set([ip_regex.search(line).group('address') for out in output for line in out if ip_regex.search(line)])
        if tacacs_servers:
            return tacacs_servers

async def extract_arista_tacacs_server(tty):
    output = await tty.async_run_commands('show tacacs | include server')
    if output:
        tacacs_servers = set([ip_regex.search(line.split('/')[0]).group('address') for out in output for line in out if ip_regex.search(line.split('/')[0])])
        if tacacs_servers:
            return tacacs_servers

async def extract_nxos_tacacs_server(tty):
    output = await tty.async_run_commands('show tacacs | exclude [a-z]')
    if output:
        tacacs_servers = set([ip_regex.search(line).group('address') for out in output for line in out if ip_regex.search(line)])
        if tacacs_servers:
            return tacacs_servers

async def extract_a10_tacacs_server(tty):
    output = await tty.async_run_commands('show tacacs-server | include server')
    if output:
        tacacs_servers = set([ip_regex.search(line).group('address') for out in output for line in out if ip_regex.search(line)])
        if tacacs_servers:
            return tacacs_servers

async def extract_f5_tacacs_server(tty):
    output = await tty.async_run_commands('show running-config auth | grep "server [0-9]"')
    if output:
        tacacs_servers = set([ip_regex.search(line).group('address') for out in output for line in out if ip_regex.search(line)])
        if tacacs_servers:
            return tacacs_servers
