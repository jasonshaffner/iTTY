import re
from . import iTTY

async def extract_make(tty):
    """
    Extracts "make" of remote device
    """
    if tty.os == 1:
        return 'alcatel'
    elif tty.os in (2, 3, 5):
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

async def extract_hostname(tty):
    """
    Extracts "hostname" of remote device
    """
    if tty.os == 1:
        return await extract_alu_hostname(tty)
    elif tty.os in (2, 3, 5, 7):
        return await extract_cisco_hostname(tty)
    elif tty.os == 4:
        return await extract_junos_hostname(tty)
    elif tty.os == 6:
        return await extract_f5_hostname(tty)
    elif tty.os == 8:
        return await extract_a10_hostname(tty)

async def extract_contact(tty):
    """
    Extracts "contact" of remote device
    """
    if tty.os == 1:
        return await extract_alu_contact(tty)
    elif tty.os in (2, 3, 5, 7):
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
    elif tty.os in (2, 3, 5, 7):
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
    elif tty.os == 3:
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

async def extract_model(tty):
    """
    Extracts "model" of remote device
    """
    if tty.os == 1:
        return await extract_alu_model(tty)
    elif tty.os == 2:
        return await extract_xr_model(tty)
    elif tty.os == 3:
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

async def extract_series(tty):
    """
    Extracts "series" of remote device
    """
    if tty.os == 1:
        return await extract_alu_series(tty)
    elif tty.os == 2:
        return await extract_xr_series(tty)
    elif tty.os == 3:
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
    elif tty.os == 3:
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

async def extract_alu_version(tty):
    """
    Extracts software version of remote alcatel/nokia device
    """
    tty.set_commands(['show version'])
    output = await tty.async_run_commands(10)
    tty.clear_output()
    if not output:
        return
    for out in output:
        for line in out:
            if re.match('TiMOS', line):
                return line.split()[0].split('-')[-1]

async def extract_xr_version(tty):
    """
    Extracts software version of remote cisco IOS-XR device
    """
    version = ''
    tty.set_commands(["show version brief | in XR"])
    output = await tty.async_run_commands(10)
    tty.clear_output()
    if output:
        for out in output:
            for line in out:
                if re.search('XR', line):
                    try:
                        version = line.split('Version')[1].split('[')[0].strip()
                    except IndexError:
                        print('IndexError async_extract_xr_version', line)
    if not version:
        return
    tty.set_commands(["show version brief | in memory"])
    output = await tty.async_run_commands(10)
    tty.clear_output()
    if output:
        dev_type = str(output)
    else:
        return version
    if re.search('ASR9K', dev_type):
        tty.set_commands(["admin show install active summary | in sp"])
        output = await tty.async_run_commands(10)
        tty.clear_output()
        if output:
            for out in output:
                for line in out:
                    if not re.search(tty.prompt, line):
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
        tty.set_commands(["admin sh install active summary | in CSC | utility wc -l"])
        output = await tty.async_run_commands(10)
        tty.clear_output()
        if output:
            ansi_escape = re.compile(r'\x1B\[[0-?]*[ -/]*[@-~]')
            for out in output:
                for line in out:
                    if not re.search(tty.prompt, line):
                        try:
                            smu = int(ansi_escape.sub('', line).strip())
                        except ValueError:
                            smu = None
                            continue
                        tty.clear_output()
                        if smu:
                            return version + '-smu' + str(smu)
                        else:
                            return version

async def extract_ios_version(tty):
    """
    Extracts software version of remote cisco IOS device
    """
    tty.set_commands(['show version'])
    output = await tty.async_run_commands(10)
    tty.clear_output()
    if output:
        for out in output:
            for line in out:
                if re.search('Version', line) and not re.search('show|LGPL|ID', line):
                    try:
                        version = line.split('Version')[1].split(',')[0].split()[0].strip()
                        return version
                    except IndexError:
                        print('extract_ios_verion: INDEXERROR: ', tty.host, line)
                elif re.search('system.*version', line):
                    return line.split('version')[1].strip()

async def extract_junos_version(tty):
    """
    Extracts software version of remote juniper device
    """
    tty.set_commands(['set cli screen-length 0', 'show version | match "Software Suite"'])
    output = await tty.async_run_commands(10)
    tty.clear_output()
    if output:
        for out in output:
            for line in out:
                if re.search('Software Suite', line) and not re.search('show|builder', line):
                    return line.split()[-1].strip('[').strip(']')
    tty.clear_output()
    tty.set_commands(['show version | match "Junos:"'])
    output = await tty.async_run_commands(10)
    tty.clear_output()
    if output:
        for out in output:
            for line in out:
                if re.search('Junos', line) and not re.search('show', line):
                    return line.split()[-1]

async def extract_asa_version(tty):
    """
    Extracts software version of remote cisco asa device
    """
    if re.search('>', tty.prompt):
        tty.set_commands(['enable', tty.password, 'show version | in Software Version', 'show version | in system:'])
    else:
        tty.set_commands(['show version | in Software Version', 'show version | in system:'])
    output = await tty.async_run_commands(10)
    tty.clear_output()
    if output:
        for out in output:
            for line in out:
                if re.search('Version', line):
                    if not re.search('show|loader:', line):
                        if re.search('system:', line):
                            return line.split('Version')[1].split()[0]
                        return line.split()[-1]

async def extract_f5_version(tty):
    """
    Extracts software version of remote f5 device
    """
    tty.set_commands(['show sys version | grep Version | grep -v Sys'])
    output = await tty.async_run_commands(10)
    tty.clear_output()
    if output:
        for out in output:
            for line in out:
                if re.search('Version', line) and not re.search('show', line):
                    return line.split()[1]

async def extract_arista_version(tty):
    """
    Extracts software version of remote arista device
    """
    tty.set_commands(['show version | in Software'])
    output = await tty.async_run_commands(10)
    tty.clear_output()
    if output:
        for out in output:
            for line in out:
                if not re.search('show', line) and re.search('Software', line):
                    return line.split('-')[0].split()[-1].strip()

async def extract_a10_version(tty):
    """
    Extracts software version of remote a10 device
    """
    tty.set_commands(['show version | in Advanced'])
    output = await tty.async_run_commands(10)
    tty.clear_output()
    if output:
        for out in output:
            for line in out:
                if not re.search('show', line) and re.search('ersion', line):
                    return line.split('ersion')[1].split()[0].strip(',')



async def extract_alu_model(tty):
    """
    Extracts model of remote alcatel/nokia device
    """
    tty.set_commands(['show chassis | match Type'])
    output = await tty.async_run_commands(10)
    tty.clear_output()
    if output:
        for out in output:
            for line in out:
                if re.search('Type', line) and not re.search('show', line):
                    return "".join(line.split(':')[1].split()).strip()

async def extract_xr_model(tty):
    """
    Extracts model of remote cisco IOS-XR device
    """
    tty.set_commands(['show version brief | in "memory|hassis"'])
    output = await tty.async_run_commands(10)
    if re.search('CRS', str(output)):
        return tty.sift_output([tty.username, tty.password, tty.prompt])[0].split()[1]
    elif re.search('ASR', str(output)):
        for out in output:
            for line in out:
                if re.search('ASR\-', line):
                    return line.split()[0]
                elif re.search('ASR\ ', line):
                    return line.split()[1]
    else:
        tty.clear_output()
        tty.set_commands(['admin show inventory'])
        output = await tty.async_run_commands(10)
        tty.clear_output()
        nxt = False
        if not output:
            return
        for out in output:
            for line in out:
                if re.search('Chassis', line):
                    nxt = True
                    continue
                if nxt:
                    return line.split()[1]

async def extract_ios_model(tty):
    """
    Extracts model of remote cisco IOS device
    """
    tty.set_commands(['terminal length 0', 'show version'])
    output = await tty.async_run_commands(10)
    tty.clear_output()
    if output:
        for out in output:
            for line in out:
                if re.search('memory.', line) \
                    and (not re.search('show', line)\
                    or not re.search('ermission', line)):
                    return line.split()[1]
                elif re.search('Nexus.*Chassis', line):
                    if re.search('Nexus\d{1,4}', line):
                        return re.search('Nexus\d{1,4}', line).group(0)
                    return line.split()[2]

async def extract_junos_model(tty):
    """
    Extracts model of remote juniper device
    """
    tty.set_commands(['set cli screen-length 0', 'show version local | match Model'])
    output = await tty.async_run_commands(10)
    tty.clear_output()
    if output:
        for out in output:
            for line in out:
                if re.search('Model', line) and not re.search('show', line):
                    return line.split()[-1]

async def extract_asa_model(tty):
    """
    Extracts model of remote cisco ASA device
    """
    if re.search('>', tty.prompt):
        tty.set_commands(['enable', tty.password, 'terminal pager 0', 'show version | in Hardware', 'show inventory | in PID'])
    else:
        tty.set_commands(['terminal pager 0', 'show version | in Hardware', 'show inventory | in PID'])
    output = await tty.async_run_commands(10)
    tty.clear_output()
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
    tty.set_commands(['show sys hardware field-fmt | grep marketing-name'])
    output = await tty.async_run_commands(10)
    tty.clear_output()
    if output:
        for out in output:
            for line in out:
                if not re.search('show', line) and re.search('marketing', line) and not re.match('Edition', line.split()[-1]):
                    return line.split()[-1]
    tty.set_commands(['show sys hardware field-fmt | grep platform'])
    output = await tty.async_run_commands(10)
    tty.clear_output()
    if output:
        for out in output:
            for line in out:
                if not re.search('show|hardware', line) and re.search('platform', line):
                    return line.split()[-1]

async def extract_arista_model(tty):
    """
    Extracts model of remote arista device
    """
    tty.clear_output()
    tty.set_commands(['show version | in Arista'])
    output = await tty.async_run_commands(10)
    tty.clear_output()
    if output:
        for out in output:
            for line in out:
                if not re.search('show', line) and re.search('Arista', line):
                    return line.split('Arista')[1].strip()

async def extract_a10_model(tty):
    """
    Extracts model of remote a10 device
    """
    tty.set_commands(['show version | include Series'])
    output = await tty.async_run_commands(10)
    tty.clear_output()
    if output:
        for out in output:
            for line in out:
                if not re.search('show', line) and re.search('Series', line):
                    return line.split()[-1]

async def extract_alu_hostname(tty):
    """
    Extracts hostname of remote alcatel/nokia device
    """
    return tty.prompt.split(":")[1].strip("#")

async def extract_cisco_hostname(tty):
    """
    Extracts hostname of remote cisco (and arista EOS) device
    """
    tty.set_commands(['show run | in "hostname"', 'show run | in "domain name"', 'show run | in "domain-name"'])
    output = await tty.async_run_commands(10)
    tty.clear_output()
    if output:
        hostname = ''
        domain = ''
        for out in output:
            for line in out:
                if not re.search('show|logging', line) and re.search('hostname', line):
                    hostname = line.split()[-1]
                elif not re.search('show|logging', line) and re.search('domain', line):
                    domain = line.split()[-1]
                if hostname and domain:
                    return '.'.join((hostname, domain))
    if tty.get_os() == 2:
        return tty.prompt.split(":")[1].strip("#")
    elif tty.get_os() == 3:
        return tty.prompt.strip('#')
    elif tty.get_os() == 5:
        return tty.prompt.split('/')[0].strip('#>')
    elif tty.get_os() == 7:
        return tty.prompt.strip("#>").split('(')[0]

async def extract_junos_hostname(tty):
    """
    Extracts hostname of remote juniper device
    """
    tty.set_commands(['set cli screen-length 0', 'show configuration | display set | match "host-name"', 'show configuration | display set | match domain-name'])
    output = await tty.async_run_commands(10)
    tty.clear_output()
    if output:
        hostname = ''
        domain = ''
        for out in output:
            for line in out:
                if not re.search('show', line) and re.search('host-name', line):
                    hostname = line.split()[-1]
                elif not re.search('show', line) and re.search('domain-name', line):
                    domain = line.split()[-1]
                if hostname and domain:
                    return '.'.join((hostname, domain))
    return tty.prompt.split("@")[1].strip('>')

async def extract_f5_hostname(tty):
    """
    Extracts hostname of remote f5 device
    """
    tty.set_commands(['list cm device | grep hostname'])
    output = await tty.async_run_commands(10)
    tty.clear_output()
    if output:
        for out in output:
            for line in out:
                if not re.search('list', line) and re.search('hostname', line):
                    return line.split()[-1]
    return tty.prompt.split("@")[1].split('(')[1].strip(')')

async def extract_a10_hostname(tty):
    """
    Extracts hostname of remote a10 device
    """
    tty.set_commands(['show run | in hostname'])
    output = await tty.async_run_commands(10)
    tty.clear_output()
    if output:
        for out in output:
            for line in out:
                if not re.search('show', line) and re.search('hostname', line):
                    if re.search('device', line):
                        return line.split()[1]
                    return line.split()[-1]
    return tty.prompt.split('-')[0].strip('#>')

async def extract_avocent_hostname(tty):
    """
    Extracts hostname of remote avocent device
    """
    tty.set_commands(['ls access/'])
    output = await tty.async_run_commands(10)
    tty.clear_output()
    if output:
        for out in output:
            for line in out:
                return line.split('/')[0]

async def extract_niagara_hostname(tty):
    """
    Extracts hostname of remote niagara device
    """
    return tty.prompt.strip('#')


async def extract_alu_contact(tty):
    """
    Extracts contact of remote alcatel/nokia device
    """
    tty.set_commands(['admin display-config | match contact'])
    output = await tty.async_run_commands(10)
    tty.clear_output()
    if output:
        for out in output:
            for line in out:
                if not re.search('display', line) and re.search('contact', line):
                    return line.split('contact')[-1].strip().strip('"')

async def extract_cisco_contact(tty):
    """
    Extracts contact of remote cisco (and arista EOS) device
    """
    tty.set_commands(['show run | in contact'])
    output = await tty.async_run_commands(10)
    tty.clear_output()
    if output:
        for out in output:
            for line in out:
                if not re.search('show|banner|sending|description', line) and re.search('contact', line):
                    return line.split('contact')[-1].strip().strip('"')

async def extract_junos_contact(tty):
    """
    Extracts contact of remote juniper device
    """
    tty.set_commands(['set cli screen-length 0', 'show configuration | display set | match contact'])
    output = await tty.async_run_commands(10)
    tty.clear_output()
    if output:
        for out in output:
            for line in out:
                if not re.search('show', line) and re.search('contact', line):
                    return line.split('contact')[-1].strip().strip('"')

async def extract_f5_contact(tty):
    """
    Extracts contact of remote f5 device
    """
    tty.set_commands(['list sys snmp sys-contact'])
    output = await tty.async_run_commands(10)
    tty.clear_output()
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
    tty.set_commands(['show run | in snmp-server contact'])
    output = await tty.async_run_commands(10)
    tty.clear_output()
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
    tty.set_commands(['admin display-config | match location'])
    output = await tty.async_run_commands(10)
    tty.clear_output()
    if output:
        for out in output:
            for line in out:
                if not re.search('display|cf\d:', line) and re.search('location', line):
                    return line.split('location')[-1].strip().strip('"')

async def extract_cisco_location(tty):
    """
    Extracts location of remote cisco (and arista EOS) device
    """
    tty.set_commands(['show run | in location'])
    output = await tty.async_run_commands(10)
    tty.clear_output()
    if output:
        for out in output:
            for line in out:
                if not re.search('show|vlan|modem|banner|cpu0|description|note', line, flags=re.IGNORECASE) and re.search('location', line):
                    return line.split('location')[-1].strip().strip('"')

async def extract_junos_location(tty):
    """
    Extracts location of remote juniper device
    """
    tty.set_commands(['set cli screen-length 0', 'show configuration | display set | match location'])
    output = await tty.async_run_commands(10)
    tty.clear_output()
    if output:
        for out in output:
            for line in out:
                if not re.search('show|\-code', line) and re.search('location', line):
                    return line.split('location')[-1].strip().strip('"')

async def extract_f5_location(tty):
    """
    Extracts location of remote f5 device
    """
    tty.set_commands(['list sys snmp sys-location'])
    output = await tty.async_run_commands(10)
    tty.clear_output()
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
    tty.set_commands(['show run | in snmp-server location'])
    output = await tty.async_run_commands(10)
    tty.clear_output()
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
    tty.set_commands(['admin display-config | match syslog context children | match address'])
    output = await tty.async_run_commands(10)
    tty.clear_output()
    if output:
        syslogs = set()
        for out in output:
            for line in out:
                if not re.search('admin', line) and re.search('address', line):
                    try:
                        syslogs.add(line.split()[-1])
                    except IndexError:
                        print('extract_alu_syslog_server: INDEXERROR: ', tty.host, line)
        return syslogs

async def extract_xr_syslog_server(tty):
    """
    Extracts configured syslog servers of remote cisco IOS-XR device
    """
    tty.set_commands(["show run formal | utility egrep '^logging [0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}'"])
    output = await tty.async_run_commands(10)
    tty.clear_output()
    if output:
        syslogs = set()
        for out in output:
            for line in out:
                if not re.search('show', line) and re.search('logging', line):
                    try:
                        syslogs.add(line.split()[1])
                    except IndexError:
                        print('extract_xr_syslog_server: INDEXERROR: ', tty.host, line)
        return syslogs

async def extract_ios_syslog_server(tty):
    """
    Extracts configured syslog servers of remote cisco IOS device
    """
    tty.set_commands(["show run | in logging"])
    output = await tty.async_run_commands(10)
    tty.clear_output()
    if output:
        syslogs = set()
        for out in output:
            for line in out:
                if not re.search('show', line) and re.match('logging', line) and re.search('\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', line):
                    try:
                        syslogs.add(re.search('\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', line).group(0))
                    except IndexError:
                        print('extract_ios_syslog_server: INDEXERROR: ', tty.host, line)
        return syslogs

async def extract_junos_syslog_server(tty):
    """
    Extracts configured syslog servers of remote juniper device
    """
    tty.set_commands(['set cli screen-length 0', "show configuration | display set | match syslog\ host"])
    output = await tty.async_run_commands(10)
    tty.clear_output()
    if output:
        syslogs = set()
        for out in output:
            for line in out:
                if not re.search('show', line) and re.search('syslog', line):
                    try:
                        syslogs.add(line.split('host')[1].split()[0])
                    except IndexError:
                        print('extract_junos_syslog_server: INDEXERROR: ', tty.host, line)
        return syslogs

async def extract_asa_syslog_server(tty):
    """
    Extracts configured syslog servers of remote cisco asa device
    """
    tty.set_commands(['show run | in logging host'])
    output = await tty.async_run_commands(10)
    tty.clear_output()
    if output:
        syslogs = set()
        for out in output:
            for line in out:
                if not re.search('show', line) and re.match('logging', line):
                    try:
                        syslogs.add(line.split()[-1])
                    except IndexError:
                        print('extract_asa_syslog_server: INDEXERROR: ', tty.host, line)
        return syslogs

async def extract_f5_syslog_server(tty):
    """
    Extracts configured syslog servers of remote f5 device
    """
    tty.set_commands(['show running-config sys syslog'])
    output = await tty.async_run_commands(10)
    tty.clear_output()
    if output:
        syslogs = set()
        for out in output:
            for line in out:
                if not re.search('show', line) and re.search('host', line):
                    try:
                        syslogs.add(line.split()[-1])
                    except IndexError:
                        print('extract_f5_syslog_server: INDEXERROR: ', tty.host, line)
        return syslogs

async def extract_arista_syslog_server(tty):
    """
    Extracts configured syslog servers of remote arista device
    """
    tty.set_commands(["show run | in logging host"])
    output = await tty.async_run_commands(10)
    tty.clear_output()
    if output:
        syslogs = set()
        for out in output:
            for line in out:
                if not re.search('show', line) and re.match('logging', line):
                    try:
                        syslogs.add(line.split()[-1])
                    except IndexError:
                        print('extract_arista_syslog_server: INDEXERROR: ', tty.host, line)
        return syslogs

async def extract_a10_syslog_server(tty):
    """
    Extracts configured syslog servers of remote a10 device
    """
    tty.set_commands(["show run | in logging host"])
    output = await tty.async_run_commands(10)
    tty.clear_output()
    if output:
        for out in output:
            for line in out:
                if not re.search('show', line) and re.match('logging', line):
                    try:
                        syslogs = set()
                        servers = line.split('host')[1].split()
                        while servers:
                            server = servers.pop()
                            if re.match('\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', server):
                                syslogs.add(server)
                        return syslogs
                    except IndexError:
                        print('extract_a10_syslog_server: INDEXERROR: ', tty.host, line)

async def extract_junos_series(tty):
    tty.set_commands(['set cli screen-length 0', 'show version local | match Model'])
    output = await tty.async_run_commands(10)
    tty.clear_output()
    if output:
        for out in output:
            for line in out:
                if re.search('Model', line) and not re.search('show', line):
                    return line.split()[-1].split('-')[0]

async def extract_ios_series(tty):
    tty.set_commands(['terminal length 0', 'show version'])
    output = await tty.async_run_commands(10)
    tty.clear_output()
    if output:
        for out in output:
            for line in out:
                if re.search('c7600', line):
                    return 'c7600'
                if re.search('Software', line)\
                    and not re.search('Nexus', line)\
                    and not re.search('Internetwork', line)\
                    and len(line.strip().split()) > 1:
                    try:
                        if re.search('Catalyst', line):
                            return line.split('Catalyst')[1].split()[0]
                        elif re.match('IOS', line):
                            return line.split(')')[1].split()[0]
                        return line.split(',')[1].split()[0]
                    except IndexError:
                        print('extract_ios_series: IndexError:', tty.host, line)
                elif re.search('bootflash.*n\d{1,4}', line):
                    return re.search('n\d{1,4}', line).group(0)
                elif re.search('Nexus\ ?\d{1,4}', line):
                    return ''.join(('n', line.split('Nexus')[1].split()[0]))

async def extract_alu_series(tty):
    return
    tty.set_commands(['show chassis | Type'])
    output = await tty.async_run_commands(10)
    tty.clear_output()
    if output:
        for out in output:
            for line in out:
                if re.search('Type', line.strip()):
                    return "".join((line.split()[-1].split('-')[0], line.split()[-2])).lower()

async def extract_xr_series(tty):
    tty.set_commands(["show version brief | in memory"])
    output = await tty.async_run_commands(10)
    tty.clear_output()
    if output:
        for out in output:
            for line in out:
                if re.search('cisco', line.strip()):
                    if re.search('CRS', line):
                        series = 'CRS'
                    else:
                        series = line.split()[1]
                    return series

async def extract_asa_series(tty):
    if re.search('>', tty.prompt):
        tty.set_commands(['enable', tty.password, 'show version | in hardware', 'show inventory | in DESCR:'])
    else:
        tty.set_commands(['show version | in hardware', 'show inventory | in DESCR:'])
    output = await tty.async_run_commands(10)
    tty.clear_output()
    if output:
        for out in output:
            for line in out:
                if re.search('Encryption hardware device', str(line)):
                    try:
                        return line.split(':')[1].split()[1]
                    except IndexError:
                        return
                elif re.search('DESCR', line):
                    return line.split('DESCR:')[1].split()[0].strip('"')

async def extract_arista_series(tty):
    tty.set_commands(['show version | in Arista'])
    output = await tty.async_run_commands(10)
    tty.clear_output()
    if output:
        for out in output:
            for line in out:
                if re.search('Arista', line) and not re.search('show', line):
                    return line.split('Arista')[1].split('-')[1].strip()
