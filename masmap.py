# coding: utf8
#!/usr/bin/env python3
import sys
import os
import re
import socket
import subprocess
from urllib.parse import urlparse

path = '/opt/masmap'

fscanElf = path + '/bin/tscan'
masscanElf = path + '/bin/masscan'
allinElf = path + '/bin/AlliN.py'


def url2ip(url):
    try:
        domain = urlparse.urlparse(url).hostname
        ip = socket.gethostbyname(domain)
        return ip
    except:
        try:
            ip = socket.gethostbyname(url)
            return ip
        except:
            pass


def location(ip):
    os.system(f'curl "http://cip.cc/{ip}" --connect-timeout 5')


def masscan(ip, rate):
    out_text = subprocess.check_output(
        [masscanElf, '-p 1-65535', '--wait=0', f'--rate={rate}', ip],
        shell=False).decode('utf-8')
    ports = out_text.split('\n')
    result = []
    for port in ports:
        if port == '':
            continue
        port = port.strip().strip('\n').split(' ')
        result.append(port[3].replace('/', '').replace('udp', '').replace('tcp', ''))
    print(f'\n[*] 可用端口: {len(result)}')
    print(result)
    return result


def masscan3(ip):
    ports = []
    for x in range(0, 3):
        ports += masscan(ip, 10000)
    ports = list(set(ports))

    return ports


# def allin(ip):
#     os.system('python2 {allin} --host {ip} -p 1-65535 -m pscan -t 100 -o {path}/results/{ip}.allin'.format(allin=allinElf, ip=ip, path=path))
#     # python2 AlliN.py --host 123.138.87.76 -p 1-65535 -m pscan
#     # print('python {allin} --host {ip} -p 1-65535 -m pscan -t 100 -o results/{ip}.allin'.format(allin=allinElf, ip=ip))


def allin(ip):
    os.system('python2 {allin} --host {ip} -p 1-65535 -m pscan -t 200 -o {path}/results/{ip}.allin'.format(allin=allinElf, ip=ip, path=path))
    # python2 AlliN.py --host 123.138.87.76 -p 1-65535 -m pscan
    # print('python {allin} --host {ip} -p 1-65535 -m pscan -t 100 -o {path}/results/{ip}.allin'.format(allin=allinElf, ip=ip, path=path))
    result = open('{path}/results/{ip}.allin'.format(ip=ip, path=path))
    result = result.readlines()
    ports = []
    for line in result:
        port = line.split('|')[3].strip().replace(']','')
        ports.append(port)

    ports = list(set(ports))
    # strPorts = ','.join(ports)
    return ports


def fscan(ip, ports):
    # print('\n[CMD] {fscan} -np -nobr -h {ip} -p {ports} -o {ip}.result'.format(fscan=fscanElf, ip=ip, ports=ports))
    os.system('{fscan} -np -h {ip} -p {ports} -o {path}/results/{ip}.result'.format(fscan=fscanElf, ip=ip, ports=ports, path=path))


if __name__ == '__main__':

    if len(sys.argv) < 1:
        print('Usage: python3 ' + sys.argv[0] + ' ip')
        sys.exit()

    ip = url2ip(sys.argv[1])

    location(ip)

    ports = masscan3(ip)

    if ports != []:
        print(f'\n[*] 可用端口: {len(ports)}')
        print(ports)
        strPorts = ','.join(ports)
        fscan(ip, strPorts)
    else:
        print('masscan scan failed, try to scan with tcp full Accept Scan.')
        ports = allin(ip)
        print(f'\n[*] 可用端口: {len(ports)}')
        print(ports)
        strPorts = ','.join(ports)
        fscan(ip, strPorts)
