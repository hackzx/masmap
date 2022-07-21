# coding: utf8
#!/usr/bin/env python3
import sys
import os
import re
import socket
import subprocess
from urllib.parse import urlparse


fscanElf = 'bin/fscan'
masscanElf = 'bin/masscan'


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
    print(result)
    return result


def masscan3(ip):
    ports = []
    for x in range(0, 3):
        ports += masscan(ip, 10000)
    ports = list(set(ports))

    return ports


def fscan(ip, ports):
    # print('\n[CMD] {fscan} -np -nobr -h {ip} -p {ports} -o {ip}.result'.format(fscan=fscanElf, ip=ip, ports=ports))
    os.system('{fscan} -np -nobr -h {ip} -p {ports} -o {ip}.result'.format(fscan=fscanElf, ip=ip, ports=ports))


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
        fscan(ip, '1-65535')