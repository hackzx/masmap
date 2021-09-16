# coding: utf8
from gevent import monkey
monkey.patch_all()
from gevent.pool import Pool
import sys
import os
import socket
import re
import subprocess
from urllib.parse import urlparse

import requests
from requests.adapters import HTTPAdapter

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

s = requests.Session()
s.mount('http://', HTTPAdapter(max_retries=3))
s.mount('https://', HTTPAdapter(max_retries=3))

timeout = 5


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
    masscan = 'masscan'
    out_text = subprocess.check_output(
        [masscan, '-p 1-65535', '--wait=0', f'--rate={rate}', ip],
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

    # result = {}
    # result[ip] = ports
    # return result
    return ports


def nmap(ip, ports):
    print('\n[CMD] nmap -Pn -T5 -sV {ip} -p{ports} -oN {ip}.result'.format(
        ip=ip, ports=ports))
    os.system('nmap -Pn -T5 -sV {ip} -p{ports} -oN {ip}.result'.format(
        ip=ip, ports=ports))


def getOpenPortUlrs(ip, ports):
    urls = []
    for port in ports:
        urls.append(f'http://{ip}:{port}')
        urls.append(f'https://{ip}:{port}')

    return urls


def getAllPortUlrs(ip):

    startPort = 1
    endPort = 30000
    http = [f'http://{ip}:{str(x)}' for x in range(startPort, endPort)]
    https = [f'https://{ip}:{str(x)}' for x in range(startPort, endPort)]

    urls = []

    for i in range(0, len(http)):
        urls.append(http[i])
        urls.append(https[i])

    return urls


def web(url):
    try:
        r = s.get(url, timeout=timeout, verify=False)

        content = r.text
        title = re.search(r'<title>(.*)</title>', content)
        if title:
            title = title.group(1).strip().strip('\r').strip('\n')
        else:
            title = 'None'

        if r.status_code != 400:
            print(url, r.status_code, f'<{title}>')
    except:
        pass


def run(urls):
    p = Pool(500)
    for i in urls:
        p.spawn(web, i.strip())
    p.join()


if __name__ == '__main__':

    if len(sys.argv) < 1:
        print('Usage: python3 ' + sys.argv[0] + ' ip')
        sys.exit()

    ip = url2ip(sys.argv[1])

    location(ip)

    ports = masscan3(ip)

    if ports is not None:
        print()
        print(f'[*] 可用端口: {len(ports)}')
        print(ports)
        print()
        print(f'[*] 可用WEB:')
        urls = getOpenPortUlrs(ip, ports)
    else:
        urls = getAllPortUlrs(ip)

    run(urls)
