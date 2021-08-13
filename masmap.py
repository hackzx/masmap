# coding: utf8
import gevent
from gevent import monkey
# monkey.patch_socket()
monkey.patch_all()
from gevent.pool import Pool
import sys
import os
import socket
import re
from urllib.parse import urlparse

import requests
from requests.adapters import HTTPAdapter

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


def Location(ip):
    os.system('curl ip.cn/index.php?ip={0}'.format(ip))


def masscan(ip, rate=5000):
    for x in range(0, 3):
        os.system('masscan -p1-65535 --wait 1 --rate=' + rate + ' -oG {tmp} {ip}'.format(tmp='/tmp/tmp_result_' + str(x), ip=ip))
        os.system('cat /tmp/tmp_result_' + str(x))
    print('\n')


def selectPorts():
    # os.system('rm -rf /tmp/tmp_result')
    os.system('cat /tmp/tmp_result_0 /tmp/tmp_result_1 /tmp/tmp_result_2 | sort | uniq > /tmp/tmp_result')
    os.system('sed -i -e \'/#/d\' /tmp/tmp_result')

    ports = ''
    with open('/tmp/tmp_result') as f:
        for line in f:
            if ports != '':
                ports += ','
            port = line.split()
            ports += port[4].replace('/', '').replace('open', '').replace('tcp', '')
    return ports


def nmap(ip, ports):
    print('\n[CMD] nmap -Pn -T5 -sV {ip} -p{ports} -oN {ip}.result'.format(ip=ip, ports=ports))
    os.system('nmap -Pn -T5 -sV {ip} -p{ports} -oN {ip}.result'.format(ip=ip, ports=ports))


def getOpenPortUlrs(ip, ports):
    # ip = ''
    # ports = []
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
        r = s.get(url, timeout=timeout)

        content = r.text
        title = re.search(r'<title>(.*)</title>', content)
        if title:
            title = title.group(1).strip().strip('\r').strip('\n')
        else:
            title = 'None'

        if r.status_code == 400:
            url = url.replace('http', 'https')
        print(url, r.status_code, f'<{title}>')
    except:
        pass


def run(urls):
    p = Pool(500)
    for i in urls:
        p.spawn(web, i.strip())
    p.join()


if __name__ == '__main__':

    if len(sys.argv) < 2:
        print('Usage: python3 ' + sys.argv[0] + ' ip rate')
        sys.exit()

    ip = url2ip(sys.argv[1])
    rate = sys.argv[2]

    print('\nIP: ' + ip + '\r')

    # masscan(ip, rate)
    # ports = selectPorts()
    # nmap(ip, ports)

    # masscan(ip, rate)
    ports = selectPorts()

    if ports is not None:
        ports = ports.split(",")
        urls = getOpenPortUlrs(ip, ports)
    else:
        urls = getAllPortUlrs(ip)

    run(urls)
