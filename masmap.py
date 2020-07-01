# coding=u8
import sys
import os
import socket
import urlparse


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


def masscan(ip, rate):
    for x in xrange(0, 3):
        os.system('masscan -p1-65535 --wait 1 --rate=' + rate + ' -oG {tmp} {ip}'.format(tmp='/tmp/tmp_result_' + str(x), ip=ip))
        os.system('cat /tmp/tmp_result')


def selectPorts():
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
    print('\n[CMD] nmap -Pn -T5 -sV -A {ip} -p{ports} -oN {ip}.result'.format(ip=ip, ports=ports))
    os.system('nmap -Pn -T5 -sV -A {ip} -p{ports} -oN {ip}.result'.format(ip=ip, ports=ports))


if __name__ == '__main__':

    if len(sys.argv) < 3:
        print('Usage: python2 ' + sys.argv[0] + ' ip rate')
        sys.exit()

    ip = url2ip(sys.argv[1])
    rate = sys.argv[2]

    print('\nIP: ' + ip + '\r')

    masscan(ip, rate)
    ports = selectPorts()
    nmap(ip, ports)
