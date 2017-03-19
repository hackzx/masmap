# coding=u8

import sys,os
import commands

# (status, output) = commands.getstatusoutput('whoami')
# print status, output
ip=sys.argv[1]
# print commands.getstatusoutput('masscan -p1-65535 --rate=1000000 {ip}'.format(ip=ip))
output = os.popen('masscan -p1-65535 --rate=10000 {ip}'.format(ip=ip))
print output.read()