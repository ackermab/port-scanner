import argparse
import ipaddress
import time
import re
from convert_dport import convert_port_input
from scapy.all import *

parser = argparse.ArgumentParser(description='Scan ports on a specified host.')
parser.add_argument('dhost', help='targets to scan in CIDR notation')
parser.add_argument('dport', help='ports to scan in single or range')
args = parser.parse_args()

def is_up(ip):
    icmp = IP(dst=ip)/ICMP()
    resp = sr1(icmp, timeout=10)
    if resp == None:
        return False
    else:
        return True

# Validate input targets
ip_net = []

re_ip_octet = '(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)'
re_ip_oct_range = re_ip_octet + '-' + re_ip_octet
re_ip_range = '(' + re_ip_octet + '.' + re_ip_octet + '.' + re_ip_octet + '.' + re_ip_oct_range + ')'

p0 = re.compile(re_ip_range)
m0 = p0.match(args.dhost)

if m0 is not None:
    ip_full = m0.group()
    print(ip_full)
    ip_split = ip_full.split('.')
    ip_last_split = ip_split[3].split('-')
    ip_last_start = ip_last_split[0]
    ip_last_end = ip_last_split[1]
    for i in range(int(ip_last_start), int(ip_last_end) + 1):
        ip_net.append(ip_split[0] + '.' + ip_split[1] + '.' + ip_split[2] + '.' + str(i))
else:
    try:
        ip_net = ipaddress.ip_network(args.dhost, strict=False)
    except ValueError:
        print('dhost not valid')
        exit()
    except:
        print('something went wrong')
        exit()
print('will scan ips: {}'.format(ip_net))

# Validate input ports
ports = []
re_port_single = '([0-9]{1,4}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5])'
re_port_range = re_port_single + '-' + re_port_single

p1 = re.compile(re_port_single)
p2 = re.compile(re_port_range)

m1 = p1.match(args.dport)
m2 = p2.match(args.dport)

if m2 is not None:
    ports_tuple = m2.group().split('-')
    for i in range(int(ports_tuple[0]), int(ports_tuple[1]) + 1):
            ports.append(i)
elif m1 is not None:
    ports.append(int(m1.group()))
else:
    print('invalid port input')
    exit()
print('will use ports: {}'.format(ports))

report = {}

# Begin Scanning
for ip in ip_net:
    ip = str(ip)
    conf.verb
    start_time = time.time()
    duration = 0
    port_report = {}
    closed_ports = 0
    open_ports = []
    host_up = 'false'
    print('Scanning {} with ICMP...'.format(ip))
    if is_up(ip):
        host_up = 'true'
        print('Host is up')

        for port in ports:
            print('Scanning {} on port {} TCP...'.format(ip, port))
            src_port = RandShort()
            p = IP(dst=ip)/TCP(sport=src_port, dport=port, flags='S')
            resp = sr1(p, timeout=2)
            if str(type(resp)) == "<type 'NoneType'>":
                closed += 1
            elif resp.haslayer(TCP):
                if resp.getlayer(TCP).flags == 0x12:
                    send_rst = sr(IP(dst=ip)/TCP(sport=src_port, dport=port, flags='AR'), timeout=1)
                    open_ports.append(port)
                elif resp.getlayer(TCP).flags == 0x14:
                    closed_ports += 1

        duration = time.time() - start_time
        print('Scan of {} completed in {}'.format(ip,duration))
        if len(open_ports) != 0:
            for open_port in open_ports:
                print('Open port {} on host {}'.format(open_port, ip))
        print('Scanned ports closed: {}'.format(closed_ports))
    else:
        print('Host {} is down'.format(ip))

    port_report = {'open':open_ports,'closed':closed_ports}
    report[ip] = {'is_up': host_up, 'port_report': port_report, 'duration': duration}

# Print Report
print('=====Report=====')
for key in report:
    print('Host: {}'.format(key))
    if report[key]['is_up'] == 'true':
        print('\tUp')
        ports = report[key]['port_report']['open']
        print('\tPorts open:')
        for port in ports:
            print('\t\t{}'.format(port))
        print('\t{} ports closed'.format(report[key]['port_report']['closed']))
    else:
        print('\tDown')

# Generate HTML Report
html_string = ''
html_string = html_string + '<html><body>'

for key in report:
    html_string = html_string + '<h2>Host: ' + key + '</h2>'
    
    if report[key]['is_up'] == 'true':
        html_string = html_string + '<div>Host is UP<br>'
        html_string = html_string + 'Ports open:<br>'
        for port in report[key]['port_report']['open']:
            html_string = html_string + str(port) + ' '
        html_string = html_string + '<br>'
        html_string = html_string + str(report[key]['port_report']['closed']) + ' closed port(s)</div>'
    else:
        html_string = html_string + '<div>Host is DOWN</div>'

html_string = html_string + '</body></html>'

html_file = open('output.html', 'w+')
html_file.write(html_string)
html_file.close()
print('Output to output.html')
