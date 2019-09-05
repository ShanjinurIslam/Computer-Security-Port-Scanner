import argparse
import re
import socket
import sys
import time
import struct
import threading


def TCP_Scan(ipaddress, port,flag):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        result = sock.connect_ex((ipaddress,port))
        if result == 0:
            print('PORT %s STATE open' % port)
        
        if(result == 111 and flag==True):
            print('PORT %s STATE closed or filtered' % port)
            
        
        if result == 113:
            print("Couldn\'t connect with Target : %s\nHost is Offline\nTerminating program..." % ipaddress)
            sys.exit(1)
            
    except socket.error:
        msg = socket.error
        sys.exit(1)
    return 

def SYN_Scan():
    return


flag_port = False

parser = argparse.ArgumentParser(description='PortScanner v1.0')
parser.add_argument('ipaddress', type=str,
                    help='Provide Target IP Address or URL')
parser.add_argument('-p', '--port', type=str,
                    help='Select Specific Port or <Port Ranges>')
parser.add_argument('-s','--SYN', action='store_true', default=False,
                    dest='flag_syn',
                    help='Force SYN Scan')
parser.add_argument('-t','--TCP', action='store_true', default=False,
                    dest='flag_tcp',
                    help='Force TCP Scan')

my_namespace = parser.parse_args()
my_ip = my_namespace.ipaddress
is_valid = re.match(
    "^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$", my_ip)
if is_valid:
    print("%s is a valid ip address\n" % my_ip)
else:
    my_hostname = my_ip
    is_valid = re.match(
        "^(([a-zA-Z]|[a-zA-Z][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z]|[A-Za-z][A-Za-z0-9\-]*[A-Za-z0-9])$", my_hostname)
    if is_valid:
        print("%s is a valid hostname" % my_hostname)
        print('Resolving IP Address...')
        my_ip = socket.gethostbyname(my_hostname)
        print(my_ip)

    else:
        print("Invalid Input\nTerminating Program")
        sys.exit(1)


if my_namespace.port is not None:
    flag_port = True 
    my_port = my_namespace.port
    if('-' in my_port):
        bounds = my_port.split('-')
        lower = int(bounds[0])
        upper = int(bounds[1])
        threads = []
        time_start = time.time()
        for port in range(lower, upper):
            t = threading.Thread(target=TCP_Scan, args=(
                my_ip, port,False))
            threads.append(t)
        
        for thread in threads:
            thread.start()
        
        for thread in threads:
            thread.join()
        time_end = time.time()
        print('Scan completed in : %f seconds' % (time_end-time_start))

    else:
        my_port = int(my_port)
        TCP_Scan(my_ip,my_port,True)


