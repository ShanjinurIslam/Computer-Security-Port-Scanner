import argparse
import re
import socket
import sys
import time
import os
import threading
from struct import *




def get_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # doesn't even have to be reachable
        s.connect(('10.255.255.255', 1))
        IP = s.getsockname()[0]
    except:
        IP = '127.0.0.1'
    finally:
        s.close()
    return IP


def checksum(msg):
    s = 0
    # loop taking 2 characters at a time
    for i in range(0, len(msg), 2):
        w = ord(msg[i]) + (ord(msg[i+1]) << 8)
        s = s + w

    s = (s >> 16) + (s & 0xffff)
    s = s + (s >> 16)

    # complement and mask to 4 byte short
    s = ~s & 0xffff

    return s


def check_status(ipaddress):
    result = os.system("ping -c 1 " + ipaddress + " > /dev/null")
    if(result==0):
        return True
    else :
        return False
    print('\n')


def TCP_Scan(ipaddress, port, flag):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        result = sock.connect_ex((ipaddress, port))
        if result == 0:
            print('PORT %s STATE open' % port)
            return

        if(result == 111 and flag == True):
            print('PORT %s STATE closed or filtered' % port)
            return

        if result == 113:
            print(
                "Couldn\'t connect with Target : %s\nHost is Offline\nTerminating program..." % ipaddress)
            sys.exit(1)

    except socket.error:
        msg = socket.error
        sys.exit(1)
    return


def SYN_Scan_Sender(ip, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    packet = ''
    source_ip = get_ip()
    dest_ip = ip
    # ip layer
    ip_ihl = 5
    ip_ver = 4
    ip_tos = 0
    ip_tot_len = 0  # kernel will fill the correct total length
    ip_id = 54321  # Id of this packet
    ip_frag_off = 0
    ip_ttl = 255
    ip_proto = socket.IPPROTO_TCP
    ip_check = 0    # kernel will fill the correct checksum
    # Spoof the source ip address if you want to
    ip_saddr = socket.inet_aton(source_ip)
    ip_daddr = socket.inet_aton(dest_ip)
    ip_ihl_ver = (ip_ver << 4) + ip_ihl
    ip_header = pack('!BBHHHBBH4s4s', ip_ihl_ver, ip_tos, ip_tot_len,
                     ip_id, ip_frag_off, ip_ttl, ip_proto, ip_check, ip_saddr, ip_daddr)
    # tcp header fields
    tcp_source = 1234   # source port
    tcp_dest = port   # destination port
    tcp_seq = 454
    tcp_ack_seq = 0
    tcp_doff = 5  # 4 bit field, size of tcp header, 5 * 4 = 20 bytes
    # tcp flags
    tcp_fin = 0
    tcp_syn = 1
    tcp_rst = 0
    tcp_psh = 0
    tcp_ack = 0
    tcp_urg = 0
    tcp_window = socket.htons(5840)  # maximum allowed window size
    tcp_check = 0
    tcp_urg_ptr = 0

    tcp_offset_res = (tcp_doff << 4) + 0
    tcp_flags = tcp_fin + (tcp_syn << 1) + (tcp_rst << 2) + \
        (tcp_psh << 3) + (tcp_ack << 4) + (tcp_urg << 5)

    # the ! in the pack format string means network order
    tcp_header = pack('!HHLLBBHHH', tcp_source, tcp_dest, tcp_seq, tcp_ack_seq,
                      tcp_offset_res, tcp_flags,  tcp_window, tcp_check, tcp_urg_ptr)

    user_data = 'SYN SCAN'

    # pseudo header fields
    source_address = socket.inet_aton(source_ip)
    dest_address = socket.inet_aton(dest_ip)
    placeholder = 0
    protocol = socket.IPPROTO_TCP
    tcp_length = len(tcp_header) + len(user_data)

    psh = pack('!4s4sBBH', source_address, dest_address,
               placeholder, protocol, tcp_length)
    psh = psh + tcp_header + user_data

    tcp_check = checksum(psh)
    # print tcp_checksum

    # make the tcp header again and fill the correct checksum - remember checksum is NOT in network byte order
    tcp_header = pack('!HHLLBBH', tcp_source, tcp_dest, tcp_seq, tcp_ack_seq, tcp_offset_res,
                      tcp_flags,  tcp_window) + pack('H', tcp_check) + pack('!H', tcp_urg_ptr)

    # final full packet - syn packets dont have any data
    packet = ip_header + tcp_header + user_data

    # Send the packet finally - the port specified has no effect
    s.sendto(packet, (dest_ip, 0))
    s.close()
    return 

def SYN_Scan_Sniffer(ipaddress, port,flag):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    except socket.error:
        print('Connection Error')
        sys.exit(1)
    time_end = time.time() + .1
    while time.time() < time_end:
        packet = s.recvfrom(65565)

        # packet string from tuple
        packet = packet[0]

        # take first 20 characters for the ip header
        ip_header = packet[0:20]

        # now unpack them :)
        iph = unpack('!BBHHHBBH4s4s', ip_header)

        version_ihl = iph[0]
        version = version_ihl >> 4
        ihl = version_ihl & 0xF

        iph_length = ihl * 4

        ttl = iph[5]
        protocol = iph[6]
        s_addr = socket.inet_ntoa(iph[8])
        d_addr = socket.inet_ntoa(iph[9])

        tcp_header = packet[iph_length:iph_length+20]

        # now unpack them :)
        tcph = unpack('!HHLLBBHHH', tcp_header)

        source_port = tcph[0]
        dest_port = tcph[1]
        sequence = tcph[2]
        acknowledgement = tcph[3]
        doff_reserved = tcph[4]
        tcp_flags = tcph[5]
        tcph_length = doff_reserved >> 4

        tcp_rst = (tcp_flags & 0b100) >> 2
        tcp_ack = (tcp_flags & 0b10000) >> 4

        if ipaddress==s_addr and source_port==port and tcp_rst==0 and tcp_ack==1:
            print('PORT %s STATE open' % port)
            s.close()
            return 

        if ipaddress==s_addr and source_port==port and tcp_rst==1 and tcp_ack==1 and flag==True:
            print('PORT %s STATE closed' % port)    
            s.close()
            return

	s.close()
	if(flag==True):
		print('PORT %s STATE filtered' % port)
	return



flag_port = False

parser = argparse.ArgumentParser(description='PortScanner v1.0')
parser.add_argument('ipaddress', type=str,
                    help='Provide Target IP Address or URL')
parser.add_argument('-p', '--port', type=str,
                    help='Select Specific Port or <Port Ranges>')
parser.add_argument('-s', '--SYN', action='store_true', default=False,
                    dest='flag_syn',
                    help='Force SYN Scan')
parser.add_argument('-t', '--TCP', action='store_true', default=False,
                    dest='flag_tcp',
                    help='Force TCP Scan')

my_namespace = parser.parse_args()
my_ip = my_namespace.ipaddress
flag_syn = my_namespace.flag_syn
flag_tcp = my_namespace.flag_tcp
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

host_up = check_status(my_ip)
if(host_up == False):
    print("Couldn\'t connect with Target : %s\nHost is Offline\nTerminating program..." % my_ip)
    sys.exit(1)

if my_namespace.port is not None:
    flag_port = True
    my_port = my_namespace.port
    if('-' in my_port):
        bounds = my_port.split('-')
        lower = int(bounds[0])
        upper = int(bounds[1])
        if(flag_syn==False):
            time_start = time.time()
            for port in range(lower, upper):
                TCP_Scan(my_ip, port, False)

            time_end = time.time()
            print('Scan completed in : %f seconds' % (time_end-time_start))
            sys.exit(1)
        sniffer_threads = []

        if(flag_syn):
        	time_start = time.time()
		for port in range(lower, upper):
		    sniff = threading.Thread(target=SYN_Scan_Sniffer, args=(
		                my_ip, port, False))
		    send = threading.Thread(target=SYN_Scan_Sender, args=(
		                        my_ip, port))
		    sniff.start()
		    send.start()
		    send.join()
		
		time_end = time.time()
        	print('Scan completed in : %f seconds' % (time_end-time_start))
        sys.exit(1)
        

    else:
        if(flag_tcp):
            my_port = int(my_port)
            TCP_Scan(my_ip, my_port, True)
        
        else:
            sniff = threading.Thread(target=SYN_Scan_Sniffer, args=(
                    my_ip, int(my_port), True))
            send = threading.Thread(target=SYN_Scan_Sender, args=(
                            my_ip, int(my_port)))
            sniff.start()
            send.start()
            send.join()
            sniff.join()

if(flag_port == False):
    time_start = time.time()
    for port in range(1, 1024):
        TCP_Scan(my_ip, port, False)
    time_end = time.time()
    print('Scan completed in : %f seconds' % (time_end-time_start))

sniffer_threads = []

if(flag_port == False and flag_syn == True):
    time_start = time.time()
    
    for port in range(1, 1024):
        sniff = threading.Thread(target=SYN_Scan_Sniffer, args=(
                    my_ip, port, False))
        send = threading.Thread(target=SYN_Scan_Sender, args=(
                            my_ip, port))
        sniff.start()
        send.start()
      
    time_end = time.time()
    print('Scan completed in : %f seconds' % (time_end-time_start))
