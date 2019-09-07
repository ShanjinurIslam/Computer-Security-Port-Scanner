import Tkinter
import socket
import threading
import sys
import time
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
            w = ord(msg[i]) + (ord(msg[i+1]) << 8 )
            s = s + w
        
        s = (s>>16) + (s & 0xffff);
        s = s + (s >> 16);
        
        #complement and mask to 4 byte short
        s = ~s & 0xffff
        
        return s

class PortScanner(Tkinter.Frame):
    def __init__(self, parent):
        Tkinter.Frame.__init__(self, parent)
        self.parent = parent
        self.initialize_user_interface()

    def initialize_user_interface(self):
        self.parent.geometry("600x500")
        self.parent.title('Port Scanner')
        Tkinter.Label(root, text='\t').grid(row=0, column=2)
        Tkinter.Label(root, text='\t\t').grid(row=1, column=0)
        Tkinter.Label(root, text='\t\t').grid(row=2, column=0)
        Tkinter.Label(root, text='IP Address').grid(row=1, column=1)
        Tkinter.Label(root, text='Port').grid(row=2, column=1)
        self.e1 = Tkinter.Entry(self.parent)
        self.e2 = Tkinter.Entry(self.parent)
        self.e1.grid(row=1, column=5)
        self.e2.grid(row=2, column=5)
        self.listbox = Tkinter.Listbox(self.parent, width=65,
                               height=20)
        self.listbox.place(x=30, y=150)
        self.scanType = Tkinter.IntVar()
        Tkinter.Radiobutton(self.parent, text='SYN Scanning', variable=self.scanType,
                    value=1).grid(row=3, column=1)
        Tkinter.Radiobutton(self.parent, text='TCP Scanning', variable=self.scanType,
                    value=2).grid(row=3, column=5)
        Tkinter.Button(self.parent, text='Submit',
               command=self.scan).place(x=220, y=110)
        Tkinter.Button(self.parent, text='Clear',
               command=self.clear).place(x=350, y=110)

    def tcp_port_scan(self, remoteServerIP, port, count, flag):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        result = sock.connect_ex((remoteServerIP, port))
        if result == 0:
            output = "Port {}: Open".format(port)
            self.listbox.insert(count, output)
        elif flag == True:
            output = "Port {}: Closed or Filtered".format(port)
            self.listbox.insert(count, output)

        sock.close()

    def syn_port_scan_send(self,remoteServerIP, port):
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        packet = '';
        source_ip = get_ip()
        dest_ip = remoteServerIP
        #ip layer
        ip_ihl = 5
        ip_ver = 4
        ip_tos = 0
        ip_tot_len = 0  # kernel will fill the correct total length
        ip_id = 54321   #Id of this packet
        ip_frag_off = 0
        ip_ttl = 255
        ip_proto = socket.IPPROTO_TCP
        ip_check = 0    # kernel will fill the correct checksum
        ip_saddr = socket.inet_aton ( source_ip )   #Spoof the source ip address if you want to
        ip_daddr = socket.inet_aton ( dest_ip )
        ip_ihl_ver = (ip_ver << 4) + ip_ihl
        ip_header = pack('!BBHHHBBH4s4s' , ip_ihl_ver, ip_tos, ip_tot_len, ip_id, ip_frag_off, ip_ttl, ip_proto, ip_check, ip_saddr, ip_daddr)
        # tcp header fields
        tcp_source = 1234   # source port
        tcp_dest = port   # destination port
        tcp_seq = 454
        tcp_ack_seq = 0
        tcp_doff = 5    #4 bit field, size of tcp header, 5 * 4 = 20 bytes
        #tcp flags
        tcp_fin = 0
        tcp_syn = 1
        tcp_rst = 0
        tcp_psh = 0
        tcp_ack = 0
        tcp_urg = 0
        tcp_window = socket.htons (5840)    #   maximum allowed window size
        tcp_check = 0
        tcp_urg_ptr = 0

        tcp_offset_res = (tcp_doff << 4) + 0
        tcp_flags = tcp_fin + (tcp_syn << 1) + (tcp_rst << 2) + (tcp_psh <<3) + (tcp_ack << 4) + (tcp_urg << 5)

        # the ! in the pack format string means network order
        tcp_header = pack('!HHLLBBHHH' , tcp_source, tcp_dest, tcp_seq, tcp_ack_seq, tcp_offset_res, tcp_flags,  tcp_window, tcp_check, tcp_urg_ptr)

        user_data = 'SYN SCAN'

        # pseudo header fields
        source_address = socket.inet_aton( source_ip )
        dest_address = socket.inet_aton(dest_ip)
        placeholder = 0
        protocol = socket.IPPROTO_TCP
        tcp_length = len(tcp_header) + len(user_data)

        psh = pack('!4s4sBBH' , source_address , dest_address , placeholder , protocol , tcp_length);
        psh = psh + tcp_header + user_data;

        tcp_check = checksum(psh)
        #print tcp_checksum

        # make the tcp header again and fill the correct checksum - remember checksum is NOT in network byte order
        tcp_header = pack('!HHLLBBH' , tcp_source, tcp_dest, tcp_seq, tcp_ack_seq, tcp_offset_res, tcp_flags,  tcp_window) + pack('H' , tcp_check) + pack('!H' , tcp_urg_ptr)

        # final full packet - syn packets dont have any data
        packet = ip_header + tcp_header + user_data

        #Send the packet finally - the port specified has no effect
        s.sendto(packet, (dest_ip , 0 ))

    def syn_port_scan_receive(self,remoteServerIP,port,count,flag):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        except socket.error:
            print(socket.error)
            sys.exit()

        time_end = time.time() + 2
        # receive a packet
        while time.time()<time_end:
            packet = s.recvfrom(65565)
            
            #packet string from tuple
            packet = packet[0]
            
            #take first 20 characters for the ip header
            ip_header = packet[0:20]
            
            #now unpack them :)
            iph = unpack('!BBHHHBBH4s4s' , ip_header)
            
            version_ihl = iph[0]
            version = version_ihl >> 4
            ihl = version_ihl & 0xF
            
            iph_length = ihl * 4
            
            ttl = iph[5]
            protocol = iph[6]
            s_addr = socket.inet_ntoa(iph[8]);
            d_addr = socket.inet_ntoa(iph[9]);
            
            tcp_header = packet[iph_length:iph_length+20]
            
            #now unpack them :)
            tcph = unpack('!HHLLBBHHH' , tcp_header)
            
            source_port = tcph[0]
            dest_port = tcph[1]
            sequence = tcph[2]
            acknowledgement = tcph[3]
            doff_reserved = tcph[4]
            tcp_flags = tcph[5]
            tcph_length = doff_reserved >> 4
            
            tcp_rst = (tcp_flags&0b100)>>2 
            tcp_ack = (tcp_flags&0b10000)>>4

            if remoteServerIP==s_addr and source_port==port and tcp_rst==0 and tcp_ack==1:
                output = "Port {}: Open".format(port)
                self.listbox.insert(count, output)
                return

            if remoteServerIP==s_addr and source_port==port and tcp_rst==1 and tcp_ack==1 and flag==True:
                output = "Port {}: Closed".format(port)
                self.listbox.insert(count, output)
                return
            
            #h_size = iph_length + tcph_length * 4
            #data_size = len(packet) - h_size
            
            #get data from the packet
            #data = packet[h_size:]


        if flag==True:
            output = "Port {}: Filtered".format(port)
            self.listbox.insert(count, output)

            


    def clear(self):
        self.listbox.delete(0, 'end')

    def scan(self):
        v = self.scanType.get()
        if(v == 1):
            address = self.e1.get()
            remoteServerIP = socket.gethostbyname(address)
            port_range = self.e2.get()
            count = 1
            if('-' in port_range):
                bounds = port_range.split('-')
                lower = int(bounds[0])
                upper = int(bounds[1])
                try:
                    for port in range(lower, upper):
                        receive = threading.Thread(target=self.syn_port_scan_receive, args=(
                    remoteServerIP, port,count, False))
                        send = threading.Thread(target=self.syn_port_scan_send, args=(
                            remoteServerIP, port))
                        receive.start()
                        send.start()
                        count = count + 1


                    
                except socket.gaierror:
                    output = "Hostname could not be resolved. Exiting"
                    self.listbox.insert(count, output)
                    sys.exit()

                except socket.error:
                    output = "Couldn't connect to server"
                    self.listbox.insert(count, output)
            else:
                port = int(port_range)
                receive = threading.Thread(target=self.syn_port_scan_receive, args=(
                    remoteServerIP, port,count, True))
                send = threading.Thread(target=self.syn_port_scan_send, args=(
                    remoteServerIP, port))
                receive.start()
                send.start()
        if(v == 2):
            address = self.e1.get()
            remoteServerIP = socket.gethostbyname(address)
            port_range = self.e2.get()
            count = 1
            if('-' in port_range):
                bounds = port_range.split('-')
                lower = int(bounds[0])
                upper = int(bounds[1])
                try:
                    threads = []
                    for port in range(lower, upper):
                        t = threading.Thread(target=self.tcp_port_scan, args=(
                            remoteServerIP, port, count, False))
                        threads.append(t)
                        count = count + 1

                    for thread in threads:
                        thread.start()

                    
                except socket.gaierror:
                    output = "Hostname could not be resolved. Exiting"
                    self.listbox.insert(count, output)
                    sys.exit()

                except socket.error:
                    output = "Couldn't connect to server"
                    self.listbox.insert(count, output)
            else:
                port = int(port_range)
                t = threading.Thread(target=self.tcp_port_scan, args=(
                    remoteServerIP, port, count, True))
                t.start()


if __name__ == '__main__':

    root = Tkinter.Tk()
    run = PortScanner(root)
    root.mainloop()
