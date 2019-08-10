from Tkinter import *
import socket
import threading


class PortScanner(Frame):
    def __init__(self, parent):
        Frame.__init__(self, parent)
        self.parent = parent
        self.initialize_user_interface()

    def initialize_user_interface(self):
        self.parent.geometry("425x500")
        self.parent.title('Port Scanner')
        Label(root, text='\t').grid(row=0, column=2)
        Label(root, text='\t\t').grid(row=1, column=0)
        Label(root, text='\t\t').grid(row=2, column=0)
        Label(root, text='IP Address').grid(row=1, column=1)
        Label(root, text='Port').grid(row=2, column=1)
        self.e1 = Entry(self.parent)
        self.e2 = Entry(self.parent)
        self.e1.grid(row=1, column=5)
        self.e2.grid(row=2, column=5)
        self.listbox = Listbox(self.parent, width=40,
                               height=20)
        self.listbox.place(x=30, y=150)
        self.scanType = IntVar()
        Radiobutton(self.parent, text='SYN Scanning', variable=self.scanType,
                    value=1).grid(row=3, column=1)
        Radiobutton(self.parent, text='TCP Scanning', variable=self.scanType,
                    value=2).grid(row=3, column=5)
        Button(self.parent, text='Submit',
               command=self.scan).place(x=180, y=110)
        Button(self.parent, text='Clear',
               command=self.clear).place(x=270, y=110)

    def port_scan(self, remoteServerIP, port, count):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        result = sock.connect_ex((remoteServerIP, port))
        if result == 0:
            output = "Port {}: 	 Open\n".format(port)
            self.listbox.insert(count, output)
        sock.close()

    def clear(self):
        self.listbox.delete(0, 'end')

    def scan(self):

        v = self.scanType.get()
        if(v == 1):
            print('SYN SCAN')
        if(v == 2):
            remoteServerIP = socket.gethostbyname('127.0.0.1')
            count = 1
            try:
                for port in range(1, 1025):
                    t = threading.Thread(target=self.port_scan, args=(
                        remoteServerIP, port, count))
                    t.start()
                    count = count + 1

            except socket.gaierror:
                output = "Hostname could not be resolved. Exiting"
                self.listbox.insert(count, output)
                sys.exit()

            except socket.error:
                output = "Couldn't connect to server"
                self.listbox.insert(count, output)


if __name__ == '__main__':

    root = Tk()
    run = PortScanner(root)
    root.mainloop()
