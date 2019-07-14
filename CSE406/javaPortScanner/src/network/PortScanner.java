package network;
import java.net.* ;

public class PortScanner {
	String remoteIP ;
	Socket socket ;
	
	
	PortScanner(String IP){
		remoteIP = IP ;
	}
	
	void startScanning() throws Exception{
		for(int port=1;port<1024;port++) {
			try {
				socket = new Socket();
				socket.connect(new InetSocketAddress(remoteIP, port));
				socket.close();
				System.out.println(port+": Open");
			}catch (Exception e) {
				// TODO: handle exception
			}
		}
	}
}
