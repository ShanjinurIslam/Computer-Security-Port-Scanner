package network;
import java.util.Scanner;

import network.PortScanner;

public class Main {
	public static void main(String args[]) throws Exception {
		System.out.print("Enter remote IP: ");
		Scanner scanner = new Scanner(System.in);
		String remoteIP = scanner.nextLine() ;
		PortScanner portScanner = new PortScanner(remoteIP);
		portScanner.startScanning();
		System.out.println("Done with Scanning");
	}
}
