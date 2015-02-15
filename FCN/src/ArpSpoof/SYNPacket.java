package ArpSpoof;
/*
 * @File: SYNPacket.java
 * 
 * @Author: Mayur Sanghavi and Rushbah Mehta
 * To investigate sender
 * @Version: 1.0, 12/4/2014
 */

import java.io.IOException;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.UnknownHostException;

import jpcap.JpcapCaptor;
import jpcap.JpcapSender;
import jpcap.NetworkInterface;
import jpcap.NetworkInterfaceAddress;
import jpcap.packet.ARPPacket;
import jpcap.packet.EthernetPacket;
import jpcap.packet.IPPacket;
import jpcap.packet.TCPPacket;

public class SYNPacket implements Runnable {
	ARPPacket arp;
	HostDatabase hdb;
	NetworkInterface device;
	
	public SYNPacket(ARPPacket _arp, HostDatabase _hdb,NetworkInterface _device ){
		arp = _arp;
		hdb = _hdb;
		device = _device;
	}
	public static void main(String[] args) throws UnknownHostException, IOException {
	    JpcapSender sender = JpcapSender.openDevice(JpcapCaptor.getDeviceList()[0]);
	    NetworkInterfaceAddress[] nia = JpcapCaptor.getDeviceList()[3].addresses;        
	    TCPPacket packet = new TCPPacket(284104, 80, 1, 0, false, false, false, false, true, false, false, false, 0, 0);
	    packet.syn = true;
	    packet.setIPv4Parameter(0, false, false, false, 0, false, true, false, 0, 34567, 64, IPPacket.IPPROTO_TCP, nia[0].address , InetAddress.getByName("192.168.1.118"));
	    
	    packet.data = ("").getBytes();
	
	    EthernetPacket ether = new EthernetPacket();
	    ether.frametype = EthernetPacket.ETHERTYPE_IP;
	    ether.src_mac = ((NetworkInterface)JpcapCaptor.getDeviceList()[3]).mac_address;
	    ether.dst_mac = new byte[]{(byte)200, (byte)205, (byte)114, (byte)68, (byte)129, (byte)162};
	    //packet.option = new byte[] {
	    packet.datalink = ether;
	    sender.sendPacket(packet);
	    
	    System.out.println(packet);
	    JpcapCaptor captor = JpcapCaptor.openDevice(JpcapCaptor.getDeviceList()[3], 65535, true, 20);
	    captor.setFilter("tcp[0xd]&2=2", true);
	    int i = 0;
	    long timeS = System.currentTimeMillis();
	    boolean spoof = true;
	    try{
	    while (true) {
	    	TCPPacket p = (TCPPacket)captor.getPacket();
	    	long timeR = System.currentTimeMillis() - timeS;
	        if (p != null ){
	        	System.out.println(i++ + ": " + p);
	        	if(p.src_ip.getHostAddress().equals("192.168.1.118")) {
	        	spoof = false;
	            System.out.println("ACK received: "+timeR);
	            System.out.println();
	            System.out.println();
	            break;
	        	}
	        }
	        if(timeR > 880180){
	        	break;
	        }
	    }
	    }catch(Exception e){
	    	
	    }
	    if (spoof){
	    	System.out.println("No Reply for TCP-SYN. Packet is spoofed.");
	    }
	}

	@Override
	public void run() {
		// TODO Auto-generated method stub
		try{
		JpcapSender sender = JpcapSender.openDevice(device);
	    NetworkInterfaceAddress[] nia = device.addresses;        
	    TCPPacket packet = new TCPPacket(284104, 80, 1, 0, false, false, false, false, true, false, false, false, 0, 0);
	    packet.syn = true;
	    packet.setIPv4Parameter(0, false, false, false, 0, false, true, false, 0, 34567, 64, IPPacket.IPPROTO_TCP, nia[1].address , (InetAddress)arp.getSenderProtocolAddress());
	    packet.data = ("").getBytes();
	
	    EthernetPacket ether = new EthernetPacket();
	    ether.frametype = EthernetPacket.ETHERTYPE_IP;
	    ether.src_mac = device.mac_address;
	    ether.dst_mac = arp.sender_hardaddr;
	    //packet.option = new byte[] {
	    packet.datalink = ether;
	    //sender.sendPacket(packet);
	    
	    // System.out.println("Thread sent TCP-SYN: "+packet);
	    JpcapCaptor captor = JpcapCaptor.openDevice(device, 65535, true, 20);
	    captor.setFilter("tcp[0xd]&2=2", true);
	    int i = 0;
	    long timeS = System.currentTimeMillis();
	    boolean spoof = true;
	    TCPPacket p = null;
	    sender.sendPacket(packet);
	    try{
	    	
	    while (true) {
	    	 p = (TCPPacket)captor.getPacket();
	    	long timeR = System.currentTimeMillis() - timeS;
	        if (p != null ){
	        	//System.out.println(i++ + ": " + p);
	        	//if(p.src_ip.getHostAddress().equals("192.168.1.118")) {
	        	//System.out.println("-----: "+p.src_ip+" : "+arp.getSenderProtocolAddress()+" :-----");
	        	if(p.src_ip.equals((InetAddress)arp.getSenderProtocolAddress())){
	        		hdb.insert(arp);
		        	spoof = false;
		            System.out.println("ACK received: "+timeR);
		            break;
	        	}
	        }
	        if(timeR > 5000){
	        	System.out.println("----------------------------------------");
	        	System.out.println("!!!!TCP-SYN time out: Packet Spoofed!!!!");
	        	System.out.println("----------------------------------------");
	        	break;
	        }
	    }
	    
	    }catch(Exception e){
	    	
	    }
	    if (spoof){
	    	System.out.println("Got spoofed packet from: "+((EthernetPacket)arp.datalink).getSourceAddress());
	    }
	    
		}catch(Exception e){
			System.out.println("Error in TCP-SYN thread\n"+e);
			e.printStackTrace();
		}
	}
}
