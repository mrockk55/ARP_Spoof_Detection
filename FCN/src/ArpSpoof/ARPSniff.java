package ArpSpoof;
/*
 * @File: ARPSniff.java
 * Java program to sniff ARP packets on n/w
 * and detect spoofing.
 * 
 * @Author: Mayur Sanghavi and Rushbah Mehta
 * 
 * @Version: 1.0, 12/4/2014
 */

//import jpcap packages
import jpcap.JpcapCaptor;
import jpcap.NetworkInterface;
import jpcap.NetworkInterfaceAddress;
import jpcap.packet.*;
//import java packages
import java.io.IOException;
import java.util.Scanner;
import java.net.*;

public class ARPSniff {
	//Initialize captor object to read from interface
    private static JpcapCaptor captor;
    private static final Scanner input = new Scanner(System.in);


    public static void main(String args[]) throws Exception {
        //Obtain the list of network interfaces
        NetworkInterface[] interfaces = JpcapCaptor.getDeviceList();
        InetAddress localAdd = null;
        int currInterface = -1;
        HostDatabase hdb = new HostDatabase();
        try{
        	localAdd = InetAddress.getLocalHost();
        }catch(Exception e){
        	System.out.println("Error detecting your local host.");
        }
        System.out.println("#########################################################");
        System.out.println("#       Following are the interfaces on your machine:   #");
        System.out.println("#                                                       #");		
        
        //for each network interface
        for (int i = 0; i < interfaces.length; i++) {
            //print out its name and description
            System.out.println(i + ": " + interfaces[i].name + "(" + interfaces[i].description + ")");
            //print out its datalink name and description
            //System.out.println(" datalink: " + interfaces[i].datalink_name + "(" + interfaces[i].datalink_description + ")");
            //print out its MAC address
            System.out.print(" MAC address:");
            for (byte b : interfaces[i].mac_address)
                System.out.print(Integer.toHexString(b & 0xff) + ":");
            System.out.print("\t");

//            //print out its IP address, subnet mask and broadcast address
            for (NetworkInterfaceAddress a : interfaces[i].addresses){
            	if(localAdd != null && localAdd.getHostAddress().equals(a.address.getHostAddress())){
            		currInterface = i;
            	}
                System.out.print("IP address:" + a.address.getHostAddress()+"\t");// + " " + a.subnet + " " + a.broadcast);
            }
            System.out.println("\n");
        }
        //System.out.println("You default interface seems to be: "+currInterface);
        System.out.println("Enter interface you want to monitor.");
        
        	//Read which interface  to monitor
            int device = input.nextInt();
             try {
                captor=captor.openDevice(interfaces[device], 65535, true, 20);
                //Set filter to capture only arp packets
                captor.setFilter("arp", true);
            } catch (IOException e) {
                e.printStackTrace();
            }
            int i=0;
            //sendARPRequest(interfaces[device]);
           while(true){
        	   try{
               //Read arp packet from network
        		   ARPPacket p = (ARPPacket)captor.getPacket();
               if(p!=null) {
            	  if(AnomalyDetector.detectAnomaly(p)){
            		  System.out.println("Spoofed Packet");
            	  }
            	  else{//send for anomaly detection
            		  System.out.println("Passed Anomaly Detection");
            	  }
            	  
            	  if(p.operation == p.ARP_REPLY){
            		  //If it is an reply packet
            		  if(p.getSenderProtocolAddress().equals(interfaces[device].addresses[1].address)){
            			  System.out.println("Out-going Reply Packet");
            		  }
            		  else{
            			  //Check in database
	            		  int res = hdb.checkPacket(p);
	            		  if(res == -1){
	            			  System.out.println("Spoofed Packet");
	            		  }
	            		  else if(res == -2){
	            			  System.out.println("No previous record");
	            			  //Confirm that sender is a legitimate host
	            			  new Thread(new SYNPacket(p, hdb, JpcapCaptor.getDeviceList()[device])).start();;
	            		  }
            		  }
            	  }
                   //Display arp packet details
                   System.out.print("Source: "+p.getSenderProtocolAddress()+" : "+p.getSenderHardwareAddress()+"\t");
                   System.out.println("Target: "+p.getTargetProtocolAddress()+" : "+p.getTargetHardwareAddress());
                   EthernetPacket dlp = (EthernetPacket)p.datalink;                   
                   System.out.println(i++ + ": " + p.toString());
                
                   System.out.println();
               }
        	   }catch(Exception e){
        		   System.out.println(e);
        	   }
           }

    }
}