package ArpSpoof;
/*
 * @File: AnomalyDetector.java
 * 
 * @Author: Mayur Sanghavi and Rushbah Mehta
 * Module to detect any anomaly in header of ARP packet
 * 
 * @Version: 1.0, 12/4/2014
 */

import jpcap.packet.ARPPacket;
import jpcap.packet.EthernetPacket;

public class AnomalyDetector {
	//Function that takes ARP packet
	static boolean detectAnomaly(ARPPacket pack){
		EthernetPacket ep = (EthernetPacket)pack.datalink;
		//Check if MAC address in ARP header and ethernet header are same 
		if(!pack.getSenderHardwareAddress().equals(ep.getSourceAddress())){
			return true;
		}
		//Check consistency of IP address
		if(pack.operation == pack.ARP_REPLY ){
			if(!pack.getTargetHardwareAddress().equals(ep.getDestinationAddress())){
				return true;
			}
		}
		//If its a genuine packet
		return false;
	}

}
