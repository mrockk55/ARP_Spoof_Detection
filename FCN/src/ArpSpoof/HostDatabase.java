package ArpSpoof;
/*
 * @File: HostDatabase.java
 * 
 * @Author: Mayur Sanghavi and Rushbah Mehta
 * 
 * @Version: 1.0, 12/4/2014
 */
import java.io.*;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.util.HashMap;

import jpcap.packet.ARPPacket;
import jpcap.packet.EthernetPacket;

public class HostDatabase {
	public HashMap<String,String> MAC2IP;//=new HashMap<String, InetAddress>();
	public HashMap<String,InetAddress> hostDatabase;
	public HostDatabase(){
		hostDatabase=new HashMap<String, InetAddress>();
		MAC2IP = new HashMap<String, String>();
	}
    public static void main(String[] args) {
//        System.out.println(getARPCache());
       //printHostDatabase();
    }

    /**
     * Prints host database
     *
     */
    public synchronized void printHostDatabase() {
        for (String key : hostDatabase.keySet()) {
            System.out.println(key + " " + hostDatabase.get(key));
        }
    }

    public synchronized void insert(String _mac, InetAddress _addr){
    	
    }
    
    //Insert into database
    public synchronized void insert(ARPPacket arp){
    	hostDatabase.put(arp.getSenderHardwareAddress().toString(), (InetAddress)arp.getSenderProtocolAddress());
    	MAC2IP.put(arp.getSenderHardwareAddress().toString(), ((InetAddress)arp.getSenderProtocolAddress()).toString());
    }
    
    //Check if address is already present in database
    public synchronized int checkPacket(ARPPacket arp){
    	String macStr = arp.getSenderHardwareAddress().toString();
    	String ipStr = ((InetAddress)arp.getSenderProtocolAddress()).toString();
    	
    	if(MAC2IP.containsKey(macStr)){
    		if(!MAC2IP.get(macStr).equals(ipStr)){
    			return -1;
    		}
    	}
    	else{
    		return -2;
    	}
    	return 0;
    }
    
    //Translate byte[] to string
    public synchronized static String getMAC(byte [] MacAdd){
    	String mac = "";
    	for (int i =0;i<MacAdd.length-1;i++)
            mac = mac + Integer.toHexString(MacAdd[i] & 0xff) + ":";
    	mac = mac + Integer.toHexString(MacAdd[MacAdd.length] & 0xff);
    	return mac;
    }
    
    /** returns arp cache table
     *  referred from http://www.java-forums.org/new-java/63347-read-arp-cache.html
     * @return
     */
    //referred from above source
    //but not using it now, initially we wanted to load arp table available
    public  String getARPCache() {

        String cmd = "arp -a";
        String cmd1="arp -d";
        Runtime run = Runtime.getRuntime();
        String result = "ARP Cache: ";
        int i=0;
        try {
            Process proc1 = run.exec(cmd1);
            Process proc = run.exec(cmd);
            proc.waitFor();
            BufferedReader buf = new BufferedReader(new InputStreamReader(proc.getInputStream()));
            String line;
            while ((line = buf.readLine()) != null) {
                result += line + "\n";
                if(i>=3) {
                    String[] parts = line.trim().split("\\s+");
                    if(parts[2].equals("dynamic")){
                        hostDatabase.put(parts[1], InetAddress.getByName(parts[0]));
                    }
                }
                i++;
            }
        } catch (Exception ex) {
            System.out.println(ex.getMessage());
        }

        return (result);
    }
}
