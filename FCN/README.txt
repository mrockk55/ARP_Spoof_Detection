This is the ReadMe document for ARP Spoofing Detection.

Before running the Spoof detection engine, user needs to install jpcap library and add jpcap.dll to user's java environment.
Both install file and .dll file are included in this submission but they can be downlaoded from the link:
http://jpcap.sourceforge.net/

After installing jpcap, .jar needs to be referrenced in the project if using an IDE or else by setting class path.

To run the program:
In cmd line you need to first compile all java files:
>javac *.java

Then start ARPSniff
>java ARPSniff

Or on an IDE simply run ARPSniff.java



Additional instructions:

The jpcap setup included in this submission is for 32-bit java. If trying to run on different environment, please install appropiate jpcap tools and .dll

This program expects that all hosts on the network have normal network stack and that each host acknowledges the TCP SYN request from same IP.