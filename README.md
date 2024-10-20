# Network Traffic Analysis Lab

## Objective

The Network Traffic Analysis Lab follows the Hack The Box Academy (HTBA) Introduction to Network Traffic Analysis module and was designed to strengthen both conceptual and practical understanding of computer networking and packet analysis. The primary focus was to examine both pre-existing Packet Capture (PCAP) files and live packet capture data (using both TCPDump and Wireshark) and extract valuable information about current and past network traffic flows, especially as they relate to cybersecurity. The key topics addressed were network security, network attack patterns, and network forensics.

### Skills Learned

- Familiarity with network analysis tools like Wireshark and TCPDump
- Proficiency in analyzing and interpreting network traffic through Pack Captures.
- Ability to discover, isolate, and analyze suspicious network activity.
- Deepened knowledge of network protocols and security vulnerabilities.
- Development of critical thinking and problem-solving skills in cybersecurity.

### Tools Used

- Wireshark and TCPDump for intercepting and scrutinizing network traffic.
- XFreeRDP for remote host communication.

## Steps
The first step in this lab was to analyze a few PCAP files using the command line tool TCPDump, which does not provide a user interface, but outputs network traffic directly into the command line. To use this tool, one requires sudo privileges, as the tool requires direct access to the hardware via the network interfaces. in any case, we first downloaded both TCPDump and Wireshark, which will be used later, to our personal Linux machine. We also downloaded the PCAP file (TCPDump-lab-2.PCAP) from the HTBA website.  
Once the tools required for the initial analysis were all assembled, we tested out the tool by opening the PCAP file using the -r flag:

    tcpdump -r ./TCPDump-lab-2.PCAP

(note, here we do not need sudo privileges, as we are reading a file and do not need access to the system hardware). We were met with the following overwhelming result:

<div>
  <img src="./lab-images/TCPDump/FirstTCPDump.png" alt="Network Traffic Analysis Image" width="1400" height="700">

  *Ref. 1: An image of the initial PCAP capture outputted via TCPDump*
</div>

So the journey had begun. The HTBA module then prompted us to examine the file and look at he types of traffic we might see. We did so, and observed that the first record in the file was from a client machine (using some arbitrarily high port number, 54940) reaching out to a server via HTTPS (port 443). The next line appeared to be a response, so perhaps this was a conversation between a web server and its client. 

A few lines down, we discovered some HTTP traffic (port 80), which is again likely a web server and client, but the traffic in this case was unencrypted. Further still, we were able to se some variation in the traffic, specificlaly noticing the client host in the previous traffic reaching out to a new machine, this time using UDP instead of TCP and utilizing 1337, which was a port not familiar to us at the time. Because 1337 was a mystery, we decided to look this port number, and discovered that one possibility is the Men&Mice DNS service. DNS thus became a possibility. 

After this initial glance at the traffic, the module prompted us to record the hosts involved in the traffic and the ports they utilized. We observed each of the following hosts
        
        172.16.146.2
        172.16.146.1
        server-13-35-106-128.mia3.r.cloudfront.net
        23.196.60.92

using the following ports

        53
        80
        443
        1337

The IP address 172.16.146.2 was acting as the client in the interactions, while the rest of the hosts seemed to be acting as servers. 

Next, we attempted to identify the very first *complete* TCP handshake in the file. To answer this question, it was best to first review what the TCP handshake looks like:

        127.0.0.1.12345 > 127.0.0.1.80:	Flags [S], seq ...
        127.0.0.1.80 > 127.0.0.1.12345:	Flags [S.], seq ...
        127.0.0.1.12345 > 127.0.0.1.80:	Flags [.], seq ...

First, there is the initial packet where one typically has a client reaching out to a server with the SYN flag sent-- [S]. After this, the server responds with both the SYN and ACK flags set-- [S.], indicating, on the one hand, that it has received the client's packet, and on the other, that it would like the client ot synchronizew with its own responses. Finally, the client responds with its own ACK packet-- [.]. 

Because the file was rather long and messy, I used the -s and -c flags, which limit the number of bytes included in each packet and the number of packets included in the cli output, respectively, to clean up the output for this stage of the analysis.

        tcpdump -s 50 -c 50 -r TCPDump-lab-2.PCAP

After analyzing the output, I was able to discern that the first TCP handshake occurs between 172.16.146.2 (as the client) and static.30.26.216.clients.your-server.de (the server).

<div>
  <img src="./lab-images/TCPDump/TCPDumpSandCFlags.png" alt="Network Traffic Analysis Image" width="1400" height="300">

  *Ref. 2: An image of the PCAP capture after reducing the output, including the first TCP handshake*
</div>

We were able to determine that static.30.26.216.clients.your-server.de is the server because 172.16.146.2 reaches out first with the SYN packet. As far as I am aware, in almost all cases, it will be the client that initiates the connection to a server. After all, how often does one ever spontaneously receive requests from a webpage enticing us to view its resources? In addition, the port numbers also suggest this client-server configuration. The host with IP address 172.16.146.2 reaches out using an large ephemeral port number, while static.30.26.216.clients.your-server.de utilizes port 443, which is the archetypal port for HTTPS traffic, utilized by servers. As a final piece of evidence, the hostname of the suspected server actally contains the phrase 'your-server' as can be ascertained by visual observation. 

The HTBA module then informed us that there was some network traffic in the file containing a DNS request for apache.org, and prompts us to recover the IP address delivered by the DNS server. 

To answer this question, we used TCPDump's -l flag, which allows the user to pipe its output into different programs, the flag 'port 53', which filters for DNS traffic, and then piped the output of the command into the grep tool, searching for the string 'apache'. The final command was as follows:

        tcpdump -lr TCPDump-lab-2.pcap port 53 | grep apache

<div>
  <img src="./lab-images/TCPDump/GrepApache.png" alt="Network Traffic Analysis Image" width="1400" height="150">

  *Ref. 3: The output of the tcpdump command, using the port and -l flags, and being piped into the grep command*
</div>

Thus, by examining the output of this command (specifically the A records we were able to see the output), we were able to recognize that there are two different servers hosting apache.org, 95.216.26.30 and 207.244.88.140.

After we had discovered this information, we moved onto the next segment of this module. Here, we were asked to find the DNS server for the network segment as well as what domain names were requested within the pcap file. To answer the first question, we simply filtered via FFIIXXXX MMMEEE

## Wireshark
The module now shifted gears, transitioning from the cli-based TCPDump to the GUI-based Wireshark. For this section of the module, a live capture and a virtual machine were used as the subject of the investigation, rather than a PCAP file. To access this machine, we needed to use a VPN to tie into the HTBA private network, using an OpenVPN file provide by the platform. The following commands established the VPN connection:

        sudo openvpn academy-regular.ovpn

We then needed to use an RDP client to connect to the specific machine in question, in this case, we will download and use XFreeRDP:

        sudo apt install freerdp2-x11
        xfreerdp /u:htb-student /p:*********** /v:***********

where /p is followed by the user's password, and /v is followed by the target host's IP address. Now, our analysis was able to begin. We opened Wireshark via the command line, and then used the Capture tab on the radial menu to select the ENS224 interface, and opened a capture session on this interface. 

After allowing the capture to run for a few minutes, we returned to the machine to look at the traffic that had been generated. The HTBA module pointed us towards examining the FTP traffic within the capture. Thus, we this is where we focused our attention, using the string 'ftp' as a display filter to eliminate everything besides FTP traffic. Almost immediately, we were able to visually identify a few interesting details. Firstly, we noticed an anonymous login, which we know from our experience dabbling in penetration testing, is a major misconfiguration. This struck us as possibly malicious or suspicious traffic. 

<div>
  <img src="./lab-images/Wireshark/FTP/StrangeFTPTraffic.png" alt="Network Traffic Analysis Image" width="1400" height="150">

  *Ref. 4: A snapshot of the suspicious FTP traffic, including the Anonymous login traffic*
</div>

The module asked us to find and save to our host the file that was transferred in this FTP exchange. Thus, we used Wireshark to follow the FTP conversation, and were able to discover a file was transferred called flag.jpeg from the FTP server to the client. 

<div>
  <img src="./lab-images/Wireshark/FTP/StrangeFTPTraffic.png" alt="Network Traffic Analysis Image" width="1400" height="150">

  *Ref. 5:*
</div>

The next section of the module gave us another PCAP ot analyze. This file, unlike the previous two sections, does not contain very much traffic, and is essentially just a single TCP session utilizing port 4444. This conversation appeared to facilitate a remote Windows shell, where each command was sent in the clear. By analyzing these commands, we were able to determine that a hacker had obtained access to a Windows host. This hacker, after some quick reconnaissance using the whoami and ipconfig commands, created a new user creatively named ‘hacker’, and then added this user to the administrators group. 

<div>
  <img src="./lab-images/Wireshark/HackerUserCommands.png" alt="Network Traffic Analysis Image" width="600" height="150">

  *Ref. 6: An image displaying the Windows commands discovered in the cleartext TCP stream*
</div>

After obtaining this information, the module moves onto a new section, in which we were given an additional PCAP file to analyze and told that in this scenario, we had discovered a TLS key (included in the course resources) which might prove useful in our analysis.  

To start out, we niavely tried to simply apply the 'rdp' display filter to the PCAP file. However, it immediately became clear that this was not going to work. Doing a little more research, it turns out the RDP, by defualt, encrypts all of its traffic using TLS (hence the TLS key included in the resources). Because the traffic is encrypted, Wireshark can't dig into the packet and determine if the packet is RDP traffic, and it thus does not show up under the 'rdp' filter. Therefore, we adjusted our search, this time using the filter

        tcp.port == 3389

This gave us an indication of traffic that at least has the potential to be RDP traffic, as 3389 is the defualt port for this service, but we still cannot be completely certain without decrypting the traffic. 

<div>
  <img src="./lab-images/Wireshark/RDP/EncryptedRDPTraffic.png" alt="Network Traffic Analysis Image" width="1000" height="250">

  *Ref. 7: A snapshot of TLS encrypted packet data, which we suspected to be RDP traffic*
</div>

We now took steps to actually decrypt this traffic using the TLS key. To do this, one selects the Edit option of the radial menu, then from there, one selects Preferences, then Protocols, and finally, TLS. Next, one must click Edit once agian, and a new window will open. At this point, one clicks the + symbol to add a new key, then enters the IP address of the server (10.129.43.29 in the case of the lab), the port used for the communication (3389), and the path to the server key file, then save and refresh the PCAP file. 

<div>
  <img src="./lab-images/Wireshark/RDP/AddingTheTLSKey.png" alt="Network Traffic Analysis Image" width="800" height="150">

  *Ref. 8: Adding the TLS key to the Wireshark session*
</div>

After following the steps above and refreshing the PCAP file, the traffic was unencrypted, and Wireshark was able to identify it as RDP traffic!

<div>
  <img src="./lab-images/Wireshark/RDP/DecryptedRDPPackets.png" alt="Network Traffic Analysis Image" width="1000" height="250">

  *Ref. 9: The RDP traffic after decryption*
</div>

Now that we had decrypted the traffic, the module asked us to dig through the packets to find the user credentials used to authenticate in the RDP session. Through visually inspecting the traffic, we found a packet called clientData. This seemed like the right place to look, and thus clicked on the packet. From there, we selected SendData, then clientInfoPDU, and after scrolling down a hair, we discovered the username and password used for the RDP session. This discovery concluded the module, and thereby, this lab. 

<div>
  <img src="./lab-images/Wireshark/RDP/UsernamePassowrd.png" alt="Network Traffic Analysis Image" width="500" height="100">

  *Ref. 10: The credentials discovered within the Wireshark window*
</div>

