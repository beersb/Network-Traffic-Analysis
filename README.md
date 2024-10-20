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

        50
        80
        443
        1337

The IP address 172.16.146.2 was acting as the client in the interactions, while the rest of the hosts seemed to be acting as servers. 


