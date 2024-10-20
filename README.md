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

We were met with the following overwhelming result:
