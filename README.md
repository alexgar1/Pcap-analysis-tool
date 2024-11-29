# Pcap-analysis-tool
Python program to analyze a trace of IP datagrams.

Run a3.py by passing pcap file containing traceroute via stdin

 % python3 a3.py your_capture.pcap

a3.py will print:

1. The IP address of the source node (computer traceroute is run on).
2. The IP address of the destination node (destination of traceroute).
3. List of IP adresses of intermediate destination nodes (source ip of TTL exceeded packet).
    router 1: IP1
    router 2: IP2
    ...
    router N: IPN (not destination node)
4. Values of protocol field of IP header.

For each fragment:
5. The number of fragments created from the original datagram and the port of the datagram (0 if no fragments).
6. The offset of the last fragment (0 if no fragments).
7. For each hop (source ip, destination ip), the average RTT and its standard deviation for the desintation nodes along traceroute including final destination node.

