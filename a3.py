from struct import *
import statistics

import sys

GLOBAL_HEADER = 24
PACKET_HEADER = 16
PACKET_DATA = 14

ETH = 14
IP = 20
GLOBAL_FORMAT = '>IHHIIII'


class IP_Header:
    src_ip = None #<type 'str'>
    dst_ip = None #<type 'str'>
    ip_header_len = None #<type 'int'>
    total_len = None    #<type 'int'>

    
    def __init__(self):
        self.src_ip = None
        self.dst_ip = None
        self.ip_header_len = 0
        self.total_len = 0
    
    def ip_set(self,src_ip,dst_ip):
        self.src_ip = src_ip
        self.dst_ip = dst_ip
    
    def header_len_set(self,length):
        self.ip_header_len = length
    
    def total_len_set(self, length):
        self.total_len = length    
        
    def get_IP(self,buffer1,buffer2):
        src_addr = unpack('BBBB',buffer1)
        dst_addr = unpack('BBBB',buffer2)
        s_ip = str(src_addr[0])+'.'+str(src_addr[1])+'.'+str(src_addr[2])+'.'+str(src_addr[3])
        d_ip = str(dst_addr[0])+'.'+str(dst_addr[1])+'.'+str(dst_addr[2])+'.'+str(dst_addr[3])
        self.ip_set(s_ip, d_ip)
        
    def get_header_len(self,value):
        length = (value & 15)*4
        self.header_len_set(length)

    def get_total_len(self,buffer):
        num1 = ((buffer[0]&240)>>4)*16*16*16
        num2 = (buffer[0]&15)*16*16
        num3 = ((buffer[1]&240)>>4)*16
        num4 = (buffer[1]&15)
        length = num1+num2+num3+num4
        self.total_len_set(length)

    def protocol_set(self, value):
        self.protocol = value


   

class packet():
    
    #pcap_hd_info = None
    IP_header = None
    TCP_header = None
    timestamp = 0
    packet_No = 0
    RTT_value = 0
    RTT_flag = False
    buffer = None
    size = 0
    
    
    def __init__(self):
        self.ip = IP_Header()
        #self.pcap_hd_info = pcap_ph_info()
        self.timestamp = 0
        self.packet_No =0
        self.RTT_value = 0.0
        self.RTT_flag = False
        self.buffer = None
        
    def timestamp_set(self,buffer1,buffer2,orig_time):
        seconds = unpack('I',buffer1)[0]
        microseconds = unpack('<I',buffer2)[0]
        self.timestamp = round(seconds+microseconds*0.000001-orig_time,6)
        #print(self.timestamp,self.packet_No)
    def packet_No_set(self,number):
        self.packet_No = number
        #print(self.packet_No)

    def setSize(self,s):
        self.size = s
        
    def get_RTT_value(self,p):
        rtt = p.timestamp-self.timestamp
        self.RTT_value = round(rtt,8)

def getpackhead(data):
    ts_sec = data[0:4]
    ts_usec = data[4:8]
    incl_len = data[8:12]
    orig_len = data[12:16]
    
    return ts_sec, ts_usec, incl_len, orig_len

def getIPhead(data):
    length = data[0]
    totalLength = data[2:4]
    id = data[4:6]

    ff = data[6:8]
    flags = (ff[0] & 0b11100000) >> 5
    fragoff = (ff[0] & 0b00011111) | ff[1]
    fragoff*=8

    ttl = data[8]
    protocol = data[9]
    src = data[12:16]
    dest = data[16:20]

    return length, totalLength, id, flags, fragoff, ttl, protocol, src, dest


def getRTT(timestamp, sendtimes, srcip, srcport, rttls):
    rtt = timestamp - sendtimes[srcport]
    if srcip not in rttls:
        rttls[srcip] = [rtt]
    else:
        rttls[srcip].append(rtt)


def ipBS(ip_bytes):
    return '.'.join(str(b) for b in ip_bytes)

def getInfo(cap):
    packets = []

    with open(cap, 'rb') as cap:
        glob = cap.read(GLOBAL_HEADER)
        magicNum, versionMaj, versionMin, thiszone, sigfigs, snaplen, network = unpack(GLOBAL_FORMAT, glob)

        if magicNum == 0xa1b2c3d4:
            endian = '>'
            ts = 'microseconds'
        elif magicNum == 0xd4c3b2a1:
            endian = '<'
            ts = 'microseconds'
        elif magicNum == 0xa1b23c4d:
            endian = '>'
            ts = 'nanoseconds'
        elif magicNum == 0x4d3cb2a1:
            endian = '<'
            ts = 'nanoseconds'
        else:
            print('Unknown byte order or timestamp resolution')
            exit(1)
        

        interNodes = {}
        protocols = set()
        fragments = {}
        sendtimes = {}
        rttls = {} # list of rtts for each path from source to destination
        ttls = {}
        srcnode = None
        dstnode = None
        last = True # indicates if fragment is last in group
        timestamp = 0
        while True:
            p = packet()
            p.packet_No_set(len(packets)+1)
            packhead = cap.read(PACKET_HEADER)

            if not packhead:
                break
            
            ##############
            # Packet header

            ts_sec, ts_usec, incl_len, orig_len = getpackhead(packhead)
    
            sec = unpack(endian + 'I', ts_sec)[0]
            usec = unpack(endian + 'I', ts_usec)[0]
            if ts == 'nanoseconds':
                timestamp = sec + usec / 1_000_000_000
            else:
                timestamp = sec + usec / 1_000_000


            # Packet data
            incl_len = unpack(endian+'I', incl_len)[0]
            packdata = cap.read(incl_len) # Read entire packet data
            
            ###########
            # IP header

            ipdata = packdata[ETH:IP+ETH] # skip eth header

            vihl, totalLength, id, flags, fragoff, ttl, protocol, srcip, dstip = getIPhead(ipdata)
            id = unpack('!H', id)[0]

            # Get protocol
            p.ip.protocol_set(protocol)

            if p.ip.protocol != 1 and p.ip.protocol != 17:
                continue
            
            # Store protocol
            protocols.add(protocol)

            # get source ip of packet
            p.ip.get_IP(srcip,dstip)
            srcip = p.ip.src_ip
            dstip = p.ip.dst_ip


            ###########
            # UDP
            if protocol == 17:
                # extract udp header
                udpdata = packdata[IP+ETH:IP+ETH+28]

                # note port for pairing
                srcport = unpack('!H', udpdata[0:2])[0]
                sendtimes[srcport] = timestamp

                # note ttl for ordering
                ttls[srcport] = ttl

            ###########
            # ICMP
            elif protocol == 1:
                # extract icmp header
                icmpdata = packdata[IP+ETH:IP+ETH+36]
                icmp_type, icmp_code = unpack(endian+'BB', icmpdata[:2])
                srcport = unpack('!H', icmpdata[28:30])[0]

                # icmp id
                icmpid = unpack(endian+'H', icmpdata[4:6])[0]
                if icmp_type == 9:
                    continue
                
                # echo request
                if icmp_type == 8 and icmp_code == 0:
                    sqnum = unpack(endian+'H', icmpdata[6:8])[0]

                    # note sequence number for pairing
                    sendtimes[sqnum] = timestamp

                    # note ttl for ordering
                    ttls[sqnum] = ttl

                # echo reply for final ping
                if icmp_code == 0 and icmp_type == 0:
                    # pair with icmp echo sequence number
                    if sqnum in sendtimes:
                        rtt = timestamp - sendtimes[sqnum]
                        if srcip not in rttls:
                            rttls[srcip] = [rtt]
                        else:
                            rttls[srcip].append(rtt)


                # ttl exceeded
                if icmp_type == 11:
                    # sequence number
                    sqnum = unpack(endian+'H', icmpdata[34:36])[0]

                    # original request nodes's ip
                    if srcnode == None:
                        srcnode = ipBS(icmpdata[20:24])
                        dstnode = ipBS(icmpdata[24:28])

                    # find coressponding ttl
                    if sqnum in ttls:
                        ttl = ttls[sqnum]
                    elif srcport in ttls:
                        ttl = ttls[srcport]
                    
                    # get intermediate node's ip
                    if srcip in interNodes:
                        interNodes[srcip].append(ttl)
                    else:
                        interNodes[srcip] = [ttl]

                    # pair with icmp echo
                    if sqnum in sendtimes:
                        rtt = timestamp - sendtimes[sqnum]
                        if srcip not in rttls:
                            rttls[srcip] = [rtt]
                        else:
                            rttls[srcip].append(rtt)

                    # pair with udp source port
                    elif srcport in sendtimes:
                        rtt = timestamp - sendtimes[srcport]
                        if srcip not in rttls:
                            rttls[srcip] = [rtt]
                        else:
                            rttls[srcip].append(rtt)

                # Destination Unreachable: Port Unreachable final UDP packet
                if icmp_type == 3 and icmp_code == 3:
                        rtt = timestamp - sendtimes[srcport]
                        if srcip not in rttls:
                            rttls[srcip] = [rtt]
                        else:
                            rttls[srcip].append(rtt)

            # Fragment handling
            if flags == 0x1:
                last = False
                pid = (p.ip.src_ip, p.ip.dst_ip, id)
            
            elif last == False and fragoff > 0:
                last = True
                if pid not in fragments:
                    fragments[pid] = [fragoff]
                else:
                    fragments[pid].append(fragoff)
            
            packets.append(p)

    # sort interNodes by ttl
    interNodes = dict(sorted(interNodes.items(), key=lambda item: item[1][0]))

    # sort rttls in same order as interNodes
    sortedRttls = {node: rttls[node] for node in interNodes if node in rttls}
    # Add the final destination node last
    for node in rttls:
        if node not in sortedRttls:
            sortedRttls[node] = rttls[node]

    return protocols, interNodes, srcnode, dstnode, fragments, sortedRttls


def main():
    args = sys.argv
    if len(args) != 2:
        print('Pass input pcap file via stdin')
        exit(1)

    protocols, interNodes, src, dst, fragments, rttls = getInfo(sys.argv[1])

    # SOURCE DESTINATION AND INTERMEDIATE NODES
    print('The IP address of the source node:', src)
    print('The IP address of ultimate destination node:', dst)
    print('The IP addresses of the intermediate destination nodes:')

    for count, (ip, _) in enumerate(interNodes.items(), start=1):
        print(f"    router {count}: {ip}")

    # PROTOCOL
    print()
    print('The values in the protocol field of IP headers:')
    for num in sorted(protocols):
        if num == 1:
            print('1: ICMP')
            
        elif num == 17:
            print('17: UDP')

    # FRAGMENT
    print()
    if fragments == {}:
            print('The number of fragments created from the original datagram is:', 0)
            print('The offset of the last fragment is:', 0)
    else:
        for frag in fragments:
            print('The number of fragments created from the original datagram',frag[2],'is:', len(fragments[frag])+1)
            print('The offset of the last fragment is:', sum(fragments[frag]))

    # RTT
    print()
    for ip, rtts in rttls.items():
        if rtts:
            #print(ip, rtts)
            avg = sum(rtts) / len(rtts)
            sd = statistics.pstdev(rtts) if len(rtts) > 1 else 0
            print(f"The avg RTT between {src} and {ip} is: {avg * 1000:.2f} ms, the s.d. is: {sd * 1000:.2f} ms")



if __name__ == "__main__":
    
    main()
