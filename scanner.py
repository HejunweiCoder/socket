import socket
import os
import struct
import threading
import time
from netaddr import IPAddress,IPNetwork

from ctypes import *

host="10.90.150.35"

subnet="10.90.150.0/24"

magic_message="PYTHONRULES!"

#send a string prepare to get it again from ICMP about the last some bytes
def udp_sender(subnet,magic_message):
    # time.sleep(5)
    sender=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
    #IPNetwork to get that subnet include all IP address
    for ip in IPNetwork(subnet):
        try:
            #we can change a port
            sender.sendto(magic_message,("%s" % ip,65212))
        except:
            pass


class IP(Structure):
    #it's ctypes Structure usages must be _fields_
    _fields_=[
        ("ihl",c_uint8,4),
        ("version",c_uint8,4),
        ("tos",c_uint8),
        ("len",c_uint16),
        ("id",c_uint16),
        ("offset",c_uint16),
        ("ttl",c_uint8),
        ("protocol_num",c_uint8),
        ("sum",c_uint16),
        ("src",c_uint32),
        ("dst",c_uint32)
    ]

    #also ctypes include we use it for _fields_ maybe I think ...it's a question
    def __new__(self, socket_buffer=None):
        return self.from_buffer_copy(socket_buffer)

    def __init__(self,socket_buffer=None):
        self.protocol_map={1:"ICMP",6:"TCP",17:"UDP"}

        self.src_address=socket.inet_ntoa(struct.pack("<L",self.src))
        self.dst_address=socket.inet_ntoa(struct.pack("<L",self.dst))

        try:
            self.protocol = self.protocol_map[self.protocol_num]

        except:
            self.protocol = str(self.protocol_map)


class ICMP(Structure):
    _fields_=[
        ('type',c_uint8),
        ('code',c_uint8),
        ('checksum',c_uint16),
        ('unused',c_uint16),
        ('next_hop_mtu',c_uint16),
        ('icmp_data',c_uint8)
    ]
    def __new__(self,socket_buffer):
        return self.from_buffer_copy(socket_buffer)

    def __init__(self,socket_buffer):
        pass

#I don't kone how many thread it opened
t =threading.Thread(target=udp_sender,args=(subnet,magic_message))
t.start()


if os.name== "nt":
    socket_protocol = socket.IPPROTO_IP
else:
    socket_protocol = socket.IPPROTO_ICMP

#raw socket usage
sniffer = socket.socket(socket.AF_INET,socket.SOCK_RAW,socket_protocol)

sniffer.bind((host,0))

sniffer.setsockopt(socket.IPPROTO_IP,socket.IP_HDRINCL,1)
if os.name=="nt":
    sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

try:
    while True:
        #the other is a address
        raw_buffer = sniffer.recvfrom(65565)[0]
        #default ip header package is 20 bytes
        ip_header = IP(raw_buffer[0:20])

        print("Protocol: %s %s -> %s" % (ip_header.protocol,ip_header.src_address,ip_header.dst_address))

        if ip_header.protocol == "ICMP":

            offset=ip_header.ihl*4
            #we offset 20 bytes to get the ICMP
            buf=raw_buffer[offset:offset+sizeof(ICMP)]

            icmp_header=ICMP(buf)

            # print("ICMP -> Type: %d Code: %d" % (icmp_header.type,icmp_header.code))
            # print("icmp_data",icmp_header.icmp_data)
            #unreachable port say it is UP host
            if icmp_header.code == 3 and icmp_header.type == 3:
                if IPAddress(ip_header.src_address) in IPNetwork(subnet):
                    if raw_buffer[len(raw_buffer)-len(magic_message):] == magic_message:
                        print("Host Up: %s" % ip_header.src_address)

except KeyboardInterrupt:
    if os.name == 'nt':
        sniffer.ioctl(socket.SIO_RCVALL,socket.RCVALL_OFF)
