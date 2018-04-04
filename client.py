import socket
# this can only run on linux which has the bindtodevice socket option, not defined in python so we add it
if not hasattr(socket, 'SO_BINDTODEVICE'):
    socket.SO_BINDTODEVICE = 25
import time
from pytun import TunTapDevice, IFF_TUN, IFF_NO_PI
from select import select
import struct
import netifaces
import _thread
import signal
import sys
from pyroute2 import IPRoute

##
from endpoints import CnxnToServer
from eventlet import timeout
from ctypes import *
import os

libpacketmod_filename = 'libpacketmod.so'
libpacketmod_directory = os.path.join(os.getcwd(),libpacketmod_filename) #assume its in the cwd
cdll.LoadLibrary(libpacketmod_directory)
libpacketmod = CDLL(libpacketmod_directory)

SERV_IP = "45.33.83.64"
SERV_PORT = 5410  # 5410
TUN_NAME = 'tun0'
# EXCLUDED_IFC_NAMES = [TUN_NAME, 'lo', 'ens9']
# EXCLUDED_IFC_NAMES = [TUN_NAME, 'lo', 'wlp3s0']
EXCLUDED_IFC_NAMES = [TUN_NAME, 'lo']

SERV_ADDR = ((SERV_IP), SERV_PORT)
LAST_BUF_ID = 1
PACKET_BUF = [None]*500
# Find all client interfaces available for use
curr_ifcs = []
for ifc in netifaces.interfaces():
    if ifc in EXCLUDED_IFC_NAMES: continue
    if netifaces.AF_INET not in netifaces.ifaddresses(ifc): continue  # link has no addr, probably down
    curr_ifcs.append(ifc)
#bind to avail interfaces
success = 0 

for interface in curr_ifcs:
    with timeout.Timeout(3) as timeout:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, (interface.encode('ascii')))
            s.bind((netifaces.ifaddresses(interface)[netifaces.AF_INET][0]['addr'], 0)) #bind to that ifc ip addr on random port
            
            s.connect(SERV_ADDR)
            s.send(struct.pack("I",12345))
            data = s.recv(100)
            s.close()
            CLIENT_ID = struct.unpack("I",data[0:4])[0]
            success = 1
            break
        except: continue

if(success==0):
    print("couldnt connect to server")
    exit()

def sigint_handler(*_):
    print("Sending kill signal to server...")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    print("created socket")
    s.connect(SERV_ADDR)
    print("connect")
    s.send(struct.pack("II", 54321,CLIENT_ID))
    print("sent to socket")
    s.close()

    # shutdown IPDB
    ipr.release()
    sys.exit(0)
#signal.signal(signal.SIGINT, sigint_handler)



server_connection = CnxnToServer(CLIENT_ID,SERV_ADDR)


##SETUP TUN
tun = TunTapDevice(name=TUN_NAME, flags=(IFF_TUN | IFF_NO_PI))
last_octet = str(100 + CLIENT_ID)
tun.addr = '10.8.0.' + last_octet

print("setup with client_id {} and tun_addr {}".format(CLIENT_ID, tun.addr))
tun.dstaddr = '10.8.0.1'
tun.netmask = '255.255.255.0'
tun.mtu = 1400
tun.up()

#### Packet priority i
#read in file with format filter_type, arg, priority number



def get_ip_header(ip_packet):
    #partly from https://www.binarytides.com/python-packet-sniffer-code-linux/
    iph = struct.unpack('!BBHHHBBH4s4s', ip_packet[0:20])
    version_ihl = iph[0]
    version = version_ihl >> 4
    ihl = version_ihl & 0xF
    iph_length = ihl * 4
    ttl = iph[5]
    protocol = iph[6]
    s_addr = socket.inet_ntoa(iph[8])
    d_addr = socket.inet_ntoa(iph[9])

    return {'version':version, 'iph_length':iph_length, 'ttl':ttl,'protocol':protocol,'src_ip':s_addr,'dest_ip':d_addr}



class QOS: #note currently only supports priority of 0 (low) or 1 (high)
    def __init__(self, priority_filename):
        self.drop_rate = 0 #drop every x packets, note that 0 means dont drop anything
        self.counter = 1
        self.priority_1_packet_last_seen_time = 0

        self.priorities = {'dest_addr': {}}
        priority_file = open(priority_filename, 'r')
        for row in priority_file:
            filter_type, args, priority = row.split(',')
            priority = int(priority)
            if filter_type == 'dest_addr':
                self.priorities['dest_addr'][args] = priority  # arg will just be an ip address

    def prioritize(self, ip_packet):
        ##give the packet a priority
        priority = 0
        ip_header = get_ip_header(ip_packet)
        if ip_header['dest_ip'] in self.priorities['dest_addr'].keys():
            priority = self.priorities['dest_addr'][ip_header['dest_ip']]

        if priority == 1:
            self.priority_1_packet_last_seen_time = time.perf_counter()
            # print("set 1")


        ###now do nothing, mangle, or drop
        #we should only start dropping packets if we are in drop rate mode AND we have recently sent priority packets
        seconds_since_p1_seen = time.perf_counter() - self.priority_1_packet_last_seen_time
        if self.drop_rate > 0 and seconds_since_p1_seen < 1.5:
            if priority == 1:
                 return ip_packet

            else:
                if ip_header['protocol'] == 6: #tcp
                    # tcp_header = ip_packet[ip_header['iph_length']:ip_header['iph_length'] + 20]
                    rcv_win = struct.unpack("H",ip_packet[ip_header['iph_length']+14:ip_header['iph_length']+16])[0]
                    print("rcv win is",rcv_win)
                    # print(ip_header['iph_length'])
                    
                    new_ip_packet = bytearray(ip_packet)
                    new_rcv_win = struct.pack("H",int(rcv_win/priority))
                    new_ip_packet[ip_header['iph_length'] + 14:ip_header['iph_length'] + 16] = new_rcv_win
                    #set checksum to 0 for tcp header and ip header
                    new_ip_packet[ip_header['iph_length'] + 16:ip_header['iph_length'] + 18] = struct.pack("H",0)
                    rcv_win = struct.unpack("H",new_ip_packet[ip_header['iph_length']+14:ip_header['iph_length']+16])[0]
                    print("rcv win is",rcv_win)
                    # new_ip_packet[10:12] = struct.pack("H",0)
                    # print(new_ip_packet[ip_header['iph_length'] + 16:ip_header['iph_length'] + 18])
                    new_ip_packet = bytes(new_ip_packet)
                    libpacketmod.FixChecksums(new_ip_packet,len(new_ip_packet))
                    print("returning ip packet")
                    return new_ip_packet

            # elif self.counter == self.drop_rate:
                # self.counter = 1
                # return None
            # else:
            #     self.counter += 1
            #     return 1
        # else:
        #     return ip_packet
        return ip_packet

    def set_drop_rate(self, drop_rate):
        self.drop_rate = drop_rate

    
## SETUP LINKS WITH SOCKETS


class IfcLinks:
    def __init__(self, server_connection: CnxnToServer):
        self.ifc_names_to_link_ids = {}
        self.next_ifc_id = 0
        self.server_connection = server_connection

    def update_ifc_links(self):
        #get list of ifcs to use
        curr_ifcs = []
        for ifc in netifaces.interfaces():
            if ifc in EXCLUDED_IFC_NAMES: continue
            if netifaces.AF_INET not in netifaces.ifaddresses(ifc): continue  # link has no addr, probably down
            curr_ifcs.append(ifc)

        print("curr ifcs", curr_ifcs)

        ifcs_to_remove = [ifc for ifc in self.ifc_names_to_link_ids.keys() if ifc not in curr_ifcs]
        ifcs_to_add = [ifc for ifc in curr_ifcs if ifc not in self.ifc_names_to_link_ids.keys()]

        for ifc in ifcs_to_remove:
            link_id = self.ifc_names_to_link_ids[ifc]
            self.server_connection.remove_link(link_id)
            del self.ifc_names_to_link_ids[ifc]

        for ifc in ifcs_to_add:
            link_id = self.next_ifc_id
            self.next_ifc_id += 1
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, (ifc.encode('ascii')))
            sock.bind((netifaces.ifaddresses(ifc)[netifaces.AF_INET][0]['addr'], 0)) #bind to that ifc ip addr on random port
            self.server_connection.add_link(link_id,sock=sock)

        self.server_connection.update_link_metrics()


# header format is client_id(uint),interface_id(uint),action_id(uint)
# for packet, after header have packet_id(uint) followed by packet
##actions: 200=introduce link, 100=packet to fwd

##from server, header should just have action
# if action is 100 will then have packet id

#
# #todo: do you really neet to introduce the links???
# ## INTRODUCE LINKS
# def introduce_link(ifc_name):
#     sock = links[ifc_name]['sock']
#     msg = struct.pack("III",CLIENT_ID,links[ifc_name]['id'],200)
#     for _ in range(5):
#         sock.sendto(msg,SERV_ADDR)
#
# for ifc, d in links.items():
#     introduce_link(ifc)


qos = QOS('priority')
ifc_links = IfcLinks(server_connection)
ifc_links.update_ifc_links()


listen_list = []
def update_listen_list():
    listen_list.clear()
    for link in server_connection.links.values():
        listen_list.append(link.sock)
    listen_list.append(tun)
update_listen_list()

print("listen_list:", listen_list)


def link_quality():
    while True:
        time.sleep(0.5)
        server_connection.send_link_quality_update()

_thread.start_new_thread (link_quality,())


def process_incoming_msg(buf, sock):
    global LAST_BUF_ID, PACKET_BUF
    #get the link id for the socket that got written to
    for link_id, link in server_connection.links.items():
        if link.sock is sock:
            # print('got message on ifc',ifc)
            break

    action_id = struct.unpack("I", buf[0:4])[0]
    if action_id == 100:

        buffer_id, packet_id = struct.unpack("II", buf[4:12])
        #print("buffer id is" ,buffer_id)
        tun.write(buf[12:])
        # PACKET_BUF[buffer_id] = buf
        # diff = buffer_id - LAST_BUF_ID

        # # if buffer_id < LAST_BUF_ID:
        # #     tun.write(buf[12:])
        # if diff > 0 and diff < 2: 
        #     tun.write(buf[12:])
        #     LAST_BUF_ID = buffer_id

        # while LAST_BUF_ID < 500 and PACKET_BUF[LAST_BUF_ID]:
        #     print("writing packet",LAST_BUF_ID)
        #     tun.write(PACKET_BUF[buffer_id][12:])
        #     LAST_BUF_ID += 1

        # if LAST_BUF_ID == 500:
        #     LAST_BUF_ID = 0
        #     PACKET_BUF = 500*[None]


        server_connection.recv_packet(link_id,packet_id)

        # print("wrote packet to tun, id:",packet_id,"from ifc:",id_num)
    if action_id == 200:
        link_quality_update_id = struct.unpack("I",buf[4:8])[0]
        l = []
        for i in range(8, len(buf), 12):
            link_id, rcv_start_id, rcv_count = struct.unpack('III', buf[i:i + 12])
            l.append((link_id, rcv_start_id, rcv_count))
        server_connection.update_link_metrics(l)

        server_connection.got_link_quality_update(link_id,link_quality_update_id)

        if server_connection.congestion_mode == 1:
            # print("congestion mode 1")
            qos.set_drop_rate(2)
        else:
            qos.set_drop_rate(0)


##setup route to direct all traffic thru tun
ipr = IPRoute()
#ipr.route('add', dst='default', gateway='10.8.0.1')


while True:
    readable, writable, exceptional = select(listen_list, [], [])
    if len(exceptional) > 0:
        ifc_links.update_ifc_links()
    for d in readable:
        if d is tun:
            ip_packet = tun.read(tun.mtu)
            ip_packet = qos.prioritize(ip_packet)
            if ip_packet is not None:
                # print("sent")
                server_connection.send_packet(ip_packet)
            # else:
                # print("dropped",priority)

        else:  # d is some socket
            buf, addr = d.recvfrom(1500)
            if addr != SERV_ADDR:
                # print("Got packet from wrong addr", addr)
                continue
            process_incoming_msg(buf, d)




