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
from ctypes import *
import os

##
from endpoints import CnxnToServer
from reorder import Reorder

libpacketmod_filename = 'libpacketmod.so'
libpacketmod_directory = os.path.join(os.getcwd(),libpacketmod_filename) #assume its in the cwd

cdll.LoadLibrary(libpacketmod_directory)
libpacketmod = CDLL(libpacketmod_directory)

##

WSIZE = 4294967295

SERV_IP = "45.33.83.64"
SERV_PORT = 5410  # 5410
TUN_NAME = 'tun0'
# EXCLUDED_IFC_NAMES = [TUN_NAME, 'lo', 'wlxc4e984d77fe2']
# EXCLUDED_IFC_NAMES = [TUN_NAME, 'lo', 'wlp3s0']
EXCLUDED_IFC_NAMES = [TUN_NAME, 'lo']

SERV_ADDR = ((SERV_IP), SERV_PORT)

# Find all client interfaces available for use
def get_usable_interfaces():
    curr_ifcs = []
    for ifc in netifaces.interfaces():
        if ifc in EXCLUDED_IFC_NAMES: continue
        if netifaces.AF_INET not in netifaces.ifaddresses(ifc): continue  # link has no addr, probably down
        curr_ifcs.append(ifc)
    return curr_ifcs
#bind to avail interfaces

CLIENT_ID = None
for interface in get_usable_interfaces():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.3)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, (interface.encode('ascii')))
        s.bind((netifaces.ifaddresses(interface)[netifaces.AF_INET][0]['addr'], 0)) #bind to that ifc ip addr on random port

        s.connect(SERV_ADDR)
        s.send(struct.pack("I",12345))
        data = s.recv(100)
        s.close()
        CLIENT_ID = struct.unpack("I",data[0:4])[0]
        break
    except:
        pass

if(CLIENT_ID is None):
    print("couldnt connect to server")
    exit()





def sigint_handler(*_):
    #rewrite to send out over udp on each socket
    ipr.release()
    print("Sending kill signal to server...")
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.25)
        s.connect(SERV_ADDR)
        s.send(struct.pack("II", 54321,CLIENT_ID))
        s.close()
    finally:
        sys.exit(0)
signal.signal(signal.SIGINT, sigint_handler)



server_connection = CnxnToServer(CLIENT_ID,SERV_ADDR, WSIZE)


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



class QOS:
    def __init__(self, priority_filename):
        self.congenstion_rate = 0
        self.counter = 0
        self.priority_packet_last_seen_time = {1:0, 2:0} #for priority 1 and 2

        self.priorities = {'dest_addr': {}}
        priority_file = open(priority_filename, 'r')
        for row in priority_file:
            filter_type, args, priority = row.split(',')
            priority = int(priority)
            if filter_type == 'dest_addr':
                self.priorities['dest_addr'][args] = priority  # arg will just be an ip address

    def prioritize(self, ip_packet):
        ##give the packet a priority, default is 3 (lowest priority)
        priority = 3
        ip_header = get_ip_header(ip_packet)
        if ip_header['dest_ip'] in self.priorities['dest_addr'].keys():
            priority = self.priorities['dest_addr'][ip_header['dest_ip']]

        if priority == -1: #low latency packet
            return -1, ip_packet

        if priority in [1,2]:
            self.priority_packet_last_seen_time[priority] = time.perf_counter()
            # print("set 1")

        seconds_since_p1_seen = time.perf_counter() - self.priority_packet_last_seen_time[1]
        seconds_since_p2_seen = time.perf_counter() - self.priority_packet_last_seen_time[2]
        # print("seconds_since_p1_seen",seconds_since_p1_seen,"seconds_since_p2_seen",seconds_since_p2_seen)

        reduced_window = None

        if (priority == 2) and (self.congenstion_rate > 0) and (seconds_since_p1_seen < 1.5):
            reduced_window = 2
            # print("REDUCTION")
        if (priority == 3) and (self.congenstion_rate > 0) and ((seconds_since_p1_seen < 1.5) or (seconds_since_p2_seen < 1.5)):
            reduced_window = 1
            # print("REDUCTION 1")

        if reduced_window is not None:
            if ip_header['protocol'] == 6: #tcp
                self.counter += 1
                if self.counter >= 2:
                    self.counter = 0
                    return 0, None

                # curr_rcv_win = struct.unpack("H",ip_packet[ip_header['iph_length']+14:ip_header['iph_length']+16])[0]
                new_ip_packet = bytearray(ip_packet)
                new_rcv_win = struct.pack("H",reduced_window)
                # self.zero_window = not self.zero_window
                new_ip_packet[ip_header['iph_length'] + 14:ip_header['iph_length'] + 16] = new_rcv_win
                new_ip_packet = bytes(new_ip_packet)
                libpacketmod.FixChecksums(new_ip_packet, len(new_ip_packet))
                return 1, new_ip_packet

        return 1, ip_packet

    def set_congenstion(self, congestion_rate):
        # print("set congestion",congestion_rate)
        self.congenstion_rate = congestion_rate



## SETUP LINKS WITH SOCKETS


class IfcLinks:
    def __init__(self, server_connection: CnxnToServer):
        self.ifc_names_to_link_ids = {}
        self.next_ifc_id = 0
        self.server_connection = server_connection

    def update_ifc_links(self):
        #get list of ifcs to use
        curr_ifcs = get_usable_interfaces()

        # print("curr ifcs", curr_ifcs)

        # ifcs_to_remove = [ifc for ifc in self.ifc_names_to_link_ids.keys() if ifc not in curr_ifcs]

        #remove from dict if link was deleted
        ifc_to_remove_from_dict = []
        for ifc, link_id in self.ifc_names_to_link_ids.items():
            if link_id not in self.server_connection.links:
                ifc_to_remove_from_dict.append(ifc)
        for ifc in ifc_to_remove_from_dict:
            del self.ifc_names_to_link_ids[ifc]


        ifcs_to_add = [ifc for ifc in curr_ifcs if ifc not in self.ifc_names_to_link_ids.keys()]

        # for ifc in ifcs_to_remove:
        #     print("deleting",ifc)
        #     link_id = self.ifc_names_to_link_ids[ifc]
        #     self.server_connection.remove_link(link_id)
        #     del self.ifc_names_to_link_ids[ifc]


        for ifc in ifcs_to_add:
            link_id = self.next_ifc_id
            print("adding",ifc,link_id)
            self.ifc_names_to_link_ids[ifc] = link_id
            self.next_ifc_id += 1
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, (ifc.encode('ascii')))
            sock.bind((netifaces.ifaddresses(ifc)[netifaces.AF_INET][0]['addr'], 0)) #bind to that ifc ip addr on random port
            self.server_connection.add_link(link_id,sock=sock)

        self.server_connection.update_link_metrics(self_gen=True)


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


def keep_alive():
    while True:
        time.sleep(0.15)
        server_connection.send_keep_alives()
_thread.start_new_thread (keep_alive,())


def update_links():
    while True:
        time.sleep(0.5)
        ifc_links.update_ifc_links()
        update_listen_list()
_thread.start_new_thread (update_links,())



reorder = Reorder(tun, WSIZE,trigger=25)

def process_incoming_msg(buf, sock):
    #get the link id for the socket that got written to
    link_id = None
    for l_id, link in server_connection.links.items():
        if link.sock is sock:
            link_id = l_id
            break
    if link_id is None: return

    action_id = struct.unpack("I", buf[0:4])[0]
    if action_id == 100: #regular data
        buffer_id, packet_id = struct.unpack("II", buf[4:12])
        server_connection.recv_packet(link_id,packet_id)
        reorder.incoming(buffer_id, buf[12:])

    if action_id == 101: #low latency packet
        tun.write(buf[4:])

    if action_id == 105: #keep alive
        packet_id = struct.unpack("I", buf[4:8])[0]
        server_connection.recv_packet(link_id,packet_id)


    if action_id == 200: #link quality update
        link_quality_update_id, outbound_fastest_link = struct.unpack("II",buf[4:12])
        first = server_connection.got_link_quality_update(link_id,link_quality_update_id)
        if not first: return

        l = []
        for i in range(12, len(buf), 16):
            link_id, rcv_start_id, rcv_count, rcv_finish_id = struct.unpack('IIII', buf[i:i + 16])
            l.append((link_id, rcv_start_id, rcv_count, rcv_finish_id))
        server_connection.update_link_metrics(l, outbound_fastest_link)
        qos.set_congenstion(server_connection.congestion_mode)


##setup route to direct all traffic thru tun
ipr = IPRoute()
ipr.route('add', dst='default', gateway='10.8.0.1')


while True:
    readable, writable, exceptional = select(listen_list, [], [], 0.15)
    # if len(exceptional) > 0:
    #     ifc_links.update_ifc_links()
    for d in readable:
        if d is tun:
            # print("got from tun ",end='')
            ip_packet = tun.read(tun.mtu)
            code, ip_packet = qos.prioritize(ip_packet)
            if code == -1: #low latency packet
                server_connection.send_ll_packet(ip_packet)
            elif code == 1:
                # print("sent")
                server_connection.send_packet(ip_packet)
            # server_connection.send_packet(ip_packet)
            # else:
                # print("dropped",priority)

        else:  # d is some socket
            # print("got from sock", end='')
            buf, addr = d.recvfrom(1500)
            if addr != SERV_ADDR:
                # print("Got packet from wrong addr", addr)
                continue
            process_incoming_msg(buf, d)

    if len(readable) == len(writable) == len(exceptional) == 0: #assume this means we timed out
        print("force empty")
        reorder.empty_buffer()




