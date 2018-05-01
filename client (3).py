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


from packet_stuff import get_ip_header, unpack_udp_header, RTP
from endpoints import CnxnToServer
from reorder import Reorder


LL_ONLY = False
if len(sys.argv) > 1 and sys.argv[1] == 'll': LL_ONLY = True



libpacketmod_filename = 'libpacketmod.so'
libpacketmod_directory = os.path.join(os.getcwd(),libpacketmod_filename) #assume its in the cwd

cdll.LoadLibrary(libpacketmod_directory)
libpacketmod = CDLL(libpacketmod_directory)

##


SERV_IP = "45.33.83.64"
SERV_PORT = 5410  # 5410
TCP_PORT = 5411
TUN_NAME = 'tun0'
# EXCLUDED_IFC_NAMES = [TUN_NAME, 'lo', 'wlxc4e984d77fe2']
# EXCLUDED_IFC_NAMES = [TUN_NAME, 'lo', 'wlp3s0']
EXCLUDED_IFC_NAMES = [TUN_NAME, 'lo']

SERV_ADDR = ((SERV_IP), SERV_PORT)
TCP_ADDR = (SERV_IP, TCP_PORT)

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

        s.connect(TCP_ADDR)
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
        s.connect(TCP_ADDR)
        s.send(struct.pack("II", 54321,CLIENT_ID))
        s.close()
    finally:
        sys.exit(0)
signal.signal(signal.SIGINT, sigint_handler)



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




flows = {}
def is_RTP_packet(ip_header, udp_header, udp_payload):
    possible_rtp = RTP(udp_payload)
    srcip = ip_header['src_ip']
    dstip = ip_header['dest_ip']
    srcport = udp_header['source']
    dstport = udp_header['destination']
    if (srcip, dstip, srcport, dstport) in flows:
      flows[(srcip, dstip, srcport, dstport)][0] += 1
    else:
      flows[(srcip, dstip, srcport, dstport)] = [1,0]
    if possible_rtp._get_version() == 2:
        if possible_rtp._get_pt() >=100:
            flows[(srcip, dstip, srcport, dstport)][1] += 1
            ratio = flows[(srcip, dstip, srcport, dstport)]
            if float(ratio[1])/float(ratio[0]) >= 0.5:
                print ('Found voip packet - Sending over low latency link')
                return True
    return False



class QOS:
    def __init__(self, priority_filename):
        self.congenstion_rate = 0
        self.counter = 0
        self.priority_packet_last_seen_time = {1: 0, 2: 0}  # for priority 1 and 2

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

        # check if its a udp packet - for RTP filtering
        if ip_header['protocol'] == 17:
            ip_payload = ip_packet[ip_header['iph_length']:]
            udp_header = unpack_udp_header(ip_payload)
            udp_payload = ip_payload[8:]
            if udp_header['source'] >= 1023 and udp_header['destination'] >= 1023:
                if len(udp_payload) >= 12:
                    if is_RTP_packet(ip_header, udp_header, udp_payload):
                        return -1, ip_packet

        if ip_header['dest_ip'] in self.priorities['dest_addr'].keys():
            priority = self.priorities['dest_addr'][ip_header['dest_ip']]

        if priority == -1:  # low latency packet
            return -1, ip_packet

        if priority in [1, 2]:
            self.priority_packet_last_seen_time[priority] = time.perf_counter()
            # print("set 1")

        seconds_since_p1_seen = time.perf_counter() - self.priority_packet_last_seen_time[1]
        seconds_since_p2_seen = time.perf_counter() - self.priority_packet_last_seen_time[2]
        # print("seconds_since_p1_seen",seconds_since_p1_seen,"seconds_since_p2_seen",seconds_since_p2_seen)

        reduced_window = None

        if (priority == 2) and (self.congenstion_rate > 0) and (seconds_since_p1_seen < 1.5):
            reduced_window = 2
            # print("REDUCTION")
        if (priority == 3) and (self.congenstion_rate > 0) and (
                (seconds_since_p1_seen < 1.5) or (seconds_since_p2_seen < 1.5)):
            reduced_window = 1
            # print("REDUCTION 1")

        if reduced_window is not None:
            if ip_header['protocol'] == 6:  # tcp
                self.counter += 1
                if self.counter >= 2:
                    self.counter = 0
                    return 0, None

                # curr_rcv_win = struct.unpack("H",ip_packet[ip_header['iph_length']+14:ip_header['iph_length']+16])[0]
                new_ip_packet = bytearray(ip_packet)
                new_rcv_win = struct.pack("H", reduced_window)
                # self.zero_window = not self.zero_window
                new_ip_packet[ip_header['iph_length'] + 14:ip_header['iph_length'] + 16] = new_rcv_win
                new_ip_packet = bytes(new_ip_packet)
                libpacketmod.FixChecksums(new_ip_packet, len(new_ip_packet))
                return 1, new_ip_packet

        return 1, ip_packet

    def set_congenstion(self, congestion_rate):
        # print("set congestion",congestion_rate)
        self.congenstion_rate = congestion_rate


class IfcLinks:
    def __init__(self, server_connection: CnxnToServer):
        self.ifc_names_to_link_ids = {}
        self.tcp_socks_to_link_id = {}
        self.next_ifc_id = 0
        self.server_connection = server_connection

    def get_tcp_socks(self):
        return [s for s in self.tcp_socks_to_link_id if s.fileno() != -1]

    def remove_link(self, link_id=None, ifc_name=None, tcp_sock=None):
        if link_id is None:
            if ifc_name in self.ifc_names_to_link_ids:
                link_id = self.ifc_names_to_link_ids[ifc_name]
            if tcp_sock in self.tcp_socks_to_link_id:
                link_id = self.tcp_socks_to_link_id[tcp_sock]

        if link_id is None:
            print("error removing link")
            return

        if ifc_name is None:
            for ifc, lid in self.ifc_names_to_link_ids.items():
                if lid == link_id:
                    ifc_name = ifc
        if tcp_sock is None:
            for s, lid in self.tcp_socks_to_link_id.items():
                if lid == link_id:
                    tcp_sock = s

        if tcp_sock in self.tcp_socks_to_link_id:
            del self.tcp_socks_to_link_id[tcp_sock]

        if ifc_name in self.ifc_names_to_link_ids:
            del self.ifc_names_to_link_ids[ifc_name]

        self.server_connection.remove_link(link_id)

    def update_ifc_links(self):
        #get list of ifcs to useifc_to_remove_from_dict
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
            print("adding",ifc)
            self.ifc_names_to_link_ids[ifc] = link_id
            self.next_ifc_id += 1
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, (ifc.encode('ascii')))
            sock.bind((netifaces.ifaddresses(ifc)[netifaces.AF_INET][0]['addr'], 0)) #bind to that ifc ip addr on random port
            # _, port = sock.getsockname()

            ##initiate tcp connection on this link with the server
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, (ifc.encode('ascii')))
            s.bind((netifaces.ifaddresses(ifc)[netifaces.AF_INET][0]['addr'],0))
            # s.settimeout(0.25)
            s.connect(TCP_ADDR)
            s.send(struct.pack("III", 1, CLIENT_ID, link_id))
            self.tcp_socks_to_link_id[s] = link_id
            self.server_connection.add_link(link_id,sock=sock, tcp_sock=s)
            print("done adding, link id:",link_id)




qos = QOS('priority')
ifc_links = IfcLinks(server_connection)
ifc_links.update_ifc_links()


reorder = Reorder(tun)

def process_incoming_msg(buf, sock):
    #get the link id for the socket that got written to
    link_id = None
    for link in server_connection.links.values():
        if link.sock is sock:
            link_id = link.link_id
            break
    if link_id is None: return

    # print("got on link,",link_id)

    bucket_id, action_id = struct.unpack("BB",buf[0:2])
    # print("---->",bucket_id,action_id,link_id)
    server_connection.count_packet_rcvd(link_id,bucket_id,len(buf))

    if action_id == 10 or action_id == 11: #regular data or low latency packet
        reorder.got_pkt(buf[2:])
        # tun.write(buf[2:])
        # reorder.incoming(buffer_id, buf[12:])

    elif action_id == 20: #link quality update
        link_quality_update_id, bucket_id = struct.unpack("II", buf[2:10])
        link_qualities = []
        for i in range(10, len(buf), 8):
            lid, rcv_amount = struct.unpack('II', buf[i:i + 8])
            link_qualities.append((lid, rcv_amount))

        server_connection.got_link_metrics(link_id, link_quality_update_id, bucket_id, link_qualities)

        qos.set_congenstion(server_connection.congestion_mode)

    elif action_id == 21: #link quality update
        link_quality_update_id = struct.unpack("I", buf[2:6])[0]
        link_qualities = []
        for i in range(6, len(buf), 4):
            lid = struct.unpack('I', buf[i:i + 4])[0]
            link_qualities.append(lid)
        server_connection.got_latency_metrics(link_id, link_quality_update_id, link_qualities)


##setup route to direct all traffic thru tun
ipr = IPRoute()
ipr.route('add', dst='default', gateway='10.8.0.1')

TICK_WAIT = 0.05
last_tick_time = time.perf_counter()
last_tf_time = time.perf_counter()


while True:
    # print("..")
    tcp_socks = list(ifc_links.get_tcp_socks())
    udp_socks = [link.sock for link in server_connection.links.values()]
    rlist = [tun]+tcp_socks+udp_socks
    readable, writable, exceptional = select(rlist, [], rlist, TICK_WAIT)
    # if len(exceptional) > 0:
    #     ifc_links.update_ifc_links()
    for d in readable:
        if d is tun:
            # print("got from tun ",end='')
            ip_packet = tun.read(tun.mtu)
            code, ip_packet = qos.prioritize(ip_packet)
            if LL_ONLY or code == -1: #low latency packet
                server_connection.send_ll_packet(ip_packet)
            elif code == 1:
                server_connection.send_packet(ip_packet)

            # server_connection.send_packet(ip_packet)
            # else:
                # print("dropped",priority)

        elif d in udp_socks:  # d is some socket
            # print("got from sock", end='')
            buf, addr = d.recvfrom(1500)
            if addr != SERV_ADDR:
                # print("Got packet from wrong addr", addr)
                continue
            process_incoming_msg(buf, d)

        elif d in tcp_socks:
            data = d.recv(500)

    for d in exceptional:
        if d is tun:
            print("error with tun ifc")
            exit()

        # elif d in udp_socks:
        #     ifc_links.remove_link()

        if d in tcp_socks:
            ifc_links.remove_link(tcp_socks)


    curr_time = time.perf_counter()


    if curr_time - last_tick_time >= TICK_WAIT:
        # go_tick()
        reorder.clear_if_timeout()
        last_tick_time = curr_time

    if curr_time - last_tf_time >= 0.3:
        # go_tick()
        server_connection.actions_to_take_every_tf()
        ifc_links.update_ifc_links()

        last_tf_time = curr_time




