import socket
from pytun import TunTapDevice, IFF_TUN, IFF_NO_PI
from select import select
import struct
import _thread
import time
import fcntl
import array
# import numpy as np
##
from endpoints import CnxnToClient
from reorder import Reorder

SERV_PORT = 5410 #5410
TUN_NAME = 'tun0'


##bind socket
master_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
master_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) #allow faster debug
master_sock.bind(("", SERV_PORT))

##SETUP TUN
tun = TunTapDevice(name=TUN_NAME, flags=(IFF_TUN | IFF_NO_PI))

# TUNSETOFFLOAD = struct.pack('I',208)
# TUNSETOFFLOAD = 0x400454d0
# TUN_F_CSUM = 0x01
# # buf = array.array('h',[1])
# o = 0x01 | 0x02 | 0x04 | 0x08 | 0x10
# fcntl.ioctl(tun, TUNSETOFFLOAD, o, 0)
# print(buf)

tun.addr = '10.8.0.1'
# tun.dstaddr = '10.8.0.1'
tun.netmask = '255.255.255.0'
tun.mtu = 1400
tun.up()

WSIZE = 4294967295

clients = [None] * 100

# clients[0] = CnxnToClient(0,master_sock)
def make_new_client(): #returns the new client index
    for i, c in enumerate(clients):
        if c is None:
            reorder = Reorder(tun, WSIZE, trigger=15)
            clients[i] = CnxnToClient(i, master_sock,WSIZE, reorder)
            return i
    return None

def remove_client(client_id):
    try:
        clients[client_id] = None
    except:
        pass



def tcp_server():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  # allow faster debug
    s.bind(("", SERV_PORT))
    s.listen(1)
    while 1:
        client_sock, addr = s.accept()
        data = client_sock.recv(500)
        # print("got tcp pkt:",data)
        req_num = struct.unpack("I",data[0:4])[0]
        if req_num == 12345: #new client
            new_client_id = make_new_client()
            if new_client_id is not None:
                client_sock.send(struct.pack("I",new_client_id))  # echo
                print("new client connection, id",new_client_id)
        elif req_num == 54321: #client exit
            client_id = struct.unpack("I",data[4:8])[0]
            remove_client(client_id)
            print("killed client, id",client_id)

        client_sock.close()

_thread.start_new_thread (tcp_server,())


def link_quality():
    while True:
        time.sleep(0.5)
        for client in clients:
            if client is None: continue
            client.send_link_quality_update()
            client.update_link_metrics(self_gen=True)

_thread.start_new_thread (link_quality,())


def keep_alive():
    while True:
        time.sleep(0.15)
        for client in clients:
            if client is None: continue
            client.send_keep_alives()

            if time.perf_counter() - client.last_reorder_activity >= 0.15:
                client.reorder.empty_buffer()
                client.last_reorder_activity = time.perf_counter()

_thread.start_new_thread (keep_alive,())



def ip_addr_to_client(ip_addr):
    if ip_addr[0:7] != '10.8.0.': return None
    client_id = int(ip_addr.split('.')[3]) - 100
    return id_to_client(client_id)


def id_to_client(client_id):
    try:
        client = clients[client_id]
        if client.client_id != client_id: return None
        return client
    except:
        return None

# switchbool = True












def process_incoming_msg(buf,addr):
    client_id, link_id, action_id = struct.unpack("III",buf[0:12])

    # #simulate packet drop todo remove
    # global switchbool
    # switchbool = not switchbool
    # if link_id == 1 and switchbool:
    #     return

    client = id_to_client(client_id)
    if client is None: return
    # print("msg from client {}".format(client_id))

    if link_id not in client.links.keys():
        # print("adding link"))
        # print(" wrote to tun")

        # print("wrote packet to tun, id:",packet_id,"
        client.add_link(link_id, dest_addr = addr)
        client.update_link_metrics()

    if action_id==100:
        buffer_id, packet_id = struct.unpack("II",buf[12:20])
        # print(buffer_id)

        # src_ip = socket.inet_ntoa(buf[16+12:16+16])
        # dest_ip = socket.inet_ntoa(buf[16+16:16+20])
        # print("got packet from SOCK", src_ip, dest_ip)

        #keep track of received packets
        client.recv_packet(link_id,packet_id)

        # tun.write(buf[20:])
        client.reorder.incoming(buffer_id, buf[20:])
        client.last_reorder_activity = time.perf_counter()

        # print(" wrote to tun")

        # print("wrote packet to tun, id:",packet_id,"client_id then link_id::",client_id,link_id,"len",len(buf))

    if action_id == 101: #low latency packet
        tun.write(buf[12:])
        dest_ip = socket.inet_ntoa(buf[12+16:12+20])
        client.low_latency_connections.add(dest_ip)


    if action_id == 105: #keep alive
        packet_id = struct.unpack("I", buf[4:8])[0]
        client.recv_packet(link_id,packet_id)

    if action_id == 200:
        link_quality_update_id, outbound_fastest_link = struct.unpack("II",buf[12:20])

        first = client.got_link_quality_update(link_id,link_quality_update_id)
        if not first: return

        l = []
        for i in range(20, len(buf), 16):
            link_id, rcv_start_id, rcv_count, rcv_finish_id = struct.unpack('IIII', buf[i:i + 16])
            l.append((link_id, rcv_start_id, rcv_count, rcv_finish_id))
        client.update_link_metrics(l, outbound_fastest_link)




while True:
    readable, w, e = select([tun,master_sock], [], [])
    for d in readable:
        if d is tun:
            # print("got pckt on tun, ",end='')
            packet = tun.read(tun.mtu)
            src_ip = socket.inet_ntoa(packet[12:16])
            dest_ip = socket.inet_ntoa(packet[16:20])
            client = ip_addr_to_client(dest_ip)
            if client is None: continue

            if src_ip in client.low_latency_connections:
                client.send_ll_packet(packet)
            else:
                client.send_packet(packet)
            # print("sent pkt")


        else: #d is the sock
            # print("got pckt on sock, ",end='')
            buf, addr = d.recvfrom(1500)
            process_incoming_msg(buf,addr)


