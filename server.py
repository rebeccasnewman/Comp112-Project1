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
from packet_stuff import get_ip_header, get_tcp_header

SERV_PORT = 5410
TCP_PORT = 5411
TUN_NAME = 'tun0'


##bind socket
master_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
master_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) #allow faster debug
master_sock.bind(("", SERV_PORT))

tcp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
tcp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  # allow faster debug
tcp_sock.bind(("", TCP_PORT))
tcp_sock.listen(5)


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

from typing import List
# clients: List[CnxnToClient] = [None] * 100
clients = [None] * 100

# clients[0] = CnxnToClient(0,master_sock)
def make_new_client(): #returns the new client index
    for i, c in enumerate(clients):
        if c is None:
            # reorder = Reorder(tun, WSIZE, trigger=15)
            clients[i] = CnxnToClient(i, master_sock)
            return i
    return None

def remove_client(client_id):
    try:
        clients[client_id] = None
    except:
        pass




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
    # struct.pack("BB", self.curr_bucket_id_for_outgoing, action_id)
    if len(buf) < 2: return
    # client_id, link_id, action_id = struct.unpack("III",buf[0:12])
    client_id, link_id, bucket_id, action_id = struct.unpack("BBBB",buf[0:4])

    client = id_to_client(client_id)
    if client is None: return
    # print("msg from client {}".format(client_id))

    if link_id not in client.links.keys(): return
    link = client.links[link_id]
    if link.dest_addr is None:
        link.dest_addr = addr
        # print("adding link"))
        # print(" wrote to tun")

        # print("wrote packet to tun, id:",packet_id,"
        # client.add_link(link_id, dest_addr = addr)
        # client.update_link_metrics()

    client.count_packet_rcvd(link_id,bucket_id,len(buf))


    if action_id==10 or action_id==11:
        pkt = buf[4:]
        # ip_header = get_ip_header(pkt)
        # if ip_header['protocol'] == 6:  # tcp
        #     tcp_header = get_tcp_header(pkt, ip_header['iph_length'])
        #     search_key = (tcp_header['dest_port'], tcp_header['src_port'],
        #            tcp_header['ack_n'], tcp_header['seq_n'])
        #     dup_ack = False
        #     if search_key in acked and tcp_header['data_size']==0:
        #         print("-----dup ack")
        #         dup_ack = True
        #         import numpy as np
        #         if np.random.randint(0,10) > 3: return
        #     else:
        #         acked.add(search_key)

            # if dup_ack and search_key in cache:
            #     if cache[search_key] is False: return
            #     print("SENDING FROM CACHE")
            #     print(search_key)
            #
            #     client.send_packet(cache[search_key])
            #     cache[search_key] = False
            #     # del cache[search_key]
            #     return

        tun.write(pkt)

        if action_id==11: #low lip_headeratency packet
            dest_ip = socket.inet_ntoa(buf[4 + 16:4 + 20])
            client.low_latency_connections.add(dest_ip)



    elif action_id == 20:
        link_quality_update_id, bucket_id = struct.unpack("II",buf[4:12])
        link_qualities = []
        for i in range(12, len(buf), 8):
            link_id, rcv_amount = struct.unpack('II', buf[i:i + 8])
            link_qualities.append((link_id, rcv_amount))

        client.got_link_metrics(link_id,link_quality_update_id,bucket_id,link_qualities)

    elif action_id == 21: #link quality update
        link_quality_update_id = struct.unpack("I", buf[4:8])[0]
        link_qualities = []
        for i in range(8, len(buf), 4):
            lid = struct.unpack('I', buf[i:i + 4])[0]
            link_qualities.append(lid)
            client.got_latency_metrics(link_id, link_quality_update_id, link_qualities)




tcp_socks_to_client_links = {}


read_from = [tun,master_sock,tcp_sock]

TICK_WAIT = 0.05
last_tf_time = time.perf_counter()

cache={}
acked=set()

while True:
    # print("read from",read_from)
    read_from = [s for s in read_from if s.fileno() != -1]

    readable, w, exceptional = select(read_from, [], read_from, TICK_WAIT)
    for d in readable:
        if d is tun:
            # print("got pckt on tun, ",end='')import
            packet = tun.read(tun.mtu)
            # ip_header = get_ip_header(packet)
            # if ip_header['protocol'] == 6: #tcp
            #     tcp_header = get_tcp_header(packet, ip_header['iph_length'])
            #     if tcp_header['data_size']>0:
            #         #ip_header['src_ip'],ip_header['dest_ip']
            #         key=(tcp_header['src_port'], tcp_header['dest_port'],
            #              tcp_header['seq_n'],tcp_header['ack_n'])
            #         cache[key] = packet
            #

            src_ip = socket.inet_ntoa(packet[12:16])
            dest_ip = socket.inet_ntoa(packet[16:20])
            client = ip_addr_to_client(dest_ip)

            if client is None: continue

            if src_ip in client.low_latency_connections:
                # client.send_packet(packet)
                client.send_ll_packet(packet)
            else:
                client.send_packet(packet)
            # print("sent pkt")


        elif d is master_sock:
            # print("got pckt on sock, ",end='')
            buf, addr = d.recvfrom(1500)
            process_incoming_msg(buf,addr)

        elif d is tcp_sock:
            client_sock, addr = tcp_sock.accept()
            read_from.append(client_sock)

        else: #d is some tcp client sock
            client_sock = d
            try:
                data = client_sock.recv(500)
            except:
                pass
            # print("got tcp pkt:",data)
            if len(data) < 4: continue
            req_num = struct.unpack("I", data[0:4])[0]
            if req_num == 12345:  # new client
                new_client_id = make_new_client()
                if new_client_id is not None:
                    client_sock.send(struct.pack("I", new_client_id))  # echo
                    print("new client connection, id", new_client_id)
                client_sock.close()
                read_from.remove(client_sock)

            elif req_num == 54321:  # client exit
                client_id = struct.unpack("I", data[4:8])[0]
                remove_client(client_id)
                print("killed client, id", client_id)
                client_sock.close()
                read_from.remove(client_sock)

            elif req_num == 1:  #this introduces a new link
                client_id, link_id = struct.unpack("II",data[4:12])
                client = id_to_client(client_id)
                if client is None: continue
                client_ip_addr = client_sock.getpeername()[0]

                client.add_link(link_id, tcp_sock = client_sock)
                tcp_socks_to_client_links[client_sock] = (client_id, link_id)
                # addressess_to_client_links[link_addr] = (client_id, link_id)
                print("registered link from client ",client_id,"id:",link_id)


    for d in exceptional:
        if d in [tun,master_sock,tcp_sock]:
            print("ERROR on a master fd:",d)
            exit(0)

        #else this is some client sock so, remove the client link
        if d in tcp_socks_to_client_links:
            client_id, link_id = tcp_socks_to_client_links[d]
        client = id_to_client(client_id)
        if client is None: continue
        client.remove_link(link_id)
        del tcp_socks_to_client_links[d]
        read_from.remove(d)
        d.close()


    curr_time = time.perf_counter()
    # if curr_time - last_tick_time >= TICK_WAIT:
    if curr_time - last_tf_time >= 0.3:
        # go_tick()
        for client in clients:
            if client is None: continue
            client.actions_to_take_every_tf()
            last_tf_time = curr_time


