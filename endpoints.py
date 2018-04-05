import struct
import numpy as np
import time
#todo deal with rollovers

class Link:
    def __init__(self, link_id, dest_addr=None, sock=None):
        self.link_id = link_id
        self.rcv_portion = 1
        self.next_packet_id = 0
        self.rcv_count = 0
        self.rcv_finish_id = 0
        self.rcv_start_id = None

        self.dest_addr = dest_addr
        self.sock = sock

        self.ratio = 1
        self.count_zero = 0
        self.last_count_zero = 0


class EndPoint:

    def update_link_metrics(self,link_qualities=[], outbound_fastest_link=None, self_gen=False): #takes a list of tuples with the result of the link quality
        links_to_update = list(self.links.keys())
        for (link_id, rcv_start_id, rcv_count, rcv_finish_id) in link_qualities:
            if link_id in self.links.keys(): #we might not have set up the link yet
                self.update_rcv_portion(link_id, rcv_start_id, rcv_count, rcv_finish_id)
            if link_id in links_to_update: links_to_update.remove(link_id)

        for link_id in links_to_update: #these didnt come in the pkt, assume 0
            if self_gen:
                self.update_rcv_portion(link_id, -2, 0, 0)
            else:
                self.update_rcv_portion(link_id, -1, 0, 0)



        links_to_del = []
        for link_id, link in self.links.items():
            if link.count_zero >= 15:
                print("deleting link",link_id)
                links_to_del.append(link_id)
                # link.count_zero = 0

        for link_id in links_to_del:
            del self.links[link_id]

        for link_id, link in self.links.items():
            base_ratio = (1 / len(self.links)) * 15
            missing_portion = max(1 - link.rcv_portion, 0)
            penalty = missing_portion * 3 * base_ratio
            link.ratio = int(max(0, base_ratio - penalty))

        self.update_congestion_mode()
        if outbound_fastest_link is not None:
            self.outbound_fastest_link_id = outbound_fastest_link

        self.update_send_list()


    def update_congestion_mode(self):
        max_rcv_portion = 0
        for link in self.links.values():
            max_rcv_portion = max(max_rcv_portion,link.rcv_portion)

        if max_rcv_portion == 0:
            self.congestion_mode = 0 #if we have no active links doesnt make sense to be in congestion mode

        elif max_rcv_portion <= .99:
            self.congestion_mode = 1

        else:
            self.congestion_mode = 0

    def update_send_list(self):
        self.send_list.clear()
        self.send_list_position = 0

        s = ''

        # #if fastest link doesnt have congestion, we use it exclusively
        # fastest_link = self.links[self.outbound_fastest_link_id]
        # print("fastest_link.rcv_portion",fastest_link.rcv_portion)
        # if fastest_link.rcv_portion >= 0.98:
        #     for _ in range(10):
        #         self.send_list.append(fastest_link.link_id)
        #     print("updated send list, using only fastest:", fastest_link.link_id)
        #     return

        #else, we send out all links
        for link_id, link in self.links.items():
            ratio = link.ratio + 1
            s += "link {}, ratio {}  ".format(link_id, round(ratio,2))
            for _ in range(ratio):
                self.send_list.append(link_id)
        print('updated send list:',s)
        np.random.shuffle(self.send_list)

    def __init__(self, client_id ,wsize):
        self.client_id = client_id
        self.wsize = wsize

        self.send_list = []
        self.send_list_position = 0
        # self.send_list_start_idx = 0
        self.links = {}
        self.congestion_mode = 0

        self.next_buffer_id = 0
        self.next_link_quality_update_id_for_sending = 0
        self.last_link_quality_id_received = 0

        self.inbound_fastest_link_id = 0
        self.outbound_fastest_link_id = 0

    def got_link_quality_update(self, link_id, link_quality_update_id):
        #we want to track which link is fastest, so the first link we get a new update on is fastest
        if link_quality_update_id <= self.last_link_quality_id_received: return False
        self.last_link_quality_id_received = link_quality_update_id
        self.inbound_fastest_link_id = link_id
        return True
        # print("fastest link is",link_id)


    def add_link(self, link_id, dest_addr=None, sock=None):
        link = Link(link_id, dest_addr=dest_addr, sock=sock)
        self.links[link_id] = link

    # def remove_link(self, link_id):
    #     del self.links[link_id]

    def count_packet(self, link_id, packet_id):
        link = self.links[link_id]
        link.rcv_count += 1
        if link.rcv_start_id is None:
            link.rcv_start_id = packet_id

    def make_header(self, link_id, action_id):
        raise NotImplementedError("abstract method must be implemented")

    def make_msg_packet(client_id, header, buffer_id, packet_id, packet):
        header += struct.pack("I", buffer_id)
        header += struct.pack("I", packet_id)
        header += packet
        return header

    def transmit_dg(self, dg, link):
        raise NotImplementedError("abstract method must be implemented")

    def send_keep_alives(self):
        for link_id, link in self.links.items():
            msg = self.make_header(link_id, 105)
            msg += struct.pack("I",link.next_packet_id)
            sent = self.transmit_dg(msg, link)
            link.next_packet_id += 1

    def send_ll_packet(self,packet):
        link_id = self.outbound_fastest_link_id
        link = self.links[link_id]
        msg = self.make_header(link_id, 101) + packet
        self.transmit_dg(msg, link)
        print("sending ll on",link_id)

    def send_packet(self,packet):
        sent = False
        max_tries = 10
        ctr = 0
        while not sent:
            if len(self.send_list) == 0:
                print("no links!!!")
                return
            if self.send_list_position >= len(self.send_list): self.send_list_position = 0#self.send_list_start_idx
            link_id = self.send_list[self.send_list_position]
            link = self.links[link_id]
            header = self.make_header(link_id, 100)
            msg = self.make_msg_packet(header, self.next_buffer_id, link.next_packet_id, packet)

            sent = self.transmit_dg(msg, link)
            self.send_list_position += 1
            link.next_packet_id += 1

            if sent:
                self.next_buffer_id += 1
                if self.next_buffer_id >= self.wsize: self.next_buffer_id = 0

            # print("sending on",link_id)
            # print("send list",self.send_list)
            ctr += 1
            if ctr >= max_tries:
                return
        #todo have to figure out rolling over the next_packet_id
        # print("sent message, linkid:",link_id,"addr_tuple",self.links[link_id]['addr_tuple'],
        #       "id",self.links[link_id]['next_packet_id'],
        #       "length",len(msg))


    def update_rcv_portion(self, link_id, rcv_start_id, rcv_count, rcv_finish_id):
        link = self.links[link_id]

        if rcv_start_id == -1:
            rcv_expected_count = 1
        elif rcv_start_id == -2:
            rcv_expected_count = 0
            # if link.next_packet_id - rcv_finish_id > 3 * rcv_count : rcv_finish_id = link.next_packet_id
        else:
            rcv_expected_count = link.next_packet_id - rcv_start_id

        # print("---------->",link_id,rcv_start_id,rcv_count,link.next_packet_id)

        if rcv_expected_count == 0: return #dont update if we didnt send anything out over link
        link.rcv_portion = rcv_count / rcv_expected_count
        # print('---->',(time.perf_counter() - link.last_count_zero))
        if link.rcv_portion == 0:
            print("######### zero")
            if (time.perf_counter() - link.last_count_zero)>=0.4:
                link.count_zero += 1
                link.last_count_zero = time.perf_counter()
        else:
            link.count_zero = 0


    def recv_packet(self,link_id,packet_id):
        link = self.links[link_id]
        link.rcv_count += 1
        link.rcv_finish_id = packet_id
        if link.rcv_start_id is None:
            link.rcv_start_id = packet_id

    def send_link_quality_update(self):
        # str = ''
        if len(self.links) == 0: return
        msg = self.make_header(0,200)
        msg += struct.pack("II",self.next_link_quality_update_id_for_sending,self.inbound_fastest_link_id)
        self.next_link_quality_update_id_for_sending += 1
        if self.next_link_quality_update_id_for_sending >= 100: self.next_link_quality_update_id_for_sending = 0
        for link_id, link in self.links.items():
            # str += 'link_id: {}, rcv_start_id: {}, rcv_count: {}  -- '.format(link_id, link.rcv_start_id,
            #                                                                   link.rcv_count)
            msg += struct.pack("IIII", link_id, link.rcv_start_id or 0, link.rcv_count, link.rcv_finish_id)
            link.rcv_count = 0
            link.rcv_start_id = None
            # print("send link quality update",link_id, link.rcv_count)
        # now send the packet on all links
        ks = list(self.links.keys())
        np.random.shuffle(ks)
        for link_id in ks:
            link = self.links[link_id]
            self.transmit_dg(msg, link)
        # print("sent update:", str)


class CnxnToClient(EndPoint): #this code runs on the server
    master_sock = None

    #
    # def update_send_list(self):
    #     self.send_list.clear()
    #     self.send_list.append(0)
    #     self.send_list.append(0)
    #     self.send_list.append(0)
    #     self.send_list.append(1)
    #     self.send_list.append(1)
    #     self.send_list.append(1)
    #     self.send_list.append(1)
    #     self.send_list.append(1)
    #     self.send_list.append(1)
    #     self.send_list.append(1)
    #     self.send_list.append(1)
    #     self.send_list.append(1)
    #     self.send_list.append(1)
    #     self.send_list_position = 0
    #     np.random.shuffle(self.send_list)
    #     print("updated send list",self.send_list)


    def transmit_dg(self, dg, link):
        self.master_sock.sendto(dg, link.dest_addr)
        return True

    def make_header(self, link_id, action_id):
        header = struct.pack("I", action_id)
        return header

    def __init__(self, client_id, master_sock, wsize, reorder):
        self.master_sock = master_sock
        self.low_latency_connections = set()
        self.reorder = reorder
        self.last_reorder_activity = 0
        EndPoint.__init__(self, client_id, wsize)


class CnxnToServer(EndPoint): #this code runs on the client
    server_addr = None

    def transmit_dg(self, dg, link):
        try:
            link.sock.sendto(dg, self.server_addr)
            return True
            # print("sent")
        except:
            # print("failed!!")
            return False

    def make_header(self, link_id, action_id):
        header = struct.pack("III", self.client_id, link_id, action_id)
        return header

    def __init__(self, client_id, server_addr, wsize):
        self.server_addr = server_addr
        EndPoint.__init__(self, client_id, wsize)
