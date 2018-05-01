import struct
import numpy as np
import time
import operator


from typing import Dict, Tuple, List


BUCKET_COUNT = 256
SEND_CAP_EWMA_ALPHA = 0.4

class Link:
    def __init__(self, link_id, dest_addr=None, sock=None, tcp_sock=None):
        self.sent_per_bucket = [0] * BUCKET_COUNT
        self.send_cap = 80000
        self.send_cap_overcap = 5
        self.send_cap_is_init_value = True
        self.rcv_per_bucket = [0] * BUCKET_COUNT


        self.link_id = link_id

        self.dest_addr = dest_addr
        self.sock = sock
        self.tcp_sock = tcp_sock

        self.latency_order_incoming = 0

        self.count_failed = 0

        # self.ratio = 1
        # self.count_zero = 0
        # self.last_count_zero = 0

    # def set_bucket_rcv(self, bucket_id, rcv_amount):
    #     self.received_per_bucket[bucket_id]=rcv_amount

    def increment_sent_bucket(self, bucked_id, sent_amount):
        self.sent_per_bucket[bucked_id] += sent_amount


class EndPoint:

    def __init__(self, client_id):
        self.client_id = client_id

        # self.links: Dict[int, Link] = {}
        self.links = {}
        self.congestion_mode = 0

        self.next_link_quality_update_id_for_sending = 0

        self.last_link_quality_id_received = 0
        self.count_link_quality_updates_at_same_id_received = 0

        self.max_bucket_id_received_in_curr_tf = 0 #tf = timeframe
        self.max_bucket_id_received_in_prev_tf = 0

        self.curr_bucket_id_for_outgoing = 0
        # self.outbound_curr_bucket = 0
        # self.inbound_curr_bucket = 0


        self.link_ids_in_order= []
        self.link_idx = 0

        self.in_overcap_mode = False

        self.tick_counts = 0
        # self.inbound_fastest_link_id = 0
        # self.outbound_fastest_link_id = 0


    ##TICK todo could implement this... needed?
    # def link_metrics_timeout(self): #should be called if link updated hasnt arrived
    #     self.inbound_curr_bucket += 1
    #     if self.inbound_curr_bucket > BUCKET_COUNT:
    #         self.inbound_curr_bucket = 0
    #
    #     bucked_id = self.inbound_curr_bucket
    #     for link in self.links.values():
    #         link.set_bucket_rcv(bucked_id,0)


    #


    def add_link(self, link_id, dest_addr=None, sock=None, tcp_sock=None):
        print("adding link",link_id)

        link = Link(link_id, dest_addr=dest_addr, sock=sock, tcp_sock=tcp_sock)
        self.links[link_id] = link
        self.link_ids_in_order.append(link_id)

    def remove_link(self, link_id):
        print("removing link",link_id)
        if link_id in self.links.keys():
            self.links[link_id].tcp_sock.close()
            del self.links[link_id]

            for link in self.links.values():
                link.send_cap = 1000000

        if link_id in self.link_ids_in_order:
            self.link_ids_in_order.remove(link_id)
            self.link_idx = 0

    def count_packet_rcvd(self, link_id, bucket_id, bytes_rcvd):
        if self.max_bucket_id_received_in_curr_tf > BUCKET_COUNT * 3/4 and bucket_id < BUCKET_COUNT *1/4:
            self.max_bucket_id_received_in_curr_tf = bucket_id
        elif bucket_id > self.max_bucket_id_received_in_curr_tf:
            self.max_bucket_id_received_in_curr_tf = bucket_id

        # print("received packet on bucket",bucket_id)
        link = self.links[link_id]
        link.rcv_per_bucket[bucket_id] += bytes_rcvd


    def transmit_dg(self, dg, link):
        try:
            self.send_on_wire(dg,link)
            link.count_failed =0
            return True
            # print("sent")
        except:
            link.count_failed += 1
            if link.count_failed > 15:
                self.remove_link(link.link_id)
            # print("failed!!")
            return False

    def send_on_wire(self, dg, link):
        raise NotImplementedError("abstract method must be implemented")

    def send_keep_alives(self):
        for link_id, link in list(self.links.items()):
            self.send_packet(bytes(1),0,link_id=link_id)
            try:
                link.tcp_sock.send(struct.pack("I", 0))
            except:
                self.remove_link(link_id)

    def send_ll_packet(self,packet):
        action_id = 11
        self.send_packet(packet, action_id, low_latency=True)
        # print("sending ll")

    def get_header(self, action_id, link_id):
        raise NotImplementedError("abstract method must be implemented")

    def send_packet(self, packet, action_id=10, low_latency=False, link_id=None):
        # if action_id == 10 and self.in_overcap_mode:
        #     return
        ##add header with client id and bucket id
        sent = False
        max_tries = 4
        ctr = 0
        while not sent:
            try:
                if link_id is None:
                    link_id = self.link_ids_in_order[0] if low_latency else self.link_ids_in_order[self.link_idx]
            except:
                pass
            if link_id not in self.links.keys():
                print("heeere")
                return
            link = self.links[link_id]

            header = self.get_header(action_id, link_id)
            packet = header + packet

            sent = self.transmit_dg(packet, link)
            if sent:
                link.increment_sent_bucket(self.curr_bucket_id_for_outgoing,len(packet))
                #now move to next ifc if we are over the cap
                sent_so_far = link.sent_per_bucket[self.curr_bucket_id_for_outgoing]
                cap = link.send_cap_overcap if self.in_overcap_mode else link.send_cap
                if sent_so_far >= cap:
                    self.link_idx += 1
                    if self.link_idx >= len(self.link_ids_in_order):
                        self.in_overcap_mode = True
                        # print("OVERCAP")
                        self.link_idx = 0

                # print("sent out packet, bucket id",self.curr_bucket_id_for_outgoing," link id",link_id)
                return True

            ctr += 1
            print("RETRY")
            if ctr >= max_tries:
                return False


    def get_next_link_quality_update_id(self):
        answer = self.next_link_quality_update_id_for_sending
        self.next_link_quality_update_id_for_sending += 1
        #todo fix the rollover stuff
        #if self.next_link_quality_update_id_for_sending >= X: self.next_link_quality_update_id_for_sending = 0
        return answer

    def update_outgoing_link_ordering(self, link_id, new_order): #we want link ids in order of latency
        self.link_ids_in_order.remove(link_id)
        self.link_ids_in_order.insert(new_order, link_id)


    def got_link_metrics(self, recvd_on_link_id, link_quality_update_id, bucket_id, link_qualities): #takes a list of tuples with the result of the link quality
        if recvd_on_link_id not in self.links.keys():
            print("wtf")
            print(self.links.keys(),recvd_on_link_id)
            return

        if link_quality_update_id > self.last_link_quality_id_received: ##we have first duplicate of the update
            self.last_link_quality_id_received = link_quality_update_id
            self.links[recvd_on_link_id].latency_order_incoming = 0
            self.count_link_quality_updates_at_same_id_received = 1
        else:
            self.links[recvd_on_link_id].latency_order_incoming = self.count_link_quality_updates_at_same_id_received
            self.count_link_quality_updates_at_same_id_received += 1
            return #we dont need to actually update the other metrics since we did that on first receipt

        #link_qualities will be sorted by their latency
        print("Updating link metrics for bucket ",bucket_id)
        max_portion = 0
        for i, lq in enumerate(link_qualities):
            link_id, rcv_amount = lq
            if link_id not in self.links.keys(): continue
            link = self.links[link_id]
            sent_amnt = link.sent_per_bucket[bucket_id]
            portion = (rcv_amount/(sent_amnt+0.00001))
            max_portion = max(portion, max_portion)
            print("Link {}    sent/rcv = {}/{} = {}    cap:{} or {} Mbps".format(
                link_id,sent_amnt,rcv_amount,round((rcv_amount/(sent_amnt+0.00001)),2),link.send_cap,
                round(link.send_cap/125000*3.33,2)))
            if sent_amnt > 200 and (rcv_amount < sent_amnt or rcv_amount > link.send_cap): #we only update the cap if we have packet loss - ie link was saturated
                r = rcv_amount - ((1-portion)/2*rcv_amount) #penalize loss
                r *= 1.15
                if link.send_cap_is_init_value:
                    link.send_cap = int(r)
                    link.send_cap_is_init_value = False
                else:
                    link.send_cap = int((SEND_CAP_EWMA_ALPHA * r + (1-SEND_CAP_EWMA_ALPHA) * link.send_cap))
                link.send_cap_overcap = max(8000, int(link.send_cap / 30))
                print("updated cap to",link.send_cap)

            self.update_outgoing_link_ordering(link_id,i)
        self.congestion_mode = int(max_portion < 0.99)

    def got_latency_metrics(self, recvd_on_link_id, link_quality_update_id, link_qualities): #takes a list of tuples with the result of the link quality
        print("got latency metrics")

        if recvd_on_link_id not in self.links.keys():
            return

        if link_quality_update_id > self.last_link_quality_id_received: ##we have first duplicate of the update
            self.last_link_quality_id_received = link_quality_update_id
            self.links[recvd_on_link_id].latency_order_incoming = 0
            self.count_link_quality_updates_at_same_id_received = 1
        else:
            self.links[recvd_on_link_id].latency_order_incoming = self.count_link_quality_updates_at_same_id_received
            self.count_link_quality_updates_at_same_id_received += 1
            return #we dont need to actually update the other metrics since we did that on first receipt

        #link_qualities will be sorted by their latency
        for i, link_id in enumerate(link_qualities):
            if link_id not in self.links.keys(): continue
            link = self.links[link_id]
            self.update_outgoing_link_ordering(link_id,i)

    ##TICK
    def actions_to_take_every_tf(self):
        # self.tick_counts += 1
        # if self.tick_counts != 3:
        #     self.link_idx = 0
        #     self.send_latency_update()
        #     self.send_keep_alives()
        #     return
        # #self.tick_counts == 3
        # self.tick_counts = 0

        self.in_overcap_mode = False
        self.link_idx = 0
        self.max_bucket_id_received_in_prev_tf = self.max_bucket_id_received_in_curr_tf
        self.send_link_quality_update()

        if self.max_bucket_id_received_in_prev_tf > 15:
            for link in self.links.values():
                for i in range(0, self.max_bucket_id_received_in_prev_tf - 10):
                    link.rcv_per_bucket[i] = 0

        self.curr_bucket_id_for_outgoing += 1
        if self.curr_bucket_id_for_outgoing == 50:
            for link in self.links.values():
                for i in range(50,BUCKET_COUNT):
                    link.sent_per_bucket[i] = 0
        if self.curr_bucket_id_for_outgoing == 100:
            for link in self.links.values():
                for i in range(0,50):
                    link.sent_per_bucket[i] = 0

        if self.curr_bucket_id_for_outgoing >= BUCKET_COUNT:
            self.curr_bucket_id_for_outgoing = 0

        self.send_keep_alives()


    def send_latency_update(self):
        if len(self.links) == 0: return
        link_quality_update_id = self.get_next_link_quality_update_id()
        msg = struct.pack("I",link_quality_update_id)
        sorted_links = sorted(list(self.links.values()), key=lambda x: x.latency_order_incoming)
        for link in sorted_links:
            msg += struct.pack("I", link.link_id)
        ks = list(self.links.keys())
        np.random.shuffle(ks)
        for link_id in ks:
            self.send_packet(msg,action_id=21,link_id=link_id)

    def send_link_quality_update(self):
        # print("sending lq updates, list is",self.links.keys())
        # str = ''
        if len(self.links) == 0: return
        link_quality_update_id = self.get_next_link_quality_update_id()
        bucket_id = self.max_bucket_id_received_in_prev_tf
        if bucket_id < 0:
            bucket_id += BUCKET_COUNT-1

        msg = struct.pack("II",link_quality_update_id,bucket_id)

        # print("Sending link quality update",link_quality_update_id,bucket_id)
        sorted_links = sorted(list(self.links.values()), key=lambda x: x.latency_order_incoming)
        for link in sorted_links:
            # print("sending update for",link.link_id)
            msg += struct.pack("II", link.link_id, link.rcv_per_bucket[bucket_id])
            # print(link.link_id,link.rcv_per_bucket[bucket_id])
        # now send the packet on all links
        ks = list(self.links.keys())
        np.random.shuffle(ks)
        for link_id in ks:
            self.send_packet(msg,action_id=20,link_id=link_id)
            # link = self.links[link_id]
            # self.transmit_dg(msg, link)
        # print("sent update:", str)


class CnxnToClient(EndPoint): #this code runs on the server
    master_sock = None

    def send_on_wire(self, dg, link):
        self.master_sock.sendto(dg, link.dest_addr)

    def get_header(self, action_id, link_id):
        header = struct.pack("BB", self.curr_bucket_id_for_outgoing, action_id)
        return header


    def __init__(self, client_id, master_sock):
        self.master_sock = master_sock
        self.low_latency_connections = set()
        EndPoint.__init__(self, client_id)


class CnxnToServer(EndPoint): #this code runs on the client
    server_addr = None

    def send_on_wire(self, dg, link):
        link.sock.sendto(dg, self.server_addr)


    def get_header(self, action_id, link_id):
        header = struct.pack("BBBB", self.client_id,link_id, self.curr_bucket_id_for_outgoing, action_id)
        return header

    def __init__(self, client_id, server_addr):
        self.server_addr = server_addr
        EndPoint.__init__(self, client_id)
