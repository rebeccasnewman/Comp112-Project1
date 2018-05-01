import time
from packet_stuff import get_tcp_header, get_ip_header

class Reorder:
    def __init__(self, tun):

        self.timeout_time = 0.05
        self.tun = tun
        self.bufs = {}

    def got_pkt(self,ip_packet):
        ip_header = get_ip_header(ip_packet)

        if ip_header['protocol'] != 6:  # we dont reorder anything but tcp
            self.tun.write(ip_packet)
            return

        tcp_header = get_tcp_header(ip_packet, ip_header['iph_length'])
        key = (ip_header['src_ip'],tcp_header['src_port'],tcp_header['dest_port'],tcp_header['ack_n'])

        if key in self.bufs:
            stream_buffer = self.bufs[key]
            stream_buffer['packets'][tcp_header['seq_n']] = (ip_packet, tcp_header['data_size'])
            wrote = False
            while stream_buffer['next_seq_num'] in stream_buffer['packets'].keys():
                pkt, size = stream_buffer['packets'][stream_buffer['next_seq_num']]
                # print("**")
                self.tun.write(pkt)
                del stream_buffer['packets'][stream_buffer['next_seq_num']]
                stream_buffer['next_seq_num'] += size
                wrote = True
            if wrote:
                stream_buffer['last_write_time'] = time.perf_counter()
        else:
            self.bufs[key] = {
                'packets':{}
                ,'next_seq_num':tcp_header['seq_n']+tcp_header['data_size']
                ,'last_write_time':time.perf_counter()
                }
            self.tun.write(ip_packet)

    #TICK
    def clear_if_timeout(self):
        ks_to_del = []
        for key, stream_buffer in self.bufs.items():
            if time.perf_counter() - stream_buffer['last_write_time'] > self.timeout_time:
                for seq_num, (pkt, size) in stream_buffer['packets'].items():
                    self.tun.write(pkt)
                    # print("-")
                ks_to_del.append(key)
        for key in ks_to_del:
            del self.bufs[key]


