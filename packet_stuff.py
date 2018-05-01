import struct
import socket
from dpkt import Packet



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


def get_tcp_header(ip_packet, iph_length):
    #partly from https://www.binarytides.com/python-packet-sniffer-code-linux/

    tcph = struct.unpack('!HHLLBBHHH', ip_packet[iph_length:iph_length+20])

    src_port = tcph[0]
    dest_port = tcph[1]
    seq_n = tcph[2]
    ack_n = tcph[3]
    doff_reserved = tcph[4]
    tcph_length = doff_reserved >> 4
    h_size = iph_length + tcph_length * 4
    data_size = len(ip_packet) - h_size

    return {'src_port':src_port, 'dest_port':dest_port, 'seq_n':seq_n, 'ack_n':ack_n, 'data_size':data_size}


_VERSION_MASK= 0xC000
_P_MASK     = 0x2000
_X_MASK     = 0x1000
_CC_MASK    = 0x0F00
_M_MASK     = 0x0080
_PT_MASK    = 0x007F
_VERSION_SHIFT=14
_P_SHIFT    = 13
_X_SHIFT    = 12
_CC_SHIFT   = 8
_M_SHIFT    = 7
_PT_SHIFT   = 0

VERSION = 2

# from https://github.com/kbandla/dpkt to parse the contents of an RTP packet
class RTP(Packet):
    __hdr__ = (
        ('_type', 'H',      0x8000),
        ('seq',     'H',    0),
        ('ts',      'I',    0),
        ('ssrc',    'I',    0),
    )
    csrc = ''

    def _get_version(self): return (self._type&_VERSION_MASK)>>_VERSION_SHIFT
    def _set_version(self, ver):
        self._type = (ver << _VERSION_SHIFT) | (self._type & ~_VERSION_MASK)
    def _get_p(self): return (self._type & _P_MASK) >> _P_SHIFT
    def _set_p(self, p): self._type = (p << _P_SHIFT) | (self._type & ~_P_MASK)
    def _get_x(self): return (self._type & _X_MASK) >> _X_SHIFT
    def _set_x(self, x): self._type = (x << _X_SHIFT) | (self._type & ~_X_MASK)
    def _get_cc(self): return (self._type & _CC_MASK) >> _CC_SHIFT
    def _set_cc(self, cc): self._type = (cc<<_CC_SHIFT)|(self._type&~_CC_MASK)
    def _get_m(self): return (self._type & _M_MASK) >> _M_SHIFT
    def _set_m(self, m): self._type = (m << _M_SHIFT) | (self._type & ~_M_MASK)
    def _get_pt(self): return (self._type & _PT_MASK) >> _PT_SHIFT
    def _set_pt(self, m): self._type = (m << _PT_SHIFT)|(self._type&~_PT_MASK)

    version = property(_get_version, _set_version)
    p = property(_get_p, _set_p)
    x = property(_get_x, _set_x)
    cc = property(_get_cc, _set_cc)
    m = property(_get_m, _set_m)
    pt = property(_get_pt, _set_pt)

    def __len__(self):
        return self.__hdr_len__ + len(self.csrc) + len(self.data)

    def __str__(self):
        return self.pack_hdr() + self.csrc + str(self.data)

    def unpack(self, buf):
        super(RTP, self).unpack(buf)
        self.csrc = buf[self.__hdr_len__:self.__hdr_len__ + self.cc * 4]
        self.data = buf[self.__hdr_len__ + self.cc * 4:]

def unpack_udp_header(ip_payload):
    udph = struct.unpack('!HHHH',ip_payload[0:8])
    src = udph[0]
    dst = udph[1]
    length = udph[2]
    check = udph[3]
    return {'source': src, 'destination': dst, 'length': length, 'check': check}




