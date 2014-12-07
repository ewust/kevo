#!/usr/bin/python

import dpkt
import sys
import struct

class ppi(object):
    FMT = '<BBHL'
    def __init__(self, pkt):
        self.pkt = pkt
        self.version, self.flags, self.header_len, self.dlt, = \
            struct.unpack(ppi.FMT, pkt[:struct.calcsize(ppi.FMT)])

        if self.header_len > len(pkt):
            raise Exception("PPI: invalid header length %d on packet size %d" % (self.header_len, len(pkt)))

        self.res = pkt[struct.calcsize(ppi.FMT):self.header_len]
        self.data = pkt[self.header_len:]


class btle(object):
    FMT = '<LH'
    ADDRS = {}      # map of access_addr to state

    STATE_UNKNOWN=0
    STATE_CONNECTED=1

    PDU_ADV_IND=0x00
    PDU_CONNECT_REQ=0x05

    def __init__(self, pkt):
        self.pkt = pkt
        self.access_addr, self.data_header = \
            struct.unpack(btle.FMT, pkt[:struct.calcsize(btle.FMT)])


    @staticmethod
    def conn_req(access_addr):
        if access_addr in btle.ADDRS:
            raise Exception("btle: CONN_REQ for %s already in state %d" % \
                            (access_addr, ADDRS[access_addr]))
        btle.ADDRS[access_addr] = btle.STATE_CONNECTED

class btle_adv_ind(btle):
    def __init__(self, pkt):
        super(btle_adv_ind, self).__init__(pkt)

        self.adv_addr = pkt[11:5:-1]
        self.adv_data = pkt[12:]


class btle_conn_req(btle):
    def __init__(self, pkt):
        super(btle_conn_req, self).__init__(pkt)

        # specify that this access addr is now a connection
        btle.conn_req(self.access_addr)

        self.length     = (self.data_header >> 8) & 0x3f

        self.init_addr  = pkt[11:5:-1]
        self.adv_addr   = pkt[17:12:-1]


class btle_data(btle):
    def __init__(self, pkt):
        super(btle_data, self).__init__(pkt)

        self.length     = (self.data_header >> 8) & 0x1f
        self.more_data  = (self.data_header >> 4) & 0x1
        self.seq_no     = (self.data_header >> 3) & 0x1
        self.next_seq   = (self.data_header >> 2) & 0x1
        self.llid       = (self.data_header >> 0) & 0x3

        self.data = pkt[6:self.length+6]


    pass

def btle_factory(pkt):
    access_addr, data_header = struct.unpack(btle.FMT, pkt[:struct.calcsize(btle.FMT)])
    if access_addr == 0x8e89bed6:
        # PDU_type (ADV_IND (0x00), CONNECT_REQ (0x05), SCAN_REQ (0x03), SCAN_RSP (0x04)..)
        pdu = data_header & 0xf

        if pdu == btle.PDU_ADV_IND:
            return btle_adv_ind(pkt)
        elif pdu == btle.PDU_CONNECT_REQ:
            return btle_conn_req(pkt)
        else:
            # generic
            return btle(pkt)

    elif access_addr in btle.ADDRS and btle.ADDRS[access_addr] == btle.STATE_CONNECTED:
        return btle_data(pkt)

    else:
        return btle(pkt)

# given \x11\x22\x33\x44\x55\x66 returns 11:22:33:44:55:66
def mac(addr):
    return ':'.join(['%02x' % ord(x) for x in addr])

for ts, pkt in dpkt.pcap.Reader(open(sys.argv[1], 'r')):
    ppi_pkt = ppi(pkt)

    btle_pkt = btle_factory(ppi_pkt.data)

    if btle_pkt.__class__ is btle_conn_req:
        print 'CONN_REQ %s -> %s' % (mac(btle_pkt.init_addr), mac(btle_pkt.adv_addr))
