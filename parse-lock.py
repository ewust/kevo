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

    @staticmethod
    def is_connected(access_addr):
        if access_addr in btle.ADDRS:
            return btle.ADDRS[access_addr] == btle.STATE_CONNECTED
        return False

class btle_adv_ind(btle):
    def __init__(self, pkt):
        super(btle_adv_ind, self).__init__(pkt)

        self.adv_addr = pkt[11:5:-1]
        self.adv_data = pkt[12:]


class btle_conn_req(btle):
    FMT = '<6s6sL3sBHHHH5sB'
    def __init__(self, pkt):
        super(btle_conn_req, self).__init__(pkt)

        # specify that this access addr is now a connection

        self.length     = (self.data_header >> 8) & 0x3f

        # ugh hack hack
        self.init_addr, self.adv_addr, self.access_addr, self.crc_init, \
        self.win_size, self.win_offset, self.interval, self.latency, self.timeout, \
        self.chan_map, self.hopclock, = \
            struct.unpack(btle_conn_req.FMT, pkt[6:6+struct.calcsize(btle_conn_req.FMT)])

        btle.conn_req(self.access_addr)


class btle_data(btle):
    def __init__(self, pkt):
        super(btle_data, self).__init__(pkt)

        self.length     = (self.data_header >> 8) & 0x1f
        self.more_data  = (self.data_header >> 4) & 0x1
        self.seq_no     = (self.data_header >> 3) & 0x1
        self.next_seq   = (self.data_header >> 2) & 0x1
        self.llid       = (self.data_header >> 0) & 0x3

        self.data = pkt[6:self.length+6]


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

    elif btle.is_connected(access_addr):
        return btle_data(pkt)

    else:
        return btle(pkt)

# given \x11\x22\x33\x44\x55\x66 returns 11:22:33:44:55:66
def mac(addr):
    return ':'.join(['%02x' % ord(x) for x in addr])



class l2cap(object):
    FMT = '<HH'
    def __init__(self, pkt):
        fmt_len = struct.calcsize(l2cap.FMT)

        self.length, self.cid, = struct.unpack(l2cap.FMT, pkt[:fmt_len])

        self.data = pkt[fmt_len:fmt_len+self.length]

# bluetooth attribute protocol
class btatt(object):
    FMT = '<B'
    HANDLE_FMT = '<H'

    OP_ERROR_RESP               = 0x01
    OP_FIND_BY_TYPE_VAL_REQ     = 0x06
    OP_FIND_BY_TYPE_VAL_RESP    = 0x07
    OP_READ_BY_TYPE_REQ         = 0x08
    OP_READ_BY_TYPE_RESP        = 0x09
    OP_READ_REQ                 = 0x0a
    OP_READ_RESP                = 0x0b
    OP_READ_BLOB_REQ            = 0x0c
    OP_READ_BLOB_RESP           = 0x0d
    OP_WRITE_REQ                = 0x12
    OP_WRITE_RESP               = 0x13

    def __init__(self, pkt):
        fmt_len = struct.calcsize(btatt.FMT)
        self.opcode, = struct.unpack(btatt.FMT, pkt[:fmt_len])

        self.str = 'UNKNOWN'

        if self.opcode == btatt.OP_ERROR_RESP:
            self.str = 'ERROR'

        elif self.opcode == btatt.OP_FIND_BY_TYPE_VAL_REQ:
            self.start_handle, self.end_handle, = \
                struct.unpack('<HH', pkt[fmt_len:fmt_len+4])
            self.str = 'FIND_BY_TYPE_VAL_REQ 0x%04x - 0x%04x' % (self.start_handle, self.end_handle)

        elif self.opcode == btatt.OP_FIND_BY_TYPE_VAL_RESP:
            self.start_handle, self.end_handle, = \
                struct.unpack('<HH', pkt[fmt_len:fmt_len+4])
            self.str = 'FIND_BY_TYPE_VAL_RESP 0x%04x - 0x%04x' % (self.start_handle, self.end_handle)

        elif self.opcode == btatt.OP_READ_BY_TYPE_REQ:
            self.start_handle, self.end_handle, = \
                struct.unpack('<HH', pkt[fmt_len:fmt_len+4])
            self.str = 'READ_BY_TYPE_REQ 0x%04x - 0x%04x' % (self.start_handle, self.end_handle)

        elif self.opcode == btatt.OP_READ_BY_TYPE_RESP:
            pass
            self.str = 'READ_BY_TYPE_RESP'

        elif self.opcode == btatt.OP_READ_REQ:
            self.handle, = struct.unpack(btatt.HANDLE_FMT, pkt[fmt_len:fmt_len+2])
            self.str = 'READ_REQ(0x%04x)' % self.handle

        elif self.opcode == btatt.OP_READ_RESP:
            self.data = pkt[fmt_len:]
            self.str = 'READ_RESP(%d bytes): %s' % (len(self.data), self.data.encode('hex'))

        elif self.opcode == btatt.OP_READ_BLOB_REQ:
            self.handle, self.offset, = struct.unpack('<HH', pkt[fmt_len:fmt_len+4])
            self.str = 'READ_BLOB_REQ(0x%04x, %d)' % (self.handle, self.offset)

        elif self.opcode == btatt.OP_READ_BLOB_RESP:
            self.data = pkt[fmt_len:]
            self.str = 'READ_BLOB_RESP(%d bytes): %s' % (len(self.data), self.data.encode('hex'))

        elif self.opcode == btatt.OP_WRITE_REQ:
            self.handle, = struct.unpack(btatt.HANDLE_FMT, pkt[fmt_len:fmt_len+2])
            self.data = pkt[fmt_len+2:]
            self.str = 'WRITE_REQ(0x%04x, %s) (%d bytes)' % (self.handle, self.data.encode('hex'), len(self.data))

        elif self.opcode == btatt.OP_WRITE_RESP:
            self.str = 'WRITE_RESP'


    def __str__(self):
        return self.str

# TODO move to main, or the rest of the stuff out of this file
for ts, pkt in dpkt.pcap.Reader(open(sys.argv[1], 'r')):
    ppi_pkt = ppi(pkt)

    btle_pkt = btle_factory(ppi_pkt.data)

    if btle_pkt.__class__ is btle_conn_req:
        print 'CONN_REQ %s -> %s' % (mac(btle_pkt.init_addr), mac(btle_pkt.adv_addr))

    elif btle_pkt.__class__ is btle_data:
        if btle_pkt.llid == 2: # L2CAP message or frag
            if len(btle_pkt.data) != 0:
                l2_pkt = l2cap(btle_pkt.data)
                bt_pdu = btatt(l2_pkt.data)

                print '%s' % (bt_pdu)
        elif btle_pkt.llid == 3: # Control PDU
            print 'CONN_TERM: %s' % (btle_pkt.data.encode('hex'))


