#!/usr/bin/python

import dpkt
import sys
from bt import *

class blob_state(object):
    def __init__(self):
        self.state = 'IDLE'
        self.handle = 0x0000
        self.offset = 0
        self.fragments = [] # offset, data

    def resp(self, data):
        if self.state == 'IDLE':
            print 'Warning: missing first request, assuming 0x0016, 0'
            self.handle = 0x0016
            self.offset = 0
        if self.state == 'RESP':
            # just increase offset...
            self.offset += self.last_diff
            print 'Warning: missing blob request, assuming 0x%04x, %d' % (self.handle, self.offset)

        self.state = 'RESP'
        self.fragments.append( (self.offset, data) )

    def req(self, handle, offset):
        if self.state != 'IDLE':
            if self.state != 'RESP':
                #raise Exception('blob request for outstanding blob state %s' % self.state)
                print 'Warning: possibly missed a RESP'
            elif self.handle != handle:
                raise Exception('blob request changing handles 0x%04x -> 0x%04x' % \
                                (self.handle, handle))

        self.state = 'REQ'
        self.handle = handle
        self.last_diff = offset - self.offset
        self.offset = offset

    def __str__(self):
        # reassemble fragments
        if self.state != 'RESP':
            print 'Unexpected stringify, expect truncated data'
        self.fragments.sort(key=lambda tup: tup[0])
        next_offset = 0
        out = ''
        for offset, data in self.fragments:
            missing_bytes = offset - next_offset
            out += '..'*missing_bytes
            out += data.encode('hex')
            next_offset = offset + len(data)
        self.state = 'IDLE'
        self.fragments = []
        return 'READ_BLOB(0x%04x): %s (%d bytes)' % (self.handle, out, len(out)/2)


read_blob = blob_state()
read_req_handle = 0x0000

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
                try:
                    bt_pdu = btatt(l2_pkt.data)
                except:
                    print 'Error parsing BT ATT protocol'

                if bt_pdu.opcode == btatt.OP_READ_BLOB_REQ:
                    read_blob.req(bt_pdu.handle, bt_pdu.offset)
                elif bt_pdu.opcode == btatt.OP_READ_BLOB_RESP:
                    read_blob.resp(bt_pdu.data)
                else:
                    if read_blob.state != 'IDLE':
                        print '%s' % (read_blob)
                    if bt_pdu.opcode == btatt.OP_WRITE_REQ:
                        if bt_pdu.handle == 0x0014:
                            # control register
                            print 'WRITE_CTL 0x%s' % (bt_pdu.data.encode('hex'))
                        else:
                            print '%s' % (bt_pdu)
                    elif bt_pdu.opcode == btatt.OP_WRITE_RESP:
                        # ignore
                        pass

                    elif bt_pdu.opcode == btatt.OP_READ_REQ:
                        read_req_handle = bt_pdu.handle

                    elif bt_pdu.opcode == btatt.OP_READ_RESP:
                        print 'READ(0x%04x): %s' % (read_req_handle, bt_pdu.data.encode('hex'))
                    else:
                        print '%s' % (bt_pdu)

        elif btle_pkt.llid == 3: # Control PDU
            if btle_pkt.data.startswith('\xa0'):
                print 'CONN_TERM: %s' % (btle_pkt.data.encode('hex'))


