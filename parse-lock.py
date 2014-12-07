#!/usr/bin/python

import dpkt
import sys
from bt import *


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

                    print '%s' % (bt_pdu)
                except:
                    print 'Error parsing BT ATT protocol'

        elif btle_pkt.llid == 3: # Control PDU
            print 'CONN_TERM: %s' % (btle_pkt.data.encode('hex'))


