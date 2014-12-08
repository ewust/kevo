#!/usr/bin/python

import struct

pkt = '''11010001130100011001003012040001000000140400
9f91015215040001000000160400ffffffff30010004
3210006735f472213b870eb746fbbec9078d07352000
17288ac7960a5fd5ac67a9ec9e2a6ca3b34fd8548b3b
5a2fd762234439f24d6f362000f77f318634ab571fb0
a346e35f7d5d35dbd9f7e421d1af7d4f23889827d5fd
c420100046b3c11d7aa7dfb82998b0babbf036702140
003a9e9cea0d9cb51e893af97bde20774b84f5d306ca
1ca18d7d4a175ee9312238fa10f32ee250318a2da8b0
8a3732e8c944b2fee0aeed206dc242e4f78b543804'''.replace('\n', '')


pkt = '''11010010130100011001003012040001000000140400
6d4ea35215040001000000160400ffffffff30010005
3210001d1ce63484a5b29b9bb1b63fd28b9cbc352000
d930b08ea18a047cee8dc6b6a43d0f8d04fced404360
d18a16fa6f02411288693620009d1d4ede79140b1119
8d4803065f6ed180862bea5c1177a1e1accba19ffca0
9873020000027210001d1ce63484a5b29b9bb1b63fd2
8b9cbc7004000100000071090047454e373a52455635
2010006735f472213b870eb746fbbec9078d07214000
b14ba6fe2c31e9edbafbf4da88b214ce6ea85cecb54a
4100a1ad9fcf0d7113c2d59b3d370dc6615ecbb78e16
fd9480f166e535417f7ee3df61f64bc00ff0850f'''.replace('\n', '')


pkt = '''1101001013010001100100301204000100000014
04007de7a75215040001000000160400ffffffff
0000000000000000000000000000000000000000
b87db1352000df3b935354d557570730a70e329e
c85b8b9608c037acf92f76503083f08f9d523620
007c33d89697fd41e334c203d3e337235d9cfd58
f28f0236611e4f18ba9aefe97e73020000017210
003c1aea88083649736a0b0158a6b87db1700400
0100000071090047454e373a5245563620100067
35f472213b870eb746fbbec9078d07214000e44e
196923669996a8504dbf056f9f2a6fd95f8ca2e3
7610941aeb476c2b183439c065e02e826b92fb26
31663f895cf61af102213c00eeb30737bfdc44b6
8801'''.replace('\n', '')

pkt = '''110100101301000110010030120400010000001404007de7a75215040001000000160400ffffffff0000000000000000000000000000000000000000'''


pkt = '0400112233441000112233445566778899aabb03ddeeff00070011223344556677'

import sys
if len(sys.argv) > 1:
    pkt = sys.argv[1]

FMTS = ['<B', '<H', '<L', '<Q', \
              '>H', '>L', '>Q']

def find_len(pkt, formats=FMTS, diff_thresh=5):

    diffs_out = []
    for i in xrange(len(pkt)):
        for fmt in formats:
            pack_size = struct.calcsize(fmt)
            if i+pack_size > len(pkt):
                continue
            cand_len,  = struct.unpack(fmt, pkt[i:i+pack_size])
            diff = abs( len(pkt[i:]) - cand_len )
            if (diff <= diff_thresh):
                diffs_out.append((fmt, i, diff))

    return diffs_out


def bold(s):
    return '***' + '\033[1m' + s + '\033[0m'


pkt = pkt.decode('hex')
orig_pkt = pkt
r = 0


def walk_back(pkt, form, diff_thresh, r):

    if len(pkt) == 0:
        return []

    ident = '   '*r

    print ident + '------'
    print ident + 'Round: %d fmt: %s offset: %d pkt len %d' % (r, form, diff_thresh, len(pkt))
    diffs = find_len(pkt, [form], diff_thresh)

    for fmt, offset, diff in diffs:
        if diff == diff_thresh:
            print ident, fmt, offset, diff
            print ident + pkt[0:offset].encode('hex') + bold(pkt[offset:offset+struct.calcsize(fmt)].encode('hex')) + pkt[offset+struct.calcsize(fmt):].encode('hex')

    results = []

    for fmt, offset, diff in diffs:
        if diff == diff_thresh:
            res = walk_back(pkt[0:offset], fmt, diff, r+1)

            if res is not None:
                #res.append((fmt, offset, diff))
                #res.append((fmt, offset, diff))
                results.append([(fmt, offset, diff), res])

    if results == []:
        return None
    return results


print '----'
print 'Round: 0 fmt: (all) pkt len: %d' % (len(pkt))

diffs = find_len(pkt, FMTS)
for fmt, offset, diff in diffs:
    print fmt, offset, diff
    print pkt[0:offset].encode('hex') + bold(pkt[offset:offset+struct.calcsize(fmt)].encode('hex')) + pkt[offset+struct.calcsize(fmt):].encode('hex')


winners = []
for fmt, offset, diff in diffs:
    res = walk_back(pkt[0:offset], fmt, diff, 1)
    if res is not None:
        res = [(fmt, offset, diff), res]
        print 'Winner winner:'
        print res
        winners.append(res)


# [('<H', 24, 2), [[('<H', 6, 2), [[('<H', 0, 2), []]]]]]
#for winner in winners:
