#! /usr/bin/env python3

import struct
from sys import argv
from OpenSSL import crypto
from typing import Tuple

def cpu_type_to_str(cpu_type : int, cpu_subtype: int) -> str:
    if cpu_type == 0x0100000c:
        if cpu_subtype == 0x0 or cpu_subtype == 0x1:
            return 'arm64'
        if cpu_subtype == 0x2:
            return 'arm64e'
    if cpu_type == 0x0000000c:
        if cpu_subtype == 0x6:
            return 'arm_v6'
        if cpu_subtype == 0x9:
            return 'arm_v7'
        if cpu_subtype == 0x13:
            return 'arm_v8'

    return 'unknown'

def read_lv(buff : bytes) -> Tuple[int,bytes]:
    assert(len(buff) >= 8)
    (l,) = struct.unpack('>I',buff[0:4])
    #print(f'seg_size = {hex(l)}')
    assert(l <= len(buff))

    return (l,buff[4:l+4])

def dump_supf(filename : str):
    # open and read file
    f = open(filename,'rb')
    buff : bytes = f.read()
    f.close()
    
    magic = buff[0:4]
    assert(magic == b'\x03507')

    pos = buff[4:]
    (length,segs) = read_lv(pos);
    (nseg,) = struct.unpack('>I',segs[0:4])    

    seg_pos = segs[4:]
    print('KeyPair Segments:')
    for i in range(0,nseg):
        (seg_l,seg_data) = read_lv(seg_pos)
        (cpu_type,cpu_subtype) = struct.unpack('>II',seg_data[0:8])
        sha1_hash = seg_data[8:28]
        (npages,) = struct.unpack('>I',seg_data[28:32])
        print(f'\tSegment {hex(i)}: {cpu_type_to_str(cpu_type,cpu_subtype)}, Keys: {hex(npages)}/4k, sha1sum = {sha1_hash.hex()}')
        seg_pos = seg_pos[seg_l+4:]
    
    print()

    pos = pos[length + 4:]
    (length,seg_data) = read_lv(pos);
    print('Fairplay ',end='')
    cert = crypto.load_certificate(crypto.FILETYPE_ASN1,seg_data)
    subject = cert.get_subject()
    issuer = cert.get_issuer()
    pub_key = cert.get_pubkey()

    dumps = crypto.dump_certificate(crypto.FILETYPE_TEXT,cert)
    print(dumps.decode())


    pos = pos[length + 4:]
    (length,seg_data) = read_lv(pos);
    print('RSA Signature:',seg_data.hex())


if __name__ == '__main__':
    import sys
    if len(sys.argv) <= 1:
        print(f'usage: {sys.argv[0]} /path/to/xxx.supf')
        sys.exit(1)
    else:
        dump_supf(sys.argv[1])