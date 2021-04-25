#! /usr/bin/env python3

from typing import Tuple
import struct

def read_ltv(buff : bytes) -> Tuple[int,str,bytes]:
    assert(len(buff) >= 8)
    (l,t) = struct.unpack('>I4s',buff[0:8])
    #print(f'seg_size = {hex(l)}')
    assert(l <= len(buff))

    return (l,t.decode(),buff[8:l])

def read_kv(buff : bytes) -> Tuple[str,bytes]:
    assert(len(buff) >= 8)
    (key,) = struct.unpack('>4s',buff[0:4])
    return (key.decode(),buff[4:8]) 

def dump_sinf(filename : str):
    # open and read file
    f = open(filename,'rb')
    buff : bytes = f.read()
    f.close()

    sinf = {}

    pos = 0
    (length,magic,_) = read_ltv(buff[pos:])
    assert(magic == 'sinf')
    pos += 8

    # iterate elements of sinf
    while pos < len(buff):
        (length,magic,data) = read_ltv(buff[pos:])
        sinf[magic] = data
        pos += length

    print('sinf.frma:',sinf['frma'].decode())
    
    assert(sinf['schm'] == b'\x00\x00\x00\x00itun\x00\x00\x00\x00')
    print('sinf.schm: itun')

    schi = {}
    schi_data = sinf['schi']
    pos = 0
    # iterate elements of sinf.schi
    while pos < len(schi_data):
        (length,magic,data) = read_ltv(schi_data[pos:])
        schi[magic] = data
        pos += length

    pos = 0
    righ = {}
    # dump sinf.schi
    for k in schi:
        if k == 'righ':
            # iterate sinf.schi.righ
            righ_data = schi['righ']
            while pos < len(righ_data):
                (kname,val)  = read_kv(righ_data[pos:pos+8])
                pos+=8
                righ[kname] = val

            for rk in righ:
                if rk == 'tool':
                    print(f'sinf.schi.righ.{rk}:', righ[rk].decode())
                else:
                    print(f'sinf.schi.righ.{rk}:', '0x' + righ[rk].hex())
        elif k == 'name':
            print('sinf.schi.name:',schi[k].split(b'\x00')[0].decode())
        elif k == 'priv':
            print('sinf.schi.priv:',schi[k][:-8].hex())
        else:
            print(f'sinf.schi.{k}:', '0x' + schi[k].hex())

    # dump sign
    print('sinf.sign:',sinf['sign'].hex())


if __name__ == '__main__':
    import sys
    if len(sys.argv) <= 1:
        print(f'usage: {sys.argv[0]} /path/to/xxx.sinf')
        sys.exit(1)
    else:
        dump_sinf(sys.argv[1])