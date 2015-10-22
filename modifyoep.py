#encoding:utf-8
__author__ = 'ling'

from zio import l32

def modify_oep(infile, outfile, oep):
    f = open(infile, 'rb')
    data = f.read()
    f.close()

    nt_header_pointer = l32(data[0x3c:0x40])
    address_of_entry_point_pointer = nt_header_pointer + 0x28

    data = data[0:address_of_entry_point_pointer]+l32(oep)+data[address_of_entry_point_pointer+4:]

    f = open(outfile, 'wb')
    f.write(data)
    f.close()

