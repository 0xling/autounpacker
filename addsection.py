#encoding:utf-8
__author__ = 'ling'

import pefile
from zio import l32
from zio import l16
from addrconvert import *

def get_new_section_pointer(data):
    nt_header_pointer = l32(data[0x3c:0x40])
    size_of_optional_header_pointer = nt_header_pointer + 0x14
    section_pointer = nt_header_pointer+0x18+l16(data[size_of_optional_header_pointer:size_of_optional_header_pointer+2])
    number_of_section_pointer = nt_header_pointer + 6
    number_of_section = l16(data[number_of_section_pointer:number_of_section_pointer+2])
    return section_pointer + 0x28*number_of_section

def add_pe_section(infile, outfile,  name,  virtual_size, virtual_address, size_of_raw_data, pointer_to_raw_data, characteristics):
    log('add pe section:'+name+':'+hex(virtual_address)+':'+hex(pointer_to_raw_data))
    name = name.ljust(8, '\x00')
    pointer_to_relocation = 0 #在obj文件中使用，重定位的偏移
    pointer_to_line_numbers = 0 #在符号表的偏移（供调试用）
    number_of_relocations = 0 #在obj文件中使用，重定位项的数目
    number_of_line_number = 0   #行号表中行号的数目


    new_section = name + l32(virtual_size) + l32(virtual_address) + l32(size_of_raw_data)
    new_section += l32(pointer_to_raw_data) + l32(pointer_to_relocation) + l32(pointer_to_line_numbers)
    new_section += l16(number_of_relocations) + l16(number_of_line_number) + l32(characteristics)

    f = open(infile, 'rb')
    data = f.read()
    f.close()

    index = get_new_section_pointer(data)

    dos_header_pointer = 0
    dos_header_e_lfanew_offset = 0x3c
    nt_header_pointer =  l32(data[dos_header_e_lfanew_offset:dos_header_e_lfanew_offset+0x4])
    nt_header_file_header_offset = 4

    file_header_pointer = nt_header_pointer + nt_header_file_header_offset
    file_header_number_of_section_offset = 2

    number_of_section_pointer = file_header_pointer + file_header_number_of_section_offset

    size_of_image_pointer = nt_header_pointer + 0x50

    if len(data) < pointer_to_raw_data:
        data = data.ljust(pointer_to_raw_data + size_of_raw_data, '\x61')
    elif len(data) < pointer_to_raw_data + size_of_raw_data:
        data = data[0:pointer_to_raw_data].ljust(pointer_to_raw_data + size_of_raw_data, '\x61')
    else:
        data = data[0:pointer_to_raw_data] + '\x61'*size_of_raw_data + data[pointer_to_raw_data+size_of_raw_data:]


    data = data[0:index] + new_section + data[index+len(new_section):]
    #add number of sections
    #print hex(number_of_section_pointer)
    old_number_of_section = l16(data[number_of_section_pointer:number_of_section_pointer+2])
    #print hex(old_number_of_section)
    data = data[0:number_of_section_pointer] + l16(old_number_of_section+1) + data[number_of_section_pointer+2:]

    #modify sizeofimage
    new_size_of_image = virtual_address + virtual_size
    data = data[0:size_of_image_pointer] + l32(new_size_of_image) + data[size_of_image_pointer+4:]

    f = open(outfile, 'wb')
    f.write(data)
    f.close()

if __name__ == '__main__':
    infile = './dump2.exe'
    outfile = './dump3.exe'
    index = 0x298
    name = '.iat'.ljust(8, '\x00')
    virtual_size = 0x1000
    virtual_address = 0x38000
    size_of_raw_data = 0x1000
    pointer_to_raw_data = 0x37000
    characteristics = 0xc0000040
    add_pe_section(infile, outfile, index, name, virtual_size, virtual_address, size_of_raw_data, pointer_to_raw_data, characteristics)

def add_section(infile, outfile):
    log('add section:'+infile+':'+outfile)
    section_info = generate_section_info_from_file(infile)
    new_rva = 0
    new_offset = 0

    for section in section_info:
        va_size = section[0]
        va = section[1]
        file_size = section[2]
        file_offset = section[3]

        va_end = (va_size + va + 0xfff)&0xfffff000
        offset_end = (file_size + file_offset + 0xfff) & 0xfffff000

        if va_end > new_rva:
            new_rva = va_end
        if offset_end > new_offset:
            new_offset = offset_end

    log('add section:'+hex(new_rva)+':'+hex(new_offset))
    name = '.iat'.ljust(8, '\x00')
    virtual_size = 0x1000
    size_of_raw_data = 0x1000
    characteristics = 0xc0000040
    add_pe_section(infile, outfile, name, virtual_size, new_rva, size_of_raw_data, new_offset, characteristics)

    return new_rva

