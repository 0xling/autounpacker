#encoding:utf-8
__author__ = 'ling'
from zio import l32
from zio import l16
from config import *

def log(msg):
    if enable_log_flag:
        print('ADDR CONVERT>'+msg)

def generate_section_info_from_data(data):
    nt_header_pointer = l32(data[0x3c:0x40])
    size_of_optional_header_pointer = nt_header_pointer + 0x14
    section_pointer = nt_header_pointer+0x18+l16(data[size_of_optional_header_pointer:size_of_optional_header_pointer+2])
    number_of_section_pointer = nt_header_pointer + 6
    number_of_section = l16(data[number_of_section_pointer:number_of_section_pointer+2])
    section_infos = parse_section(data, section_pointer, number_of_section)
    return section_infos

def generate_section_info_from_file(pefile):
    f = open(pefile, 'rb')
    d = f.read()
    f.close()
    return generate_section_info_from_data(d)

def parse_section(data, section_pointer, number_of_section):
    log('parse section:'+hex(section_pointer)+':'+hex(number_of_section))
    section_infos = []
    for i in range(number_of_section):
        rva_size = l32(data[section_pointer+i*0x28+8:section_pointer+i*0x28+0xc])
        rva = l32(data[section_pointer+i*0x28+0xc:section_pointer+i*0x28+0x10])
        file_size = l32(data[section_pointer+i*0x28+0x10:section_pointer+i*0x28+0x14])
        file_offset = l32(data[section_pointer+i*0x28+0x14:section_pointer+i*0x28+0x18])
        section_infos.append((rva_size,  rva, file_size, file_offset))
    return section_infos

def in_range(value, start, size):
    if (value >= start) & (value < (start+size)):
        return True
    return False

def rva2offset(rva, section_infos):
    #log('rva2offset:'+hex(rva))
    for section in section_infos:
        va_size = section[0]
        va = section[1]
        file_size = section[2]
        file_offset = section[3]

        if in_range(rva, va, va_size):
            if (rva - va) > file_size:
                log('rva is in .bss section:%08x' %rva)
            else:
                return file_offset + rva - va

    log('rva not find offset :%08x' %rva)



def offset2rva(offset, section_infos):
    #log('offset2rva:'+hex(offset))
    for section in section_infos:
        va_size = section[0]
        va = section[1]
        file_size = section[2]
        file_offset = section[3]

        if in_range(offset, file_offset, file_size):
            return va + offset - file_offset

    log('offset not find rva:%08x' %offset)
