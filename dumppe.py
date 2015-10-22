#encoding:utf-8
__author__ = 'ling'

from zio import l32
from zio import l16
from pydbg import *
from pydbg.defines import *
import pefile
from addrconvert import *
from config import *

dumpfile = './dump.bin'

def log(msg):
    if enable_log_flag:
        print('dump pe>'+msg)


def fix_pe_section(data):
    log('fix_pe_section')
    def set_data(data, index, value):
        return data[0:index]+value+data[index+len(value):]
    nt_header_pointer = l32(data[0x3c:0x40])
    size_of_optional_header_pointer = nt_header_pointer + 0x14
    section_pointer = nt_header_pointer+0x18+l16(data[size_of_optional_header_pointer:size_of_optional_header_pointer+2])
    number_of_section_pointer = nt_header_pointer + 6
    number_of_section = l16(data[number_of_section_pointer:number_of_section_pointer+2])

    for i in range(number_of_section):
        rva_size = l32(data[section_pointer+i*0x28+8:section_pointer+i*0x28+0xc])
        rva = l32(data[section_pointer+i*0x28+0xc:section_pointer+i*0x28+0x10])
        file_size = l32(data[section_pointer+i*0x28+0x10:section_pointer+i*0x28+0x14])
        file_offset = l32(data[section_pointer+i*0x28+0x14:section_pointer+i*0x28+0x18])
        if file_size < rva_size: #.bss ?? to do
            #print 'fix file_size:'+hex(rva_size)
            data = set_data(data, section_pointer+i*0x28+0x10, l32(rva_size))
    return data

def fix_pe(mem, dumpfile):
    log('fix pe')
    section_info = generate_section_info_from_data(mem)

    data = mem[0:0x1000]

    for section in section_info:
        va_size = section[0]
        va = section[1]
        file_size = section[2]
        file_offset = section[3]

        if (file_offset + file_size) < len(data):
            data = data.ljust(file_offset+file_size, '\x00')
        data = data[0:file_offset]+mem[va:va+file_size]

    f = open(dumpfile, 'wb')
    f.write(data)
    f.close()

def build_a_section(name, size, offset, characteristics):
    log('build_a_section:'+hex(size)+':'+hex(offset)+":"+hex(characteristics))
    name = name.ljust(8, '\x00')
    new_section = name + l32(size) + l32(offset) + l32(size)
    new_section += l32(offset) + l32(0) + l32(0)
    new_section += l16(0) + l16(0) + l32(characteristics)
    return new_section

def rebuild_section(data, map_info):
    def set_data(data, index, value):
        return data[0:index]+value+data[index+len(value):]
    nt_header_pointer = l32(data[0x3c:0x40])
    size_of_optional_header_pointer = nt_header_pointer + 0x14
    section_pointer = nt_header_pointer+0x18+l16(data[size_of_optional_header_pointer:size_of_optional_header_pointer+2])
    number_of_section_pointer = nt_header_pointer + 6

    data = set_data(data, number_of_section_pointer, l32(len(map_info)))

    index = 0
    for map in map_info:
        offset = map[0]
        size = map[1]
        character = map[2]
        #log('offset='+hex(offset)+';size='+hex(size)+';character='+hex(character))
        name = str(index)
        section = build_a_section(name, size, offset, character)
        data = set_data(data, section_pointer+0x28*index, section)
        index += 1

    return data

#code: read_executable character:0x60000020 mbi.protect:
#code&data: read_write_executable character: 0xf00000060
#data: read_write character:0xc00000040
def protect2character(protect):
    if (protect&PAGE_READONLY)|(protect&PAGE_WRITECOPY)|(protect&PAGE_READWRITE):
        return 0xc0000040
    elif protect&PAGE_EXECUTE_READ:
        return 0x60000020
    elif (protect&PAGE_EXECUTE_READWRITE) | (protect&PAGE_EXECUTE_WRITECOPY):
        return 0xf0000060
    else:
        log('not known protect:'+hex(protect))
        return 0


def dumppe(dumpfile, dbg, base, size):
    log('dumppe:'+dumpfile+':'+hex(base)+':'+hex(size))

    mem = dbg.read_process_memory(base, size)

    total_size = 0x1000

    memory_map_info = []
    while total_size < size:
        mbi = dbg.virtual_query(base+total_size)
        character = protect2character(mbi.Protect)
        memory_map_info.append((total_size, mbi.RegionSize, character))
        total_size += mbi.RegionSize

    map_info = []
    old_chracter = -1
    old_offset = 0
    old_size = 0

    for memory_map in memory_map_info:
        if old_chracter == -1:
            old_character = memory_map[2]
            old_offset = memory_map[0]
            old_size = memory_map[1]
            continue

        if memory_map[2] == old_character:
            if (old_offset + old_size) == memory_map[0]:
                old_size += memory_map[2]
                continue

        map_info.append((old_offset, old_size, old_character))
        old_character = memory_map[2]
        old_offset = memory_map[0]
        old_size = memory_map[1]

    map_info.append((old_offset, old_size, old_character))

    #print map_info
    mem = rebuild_section(mem, map_info)
    fix_pe(mem, dumpfile)
