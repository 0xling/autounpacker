#encoding:utf-8
__author__ = 'ling'

import pefile
from addrconvert import *
from config import *

def log(msg):
    if enable_log_flag:
        print("EAT OP> " + msg)

def get_eat_data_directory(in_data):
    nt_header_pointer = l32(in_data[0x3c:0x40])
    data_directory_pointer = nt_header_pointer + 0x78
    eat_pointer = data_directory_pointer

    eat_rva = l32(in_data[eat_pointer:eat_pointer+4])
    eat_size = l32(in_data[eat_pointer+4:eat_pointer+8])

    return (eat_rva, eat_size)

def get_str(in_data, offset):
    name = in_data[offset:].split('\x00')[0]
    return name

def generate_export_info(dll_file):
    f = open(dll_file, 'rb')
    in_data = f.read()
    f.close()

    log('generate_export_info:'+dll_file)

    export_info = {}

    export_info_by_index = {}

    (eat_rva, eat_size) = get_eat_data_directory(in_data)
    section_infos = generate_section_info_from_data(in_data)
    eat_offset = rva2offset(eat_rva, section_infos)

    base_index = l32(in_data[eat_offset+0x10:eat_offset+0x14])

    number_of_functions = l32(in_data[eat_offset+0x14:eat_offset+0x18])
    number_of_names = l32(in_data[eat_offset+0x18:eat_offset+0x1c])

    address_of_functions_rva = l32(in_data[eat_offset+0x1c:eat_offset+0x20])
    address_of_names_rva = l32(in_data[eat_offset+0x20:eat_offset+0x24])
    address_of_name_ordinals_rva = l32(in_data[eat_offset+0x24:eat_offset+0x28])

    address_of_functions_offset = rva2offset(address_of_functions_rva, section_infos)
    address_of_names_offset = rva2offset(address_of_names_rva, section_infos)
    address_of_name_ordinals_offset = rva2offset(address_of_name_ordinals_rva, section_infos)


    '''
    for i in range(number_of_functions):
        fun_address = l32(in_data[address_of_functions_offset+i*4:address_of_functions_offset+i*4+4])
        print 'fun_address:'+hex(fun_address)
        if not export_info.has_key(fun_address):
            export_info[fun_address] = (base_index+i, '')

    for i in range(number_of_names):
        fun_name_pointer = l32(in_data[address_of_names_offset+i*4:address_of_names_offset+i*4+4])
        ordinals_index = l16(in_data[address_of_name_ordinals_offset+i*2:address_of_name_ordinals_offset+i*2+2])
        fun_name = get_str(in_data, rva2offset(fun_name_pointer, section_infos))

        for key in export_info.keys():
            if export_info[key][0] == (base_index + ordinals_index):
                if export_info[key][1] == '':
                    print fun_name
                    export_info[key] = (base_index+ordinals_index, fun_name)
                    break
    '''

    for i in range(number_of_functions):
        fun_address = l32(in_data[address_of_functions_offset+i*4:address_of_functions_offset+i*4+4])
        #print 'fun_address:'+hex(fun_address)
        if not export_info.has_key(fun_address):
            export_info_by_index[base_index+i] = (fun_address, '')

    for i in range(number_of_names):
        fun_name_pointer = l32(in_data[address_of_names_offset+i*4:address_of_names_offset+i*4+4])
        ordinals_index = l16(in_data[address_of_name_ordinals_offset+i*2:address_of_name_ordinals_offset+i*2+2])
        fun_name = get_str(in_data, rva2offset(fun_name_pointer, section_infos))

        if export_info_by_index[base_index+ordinals_index][1] == '':
            fun_address = export_info_by_index[base_index+ordinals_index][0]
            export_info_by_index[base_index+ordinals_index] = (fun_address, fun_name)

    for key in export_info_by_index.keys():
        fun_address = export_info_by_index[key][0]
        fun_name = export_info_by_index[key][1]
        export_info[fun_address]=(key, fun_name)

    return export_info

#print generate_export_info('./mfc42_32.dll')
def get_fun_name(fun_address, export_info):
    log('get_fun_name:'+hex(fun_address))
    fun_name = export_info[fun_address][1]
    if fun_name != '':
        return fun_name
    index = export_info[fun_address][0]

    return '#'+str(index)


