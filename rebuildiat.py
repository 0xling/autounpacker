#encoding:utf-8
__author__ = 'ling'

import pefile
from zio import l32
from zio import l16
from iatconf import *
from addrconvert import *
from config import *

def log(msg):
    if enable_log_flag:
        print('Rebuild Iat>'+msg)

def build_import_descriptor(original_first_thunk, name, first_thunk):
    time_date_stamp = 0 #可以忽略
    forwarder_chain = 0 #一般为0

    import_descriptor = l32(original_first_thunk) + l32(time_date_stamp) + l32(forwarder_chain)
    import_descriptor += l32(name) + l32(first_thunk)

    return import_descriptor

def build_import_by_name(name):
    hint = 0
    import_by_name = l16(hint)+name
    return import_by_name


def set_iat_data(data, index, value):
    if (index + len(value)) > 0x1000:
        log('iat index too big:'+hex(index+len(value)))
        return
    data = data[0:index] + value + data[index + len(value):]
    return data

def set_align(pointer):
    if pointer&1:
        return pointer+1
    else:
        return pointer

def set_iat_name(data, name, name_pointer):
    name += '\x00'
    data = set_iat_data(data, name_pointer, name)
    name_pointer += len(name)
    name_pointer = set_align(name_pointer)
    return (data, name_pointer)

def add_a_dll(dll_name, thunk_data_pointer, name_pointer, func_list, data, iat_rva):
    thunk_data = ""
    for func in func_list:
        if not func.startswith('#'):
            func_name = build_import_by_name(func)
            thunk_data += l32(iat_rva + name_pointer)
            (data, name_pointer) = set_iat_name(data, func_name, name_pointer)
        else:
            index = int(func.strip('#'), 10)
            thunk_data += l32(0x80000000+index)
    thunk_data += l32(0)
    data = set_iat_data(data, thunk_data_pointer, thunk_data)
    return (data, name_pointer, thunk_data)

def modify_a_dll_iat_first_thunk(in_data, base_address, thunk_data, section_info):
    offset = rva2offset(base_address, section_info)
    in_data = in_data[0:offset]+thunk_data+in_data[offset+len(thunk_data):]
    return in_data
    
def modify_iat_data_directory(in_data, iat_rva, number_of_dll):
    #dos_header_pointer = 0
    nt_header_pointer = l32(in_data[0x3c:0x40])
    data_directory_pointer = nt_header_pointer + 0x78
    iat_pointer = data_directory_pointer + 8
    iat_size = 0x14*(number_of_dll + 1)
    in_data = in_data[0:iat_pointer]+ l32(iat_rva)+l32(iat_size)+in_data[iat_pointer+8:]
    return in_data

def rebuild_iat(infile, outfile, conffile, iat_rva):
    log('enter rebuild_iat:'+hex(iat_rva))
    f = open(infile, 'rb')
    in_data = f.read()
    f.close()

    section_info = generate_section_info_from_data(in_data)

    iat_info_dict = parse_conf(conffile)
    log('lib_num:'+hex(len(iat_info_dict.keys())))

    #remove old iat section, just for test
    #in_data = in_data[0:0x34000]+'\x00'*0x1000+in_data[0x35000:]

    size_import_descriptor = 0x14
    number_of_dll = len(iat_info_dict.keys())
    thunk_data_pointer = size_import_descriptor * (number_of_dll + 1)
    name_pointer = 0

    dll_index = 0
    iat_data = '\x00'*0x1000

    for key in iat_info_dict.keys():
        func_list = iat_info_dict[key][0]
        base_addr = iat_info_dict[key][1]

        if name_pointer != 0:
            thunk_data_pointer = name_pointer

        name_pointer = thunk_data_pointer + (len(func_list)+1)*4

        desc = build_import_descriptor(thunk_data_pointer + iat_rva, \
                                       name_pointer + iat_rva, base_addr)

        (iat_data, name_pointer) = set_iat_name(iat_data, key, name_pointer)
        iat_data = set_iat_data(iat_data, dll_index*size_import_descriptor, desc)
        (iat_data, name_pointer, thunk_data) = add_a_dll(key, thunk_data_pointer, name_pointer, func_list, iat_data, iat_rva)

        in_data = modify_a_dll_iat_first_thunk(in_data, base_addr, thunk_data, section_info)

        dll_index += 1

    #add iat_data to in_data
    iat_offset = rva2offset(iat_rva, section_info)
    in_data = in_data[0:iat_offset] + iat_data + in_data[iat_offset+0x1000:]

    #modify data directory's iat
    in_data = modify_iat_data_directory(in_data, iat_rva, number_of_dll)

    f = open(outfile, 'wb')
    f.write(in_data)
    f.close()
    log('iat_rebuild done')

#rebuild_iat('dump3.exe', 'dump6.exe','./iat.conf', 0x38000)