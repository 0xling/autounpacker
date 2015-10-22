#encoding:utf-8
__author__ = 'ling'

from pydbg import *
from zio import l32
from config import *
from eat_op import *

def log(msg):
    if enable_log_flag:
        print("IAT CONF> " + msg)

def parse_conf(conffile):
    iat_info = {}
    dll_name = ''
    base_addr = 0
    func = []

    f = open(conffile, 'rb')
    for line in f:
        if line.startswith('['):
            if dll_name != "":
                iat_info[dll_name] = (func, base_addr)
            dll_name = line.strip('\n').strip('[').strip(']')
            func = []
            base_addr = 0
        else:
            if base_addr == 0:
                base_addr = int(line.split(' ')[0], 16)
            if '.dll' in line:
                func.append(line.split(' ')[1].split('.dll.')[1].strip('\n'))
            else:
                func.append(line.split(' ')[1].split('.DLL.')[1].strip('\n'))

    if (func != []) & (dll_name != "") & (base_addr != 0):
        iat_info[dll_name] = (func, base_addr)

    return iat_info

def in_range(value, start, size):
    if (value >= start) & (value < (start+size)):
        return True
    return False


def get_module(fun_addr, modules):
    #log('get_module:'+hex(fun_addr))
    for module in modules:
        if not (module[0].endswith('.dll') | module[0].endswith('.DLL')):
            continue
        if in_range(fun_addr, module[1], module[2]):
            return module
    return None


def print_module_info(modules):
    for module in modules:
        log(module[0] + ':' + hex(module[1]) + ':' + hex(module[2]))


def generate_conf(dbg, conffile, base, iat_addr, iat_size):
    log("enter generateconf:"+hex(iat_addr)+':'+hex(iat_size))
    f = open(conffile, 'wb')

    iat_mem = dbg.read_process_memory(base + iat_addr, iat_size)

    modules = dbg.enumerate_modules()
    #print_module_info(modules)

    cur_module = None
    export_info = {}

    for i in range(iat_size/4):
        fun_addr = l32(iat_mem[i*4:i*4+4])
        #log('fun_addr:%08x' %fun_addr)
        if fun_addr == 0:
            cur_module = None
            continue
        if cur_module is None:
            cur_module = get_module(fun_addr, modules)
            if cur_module == None:
                continue
            export_info = generate_export_info(cur_module[3])
            f.write('['+cur_module[0]+']\n')

        temp_module = get_module(fun_addr, modules)

        if temp_module == None:
            cur_module = None
        if get_module(fun_addr, modules)[1] == cur_module[1]:
            fun_name = get_fun_name(fun_addr-cur_module[1], export_info)
            f.write(hex(iat_addr+i*4)+' '+cur_module[0]+'.'+fun_name+'\n')
        else:
            cur_module = temp_module
            export_info = generate_export_info(cur_module[3])
            f.write('['+cur_module[0]+']\n')
            fun_name = get_fun_name(fun_addr-cur_module[1], export_info)
            f.write(hex(iat_addr+i*4)+' '+cur_module[0]+'.'+fun_name+'\n')

    f.close()


