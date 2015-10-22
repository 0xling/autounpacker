#encoding:utf-8
__author__ = 'ling'

from pydbg import *
from pydbg.defines import *
from dumppe import *
from module_op import *
from addsection import *
from rebuildiat import *
from modifyoep import *

dbg = pydbg()
target = './unpackme3.exe'


main_module_base = 0x400000
oep = 0x1700
iat_rva = 0x2000
iat_size = 0x1e4

def reach_oep(dbg):
    global oep
    print 'reach oep:'+ hex(dbg.context.Eip)


    (base, size) = get_main_module(dbg)
    print 'main_module:'+hex(base)+','+hex(size)

    for i in range(0xc):
        mbi = dbg.virtual_query(base+i*0x1000)
        print hex(base+i*0x1000), hex(mbi.Protect), hex(mbi.RegionSize)


    dumpfile = 'dump2.exe'
    dumppe(dumpfile, dbg, base, size)

    new_rva = add_section(dumpfile, 'dump2_2.exe')
    generate_conf(dbg, 'iat.conf', base, iat_rva, iat_size)

    rebuild_iat('dump2_2.exe', 'dump2_3.exe', 'iat.conf', new_rva)

    modify_oep('dump2_3.exe', 'dump2_4.exe', oep)
    print 'dump and fix done'
    #dbg.detach()

    #dbg.detach()


count = 0
esp_addr = 0

def single_step(dbg):
    global esp_addr
    dbg.single_step(False)
    dbg.bp_set_hw(esp_addr, 4, HW_ACCESS, restore=True, handler=reach_esp_balance)
    return DBG_CONTINUE


def reach_esp_balance(dbg):
    global count
    global esp_addr

    count += 1
    print 'reach_esp_balance:'+hex(count)+':'+hex(dbg.context.Eip)

    if count == 3:
        dbg.bp_del_hw(esp_addr)
        #dbg.bp_set_hw(0x401700,1, HW_EXECUTE, handler=reach_oep)
        dbg.bp_set(0x401700, handler=reach_oep)
        return DBG_CONTINUE
    else:
        print 'del_hw_bp:'+hex(esp_addr)
        #dbg.dbg_print_all_debug_registers()
        dbg.bp_del_hw(esp_addr)

    dbg.single_step(True)
    dbg.set_callback(EXCEPTION_SINGLE_STEP, single_step)
    return DBG_CONTINUE

'''
def test(dbg):
    print 'enter test'
    return DBG_CONTINUE
'''

def enter_esp_balance(dbg):
    global esp_addr

    print 'enter_esp balance'
    esp_addr = dbg.context.Esp
    print hex(esp_addr)

    dbg.bp_set_hw(dbg.context.Esp, 4, HW_ACCESS, handler=reach_esp_balance)
    #dbg.dbg_print_all_debug_registers()
    return DBG_CONTINUE

def entry_point(dbg):
    print 'entry_point'
    dbg.bp_del(0x4087a2)
    dbg.bp_set(0x4087a4, handler=enter_esp_balance)
    #dbg.bp_set(0x40c605, handler=test)
    return DBG_CONTINUE

dbg.load(target, create_new_console = True)

#dbg.enable_log()
dbg.bp_set(0x4087a2, handler=entry_point)


dbg.run()


