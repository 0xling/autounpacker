from pydbg import *
from pydbg.defines import *
from dumppe import *
from module_op import *
from addsection import *
from rebuildiat import *
from modifyoep import *

dbg = pydbg()
target = './unpackme1.exe'

esp_addr = 0

main_module_base = 0x3f0000
oep = 0x11700
iat_rva = 0x12000
iat_size = 0x1e4

def reach_oep(dbg):
    global oep
    print 'reach oep:'+ hex(dbg.context.Eip)

    (base, size) = get_main_module(dbg)
    #print hex(base)

    dumpfile = 'dump2.exe'
    dumppe(dumpfile, dbg, base, size)

    new_rva = add_section(dumpfile, 'dump2_2.exe')
    #generate_conf(dbg, 'iat.conf', base, iat_rva, iat_size)

    rebuild_iat('dump2_2.exe', 'dump2_3.exe', 'iat.conf', new_rva)

    modify_oep('dump2_3.exe', 'dump2_4.exe', oep)
    print 'dump and fix done'
    #dbg.detach()

def reach_esp_balance(dbg):
    print 'reach esp balance'
    global esp_addr, oep, main_module_base
    dbg.bp_del_hw(esp_addr)
    dbg.bp_set_hw(main_module_base+oep, 1, HW_EXECUTE, handler=reach_oep)
    #print dbg.dbg_print_all_debug_registers()
    return DBG_CONTINUE

'''
def test(dbg):
    print 'enter test'
    #print dbg.context.Esp
    print repr(dbg.read_process_memory(0x401700, 1))
    dbg.dbg_print_all_debug_registers()
    return DBG_CONTINUE
'''

def esp_balance(dbg):
    print 'esp balance'
    global esp_addr
    dbg.bp_del(0x3f159f)
    esp_addr = dbg.context.Esp
    print hex(esp_addr)
    dbg.bp_set_hw(esp_addr, 4, HW_ACCESS, handler = reach_esp_balance)
    #dbg.bp_set_hw(0x3ffce4, 4, HW_EXECUTE, handler = test)
    #dbg.bp_set_hw(0x401700, 4, HW_ACCESS, handler = test)
    #dbg.dbg_print_all_debug_registers()
    return DBG_CONTINUE

dbg.load(target, create_new_console = True)

#dbg.enable_log()
dbg.bp_set(0x3f159f, handler=esp_balance)
dbg.run()

