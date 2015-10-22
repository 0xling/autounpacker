from pydbg import *
from pydbg.defines import *
from dumppe import *
from module_op import *
from addsection import *
from rebuildiat import *
from modifyoep import *
from zio import HEX

dbg = pydbg()
target = './unpackme4.exe'


main_module_base = 0x400000
oep = 0x1700
iat_rva = 0x2000
iat_size = 0x1e4

def reach_oep(dbg):
    global oep
    dbg.dbg_print_all_debug_registers()
    print 'reach oep:'+ hex(dbg.context.Eip)

    (base, size) = get_main_module(dbg)
    print 'main_module:'+hex(base)+','+hex(size)
	
    dumpfile = 'dump2.exe'
    dumppe(dumpfile, dbg, base, size)

    new_rva = add_section(dumpfile, 'dump2_2.exe')
    #generate_conf(dbg, 'iat.conf', base, iat_rva, iat_size)

    rebuild_iat('dump2_2.exe', 'dump2_3.exe', 'iat.conf', new_rva)

    modify_oep('dump2_3.exe', 'dump2_4.exe', oep)
    print 'dump and fix done'
    dbg.detach()
    
    #dbg.detach()
	

def code_access(dbg):
    print 'code_access:'+hex(dbg.context.Eip)
    dbg.bp_del_mem(0x401000)
    dbg.bp_set_hw(main_module_base+oep, 1, HW_EXECUTE, handler=reach_oep)
    return DBG_CONTINUE

def rsrc_access(dbg):
    print 'data_access:'+hex(dbg.context.Eip)
    print hex(dbg.context.Eax)
    print HEX(dbg.read_process_memory(dbg.context.Eip, 5))
    dbg.bp_del_mem(0x404000)
    dbg.bp_set_mem(0x401000, 0x1000-1, description='text', handler=code_access)
    dbg.dbg_print_all_debug_registers()
    return DBG_CONTINUE

	
def entry_point(dbg):
    dbg.bp_del(0x401000)
    dbg.bp_set_mem(0x404000, 0x3000-1, description='rsrc', handler=rsrc_access)
    #dbg.bp_set_hw(0x40976b, 1, HW_EXECUTE, handler=test)
    #dbg.bp_set_hw(0x4098f9, 1, HW_EXECUTE, handler=test)
    return DBG_CONTINUE
	
dbg.load(target, create_new_console = True)

dbg.bp_set(0x401000, handler=entry_point)


dbg.run()

