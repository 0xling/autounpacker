from pydbg import *
from pydbg.defines import *
from dumppe import *
from module_op import *
from addsection import *
from rebuildiat import *
from modifyoep import *

dbg = pydbg()
target = './unpackme2.exe'


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
	

def code_access(dbg):
    print 'code_access:'+hex(dbg.context.Eip)
    dbg.bp_del_mem(0x401000)
    dbg.bp_set_hw(main_module_base+oep, 1, HW_EXECUTE, handler=reach_oep)
    return DBG_CONTINUE

def data_access(dbg):
    print 'data_access:'+hex(dbg.context.Eip)
    dbg.bp_del_mem(0x408000)
    dbg.bp_set_mem(0x401000, 0x7000-1, description='text', handler=code_access)
    return DBG_CONTINUE


def iat_access(dbg):
    print 'iat_access:'+hex(dbg.context.Eip)
    dbg.bp_del_mem(0x40b000)
    dbg.bp_set_mem(0x408000, 0x3000-1, description='sfx', handler=data_access)
    return DBG_CONTINUE

def entry_point(dbg):
	dbg.bp_del(0x40955c)
	dbg.bp_set_mem(0x40b000, 0x1000-1, description='iat', handler=iat_access)
	return DBG_CONTINUE
	
dbg.load(target, create_new_console = True)

dbg.bp_set(0x40955c, handler=entry_point)


dbg.run()

