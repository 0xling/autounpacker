#encoding:utf-8
__author__ = 'ling'

def enum_modules(dbg):
    return dbg.enumerate_modules()

def get_main_module(dbg):
    modules = enum_modules(dbg)
    #print modules
    for module in modules:
        if module[0].endswith('.exe'):
            return (module[1], module[2])
    return (0, 0)
