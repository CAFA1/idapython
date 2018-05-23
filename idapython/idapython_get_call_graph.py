from idaapi import *
from idautils import *
import os
import re
import idc
import time
import ida_hexrays
def save_call_graph():
	cur = idc.MinEA()
	end = idc.MaxEA()
	#D:\source\test1\test_dir\p_16
	#path_dir=os.path.dirname(idc.GetIdbPath())
	#p_dir=path_dir.split('\\')[-1]
	#elf_name=os.path.basename(idc.GetIdbPath()).split('.')[-2]
	i64_file=idc.GetIdbPath()
	first_dot=i64_file.find('.')
	no_dot_file=i64_file[:first_dot]
	gdl_path = no_dot_file+'.gdl'
	idc.GenCallGdl(gdl_path, 'Call Gdl', idc.CHART_GEN_GDL)
	#idc.Message('Gdl file has been saved to {}\n'.format(path))				
def save_function_name_addr():
	#D:\source\test1\test_dir\p_16
	#.i64
	i64_file=idc.GetIdbPath()
	first_dot=i64_file.find('.')
	no_dot_file=i64_file[:first_dot]
	funcs_path = no_dot_file+'.funcs'
	#funcs_path = idc.GetIdbPath()[:-4]+'.funcs'
	myfile=open(funcs_path,'w')
	ea = BeginEA()
	for funcea in Functions(SegStart(ea), SegEnd(ea)):
	    functionName = GetFunctionName(funcea)
	    myfile.write(hex(funcea)+' '+functionName+'\n')
	    #print hex(funcea),functionName
	myfile.close()
idc.Wait()
save_call_graph()
save_function_name_addr()
idc.Exit(0)
print 'okkkk'



