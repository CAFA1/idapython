from idaapi import *
from idautils import *
import re
import idc
import time
import ida_hexrays
def save_call_graph():
	cur = idc.MinEA()
	end = idc.MaxEA()
	path = idc.GetIdbPath().rsplit('.')[0] + '.gdl'
	idc.GenCallGdl(path, 'Call Gdl', idc.CHART_GEN_GDL)
	idc.Message('Gdl file has been saved to {}\n'.format(path))				

idc.Wait()
save_call_graph()
idc.Exit(0)
print 'okkkk'



