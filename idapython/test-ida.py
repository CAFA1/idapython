from idaapi import *
from idautils import *
import re
import idc
import time
import ida_hexrays

	addrs=get_all_addr('D:\\source\\test1\\addrs\\'+file_name+'.recv')
	funcs=[]
	for addr in addrs:
		f = get_func_name(addr)
		if(f is not None and f  not in funcs):
			flag_out=0
			mylog.write('start recv_shellcode analysis func: '+f)
			print 'start recv_shellcode analysis func: '+f,
			funcs.append(f)
			c_lines=decompile_func(addr)
			lines_num=len(c_lines)
			#all_lines='\n'.join(c_lines)
			if(c_lines==''):
				print 'decompile_func error'
			else:
				recv_lines=[]
				taint_values=[]
				#1. find recv value
				for i in range(lines_num):
					if(flag_out):
						break
					#if ( recv(v19, _5924fc070d840801bdbed7cbbbc52f3e, 0x7D0uLL, 0) < 0 )
					regex=re.search('recv\((.*), (?P<src>(.*)), (.*), .*\)',c_lines[i])
					if regex:
						recv_value=regex.group('src')
						recv_lines.append((i,recv_value))
						taint_values.append(recv_value)
						#print recv_value
				#2. find taint value from =
				for (tmp_i,tmp_recv_value) in recv_lines:
					for i in range(tmp_i,lines_num):
						#*v28 = _5924fc070d840801bdbed7cbbbc52f3e[0];
						#v30 = _5924fc070d840801bdbed7cbbbc52f3e;
						regex_recv=re.search('(?P<src>(.*)) = '+tmp_recv_value+'.*;',c_lines[i])
						if regex_recv:
							taint_value=regex_recv.group('src').strip(' ').strip('*')
							taint_values.append(taint_value)
				#2.1 find taint value from strcpy
				for (tmp_i,tmp_recv_value) in recv_lines:
					for i in range(tmp_i,lines_num):
						#*v28 = _5924fc070d840801bdbed7cbbbc52f3e[0];
						#v30 = _5924fc070d840801bdbed7cbbbc52f3e;
						regex_recv=re.search('(?P<src>(.*)) = '+tmp_recv_value+'.*;',c_lines[i])
						if regex_recv:
							taint_value=regex_recv.group('src').strip(' ').strip('*')
							taint_values.append(taint_value)
				#3. find call shellcode
				for taint_value1 in taint_values:
					if(flag_out==1):
						break
					#print taint_value1
					for (tmp_i,tmp_recv_value) in recv_lines:
						if(flag_out==1):
							break
						for i in range(tmp_i,lines_num):
							#((void (__fastcall *)(_DWORD *, char *, signed __int64, signed __int64))v28)(v34, v35, v31, v33);
							regex_recv1=re.search('call \*\).*'+taint_value1+'.*;',c_lines[i])
							if regex_recv1:
								mylog.write(',yes\n')
								print ',yes'
								flag_out=1
								break
			if(flag_out==0):
				mylog.write(',no\n')
				print ',no'
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



