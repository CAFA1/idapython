import os
import subprocess
import r2pipe
import sys
#return file name
work_dir='/mnt/hgfs/test1/'

#return file name
def get_file_name_strings(file_dir):
    #system
    string_interesting='"evil|system|read|recv|popen|hack|exec|setuid|http|send|write|passwd|yum.repos.d"'
    file_elf=[]
    i=0
    for root,dirs,files in os.walk(file_dir):
        for file in files:
            this_file=os.path.join(root,file)
            out_bytes=subprocess.check_output(['file',os.path.join(root,file)])
            
            if(out_bytes.find('ELF')!=-1 and out_bytes.find('LSB relocatable')==-1):
                try:
                    #print 'file output:\n'+out_bytes
                    out_bytes1=subprocess.check_output('strings '+os.path.join(root,file)+' |egrep -n'+string_interesting,shell=True)
                    print 'string output:\n '+out_bytes1
                    if(out_bytes1!=''):
                        good=''
                        if(out_bytes1.find('evil')!=-1 or out_bytes1.find('passwd')!=-1 or out_bytes1.find('yum.repos.d')!=-1):
                            good='good!!!'
                        print 'find file : '+this_file+' !!!!!!' + ' '+str(i)+' '+good
                        file_elf.append(this_file)
                        i=i+1
                except:
                    pass
    return file_elf
#return the file name which has the func
def get_func_elf(file_name_list,func_name):
    file_elf_func=[]
    for file_tmp in file_name_list:
        r2 = r2pipe.open(file_tmp)
        #axt find reference
        read_str = r2.cmd("aaa;afl |grep "+func_name)
        print read_str
        if(read_str!=''):
            file_elf_func.append(file_tmp)
            print file_tmp
    return file_elf_func

def cp_test_dir(file_name_path,p_dir_str):
    global work_dir
    file_base_name=os.path.basename(file_name_path)   
    mnt_dir=work_dir+'test_dir/'+p_dir_str+'/'
    mnt_file_name=mnt_dir+file_base_name
    try:
        os.makedirs(mnt_dir,0777)
    except:
        print 'dir already exists.'
    cp_cmd='cp '+file_name_path+' '+mnt_dir
    print cp_cmd
    os.system(cp_cmd)
    print 'windows cmd:\npython test.py D:\\source\\test1\\test_dir\\'+p_dir_str+'\\'+file_base_name+'\n'


if __name__ == '__main__':
    #main()
    work_dir='/mnt/hgfs/test1/'
    if(len(sys.argv)!=2):
        print "python .py dir"
        exit()
    dir1= sys.argv[1]
    dir2=work_dir+dir1
    #string1 = sys.argv[2]
    files_name=get_file_name_strings(dir2)

    if(len(files_name)):
        for i in range(len(files_name)):
            print i,files_name[i]
        optinstr='which file do you want to test[0-'+str(len(files_name)-1)+']: '
        input_file_int = input(optinstr)
        test_file=files_name[input_file_int]
        cp_test_dir(test_file,dir1)
    else:
        print 'no file'
    
    print 'ok'