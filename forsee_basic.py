#!/usr/bin/env python
#Author: mosesjike@gatech.edu

# Minimized FORSEE because the original code was hacky af!
import subprocess, sys, os, time, copy, gc, datetime, socket, threading




if len(sys.argv) != 4:
    print "Usage: python forsee_stitch.py <malware.exe> <path_to_malware_repo> <remote_vm_ip>"
    sys.exit(0)

malware = sys.argv[1]
malware_repo = sys.argv[2]
remote_vm_ip = sys.argv[3]
if "-" in malware:
    print "please change you malware name to", malware.replace("-","_"), "windbg does not like -. Aborting .."
    sys.exit(0)



import angr, claripy, IPython, graphviz, matplotlib.pyplot
print "\n\n ==== STARTING  ===="
#global variables
workspace_folder = "/home/moses/forsee/workspace/" + malware
results_folder = "/home/moses/forsee/results/" + malware



stack_frame_no = "0"
#malware_repo = "/home/moses/forsee/forsee/from_win7/samples"
#malware_repo = "/home/moses/unzipped_samples"
malware_ran_folder = "/home/moses/forsee/workspace/malware_ran"
malware_not_ran_folder = "/home/moses/forsee/workspace/malware_not_ran"
malware_multi_threaded_folder = "/home/moses/forsee/workspace/multi_threaded"
malware_packed_folder = "/home/moses/forsee/workspace/packed"
malware_x86_folder = "/home/moses/forsee/workspace/x86"
malware_x64_folder = "/home/moses/forsee/workspace/x64"
malware_crashed_folder = "/home/moses/forsee/workspace/crashed"
malware_unknown_arch = "/home/moses/forsee/workspace/unknown_arch"
manual_triage = "/home/moses/forsee/workspace/manual_triage"
vm_ready_pool= "/home/moses/forsee/forsee/vm_ready_pool"
#path_to_malware = malware_repo + "/" + malware
if malware_repo[-1] != "/":
    malware_repo += "/"
path_to_malware = malware_repo  + malware

path_to_empty_file = workspace_folder + "/empty_file.dmp"
malware_output_file = results_folder + "/" + malware +".output.txt"
#make folders
for folder in [workspace_folder, malware_ran_folder, malware_not_ran_folder, malware_multi_threaded_folder, malware_packed_folder,malware_x86_folder, malware_x64_folder, malware_crashed_folder, malware_unknown_arch, manual_triage, vm_ready_pool]:
    subprocess.call("mkdir -p "+folder +">/dev/null 2>&1",shell=True)
if not os.path.isfile(path_to_malware):
    print "Cannot find path to sample:", path_to_malware
    subprocess.call("touch " + vm_ready_pool + "/" + remote_vm_ip, shell=True) #release the vm
    sys.exit(0)


subprocess.call("echo EMPTY > "+path_to_empty_file,shell=True)
path_to_ida_executable = "/home/moses/ida-7.0/ida64"
local_dumps_folder = workspace_folder + "/dumps"
subprocess.call("mkdir "+ local_dumps_folder +">/dev/null 2>&1",shell=True)
#remote_vm = "moses@192.168.56.101"
remote_vm = "moses@"+remote_vm_ip
path_to_remote_dumps = "/cygdrive/c/Users/moses/Documents/from_windbg/" + malware + "/dumps"
known_external_libs = ["ntdll", "kernel32", "ucrtbased"]
dot = dot_label = dot2 = dot2_label = ""
ida = ida2 = ""
#measurements#
#pe_ps_data = ""
#total_paths_seen = 1;

steping = {0:{'cond_jmps':0, 'ps':1, 'pe':1, 'all_mem_write':1, 'sym_mem_write':0, 'all_mem_read':1, 'sym_mem_read':0, 'BUI_reached_funcs': 0}} #to avoid division by zero make all_mem = 1
#the first time we will only see one path, and we will only explore one
#end of measurements#

p = regs_dict = init_state= active_states = ""
ss = backtrace = step_track =  bt_frame_track = ""
program_end_addrs = [] # I think the last three return address of the backtrack frame

BUI_prefix_len = BUI_addr_prefix = BUI_bt_ret_addr = BUI_seg_start = BUI_seg_end = call_trace_END_len = ""
BUI_bt_addrs = []  #we will keep a track of the BUI ret addresses in the backtrace. The first one and last one in the list are more important
BUI_bt_addrs_frame_no = {} # maps each BUI_bt_addrs to their frame no
bt_after_BUI_lib_func = ""

x_segs = [] #executable segments. If IP falls outside of this range, prune the path
already_hooked_addrs = [] #so I don't have to rehook, and get the warning message
merge_track = {} # indexed by step_no, then indexed by merger_path, shows all the paths that were merged
min_bt_size_attained = "" # to track the size of the backtrace call stack as it reduces, to know where we are in terms of from IP to to the botton most call frame in the backtrace
addrs_to_prune = {} #info only now. holds addrs where state is always prunned, like the VEX errror, and no sucessors
syscalls = [] #info only. holds all encountered syscalls
sigs={}
cc_seen = {}
return_now = False
flirt_enabled = False
step_history = "" #something to use to generate a run configuration after manually stepping to completion
completed_paths = []
pruned_paths = []
BUI_reached = False
symbols_dict = {}
paths_info = {}
paths_info['lib_calls'] = {}
lib_calls_seen = {}
#paths_info['cond_jmps'] = set()
BUI_total_funcs = ""
BUI_reached_funcs = set() #populated during sym exploration when a call to a BUI function is made
BUI_funcs = {}
indirect_calls = {}# holds where_they_were_called:what_they_are. i.e address_0x403874:rax
BUI_exe_lib_funcs = {} #holds lib_addr:lib_name
BUI_total_paths = BUI_total_paths_from_dump_site = BUI_intra_func_paths = BUI_inter_func_paths = BUI_intra_func_blocks = BUI_total_blocks = ""
#BUI_offset_dump_to_exe = "" # a value that hold the offset between the BUI code section in the memory dump to the BUI code in the static executable
BUI_exe_entry_point = BUI_exe_entry_func = BUI_exe_seg_start = BUI_exe_seg_end = ""
BUI_explored_blocks = set()
BUI_branches_potentially_not_taken = set()
BUI_branches_not_taken = set()
BUI_paths_not_explored_post_snapshot = ""
BUI_pre_capture_capabilities = {} #{f1:f2:[], f2:f3:[] ..} between f1:f2, what capabilities/func/libs were called
BUI_pre_capture_funcs_recovered = ""
temp_start_time = ""
thread_reported_problem = False #if thread see something wrong, they make this True and append info to thread_message
thread_message = ""
thread_crashed = {}
malware_did_not_run = False # will be set to True if after running the malware, it did not run
ONE_TO_ONE_MAPING_WORKED = False #
POSSIBLE_MALWARE_VM_HIJACK = True
sample_hash = ""
vm_released = False



#ip address to vm_name of all VMs used in this work
vm_clones = {'192.168.56.111':'win7_c1' }
if remote_vm_ip in vm_clones:
    vm_name = vm_clones[remote_vm_ip]
    print "I will be using vm:", vm_name, " on ip:", remote_vm_ip
else:
    print "Could not find remote_vm_ip:", remote_vm_ip, " in vm_clones dictionary: ", vm_clones, " Aborting.."
    subprocess.call("touch " + vm_ready_pool + "/" + remote_vm_ip, shell=True) #release the vm
    sys.exit(1)




check_arch = subprocess.check_output("file " + path_to_malware, shell=True)
if "x86-64" in check_arch:
    print malware + " is 64 bits"
    BUI_arch = "64"
    regs_map = {"ax":"rax", "bx":"rbx","cx":"rcx", "dx":"rdx", "si":"rsi","di":"rdi","sp":"rsp","ip":"rip","bp":"rbp","r":["r8","r9","r10","r11","r12","r13","r14","r15"]}

    #subprocess.call("cp " + path_to_malware + " " + malware_x64_folder + "/"+malware, shell=True)
elif "80386" in check_arch:
    regs_map = {"ax":"eax", "bx":"ebx","cx":"ecx", "dx":"edx", "si":"esi","di":"edi","sp":"esp","ip":"eip","bp":"ebp","r":[]}
    print malware + " is 32 bits"
    BUI_arch = "32"

    subprocess.call("mv " + path_to_malware + " " + malware_x86_folder + "/"+malware, shell=True)
    print "Aborting 32 bits for now..."
    subprocess.call("touch " + vm_ready_pool + "/" + remote_vm_ip, shell=True) #release the vm
    sys.exit(1)

else:
    print check_arch
    print "**WARNING** Cannot determine ARCH of malware", malware, " Aborting ..."
    subprocess.call("mv " + path_to_malware + " " + malware_unknown_arch + "/"+malware, shell=True)
    subprocess.call("touch " + vm_ready_pool + "/" + remote_vm_ip, shell=True) #release the vm
    sys.exit(1)


folder = malware_ran_folder + "/" + BUI_arch
subprocess.call("mkdir -p "+folder +">/dev/null 2>&1",shell=True)

#if results exist, then don't run, because we already have results for that malware
if os.path.isdir(results_folder):
    print malware, "already has results. Aborting.."
    subprocess.call("mv " + path_to_malware + " " + malware_ran_folder + "/" + BUI_arch, shell=True)
    subprocess.call("touch " + vm_ready_pool + "/" + remote_vm_ip, shell=True) #release the vm
    sys.exit(0)



class mythread(threading.Thread):
    def __init__(self, var, thread_id):
        threading.Thread.__init__(self)
        self.var = var
        self.thread_id = thread_id
    def run(self):
        global thread_crashed
        if self.var == "run":
            remote_run_malware()
            print "remote_run_malware. DONE"
        elif self.var == "capture":
            #capture in 2 secs. Remember since we first check if the process is running before capturing, then the actual time of capture after execution should be more than 2 seconds
            remote_attempt_capture(2)
            #lets update an indicator that the malware did not HIJACK the VM used
            global POSSIBLE_MALWARE_VM_HIJACK
            POSSIBLE_MALWARE_VM_HIJACK = False
            print "remote_attempt_capture(). DONE"
        elif self.var == "static_analysis":
            do_static_analysis()
            print "Static Analysis. DONE"
        elif self.var == "forensic_analysis":
            do_forensic_analysis()
            print "Forensic Analysis. DONE"
        else:
            print " INVALID ARGUMENT", self.var, "SHOULD NEVER HAPPEN PLEASEN CHECK"
            #subprocess.call("mv " + path_to_malware + " " + malware_crashed_folder + "/"+malware, shell=True)
            forsee_exit(1)

        thread_crashed[self.thread_id] = False # let main thread know you did not crash


def is_packed():
    #I read that you will not see the .text and .data segments as strings when you run the strings command against a packed binary
    dot_data = subprocess.check_output("strings " + path_to_malware + " | grep '\.data'", shell=True)
    dot_text = subprocess.check_output("strings " + path_to_malware + " | grep '\.text'", shell=True)
    if '.data' in dot_data and '.text' in dot_text:
        return False
    else:
        return True




def dump_to_exe(addr):
    return addr - long(BUI_seg_start,16) + long(BUI_exe_seg_start,16)

def exe_to_dump(addr):
    return addr -  long(BUI_exe_seg_start,16) + long(BUI_seg_start,16)

def init_dot_graph():
    global dot, dot_label
    dot = graphviz.Digraph(comment='memory-symbex')
    moment = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
    global sample_hash
    sample_hash = subprocess.check_output("md5sum " + path_to_malware, shell=True).split()[0]
    dot_label = malware+ " "+ sample_hash + " " + moment + "\nmemory forensics + symbolic execution"
    dot.attr(label=dot_label, fontsize="20", labelloc="t")
    dot.attr('node',fontsize='7', margin='0')


def remote_deliver_malware():
    print "Delivering ", malware, "to remote machine to execute ..."
    run_status = subprocess.call('scp   ' +path_to_malware + " "+ remote_vm+":~ > /dev/null", shell=True)
    if str(run_status) != '0':
        print "[ERROR] subprocess call to deliver binary to remote machine had a problem, aborting .."
        forsee_exit(1)
    #make malware binary executable
    subprocess.call('ssh '  + remote_vm +  ' " chmod ugo+x ' +malware +'" ', shell=True)
    #shutdown network interface
    command_to_run = 'netsh interface set interface "Local Area Connection" admin=disable'
    print remote_command(command_to_run)

def remote_run_malware():
    print "Executing ", malware, "on remote machine to execute ..."

    run_status = ""
    if "crackme" in malware: # for my test binary. if it does not get exactly one argument, it does not run
        run_status = subprocess.call('ssh '  + remote_vm +  ' " ./'+malware + ' ARG1  " ', shell=True)
        if str(run_status) != '0':
            print "Deployed malware execution", malware, "had a problem"
    else:
        try:
            run_status = subprocess.check_output('ssh '  + remote_vm +  ' " ./'+malware + ' ARG1 ARG2 ARG3 ARG4 AGR5 AGR6 > /dev/null "', shell=True)
        except Exception, e:
            print "An exception occurred during the execution of ", malware, "on ", remote_vm, str(e)
        print "Deployed malware execution finished: ", run_status

    #time.sleep(60)

def remote_attempt_capture(sleep_time):
    #time.sleep(1) #to ensure that the remote_run_malware runs first. since we are uncertain how the threads will be scheduled


    #time.sleep(60)

    #check to see if the process is running first
    is_running = False
    for i in xrange(0,4): #lets wait for a maximum of 4 seconds
        if check_if_running(malware.replace(".exe","")):
            is_running = True
            break
        print "not running after this one check"
        time.sleep(1)


    if is_running:
        print "Capturing ", malware, "on remote machine after ", sleep_time, "secs ..."
        command_to_run= "./dump.sh " + malware + " " + str(sleep_time)
        print remote_command(command_to_run) # this will execute on the remote machine and returns without waiting on windbg to finish
    else: #set something that will be checked by the person who is gonna call was_captured(), so they dont waste their time
        print "check_if_running() reported that malware did not run"
        global malware_did_not_run
        malware_did_not_run = True

def check_if_running(process_name):
    try:
        print "checking if", process_name, "is running ..."
        output = subprocess.check_output('ssh '+remote_vm +' " echo get-process -name '+ process_name + ' | powershell -c -"', shell=True)
        #lets confirm, although if the process does not exist it will return error, which will make the subprocess call crash, leading to an exception
        print output
        if "Cannot find a process with the name" not in output:
            return True
    except Exception, e:
        pass
    return False

def was_captured(my_bool):
    #this function just check if a .dmp exists on the remote machine for the malware under consideration
    if not my_bool:# I put my_bool incase I am reverting snapshot to an initial state, and I am  checking if dump already exist.
        #if this was the initial check in main, of course I know there is no dump, so just return False
        return False

    #lets check if the malware was actually captured. check for dump output file
    command_to_run = "ls /cygdrive/c/Users/moses/Documents/from_windbg/"+malware
    response = remote_command(command_to_run)


    if malware + ".dmp" in response:
        return True
    else:
        print "Attempt to capture the process using Windbg had an exception which means that Windbg did not see the process. It is possible that the malware has injected itself into another process, and has just exited since for program to get to this stage, we earlier detected that it was running"
        return False

def remote_command(command_to_run):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_para = (remote_vm_ip, 22222)
    s.connect(server_para)
    #command_to_run= "./dump.sh " + malware + " " + str(sleep_time)
    s.send(command_to_run)
    response = s.recv(8192)
    s.close()
    return response



def remote_run_windbg():
    #make a remote call to run windbg script in the windows vm
    print "Remotely executing  windbg and associated scripts ..."

    if BUI_arch == "64":
        writer = "command_writer.ps1"
    elif BUI_arch == "32":
        writer = "command_writer_x86.ps1"
    else:
        print "ERROR: Unknown or Unspecified Architecture for BUI"
    run_status = subprocess.call('ssh '  + remote_vm +  ' " echo ./process_core.ps1 -malware '+malware+' -writer ' + writer + ' | powershell -file -"', shell=True)
    if str(run_status) != '0':
        print "[ERROR] subprocess call to run process_core had a problem, aborting .."
        forsee_exit(1)
    #time.sleep(1)

def remote_retrieve_output():
    #make a remote call to retrieve the output of windbg script run in the windows vm
    #remove my local store before
    if len(os.listdir(local_dumps_folder)) > 0:
        run_status = subprocess.call('rm ' + local_dumps_folder + "/*", shell=True)
        if str(run_status) != '0':
            print "[ERROR] subprocess call to remove local files  had a problem, aborting .."
            forsee_exit(1)

    print "Remotely retrieving output files ..."
    run_status = subprocess.call('scp -r  ' + remote_vm+':'+path_to_remote_dumps + " " +  workspace_folder + " > /dev/null", shell=True)
    if str(run_status) != '0':
        print "[ERROR] subprocess call to retrieve output had a problem, aborting .."
        forsee_exit(1)

def sort_dumps():
    #sort the dumps by addresses, so we can load them in order
    print "Sorting", malware, " dumps ...."
    file_dict = {}
    addr_set = set()
    for dump_file in os.listdir(local_dumps_folder):
        file_path = os.path.abspath(os.path.join(local_dumps_folder, dump_file))
        if os.path.isfile(file_path) and os.path.getsize(file_path) > 0 and ".dmp" in dump_file:
            start_addr = long(dump_file.split("-")[1], 16)
            file_dict[start_addr] = {}
            file_dict[start_addr]["path"] = file_path
            file_dict[start_addr]["size"] = os.path.getsize(file_path)
            file_dict[start_addr]["perm"] = dump_file.split("-")[4]
            addr_set.add(start_addr)
    addr_set = sorted(addr_set)
    return addr_set, file_dict

def angr_load_blobs(addr_set, file_dict):
    print "loading into angr ......"
    my_force_load_libs = []
    my_lib_opts = {}
    my_extra_info = {}
    seg_id = 0
    if BUI_arch == "64":
        arch = "amd64"
    elif BUI_arch == "32":
        arch = "x86"
    else:
        print "ERROR: Unknow Specified Architecture"

    for start_addr in addr_set:
        seg_id += 1
        file_path = file_dict[start_addr]['path']
        permission = file_dict[start_addr]["perm"]
        size = file_dict[start_addr]["size"]


        #identify the segment where  BUI  is loading and initialize the start and end segment addr
        if long(BUI_bt_addrs[0],16) <= (start_addr + size) and long(BUI_bt_addrs[0],16) >= start_addr:
            global BUI_seg_start, BUI_seg_end, BUI_prefix_len, BUI_addr_prefix
            BUI_seg_start = hex(start_addr)
            BUI_seg_end = hex(start_addr + size)
            #let me get the BUI_prefix_len
            BUI_prefix_len = 0
            for c_index in xrange(0,len(BUI_seg_start)):
                if BUI_seg_start[c_index] == BUI_seg_end[c_index]:
                    BUI_prefix_len += 1
                else:
                    break
            BUI_addr_prefix = BUI_seg_start[0:BUI_prefix_len]
            if "EXECUTE" not in permission:
                print "**ERROR** somehow the BUI segment does not have the EXECUTE permission. This is wrong so investigate. seg", seg_id, "start_addr:", hex(start_addr)



        if "EXECUTE" in permission:
            x_segs.append({'start':start_addr, 'end':start_addr + size})

        my_force_load_libs.append(file_path)
        my_lib_opts[file_path] = {'backend': 'blob', 'custom_arch': arch, 'custom_base_addr': start_addr}
        my_extra_info[start_addr] = {'perm': permission, 'size': size, 'id' : seg_id}


    p = angr.Project(path_to_empty_file, main_opts={'backend':'blob', 'custom_arch':arch, 'custom_base_addr':0x0}, force_load_libs=my_force_load_libs, lib_opts=my_lib_opts )
    return p




def check_if_multi_threaded():

    threads = subprocess.check_output("grep '\<Id.*Teb\>:' " + local_dumps_folder + "/windbg.log", shell=True)
    num_threads = len(threads.splitlines())
    print "threads :", num_threads
    if num_threads > 2:
        print threads
        return True
    elif num_threads == 2 and "Id:" in threads:
        print "malware", malware, "is single threaded, yay !"
        return False
    else:
        print "We could not determine how many threads it has\n", threads
        return True

def initial_process_windbg_log():
    #retrieve register values from windbg.log
    regs_dict = {}
    print "\n ===== Processing the windbg output log====="
    print "\n==== REGISTERS ===="
    if BUI_arch == "64":
        regs = subprocess.check_output("grep '\<r.x\>=\|\<r.p\>=\|\<r.i\>=\|\<r[0-9][0-9]*\>=\|\<[cdefgs]s\>=\|\<[oditszapc]f\>=\|efl=\|iopl=' " + local_dumps_folder + "/windbg.log", shell=True)
    else:
        regs = subprocess.check_output("grep '\<e.x\>=\|\<e.p\>=\|\<e.i\>=\|\<[cdefgs]s\>=\|\<[oditszapc]f\>=\|efl=\|iopl=' " + local_dumps_folder + "/windbg.log", shell=True)

    print regs

    print "\n==== BACK TRACE ===="
    call_trace = subprocess.check_output("grep -i -A 50 '\<child.*retaddr\>' " + local_dumps_folder + "/windbg.log", shell=True)
    #I just used 50 because I assume that there will not be more than 50 lines of backtrace
    #print call_trace


    regs_array = regs.splitlines()
    for entry in regs_array:
        part = entry.split("=")
        regs_dict[part[0]] = part[1]
    return regs_dict

def analyze_loaded_symbols():
    global symbols_dict
    print "\n === Analyzing loaded modules and symbols =="
    sym = subprocess.check_output("grep ! " + local_dumps_folder + "/windbg.log", shell=True)
    sym_list = sym.splitlines()
    for entry in sym_list:
        addr = entry.split()[0]
        try: #to make sure the line is valid
            long_addr = long("0x" + addr.replace("`",""),16)
        except ValueError:
            continue
        symbol = entry.split()[1]
        symbols_dict[hex(long_addr)] = symbol

def structure_backtrace():
    global program_end_addrs
    backtrace = {}
    backtrace_lines = ""
    call_stack = subprocess.check_output("grep -i -A 50 '\<child.*retaddr\>' " + local_dumps_folder + "/windbg.log", shell=True)
    lines = call_stack.splitlines()
    last_frame = ""
    BUI_frame = "" #frame where BUI/malware was last seen. To be used to calculate the call_trace_END_len (should be around 2 or 3 mostly)
    global BUI_bt_addrs, BUI_bt_addrs_frame_no #we will keep a track of the BUI ret addresses in the backtrace. The first one and last one in the list are more important

    #since the backtrace fields in windbg is different in 32 vs 64 bit. 32 shows EPB, 64 shows RSP
    if BUI_arch == "64":
        pointer_used = "sp"
    elif BUI_arch == "32":
        pointer_used = "bp"
    else:
        print "**ERROR** Cannot determine the BUI architecture. This is a problem"

    for frame_line in lines: #for each of the backtrace lines
        try: #to make sure the line is valid
            first_token = frame_line.split()[0]
            int(first_token,16) #make sure its makable into an int
            if len(first_token.strip()) != 2: #make sure the frame no is 2 digit as it always is unless windbg changed how they output stuff
                continue
        except ValueError:
            continue
        entries = frame_line.split()
        backtrace[hex(int(entries[0], 16))] = {'frame_no': hex(int(entries[0], 16)), pointer_used: hex(long("0x" + entries[1].replace("`",""),16)), 'ret_addr': hex(long("0x" + entries[2].replace("`",""),16)), 'call_site': entries[3]}
        #also remember that the ret addr and the pointer is used later in the symbolic exploration to check the correctness of the backtrace transition
        #lets get the BUI addr information, and then use in during the IDA loading to get the BUI segment start/end addr
        #print "callsite", entries[3:]
        if malware.replace(".exe","") in str(entries[3:]):
            global BUI_bt_ret_addr, BUI_addr_prefix, bt_after_BUI_lib_func
            #lets record the libcall just on top of BUI in the backtrace
            if bt_after_BUI_lib_func == "":
                bt_after_BUI_lib_func = backtrace[hex(last_frame)]['call_site'].replace(":","")

            BUI_bt_ret_addr = backtrace[hex(last_frame)]['ret_addr'] #eventually, this will store the first BUI function that was called after START or wmain
            BUI_bt_addrs.append(BUI_bt_ret_addr)
            BUI_bt_addrs_frame_no[BUI_bt_ret_addr] = hex(int(entries[0],16))
            BUI_frame = int(entries[0],16)
        backtrace_lines += frame_line + "\n"
        last_frame = int(entries[0],16)
    #lets make sure BUI parameters was set, otherwise it means that the malware did not show up in the backtrace
    if BUI_frame == "":
        global thread_reported_problem, thread_message
        thread_reported_problem = True
        thread_message += "\n***ERROR** It appears that BUI " + malware + " did not appear in backtrace. Please investigate\n\n" + backtrace_lines + "\n\noriginal\n" + call_stack
        print thread_message
        forsee_exit(1)

    global call_trace_END_len #to be used to determine what len of the call_trace signifies the END
    call_trace_END_len = last_frame - BUI_frame
    #now lets generate the list of addresses that anytime execution IP finds itself here,  we know it  signifies the END
    for x in xrange(0,call_trace_END_len + 1):
        program_end_addrs.append(backtrace[hex(last_frame - x)]['ret_addr'])
    #program_end_addrs  = [backtrace[hex(last_frame)]['ret_addr'], backtrace[hex(last_frame-1)]['ret_addr'],backtrace[hex(last_frame -2)]['ret_addr']]
    return backtrace, backtrace_lines

#This function is not really implemented well to do what was originally planned
def determine_stack_frame_of_interest(do_it, given_value):
    if do_it == False:
        return given_value
    call_stack = subprocess.check_output("grep -i -A 1000 '\<child.*retaddr\>' " + local_dumps_folder + "/windbg.log", shell=True)
    frames = call_stack.splitlines()
    is_external = False
    frame_no = '0' #the default, the last function to be called in the backtrace
    for frame_line in frames: #for each of the backtrace lines
        try: #to make sure the line is valid
            int(frame_line.split()[0],16)
        except ValueError:
            continue
        for modules in known_external_libs:
            if modules in frame_line:
                is_external = True
                break
        if is_external:
            is_external = False
            continue
        frame_no = frame_line.split()[0]
        break
    return frame_no

def remote_windbg_run_frame_registers(frame_number):
    #make a remote call to run windbg script in the windows vm
    print "Remotely executing  windbg to get the frame registers of interest ..."


    run_status = subprocess.call('ssh '  + remote_vm +  ' " echo ./get_frame_registers.ps1 -frame_no ' +frame_number+ ' -malware ' +malware +' -arch '+BUI_arch + ' | powershell -file - " ', shell=True)
    if str(run_status) != '0':
        print "[ERROR] subprocess call to run process_core had a problem, aborting .."
        forsee_exit(1)
    #time.sleep(3)
    #make a remote call to retrieve the output of windbg script run in the windows vm
    print "Remotely retrieving output files for", malware, "..."
    run_status = subprocess.call('scp  ' + remote_vm + ':'+path_to_remote_dumps+'/frame_registers-'+frame_number+"-"+malware+'.log ' + local_dumps_folder + "/", shell=True)
    if str(run_status) != '0':
        print "[ERROR] subprocess call to retrieve output had a problem, aborting .."
        forsee_exit(1)

def process_frame_register_log(frame_no):
    print "\n ==== FRAME", frame_no, "REGISTERS ===="
    if BUI_arch == "64":
        #regs = subprocess.check_output("grep '\<r.x\>=\|\<r.p\>=\|\<.*r[0-9].*r[0-9][0-9]\>=\|iopl=\|efl=' " + local_dumps_folder + "/frame_registers-"+str(frame_no)+".log", shell=True)
        regs = subprocess.check_output("grep '\<r.x\>=\|\<r.i\>=\|\<r.p\>=\|\<.*r[0-9].*r[0-9][0-9]\>=\|iopl=\|efl=' " + local_dumps_folder + "/frame_registers-"+str(frame_no)+".log", shell=True)
        #reg_pos specifies what line and field to extract the non-volatile registers
        reg_pos = {'rbx': [0,1], 'rsi': [1,1], 'rdi': [1, 2], 'rip': [2, 0], 'rsp': [2, 1], 'rbp': [2, 2], 'r12': [4, 1], 'r13': [4, 2], 'r14': [5, 0], 'r15': [5, 1], 'fs':[7,4], 'gs':[7, 5]}
    elif BUI_arch == "32":
        regs = subprocess.check_output("grep '\<e.x\>=\|\<e.i\>=\|\<e.p\>=\|iopl=\|efl=' " + local_dumps_folder + "/frame_registers-"+str(frame_no)+".log", shell=True)
        reg_pos = {'ebx': [0,1], 'esi': [0,4], 'edi': [0, 5], 'eip': [1, 0], 'esp': [1, 1], 'ebp': [1, 2], 'fs':[2,4], 'gs':[2, 5]}
    else:
        print "**ERROR** Cannot determine the BUI architecture is 32 or 64 bit. This is a problem"
    print regs
    lines = regs.splitlines()
    #extracting all the Non volatile registers. And i know what line and field to extract each one based on the format windbg outputs them
    #global regs_dict
    regs_dict = {}
    for reg in reg_pos:
        line_index = reg_pos[reg][0]
        line_entry = reg_pos[reg][1]
        if reg not in lines[line_index]:
            print "ERROR: It looks like Windbg has changed the format they output the registers, so your register initialization will be wrong"
            return
        entry = lines[line_index].split()[line_entry]
        regs_dict[reg] = entry.split("=")[1]
    return regs_dict
def populate_registers_flags(state, regs_dict, only_non_volatile=bool):
    #the non volatile ones first
    for reg, val in regs_dict.iteritems(): #so angr only can set gs only, I think
        if reg[1] == "f" or reg in ["efl", "iopl", "cs", "ds", "ss", "es"]: #if its a flag or other unused registers
            continue
        setattr(state.regs, reg, long("0x" + val, 16))
    if only_non_volatile:
        return state

    eflags_index = {'cf': 1, 'pf': 2, 'af': 4, 'zf': 6, 'sf': 7, 'of': 11}
    for eflag in eflags_index:
        if regs_dict[eflag] == "1":
            state.regs.eflags = state.regs.eflags | (eflags_index[eflag] << 0)
        elif regs_dict[eflag] ==  "0":
            state.regs.eflags = state.regs.eflags & ~(eflags_index[eflag] << 0)
        else:
            print "[ERROR]", regs_dict[eflag], "does not have a proper value from Windbg, please check"
    #IF, TF, and DF are not emulated by ANGR or valgrind

    return state



def track_mem_write(state):
    #p.factory.block(state.addr).pp()
    #print state.inspect.mem_write_expr, type(state.inspect.mem_write_expr), state.inspect.mem_write_expr.concrete, state.inspect.mem_write_address, state.inspect.mem_write_length
    #print state.mem[state.inspect.mem_write_address].word, type(state.mem[state.inspect.mem_write_address].word), state.mem[state.inspect.mem_write_address].word.concrete
    #forsee_exit()

    steping[step_track['count']]['all_mem_write'] += 1
    if not state.inspect.mem_write_expr.concrete:
        steping[step_track['count']]['sym_mem_write'] += 1

def track_mem_read(state):
    steping[step_track['count']]['all_mem_read'] += 1
    if not state.inspect.mem_read_expr.concrete:
        steping[step_track['count']]['sym_mem_read'] += 1



def do_nothing(state):
    pass

def show_block(addr):
    p.factory.block(addr).pp()

def check_NX(addr):
    #check if these addresses are in the executable space, if not ALERT and prune
    for mapping in x_segs:
        if addr >= mapping['start'] and addr <= mapping['end']:
            return True
    return False

def end_of_BUI(addr):
    for address in p.factory.block(addr).instruction_addrs:
        if address in program_end_addrs:
            return True
    return False



#is this instruction present in this block
def is_ins_present(mnemonic, operand,  addr):#input_str should be
    for ins in p.factory.block(addr).capstone.insns:
        if mnemonic in str(ins.mnemonic) and operand in str(ins.op_str):
            return True

    print "FXN prologue not present in", hex(addr)
    return False


def update_trace_and_check_symbolic_loop(state, uid, path_id, BUI_restrict, parent_states):
    global step_track, addrs_to_prune


    #just on the side check. incase you have one of those state split due to symbolic IP or something other than unconditional jumps
    parent_uid = step_track['prev_states'][uid]['parent']
    if state.history.jumpkind in ["Ijk_Call", "Ijk_Ret"] and len(parent_states[parent_uid]['children']) > 1:
        steping[step]['ps'] += len(parent_states[parent_uid]['children']) - 1
    #i.e, we were supposed to see it if we knew that IP was symbolic or other stuff like that
    #end


    steps = step_track['count']
    call_trace = step_track['prev_states'][uid]['call_trace']
    current_func_addr = ""
    for key in call_trace[-1]: #the last dictionary is the current info for the current function
        current_func_addr = key
    # call_trace = [{'addr':{'block_count:0'}}, {}, {}]
    if state.history.jumpkind in ["Ijk_Boring", "Ijk_Yield"]:
        call_trace[-1][current_func_addr]['block_count'] += 1
    elif state.history.jumpkind == "Ijk_Call":
        #track BUI functions called
        if  hex(state.addr)[0:BUI_prefix_len] in BUI_addr_prefix:
            global BUI_reached_funcs
            BUI_reached_funcs.add(hex(state.addr))


        #attemp to identify the function with flirt. This takes a long time
        if flirt_enabled:
            global BUI_reached
            if  hex(state.addr)[0:BUI_prefix_len]  in BUI_addr_prefix or BUI_reached:# Im saying, ones BUI has been reached, starting doing IDA flirt
                flirt(state.addr)
                #just to see if I can identify printf in crackme code
                BUI_reached = True #when we see that BUI_addr_prefix, BUI has been reached, and eventhough the code wanders off in lib code, we know BUI has been reached
                BUI_restrict = False


        #check if we just wanna stay within the BUI code, only if loop is not present, just to be safe

        if BUI_restrict  and (BUI_arch == "64" or is_ins_present("push", regs_map['bp'], state.addr)): # Normal function have "push ebp" in the first block. If it does not have it then do not skip beacause it may be doing things to stack
            #don't enter if you are a fastcall since fastcalls are inline
            #don't enter if you don't have the fxn prologue, but if you are x64 enter

            #see if a library call
            if  hex(state.addr)[0:BUI_prefix_len] not in BUI_addr_prefix:
                #lets determine if the caller is in BUI or not_BUI
                if hex(state.callstack.top.ret_addr)[0:BUI_prefix_len]  in BUI_addr_prefix:
                    BUI_caller = True
                else:
                    BUI_caller = False

                #note the function being called in the exploration graph
                address = hex(state.addr)
                sym = symbols_dict[address]
                #edit_graph_label(uid=uid, to_append="\n"+sym)
                paths_info['lib_calls'][path_id].append(sym)
                global lib_calls_seen
                #lib_calls_seen[hex(state.addr)] = sym
                lib_calls_seen[hex(state.addr)] = {}
                lib_calls_seen[hex(state.addr)]['name'] = sym



                #if the lib call is exit, we need to exit
                # I later decided not to do this because I want the malware to just continue executing incase there are more capabilities it is trying to hide by exiting
                #"""
                #if "exit" in sym and "exit" in BUI_exe_lib_funcs[hex(dump_to_exe(state.addr))]['name']:
                if "exit" in sym:
                    if BUI_caller: #if not BUI_caller, then we cannot really do the further processing below. I guess we can just exit but no, we want it to continue
                        print "we saw an exit @path", path_id, " @steps", steps
                        #get the exact caller addr
                        called_from_addr = p.factory.block(state.history.bbl_addrs[-1]).capstone.insns[-1].insn.address
                        for lib_plt_addr in BUI_exe_lib_funcs:
                            if hex(dump_to_exe(called_from_addr)) in BUI_exe_lib_funcs[lib_plt_addr]['call_sites']:
                                print "we found the caller address in the call_site, so perhaps this works: @path", path_id, "@steps", steps, " dump_to_exe", hex(dump_to_exe(called_from_addr))
                                if "exit" in BUI_exe_lib_funcs[lib_plt_addr]['name']:
                                    print "we now confirmed that the libs name is exit plt_addr:", lib_plt_addr, " lib_name:",  BUI_exe_lib_funcs[lib_plt_addr]['name']

                                    #print "* ALERT * path", path_id," has reached end via EXIT <", sym,">. size of call_trace:", len(call_trace), "@steps", steps
                                    #return False, "EXIT"
                    else:
                        print "we saw an exit, but it was not by a BUI_caller @path", path_id, "@steps", steps, "BUI_reached", BUI_reached
                #"""
                #end



                #lets make sure this BUI_restrict thing is not causing looping due to us giving the possible return register i.e rax several values
                block_count = call_trace[-1][current_func_addr]['block_count']
                history = state.history.bbl_addrs.hardcopy
                #loop_count = history[len(history)-block_count:len(history)].count(state.addr)
                loop_count = history[len(history)-block_count:len(history)].count(state.callstack.top.ret_addr) # state.callstack.top.ret_addr is the addr we are about to return it to
                if loop_count > 1: #prune only when the loop has occurred twice
                    #print "possible looping count-", loop_count, "- due to the BUI_restrict thing @path", path_id, "@steps", steps

                    ax_val = getattr(state.regs, regs_map['ax'])
                    print " to be pruned. rax: ", state.se.eval_upto(ax_val, 10), "@path", path_id, "@", state.addr, "@step", steps, "loop_count:", loop_count
                    return True, "loop possibly caused by BUI_restrict"
                if loop_count == 1:
                    ax_val = getattr(state.regs, regs_map['ax'])
                    print "first loop seen", state.se.eval_upto(ax_val, 10), "@path", path_id, "@", hex(state.addr), "@step", steps, "loop_count:", loop_count

                ret_addr = state.callstack.top.ret_addr #this is ok since when the call was made, angr added stuff to the call stack top
                #print "**BUI restrict** @path",path_id, "@addr",hex(state.addr), "@steps", steps, "return to", hex(ret_addr)

                #we have to pop the return address of the stack, since it was put there by the caller.
                #We might also have to see if it is stdcall, and clean the pushed args, but now doing that now, so there could be errors
                ret_addr_another_way = state.se.eval(state.stack_pop())
                if ret_addr != ret_addr_another_way:
                    print "**FYI** the two ways of obtaining return address not same result", hex(ret_addr), hex(ret_addr_another_way)




                #point the IP to the return addr
                if BUI_arch == "64":
                    state.regs.rip = state.callstack.top.ret_addr
                else:
                    state.regs.eip = state.callstack.top.ret_addr

                #if True:
                if BUI_caller or (loop_count == 1 and not BUI_caller): #basically, I am not modifying rax if the caller is from a lib unless it caused a loop earlier. The reason i do this is because, when the bt trace is returning from lib space, I do not want to many paths to result when I have not even returned to BUI.
                    #make rax, which i presume is the return register for the function hold either a 0 or a 1
                    reg_ax = regs_map['ax']

                    #rax_current_val = state.regs.rax
                    ax_old_val = getattr(state.regs,reg_ax)
                    #state.regs.rax = claripy.BVS("regs_rax",64)
                    setattr(state.regs,reg_ax, claripy.BVS("reg_ax",64))
                    ax_new_val = getattr(state.regs,reg_ax)
                    #OR use this maybe: state.regs.rax = state.solver.If(state.solver.BoolS('0_or_1'), state.solver.BVV(0, 64), state.solver.BVV(1, 64))
                    #state.add_constraints(state.regs.rax >=0, state.regs.rax <=1)

                    if BUI_arch == "64":
                        """
                        #if the old value of rax is not concrete or has more than say 3 values, do not include it
                        if len(state.se.eval_upto(state.regs.rax, 4)) > 3:
                            print "old value not added because is symbolic - delete this message later" #remember to also do this for x86 later below
                            state.add_constraints(state.solver.Or(state.regs.rax == 0, state.regs.rax == 1))
                        else:
                        """
                        state.add_constraints(state.solver.Or(state.regs.rax == 0, state.regs.rax == 1, state.regs.rax == ax_old_val))
                    else:
                        state.add_constraints(state.solver.Or(state.regs.eax == 0, state.regs.eax == 1, state.regs.eax == ax_old_val))
                    #state.add_constraints(state.solver.Or(ax_new_val == 0, ax_new_val == 1, ax_new_val == ax_old_val))

                    ax_newest_val = getattr(state.regs,reg_ax)

                    state.solver.simplify()
                    #print "rax: ", state.se.eval_upto(state.regs.rax, 10), "@path", path_id, "@", hex(state.addr), "@step", steps
                    #print regs_map['ax'], ax_old_val, state.se.eval_upto(ax_newest_val, 10), "@path", path_id, "@", hex(state.addr), "@step", steps


                #since we will not be appending a new func to the call_trace
                call_trace[-1][current_func_addr]['block_count'] += 1


                #there should be no need to check for loops in this case, i hope, so just return
                return False, "new uid" #instruct caller function to make and continue things with new uid

            else:
                call_trace.append({hex(state.addr):{'block_count':1, 'ret_addr':hex(state.callstack.top.ret_addr)}})
                current_func_addr = hex(state.addr)
        else:
            call_trace.append({hex(state.addr):{'block_count':1, 'ret_addr':hex(state.callstack.top.ret_addr)}})
            current_func_addr = hex(state.addr)



    elif state.history.jumpkind == "Ijk_Ret":
        #print "path ", path_id, " poping..."
        #print "value of rax on return", state.regs.rax

        #check if we are returning at the right place. if not panic.
        if long(call_trace[-1][current_func_addr]['ret_addr'],16) != long(hex(state.addr),16):
            print "**PANIC** Return Addr Mismatch: from_bt:", call_trace[-1][current_func_addr]['ret_addr'], "retuned_here:", hex(state.addr), "path", path_id, "@step", steps

        call_trace.pop()
        if len(call_trace) <= call_trace_END_len:
            print "* ALERT * path", path_id," has reached end. size of call_trace:", len(call_trace), "@steps", steps
            return False, "END"
        for key in call_trace[-1]: #the last dictionary is the current info for the current function
            current_func_addr = key
        call_trace[-1][current_func_addr]['block_count'] += 1

        if step_track['prev_states'][uid]['min_bt_size_attained'] > len(call_trace):
            step_track['prev_states'][uid]['min_bt_size_attained'] = len(call_trace)

        #print "path ", path_id, "after popping", call_trace
    elif state.history.jumpkind == "Ijk_NoHook":# or state.history.jumpkind == "Ijk_Sys_syscall":
        return False, ""
    elif state.history.jumpkind == "Ijk_SigTRAP":
        return False, "" #This will be prunned off when the successor is stepped

    else:
        print "**FYI** JumpKind Encountered:", state.history.jumpkind, "by state ", state, "@path", path_id, "@step", steps


    block_count = call_trace[-1][current_func_addr]['block_count']
    history = state.history.bbl_addrs.hardcopy

    #ways to check for symbolic loops
    if state.addr in history[len(history)-block_count:len(history)]:#If I am looping within the same function
        #lets check for simbolic loop based on if there is was a split in the loop under investigation

        """
        u, parent_uid = make_uid(state)
        if len(parent_states[parent_uid]['graph_label']['child_list']) > 1:
            #this state came from a symbolic loop
            return True, "spliting inside a loop"
        """
        #Another check based on the rep and dec instructions
        cx = regs_map['cx']
        cx_reg = getattr(state.regs,cx)
        for ins in p.factory.block(state.addr).capstone.insns:
            #if 'rep' in ins.insn.mnemonic and len(state.se.eval_upto(state.regs.rcx,257))>256:
            if 'rep' in ins.insn.mnemonic and len(state.se.eval_upto(cx_reg,257))>256:
                return True, "rep, and",cx,"is symbolic"
            if 'dec' in ins.insn.mnemonic:
                if BUI_arch == "32":
                    #i think this is x86 specific stuff, not sure
                    if cx in str(ins.insn.op_str) and len(state.se.eval_upto(cx_reg,257))>256:
                        return True, "dec and", cx, "is symbolic on x86"
                else:
                    if 'r9' in str(ins.insn.op_str) and len(state.se.eval_upto(state.regs.r9,257))<256:
                        return True, "dec r9 and r9 is symbolic @ "+str(path_id)

    return False, ""

def initial_processing(state):
     global step_track, dot, addrs_to_prune
     successors_to_return = []
     uid, parent_uid = make_uid(state)

     steps = step_track['count']
     path_id = step_track['prev_states'][uid]['path_id']
     bt_frame = step_track['prev_states'][uid]['bt_frame']
     try:
         successors = p.factory.successors(state)
         leaves = successors.flat_successors

         #lets keep track of the branches not taken if any
         global BUI_branches_potentially_not_taken
         for s in successors.unsat_successors:
            if  hex(s.addr)[0:BUI_prefix_len] in BUI_addr_prefix: #make sure they are valid ones
                BUI_branches_potentially_not_taken.add(hex(s.addr))
         # == END of tracking == #

         if len(leaves) == 0:
            #maybe there are unconstrained sucessors. lets just FYI
            print "No flat successors for state", state, "@path", path_id, "@bt_frame", bt_frame, "@step", steps, "unconstrained states:", len(successors.unconstrained_successors), "unsat states:", len(successors.unsat_successors), "all:", len(successors.all_successors)
            p.factory.block(state.addr).pp()

            if hex(state.addr) not in addrs_to_prune:
                addrs_to_prune[hex(state.addr)] = {}
                addrs_to_prune[hex(state.addr)]['reason'] = "likely unconstrained successors"
                addrs_to_prune[hex(state.addr)]['count'] = 1
            else:
                addrs_to_prune[hex(state.addr)]['count'] += 1

            #lets also mark that state as pruned
            to_append = "No_Succ" + hex(state.addr) + "\n@step " +str(steps)
            do_prune_things(state, uid, to_append, path_id, "No_Succ")


         successors_to_return.extend(leaves)
     except Exception, e:
        #to avoid one error I encountered: angr.engines.vex.statements.dirty | Unsupported dirty helper amd64g_dirtyhelper_XSAVE_COMPONENT_0
        print "**WARNING** Exception in stepping state:",state, "@ path", path_id, "@step", steps,"Error:", str(e)
        p.factory.block(state.addr).pp()
        if hex(state.addr) not in addrs_to_prune:
            addrs_to_prune[hex(state.addr)] = {}
            addrs_to_prune[hex(state.addr)]['reason'] = str(e)
            addrs_to_prune[hex(state.addr)]['count'] = 1
        else:
            addrs_to_prune[hex(state.addr)]['count'] += 1

        #lets also mark that state as pruned
        to_append = "Exception" + hex(state.addr) + "\n@step " +str(steps)
        do_prune_things(state, uid, to_append, path_id, "Exception")

        return []



     step_track['prev_states'][uid]['graph_label']['child_list'] = []
     for child in leaves:
        step_track['prev_states'][uid]['graph_label']['child_list'].append(child.addr)

     if len(leaves) > 2: #if you have more than 2 children, it means the rip which was symbolic resulted in > 2 possibles addresses. I don't like that
        print "**FYI** state:",state, "@ path", path_id, "@step", steps,"has", len(leaves), "children"

     return successors_to_return

def do_prune_things(state,uid,to_append,path_id,reason):
    edit_graph_label(uid=uid, to_append=to_append, key='prune')
    paths_info['lib_calls'][path_id].append(" *"+reason+" PRUNED*")

def make_uid(state):
    build_uid = ""
    for bb in state.history.bbl_addrs.hardcopy:
        build_uid += str(bb)
    parent_uid = hash(build_uid)
    uid = hash(build_uid+str(state.addr))
    return uid, parent_uid


def attach_to_graph(uid):

    frame_no = step_track['prev_states'][uid]['bt_frame']
    state= step_track['prev_states'][uid]['state']

    graph_id = step_track['prev_states'][uid]['graph_label']['graph_id']
    parent_graph_id = step_track['prev_states'][uid]['graph_label']['parent_graph_id']
    label = step_track['prev_states'][uid]['graph_label']['label']
    dot.node(graph_id,label=label)
    dot.edge(parent_graph_id, graph_id)

def edit_graph_label(uid=long, to_append=None, fontcolor=None, shape=None, fill=None, key=None):
    parent_graph_id = step_track['prev_states'][uid]['graph_label']['parent_graph_id']
    label = step_track['prev_states'][uid]['graph_label']['label']
    steps = step_track['count']
    if key != None:
        if key == "bt_filter":
            fontcolor='red3'
            shape = 'hexagon'
        elif key == "END" or key == "EXIT":
            cfa=""
            call_trace = len(step_track['prev_states'][uid]['call_trace'])
            for key in step_track['prev_states'][uid]['call_trace'][-1]:
                cfa = key.replace("L","")

            state = step_track['prev_states'][uid]['state']
            addr  = state.addr
            frame_no = step_track['prev_states'][uid]['bt_frame']
            delete_this = len(state.se.constraints)
            state.solver.simplify()
            to_append="end@ "+str(steps)+"\n"+hex(addr).replace("L","")+"\nf: "+cfa+"\ncall_trace: "+str(call_trace)+"\nframe "+str(frame_no)[2:]+"\ncons:"+str(len(state.se.constraints))
            fontcolor = 'green4'
            if key == "EXIT":
                fontcolor = "blue"
            shape = 'Msquare'
            completed_paths.append(step_track['prev_states'][uid]['path_id'])
        elif key == "merged":
            fontcolor = 'blue3'
            shape = 'Mcircle'
        elif key == "merger":
            fontcolor = 'blue3'
            shape = 'doublecircle'
        elif key == 'prune':
            fontcolor = 'red3'
            shape = 'Mcircle'
            pruned_paths.append(step_track['prev_states'][uid]['path_id'])
        else:
            pass
    dot.node(parent_graph_id, fontcolor=fontcolor, label=str(label)+"\n"+to_append, shape=shape)
    step_track['prev_states'][uid]['graph_label']['label'] += "\n"+str(to_append)

def initialize_state_properties(state, parent_states, stop_at_split, show_split, verbose_r):
            global step_track
            addr = state.addr
            to_return = False
            to_display = ""
            uid, parent_uid = make_uid(state)
            #print uid
            if uid in step_track['prev_states']:
                print "**NOT GOOD**, state uid is not unique and may be overwriting other states"
                print "this state", step_track['prev_states'][uid]['state'], "has same uid as this state", state

            step_track['prev_states'][uid] = {}
            step_track['prev_states'][uid]['parent'] = parent_uid
            step_track['prev_states'][uid]['addr'] = addr
            step_track['prev_states'][uid]['state'] = state
            #populate your call_trace with your parents
            step_track['prev_states'][uid]['call_trace'] = copy.deepcopy(parent_states[parent_uid]['call_trace'])
            frame_no = parent_states[parent_uid]['bt_frame']
            step_track['prev_states'][uid]["bt_frame"] = frame_no
            step_track['prev_states'][uid]['min_bt_size_attained'] = parent_states[parent_uid]['min_bt_size_attained']
            step_track['prev_states'][uid]["children"] = [] # we don't know its children yet
            path_id = parent_states[parent_uid]['path_id']
            step_track['prev_states'][uid]['path_id'] = path_id# inherit your parents path id
            parent_addr = state.history.bbl_addrs.hardcopy[-1]
            parent_path_id = path_id
            parent_bt = parent_states[parent_uid]['bt_frame']
            step_track['prev_states'][uid]["parent_bt"] = parent_bt
            parent_states[parent_uid]['children'].append(uid)


            if len(parent_states[parent_uid]['children']) > 1: # a branch is gonna happen. particularly important  to assigning next path_id
                step_track['max_path_id'] += 1
                path_id =  step_track['max_path_id']  #get the next path_id
                #path_inc +=  1
                step_track['prev_states'][uid]['path_id'] = path_id
                #inherit my parent paths_info
                paths_info['lib_calls'][path_id] = ["<path "+str(parent_path_id)+">"]
                #paths_info['lib_calls'][path_id].extend(paths_info['lib_calls'][parent_path_id])
                if not verbose_r:

                    to_display += "\n**NEW PATH**" +  hex(parent_addr)+" @frame "+parent_bt+" @path "+str(parent_path_id) +  "-->" + str([hex(step_track['prev_states'][u]['addr'])+" @path "+str(step_track['prev_states'][u]['path_id']) for u in parent_states[parent_uid]['children']])
                    to_display += "@ step "+str(step_track['count'])
                    if show_split:
                        to_display += str(state.se.constraints)
                        to_display += "\n== Parent ==\n"
                        to_display += str(p.factory.block(parent_addr).capstone)
                        count = 0
                        for u in parent_states[parent_uid]['children']:
                            #to_display += "\n== Child " + str(count) + " ==\n"
                            #to_display += str(p.factory.block(step_track['prev_states'][u]['addr']).capstone)
                            count += 1
                        #to_display += " * * *"
                    if stop_at_split:
                        to_return = True

            #graph stuff
            step_track['prev_states'][uid]['graph_label']={}
            graph_id = str(path_id) +"-"+ str(step_track['count'])
            #step_track['prev_states'][uid]['graph_label'] = copy.deepcopy(parent_states[parent_uid]['graph_label'])

            step_track['prev_states'][uid]['graph_label']['graph_id'] = graph_id


            #parent_graph_id need to be tracked incase you need to attach yourself to your parent, i.e when you are a split
            step_track['prev_states'][uid]['graph_label']['parent_graph_id'] = parent_states[parent_uid]['graph_label']['parent_graph_id']
            #parent_graph_label need to be tracked incase you want to edit this label, i.e when you are prunned
            step_track['prev_states'][uid]['graph_label']['label'] = parent_states[parent_uid]['graph_label']['label']
            if len(parent_states[parent_uid]['graph_label']['child_list']) > 1:
                #my parent said i have a sibling
                #attack myself to the graph

                #get the current function address
                cfa=""
                call_trace = len(step_track['prev_states'][uid]['call_trace'])
                for key in step_track['prev_states'][uid]['call_trace'][-1]:
                    cfa = key
                state.solver.simplify()
                label = graph_id + "\n"+hex(addr).replace("L","")+"\nf: "+cfa+"\ncall_stack: "+str(call_trace)+"\nframe:"+str(frame_no)[2:] + "\ncons:" + str(len(state.se.constraints))
                step_track['prev_states'][uid]['graph_label']['label'] = label
                attach_to_graph(uid)
                #since I am a split,I will be the parent for my next descendant that will come from a split
                step_track['prev_states'][uid]['graph_label']['parent_graph_id'] = graph_id


            return [path_id, parent_path_id, frame_no, parent_bt, addr, parent_addr, uid, parent_uid, to_display, to_return]
def check_backtrace_transition(frame_no, uid, path_id, parent_bt, addr, stop_at_backtrace_hit, verbose_r ):
            #check for backtrace stuff. We only update if it is a "progress" backtrace transition
            global step_track
            to_display = ""
            for num_frame in backtrace:
                ret_addr = long(backtrace[num_frame]['ret_addr'], 16)
                #if ret_addr in str(p.factory.block(long(addr, 16)).capstone):
                if ret_addr in p.factory.block(addr).instruction_addrs:
                    #lets make sure its the good transistion. from low to high, before we update it
                    if int(frame_no,16) < int(num_frame, 16)+1: #good
                        frame_no = hex(int(num_frame, 16)+1)
                        step_track['prev_states'][uid]["bt_frame"] = frame_no


                        #Correctness checking:
                        #lets make sure that this event is in line with the min_bt_size_attained property of the state
                        call_trace_len = len(step_track['prev_states'][uid]['call_trace'])
                        if len(backtrace) - int(frame_no,16) != call_trace_len:
                            print "**FYI** Logic Error: ", "bt transition occured, but frame_no =", frame_no, "and len(call_trace)=", call_trace_len, "path",path_id,"step", step_track['count'],"@", hex(addr)
                        #lets make sure it is also in line with the stack/base pointer of the frame, or did it return to previous previous callers
                        if BUI_arch == "64":
                            bt_sp = backtrace[frame_no]['sp'].replace("L","")
                            state_sp = str(step_track['prev_states'][uid]['state'].regs.rsp).split()[1].replace(">","")
                            if bt_sp != state_sp:
                                print "**FYI** Logic Error: ", "bt transition occured",parent_bt, "->",frame_no, "but state rsp =", state_sp, "and backtrace sp=", bt_sp, "path", path_id, "step", step_track['count'], "@", hex(addr)
                        else:
                            bt_bp = backtrace[frame_no]['bp'].replace("L","")
                            state_bp = str(step_track['prev_states'][uid]['state'].regs.ebp).split()[1].replace(">","")
                            if bt_bp != state_bp:
                                print "**FYI** Logic Error: ", "bt transition occured",parent_bt, "->",frame_no, "but state ebp =", state_bp, "and backtrace bp=", bt_bp, "path", path_id, "step", step_track['count'], "@", hex(addr)

                    if not verbose_r:
                        to_display +="\n** BACKTRACE HIT ** by state " + hex(addr) + "@path "+str(path_id)+" from frame "+ str(parent_bt) + " to: " + hex(int(num_frame,16)+1)
                       # print "Frame", hex(int(frame_no,16)+1),backtrace[hex(int(frame_no, 16) + 1)]
                    if stop_at_backtrace_hit:
                        return frame_no, True, to_display
            return frame_no, False, to_display


def check_stop_strings(stop_strings, state, path_id, stop_at_stop_strings):
            to_display= ""
            addr = state.addr
            to_return = False
            assembly = str(p.factory.block(addr).capstone)

            #check for some weird stuff I observed in net-traveller-malware.exe
            if len(assembly) == 0:
                print "**FYI** NO BYTE @", hex(state.addr), " NOPPING.."
                nop_addr(state.addr, 1)
                return to_return, to_display


            for item in stop_strings:
                if item in assembly:
                    to_display +=  "\n** CUSTOM HIT ** ["+ item+ " ] by state "+hex(addr) + "@path "+str(path_id)
                    #p.factory.block(addr).pp()
                    if stop_at_stop_strings:
                        to_return = True
            if "syscall" in assembly:
                nop_syscalls(state)

            return to_return, to_display
def nop_addr(addr,size):
    global already_hooked_addrs
    if addr not in already_hooked_addrs:
        p.hook(addr, do_nothing, length=size)


def nop_syscalls(state):
    global p, syscalls, already_hooked_addrs
    addr = state.addr
    #NOP syscalls
    prev_ins = ""# to keep track of the instr b4 syscall, which is usually: mov eax <number>
    for ins in p.factory.block(addr).capstone.insns:
        if 'syscall' in ins.insn.mnemonic:
            #print "NOP-ing syscall.."
            if ins.insn.address not in already_hooked_addrs:
                p.hook(ins.insn.address, do_nothing, length=ins.insn.size)
                uid, parent_uid = make_uid(state)
                print "**FYI** syscall seen @", hex(ins.insn.address),  ", bt_frame", step_track['prev_states'][uid]['bt_frame'], ", prev instr:", prev_ins
                syscalls.append(hex(ins.insn.address)+":"+str(prev_ins)+":"+str(step_track['count']))
                already_hooked_addrs.append(ins.insn.address)
        else:
            prev_ins = hex(ins.insn.address)+":"+str(ins.insn.mnemonic)+" "+str(ins.insn.op_str)



def merge_states(rips, mode):
    total_merged = 0
    global active_states, step_track, merge_track
    steps = step_track['count']
    for rip in rips:
        if len(rips[rip]) == 1: #there were just one state with that rip
            continue
        #print "dict:", rips[rip]
        #print "lenght of ", rips[rip], "is ", len(rips[rip])
        #order of choosing which state you all states be merged to
        #bt_frame -> smaller_constraints -> smaller_call_trace -> arbitrary
        best_bt  = 0
        best_cons = best_ct = 99999999
        best_state = ""
        best_path = ""
        uid_list = copy.copy(rips[rip])
        for uid in rips[rip]:
            if len(uid_list) < 2: #checking because we may remove some elements below is not in active_states
                #this uid list will not be considered. There is another check after this loop
                continue

            #see if this uid points to a state that is actually in the active_states, because it could have been pruned before merge_state was called
            if step_track['prev_states'][uid]['state'] not in active_states:
                uid_list.remove(uid)
                if len(uid_list) == len(rips[rip]):
                    print "This is the error I am trying to avoid, please investigate in merge_states()"
                continue
                #check if it is less than 2 rips in rip, in which case nothing to be merged
                #if len(rips[rip]) < 2:
                 #   continue

            bt = int(step_track['prev_states'][uid]["bt_frame"],16)
            step_track['prev_states'][uid]["state"].solver.simplify()
            cons = len(step_track['prev_states'][uid]["state"].se.constraints)
            ct = len(step_track['prev_states'][uid]["call_trace"])
            if bt > best_bt:
                best_bt = bt
                best_cons = cons
                best_ct = ct
                #print "path", step_track['prev_states'][uid]['path_id'], "selected on bt"
                best_state = step_track['prev_states'][uid]['state']
                best_path = step_track['prev_states'][uid]['path_id']
            elif bt == best_bt and cons < best_cons:
                #print "path", step_track['prev_states'][uid]['path_id'], "selected on cons"
                best_bt = bt
                best_ct = ct
                best_cons = cons
                best_state = step_track['prev_states'][uid]['state']
                best_path = step_track['prev_states'][uid]['path_id']
            elif cons == best_cons and ct < best_ct:
                best_bt= bt
                best_cons = cons
                #print "path", step_track['prev_states'][uid]['path_id'], "selected on ct"
                best_ct = ct
                best_state = step_track['prev_states'][uid]['state']
                best_path = step_track['prev_states'][uid]['path_id']

            else:
                #features are same, so the first state in the list retains the best state
                pass

        if len(uid_list) < 2:
            print "**FYI** rip", rip, "no longer to be merged since some member(s) were already pruned"
            continue


        path_ids = []
        #merger_path = ""
        merger_path = str(best_path)
        merged_state = best_state
        best_state_uid = ""
        #print "best state has been selected", best_state
        #for uid in rips[rip]:#remove the other states from active states
        for uid in uid_list:#remove the other states from active states
            if step_track['prev_states'][uid]['state'] not in active_states:
                print "I don't see why this should happen, check later in merge_states()"
                continue
            state = step_track['prev_states'][uid]['state']
            path_id = step_track['prev_states'][uid]['path_id']
            path_ids.append(path_id)
            #print "path", path_id, "cons:", len(state.se.constraints), "bt:", step_track['prev_states'][uid]['bt_frame'], "ct:", len(step_track['prev_states'][uid]["call_trace"])
            #print path_ids
            if state != best_state:
                merged_state, merge_flag, is_merged = merged_state.merge(state)
                if not is_merged: #not sure why
                    print "***WARNING *** For some reason, states cannot be merged please investigate\n"
                    continue #don't remove the state from active_states
                to_append = "_m @"+str(steps)+"->"+merger_path
                edit_graph_label(uid=uid, to_append=to_append, key="merged")
            else:
                #merger_path = step_track['prev_states'][uid]['path_id']
                best_state_uid = uid
            if state in active_states:
                active_states.remove(state) #remove all states to be merged. the merged one will be appended in the end
            else:
                print "** WARNING Trying to remove a state from active_states, but the state is not there", state, "path", path_id, path_ids, "step", steps
        #print "Merged paths", path_ids, "into path", merger_path, "at Step", steps
        active_states.append(merged_state)
        merged_state_uid, parent_uid = make_uid(merged_state) #parent_uid not used here

        #let the merged state inherit all the best_state's properties. #most importantly its path ID, bt_frame, and call_trace
        if merged_state_uid in step_track['prev_states']:
            print "**WARNING  should never happen ** Merged State UID already exist, expect incorrect results"
        step_track['prev_states'][merged_state_uid] = {}

        #Never use deepcopy. causes some weird unexplanable issues
        #step_track['prev_states'][merged_state_uid] = copy.deepcopy(step_track['prev_states'][best_state_uid])
        """
        step_track['prev_states'][merged_state_uid]['path_id'] = step_track['prev_states'][best_state_uid]['path_id']
        step_track['prev_states'][merged_state_uid]['bt_frame'] = step_track['prev_states'][best_state_uid]['bt_frame']
        step_track['prev_states'][merged_state_uid]['call_trace'] = step_track['prev_states'][best_state_uid]['call_trace']
        step_track['prev_states'][merged_state_uid]['graph_label'] = step_track['prev_states'][best_state_uid]['graph_label']
        step_track['prev_states'][merged_state_uid]['min_bt_size_attained'] = step_track['prev_states'][best_state_uid]['min_bt_size_attained']
        step_track['prev_states'][merged_state_uid]['children'] = step_track['prev_states'][best_state_uid]['children']
        step_track['prev_states'][merged_state_uid]['state'] = merged_state
        """

        #edit best_uid graph node, to indicate it is now a merger
        merged_state.solver.simplify()
        to_append = "_m @"+str(steps)+"\n"+str(path_ids)+"\ncons:"+str(len(merged_state.se.constraints))
        edit_graph_label(best_state_uid, to_append=to_append, key="merger")

        step_track['prev_states'][merged_state_uid] = step_track['prev_states'][best_state_uid]
        step_track['prev_states'].pop(best_state_uid)
        step_track['prev_states'][merged_state_uid]['state'] = merged_state
        #print "making sure the pop did not remove the merged state", step_track['prev_states'][merged_state_uid]


        """
        #attach merged state to graph
        graph_id = step_track['prev_states'][merged_state_uid]['graph_label']['graph_id']
        graph_id = graph_id + "_m_"+str(path_ids) # m signifies it is a merger of paths
        frame_no = step_track['prev_states'][merged_state_uid]['bt_frame']
        label = graph_id + "\nframe:"+str(frame_no)[2:] + "\ncons:" + str(len(merged_state.se.constraints))
        step_track['prev_states'][merged_state_uid]['graph_label']['label'] = label
        attach_to_graph(merged_state_uid)
        edit_graph_label(merged_state_uid, shape='doublecircle')
        """
        step_no = steps
        if step_no in merge_track:
            merge_track[step_no][merger_path] = path_ids
        else:
            merge_track[step_no] = {}
            merge_track[step_no][merger_path] = path_ids
        total_merged += len(path_ids) -1 # -1 because we added a new merged state

    print "total states removed from merging", total_merged
    #print "length of active states", len(active_states)

def check_filter_by_bt(bt_frame_track):
    global active_states
        #for step in filter_by_bt:
         #   if step_track['count'] == step:
    temp = active_states
    active_states = []

    for uid in step_track['prev_states']:
        s = step_track['prev_states'][uid]['state']


        if s in temp:
        #trying to capture some error: if there are duplicate states in step_track['prev_states']
            if s in active_states: #this means it was appended before, which is weird
                print "**Duplicate Error**(during check_by_bt), temp_size", len(temp), "active_states_size", len(active_states), "prev_states_size", len(step_track['prev_states'])
                continue #no need to append twice

            frame_no = step_track['prev_states'][uid]['bt_frame']
            path_id = step_track['prev_states'][uid]['path_id']
            if int(frame_no,16) >= int(bt_frame_track, 16):
                active_states.append(s)
            else:
                #indicate their demise in the graph
                to_append = "bt_filter@" + str(step_track['count'])+"\n"+str(frame_no)[2:]+","+str(bt_frame_track)[2:]
                edit_graph_label(uid=uid,to_append=to_append, key="bt_filter")
    print "Guide by bt @ step", step_track['count'], "number of states changed from:", len(temp), "to",  len(active_states)



def step_and_show(times, stop_at_backtrace_hit=False, stop_at_split=False, show_split=False, stop_strings=[], stop_at_stop_strings=False, limit=10**4, BUI_restrict=False, filter_by_bt=[], state_merge=("soft",[]), enable_flirt=False, shake=[], verbose=False, verbose_r=False):
    start_time = int(round(time.time()))

    global step_track, active_states, min_bt_size_attained, bt_frame_track, addrs_to_prune, return_now, flirt_enabled, step_history
    step_history += ' '.join([str(times), str(BUI_restrict), str(filter_by_bt), str(state_merge), str(shake)]) + "\n"
    flirt_enabled = enable_flirt
    active_states = [state for state in active_states if state != ""] # clean it up, because I messed it up at after_stepping_ops() to make it indexable by path_id
    to_display=""
    #to track backtrace progress
    #bt_frame_track = stack_frame_no # this will be used to track what the current best bt frame is for all of the states
    for step_iteration in xrange(0, times):
        gc.collect()
        #let me stop when active state is more than some number during the iteration
        if len(active_states) > limit and step_iteration > 0:
            print "As requested, active_states is more than",limit," so returning control to you. Try doing a merge. step", step_track['count']
            break
        input_states = active_states
        active_states = []
        step_track['count'] += 1
        steps = step_track['count']

        #mem reads/writes is cumulative
        steping[steps] = {'cond_jmps':0, 'all_mem_write':steping[steps-1]['all_mem_write'], 'sym_mem_write':steping[steps-1]['sym_mem_write'], 'all_mem_read':steping[steps-1]['all_mem_read'], 'sym_mem_read':steping[steps-1]['sym_mem_read']}
        steping[steps]['BUI_reached_funcs'] = len(BUI_reached_funcs)

        for state in input_states:
            #if initial_processing(state): #includes getting info to help in tree construction and checking if rip is symbolic

            #STEP the states
            #before stepping lets add track when a symbolic write is made
            state.inspect.b('mem_write', when=angr.BP_AFTER, action=track_mem_write)
            state.inspect.b('mem_read', when=angr.BP_AFTER, action=track_mem_read)
            active_states.extend(initial_processing(state)) # steps the states and return sucessors

        #lets record ps and pe since at the point, we have the paths that will be stepped in the next round
        #steping[steps]['pe'] = len(step_track['prev_states']) # how many did we explore ? i.e the states that were input to initial_processing(), but also include those that were pruned/merged. all of which are in step_track['prevs_states']
        steping[steps]['pe'] = step_track['max_path_id'] + 1
        #ps is cumulative
        steping[steps]['ps'] = steping[steps - 1]['ps'] +  steping[steps -1]['cond_jmps'] #during analysis, steping[steps]['cond_jump'] is updated based on unconditional jumps encountered
        #the above is also being updated when we see that there was a split caused by something other than conditional jumps. like symbolic IP
        #because cond_jmps or ps is not tracking to see if other states have counted the basic blocks they are recording, this values may be more than what it really is


        parent_states = step_track['prev_states']
        #num_parents = len(parent_states)
        step_track['prev_states'] = {}
        #all_states = []
        #all_paths_ordered = {} # to store all paths ordered by path id
        states_to_prune = []
        rips = {}#to be used for merging.
        #use_these_states_only = []# to be used to only process the states that made progress: bactrace transitions
        #path_inc = 0
        to_return = False
        #for state in a:
        for state in active_states:
            #== INITIALIZE STATE PROPERTIES ==#
            [path_id, parent_path_id, frame_no, parent_bt, addr, parent_addr, uid, parent_uid, add_to_display, if_to_return] = initialize_state_properties(state, parent_states,stop_at_split, show_split, verbose_r)
            to_display += add_to_display
            to_return = to_return or if_to_return

            #track all explored blocks
            global BUI_explored_blocks
            BUI_explored_blocks.add(hex(state.addr))

            #check for unconditional jumps
            #p.factory.block(state.addr).pp()
            to_check = str(p.factory.block(state.addr).capstone)
            if "j"  in to_check and 'jmp' not in to_check:
                #global total_paths_seen
                #print "we seen it"
                steping[steps]['cond_jmps'] += 1
                #total_paths_seen += 1
            #== CHECK NX ==#
            if not check_NX(addr):
                print "**PRUNING** @path " + str(path_id) + " has address " + hex(addr) + " outside of executable space. Prunning @step", str(steps)
                states_to_prune.append(state)
                to_append = "NX: ip:" + hex(addr) + "\n@step " +str(steps)
                edit_graph_label(uid=uid, to_append=to_append, key='prune')
                paths_info['lib_calls'][path_id].append(" *NX PRUNED*")
                continue

            #== CALL TRACE and LOOP CHECK ==#
            result, msg  =  update_trace_and_check_symbolic_loop(state, uid, path_id,BUI_restrict, parent_states)
            if msg == "END":
                edit_graph_label(uid=uid,key="END")
                states_to_prune.append(state)
                #completed_paths.append(path_id)
                #don't do a continue so that we can do the check_backtrace_transition
                #continue
            elif msg == "new uid":
                new_uid, p_uid = make_uid(state)
                step_track['prev_states'][new_uid] = step_track['prev_states'][uid]
                step_track['prev_states'][new_uid]['addr'] = state.addr

                addr = state.addr  #use the new addr for the remainder of the loop
                step_track['prev_states'].pop(uid) #remove old uid from step_tract
                uid = new_uid# this func should now use the new 'uid' locally
            elif msg == "EXIT":
                edit_graph_label(uid=uid,key="EXIT")
                states_to_prune.append(state)

            if result:
                print "**PRUNING** path", path_id,  hex(state.addr), msg, "@ step", step_track['count'], "Prunning.."
                states_to_prune.append(state)
                #caller = state.history.bbl_addrs.hardcopy[-1]
                to_append = "SYMLOOP: ip:" + hex(addr) + "\n@step " +str(steps)
                edit_graph_label(uid=uid, to_append=to_append, key='prune')
                paths_info['lib_calls'][path_id].append(" *SYMLOOP PRUNED*")
                continue


            if verbose:
                print "\n=== PATH", path_id, "==="
                p.factory.block(addr).pp()


            #== CHECK/UPDATE FOR BACKTRACE TRANSITION ==#
            frame_no, if_to_return, add_to_display = check_backtrace_transition(frame_no, uid, path_id, parent_bt, addr, stop_at_backtrace_hit, verbose_r)
            to_return = to_return or if_to_return
            to_display += add_to_display
            #let each state indicate if they have a better bt transition
            if int(frame_no, 16) > int(bt_frame_track,16):
                print "**FYI** backtrace transition seen from", bt_frame_track, "to", frame_no, "@path", path_id, "@ step", step_track['count']
                bt_frame_track = frame_no

            #== DETERMINE STATES TO MERGE ==#
            if steps in state_merge[1]:
                mode = state_merge[0]
                if mode == "soft":
                    call_trace = step_track['prev_states'][uid]['call_trace']
                    cfa = ""
                    for key in call_trace[-1]:
                        cfa = key
                    key = "-".join([hex(addr),str(frame_no),str(len(call_trace)),cfa,str(state.regs.rsp)])
                    if key in rips:
                        rips[key].append(uid)
                    else:
                        rips[key] = []
                        rips[key].append(uid)
                elif mode == "mild":
                    call_trace = step_track['prev_states'][uid]['call_trace']
                    cfa = ""
                    for key in call_trace[-1]:
                        cfa = key
                    key = "-".join([hex(addr),str(frame_no),str(len(call_trace)),cfa])
                    if key in rips:
                        rips[key].append(uid)
                    else:
                        rips[key] = []
                        rips[key].append(uid)
                elif mode == "aggressive":
                    if hex(addr) in rips:
                        rips[hex(addr)].append(uid)
                    else:
                        rips[hex(addr)] = []
                        rips[hex(addr)].append(uid)
                else:
                    print "wrong mode for state_merger", state_merger[0]
                    state_merge[1] = []
            #== CHECK FOR STOP STRINGS, and NOP SYSCALLS ==#
            if_to_return, add_to_display = check_stop_strings(stop_strings, state, path_id, stop_at_stop_strings)
            to_return = to_return or if_to_return
            to_display += add_to_display


            #== END OF BUI CHECK==#
            if end_of_BUI(addr):
                to_return = True
                states_to_prune.append(state)
                print "* ALERT * path", path_id," has reached end. @steps", steps, "WEIRD place to happen though, becos the execution should progress via bt frames.  Unless the backtrace obtained from Windbg is incorrect"
                edit_graph_label(uid=uid,key="END")
                to_display += "** END OF BUI REACHED ** for path "+str(path_id)+ "@frame "+str(frame_no)
                continue

        if verbose:
            print "StepCount:", step_track['count'] , "(" + str(step_iteration+1) + ")"

        #== SHAKING BY BUI_restrict toggle ==#
        for num in shake:
            if steps%num == 0:
                BUI_restrict = not BUI_restrict
                break


        #=== PRUNNING ===#
        if len(states_to_prune) > 0:
             temp = len(active_states)
             #print "pruning", len(states_to_prune), "states"
             for this_state in states_to_prune:
                 active_states.remove(this_state)
             #print "active_states reduced by", temp - len(active_states)

        #=== MERGING ===#
        temp = len(active_states)
        if step_track['count'] in state_merge[1]:
            #print "attempting to merge", len(rips), "IPs"
            error =  merge_states(rips, state_merge[0]) #This will update active_states with the merged_state, and remove the states that were merged. Will also add to step_track['prev_states']
            if error:
                print "Investigate Error from state merging"
                break
            #print "active_states reduced by", temp - len(active_states)

        #=== GUIDE BY BT ===#
        temp = len(active_states)
        if step_track['count'] in filter_by_bt:
            check_filter_by_bt(bt_frame_track)
            #print "active_states - by_bt - reduced by", temp - len(active_states)


        #record the pe_ps data#
        #global pe_ps_data
        #pe_ps_data += str(step_track['count']) + "," + str(round((float(len(step_track['prev_states']))/total_paths_seen),3)) + "\n"
        #print steps,  len(step_track['prev_states']), total_paths_seen
        #print steps,  steping[steps]['pe'], steping[steps]['ps']
        #if steps == 6:
        #    return


        if len(active_states) == 0: #no need to continue. no states to step
            break

        if to_return:
            break

    #AFTER the STEPPING times loop finishes
    #print "\n"+to_display
    active_states_count = after_stepping_ops(filter_by_bt, bt_frame_track)
    if active_states_count == 0:
        print "No more active states. I guess this is the END"
        subprocess.call("mkdir -p "+results_folder +">/dev/null 2>&1",shell=True)
        time_elapsed = int(round(time.time())) - start_time
        print "elapsed time: ", time_elapsed, "s"

        #lets see which branches encountered where not taken
        global BUI_branches_not_taken
        for my_addr in BUI_branches_potentially_not_taken:
            if my_addr not in BUI_explored_blocks:
                BUI_branches_not_taken.add(my_addr)


        global BUI_paths_not_explored_post_snapshot
        BUI_paths_not_explored_post_snapshot = "no SA"
        #for my_addr in BUI_branches_not_taken:
            #BUI_paths_not_explored_post_snapshot += get_total_paths_from_addr(long(my_addr,16))





        #get the total paths merged
        total_merged = 0
        for step_no in merge_track:
            total_merged += len(merge_track[step_no]) - 1 #because one path continued, i.e the merger path
        #get the list of library calls for each path
        path_calls = "\n*Post-capture Capabilities"
        for path in paths_info['lib_calls']:
            path_calls += "\n\n path " + str(path) + " " + str(paths_info['lib_calls'][path])

        #prepare to present the exploration graph
        #graph_filename = "/home/moses/forsee/"+malware+str(datetime.datetime.now().strftime("-%d-%H-%M-%S"))+".gv"
        graph_filename = results_folder + "/"+malware+".gv"
        add_to_label = "\n\n BUI_paths_not_explored: " + str(BUI_paths_not_explored_post_snapshot) + "\n\n ONE-TO-ONE Mapping Achieved: " + str(ONE_TO_ONE_MAPING_WORKED) + "\n\n Exploration Time: "+str(time_elapsed)+" s\npaths_seen: " + str(steping[step_track['count']]['ps']) + ", paths_explored: " + str(steping[step_track['count']]['pe']) + ", reached_end: " + str(len(completed_paths)) +", pruned: " + str(len(pruned_paths)) +  ", merged: "+ str(total_merged) + ", longest_path: "+ str(step_track['count'])
        dot.attr(label=dot_label + add_to_label, fontsize="20", labelloc="t")
        dot.render(graph_filename)
        dot.format = 'png' #also save in png
        dot.render(graph_filename)
        #subprocess.call("firefox " +graph_filename + ".pdf &", shell=True)

        #lets get the pre-capture calls from the backtrace
        pre_capture_calls = ""
        for i in xrange(0,len(backtrace)):
            pre_capture_calls +=  str(backtrace[hex(i)]['frame_no']) + ": "+  str(backtrace[hex(i)]['ret_addr']).replace("L","") + " "+ str(backtrace[hex(i)]['call_site']) + "\n"

        #prepare the pre-capture capabilities string to display
        global BUI_pre_capture_funcs_recovered
        for addr_pair in BUI_pre_capture_capabilities:
            frame_pair = ""
            dump_addr_pair = ""
            for ret_addr in addr_pair.split(":"):
                if ret_addr == bt_after_BUI_lib_func:
                    frame= hex(len(backtrace) + 1 - call_trace_END_len - len(BUI_bt_addrs)) # the frame of the first lib called by BUI in the backtrace
                    frame_pair += frame + "-"
                    dump_addr_pair += backtrace[frame]['ret_addr'] + "-"
                else:
                    dump_ret_addr = hex(exe_to_dump(long(ret_addr,16)))
                    dump_addr_pair += dump_ret_addr + "-"
                    if dump_ret_addr not in BUI_bt_addrs_frame_no:
                        IPython.embed(banner1="Please find out why "+ dump_ret_addr + " not  in BUI_bt_addrs_frame_no")
                    frame_pair += BUI_bt_addrs_frame_no[dump_ret_addr] + "-"

            if len(BUI_pre_capture_capabilities[addr_pair]) < 1:
                IPython.embed(banner1="Please find out why index <"+ addr_pair +  "> of BUI_pre_capture_capabilities has an empty list")
            BUI_pre_capture_funcs_recovered += addr_pair + "(" + dump_addr_pair + ")"+ "("+frame_pair+"): possible_paths: "+ str(len(BUI_pre_capture_capabilities[addr_pair])) + ", discovered funcs: " + str(len(BUI_pre_capture_capabilities[addr_pair][0])) + "\n"



        #also output a text file of the lib calls
        lib_calls_filename = graph_filename.replace(".gv",".lib_calls.txt")
        with open(lib_calls_filename, "w") as f:
            f.write(dot_label + add_to_label + "\n\nBacktrace Functions \n\n" + pre_capture_calls +"\n\n Pre-capture Capabilities \n\n "+ BUI_pre_capture_funcs_recovered + "\n\n"+ path_calls)
        #subprocess.call("firefox " +lib_calls_filename + " &", shell=True)

        #lets plot the pe_ps and  memory read/write and function reached figure
        pe_ps_filename = graph_filename.replace(".gv",".pe_ps.txt")
        mem_write_filename = graph_filename.replace(".gv",".mem_write.txt")
        mem_read_filename = graph_filename.replace(".gv",".mem_read.txt")
        #funcs_reached_filename = graph_filename.replace(".gv",".funcs_reached.txt")
        pe_ps_data = mem_write_data = mem_read_data = funcs_reached_data = ""
        for step in xrange(0, len(steping)):
            val = round((float(steping[step]['pe'])/steping[step]['ps']),3)
            pe_ps_data += str(step) + "," + str(val) + "\n"

            write_val = round((float(steping[step]['sym_mem_write'])/steping[step]['all_mem_write']),3)
            mem_write_data += str(step) + "," + str(write_val) + "\n"

            read_val = round((float(steping[step]['sym_mem_read'])/steping[step]['all_mem_read']),3)
            mem_read_data += str(step) + "," + str(read_val) + "\n"

            #f_val = round((float(steping[step]['BUI_reached_funcs'])/BUI_total_funcs),3)
            #funcs_reached_data += str(step) + "," + str(f_val) + "\n"

        write_to_file(pe_ps_data, pe_ps_filename)
        write_to_file(mem_write_data, mem_write_filename)
        write_to_file(mem_read_data, mem_read_filename)
        #write_to_file(funcs_reached_data, funcs_reached_filename)

        plot2d(pe_ps_filename, "# of blocks explored", "PE/PS", "Measuring concreteness based on paths explored vs paths seen")
        plot2d(mem_write_filename, "# of blocks explored", "Symbolic Writes/All Writes", "Measuring concreteness based on cumulative memory writes instances")
        plot2d(mem_read_filename, "# of blocks explored", "Symbolic Reads/All Reads", "Measuring concreteness based on cumulative memory reads instances")
        #plot2d(funcs_reached_filename, "# of blocks explored", "BUI_funcs_reached/BUI_total_funcs", "Measuring code coverage  based on total malware functions executed")

        #before you return append all your result to a text file
        """
        with open(data_file) as f:
            featured = [malware,BUI_arch,threaded,exe_size,dmp_size,exploration_time,len(BUI_funcs), len(BUI_reached_funcs),BUI_total_paths_from_dump_site, steping[step_track['count']]['ps'], steping[step_track['count']['pe'], len(BUI_branches_not_taken), len(pre_capabilities), len(lib_calls_seen)]
            to_append = ""
            for field in features:
                to_append += field + ","
            f.write(to_append)

        """
        return False # false means no more active states





    print "elapsed time: ", int(round(time.time())) - start_time, "s"
    return True #true means that there are still active states

def write_to_file(my_str, filename):
    with open(filename, "w") as f:
            f.write(my_str)

def plot2d(filename, x_label, y_label, title):
    return
    plt = matplotlib.pyplot
    fig_filename = filename.replace(".txt",".png")
    with open(filename, 'r') as f:
        data = [line.split(",") for line in f.readlines()]
        out = [(float(x), float(y)) for x, y in data]
        for i in out:
            plt.scatter(i[0],i[1])
            plt.xlabel(x_label)
            plt.ylabel(y_label)
            plt.title(title)
            plt.ylim(0,1)
        plt.savefig(fig_filename)
        plt.clf()
        plt.close()
    #subprocess.call("firefox " +fig_filename + " &", shell=True)


def after_stepping_ops(filter_by_bt, bt_frame_track):
    #lets not do filter_by_bt at the end for now
    #this function should just be for ordering the active states

    filter_by_bt = False
   #lets generate an ordered state info to print, and also order the actives states by path_id
    global active_states
     #we also order active_states by path_id, just so i can be indexable by path_id
    temp = active_states
    ordered_paths = [""]*(step_track['max_path_id'] + 1)
    active_states = [""]*(step_track['max_path_id'] + 1)

    bt_present = {}

    for uid in step_track['prev_states']:
        s = step_track['prev_states'][uid]['state']
        if s in temp:

            if s in active_states:
                print "**Duplicate Error**(during after_stepping_ops), temp_size", len(temp), "active_states_size", len(active_states), "prev_states_size", len(step_track['prev_states'])
                continue
            frame_no = step_track['prev_states'][uid]['bt_frame']
            path_id = step_track['prev_states'][uid]['path_id']

            #lets know how many states are in which bt_frame
            if frame_no in bt_present:
                bt_present[frame_no] += 1
            else:
                bt_present[frame_no] = 1

            if filter_by_bt:
                if int(frame_no,16) >= int(bt_frame_track, 16):
                    active_states[int(path_id)] = s
                    ordered_paths[int(path_id)] = hex(s.addr) + "@path "+str(path_id)+" @frame "+str(frame_no)
            else:
                active_states[int(path_id)] = s
                ordered_paths[int(path_id)] = hex(s.addr) + "@path "+str(path_id)+" @frame "+str(frame_no)

    active_states_count = len([s for s in active_states if s != "" ])
    if filter_by_bt:
        print "No of paths b4 filter_by_bt:", len(temp)
    #print "\n #Paths:", active_states_count, "@bt_frame", bt_frame_track,"@step", step_track['count']
    print "\n #Paths:", active_states_count, "@bt_frames", bt_present,"completed:", completed_paths,"pruned:", pruned_paths,"@step", step_track['count']

    return active_states_count



    #print "\n#Paths:", active_states_count, filter(lambda a: a != "", ordered_paths), "StepCount:", step_track['count']
    #print "\nGuide by BT: #Paths:", active_states_count, [s for s in  ordered_paths if s != ""], "StepCount:", step_track['count']






def start_timer():
    global temp_start_time
    temp_start_time = int(round(time.time()))

def end_timer():
    return int(round(time.time())) - temp_start_time



def do_forensic_analysis():
    # ==== FORENSIC LOADING AND EXTRACTION ===#
    print "Forensic Loading and Extraction ..."
    global regs_dict, p, init_state, backtrace, backtrace_lines, stack_frame_no, min_bt_size_attained, bt_frame_track, ida



    #== REMOTE OP===#
    if not os.path.isfile(local_dumps_folder + "/windbg.log"): #check if dumps have already being extracted
        #open the win7 vm network interface. if dumps already exist then you did not shut it down in the first place
        command_to_run = 'netsh interface set interface "Local Area Connection" admin=enable'
        print remote_command(command_to_run)
        command_to_run = 'netsh interface ip set dns  "Local Area Connection" static 8.8.8.8'
        print remote_command(command_to_run)
        command_to_run = 'netsh interface ip set dns  "Local Area Connection 2" static 8.8.8.8'
        print remote_command(command_to_run)
        remote_run_windbg()
        remote_retrieve_output()
    else:
        print local_dumps_folder + "/windbg.log already exists"
    #====+++++======#
    addr_set, file_dict =  sort_dumps()
    regs_dict = initial_process_windbg_log()
    analyze_loaded_symbols()
    backtrace, backtrace_lines = structure_backtrace()



    p = angr_load_blobs(addr_set, file_dict)
    init_state = p.factory.blank_state()

    if len(stack_frame_no) > 0: #if I have initialized it to something via command line arguments
        pass
    else:
        stack_frame_no = determine_stack_frame_of_interest(False, "0") #False means just return what value I passed to it
    print "\nFrame of Interest:", stack_frame_no
    if int(stack_frame_no, 16) != 0:
        #== REMOTE OP ==#
        remote_windbg_run_frame_registers(stack_frame_no)
        #====+++++++====#
        regs_dict = {}
        regs_dict = process_frame_register_log(stack_frame_no)
        init_state =  populate_registers_flags(init_state, regs_dict, only_non_volatile=True)
    else:
        init_state =  populate_registers_flags(init_state, regs_dict, only_non_volatile=False)

    #based on size of backtrace and stack_frame_no, initalize reamining backtrace stack size
    min_bt_size_attained = len(backtrace) - int(stack_frame_no, 16)
    bt_frame_track = stack_frame_no #bt_frame_track is used to track the global current best bt as the states are stepping
    ## == END OF FORENSIC LOADING AND STUFF ====#


def remote_deliver_run_capture():
    #deliver malware, execute, and attempt to capture
    remote_deliver_malware()
    global thread_crashed
    thread_crashed["thread1"] = True # on completion, thread should set this to False
    t = mythread("run", "thread1")
    t.setDaemon(True) #this enables the thread to die when my program exits
    t.start()
    #remote_run_malware()
    thread_crashed["thread2"] = True # on completion, thread should set this to False
    t2 = mythread("capture","thread2")
    t2.setDaemon(True) #this enables the thread to die when my program exits
    t2.start()
    #remote_attempt_capture(5)


    #suppose the malware hijacks the VM that the above two threads will be accessing, and holds those threads permanently for example asking for a password, and making them wait indefinetely, I want to detect that and tell the hypervisor to revert that VM
    detect_possible_malware_vm_hijack()
    print "sleeping for 10 secs to allow Windbg to finish the attach and dump of the process"
    time.sleep(10) #allowing Windbg time to inject itself and capture the process, before I check to see if a .dmp file is created. Also since the next step is to check whether remote_run_malware thread is still alive, its possible that the windbg inject and dump has not happened, so the remote_run_winbg may still be running. so lets wait for about 5 seconds for windbg to inject and jump the process, after which remote_run_malware will return and everything is good
    #if this is not enough, there is 4 more additional polling period to check if a .dmp was captured

    #at this point, remote_attempt_capture thread must have finished, otherwise detect_possible_malware_vm_hijack() will not return
    #it is also possible the there is problem with remote_run_malware() that made it not to return and hangs on the remote machine
    #it also possible the the .dump.sh command to capture the image with windbg hangs. I have seen this when windbg (on trying to capture a malicious process that is knowinly causing Windbg to act like this) is trying to communicate out (perhaps to get something from microsoft), but becos I have a honeypot, it will get stuck on asking if I want to trust the certificate of the honeypot (i.e asking me to press yes or no).
    #if all threads have returned,  this will eventually result in the VM ultimately getting reverted if no .dmp is present in the remote machine. So I have to check if all threads have returned, if not, i have to exit
    #lets check if remote_run_malware() has returned, if not, something went wrong, exit

    for my_thread in threading.enumerate():# this only enumerate thread that are still alive. still running the run() method
        if my_thread is not threading.current_thread():
            if my_thread.var == "run":
                #before we exit, lets give is a chance and poll of 50 seconds
                max_poll_time = 50 # secs.
                total_poll_time = 0
                poll_interval = 5 # secs
                while True:
                    if not my_thread.is_alive(): #to be set by remote_attempt_capture() after it completes
                        break
                    time.sleep(poll_interval)
                    total_poll_time += poll_interval
                    print "polling for the remote_run_malware() thread to finish..total poll time:", total_poll_time
                    if total_poll_time > max_poll_time:
                        print "So it appears that the remote_run_malware, i.e the 'run' thread, has not returned eventhough the 'capture' thread has. So this is not supposed to be the case unless malware has done something to hang our Windbg .dump operation, like asking Windbg a question that needs an answer, or doing something that is making Windbg ask for a certificate, or something like that. I have seen this with the hash d2a4e5b85df10366bfffd44556e58aeb20c58acee8fff2b37ca48e13ef37fad4. So I am aborting ..."
                        print "moving this sample", sample_hash, "to ", manual_triage
                        subprocess.check_output("mv " + path_to_malware + " " + manual_triage, shell=True)
                        forsee_exit(1)
            elif my_thread.var == "capture":
                print "Since threading.enumerate() only enumerates threads that are alive,  this should not happen because thread 'capture' should have returned before detect_possible_malware_vm_hijack() returns unless on some severe race condition issue "
                forsee_exit(1)
            else:
                print "This should not happen because I only have two threads"
                forsee_exit(1)


    for my_thread in threading.enumerate():
        if my_thread is not threading.current_thread():
            my_thread.join()

    if any_thread_crashed():
        print "It appears one of the thread run_malware or capture_malware crashed"
        #lets copy that sample into the crashed folder
        subprocess.call("mv " + path_to_malware + " " + malware_crashed_folder +"/"+malware, shell=True)
        #revert snapshot of vm for next malware
        forsee_exit(0)

    #lets check if the malware even ran
    if malware_did_not_run:
        print "It appears Malware", malware, "did not run. Aborting ..."
        #lets copy that sample into the malware_not_ran folder
        subprocess.call("mv " + path_to_malware + " " + malware_not_ran_folder +"/"+malware, shell=True)
        #revert snapshot of vm for next malware
        forsee_exit(0)

    if not was_captured(True):
        time.sleep(2)
        if not was_captured(True):
            time.sleep(2)
            if not was_captured(True):
                print "Attempt to capture Malware", malware, "had a problem. Aborting ..."
                #lets copy that sample into the malware_not_ran folder
                subprocess.call("mv " + path_to_malware + " " + malware_not_ran_folder +"/"+malware, shell=True)
                #revert snapshot of vm for next malware
                forsee_exit(0)


def any_thread_crashed():
    for t in thread_crashed:
        if thread_crashed[t]:
            print "Thread", t, "did not set its thread_crashed to False, hence it crashed"
            return True
    return False


def start_vm():
    try:
        status = subprocess.check_output('ssh moses@192.168.56.1 "/home/moses/forsee/start_vm.bash ' + vm_name + '"', shell=True)
        if "successfully started" not in status:
            print "I started VM ", vm_name, "but it looks like it did not start. Perhaps the output from vboxmanage changed:", status
    except Exception, e:
            print "attempt to start VM", vm_name, "had an exception. This forsee instance will poll and then finally exit. Other instances will do the same. Not good. Decommission this VM and find out whats going on: error: ", str(e)

def poweroff_vm():
    try:
        status = subprocess.check_output('ssh moses@192.168.56.1 "bash /home/moses/forsee/list_running_vms.bash ' + vm_name + '"', shell=True)
        if vm_name in status:
            status = subprocess.check_output('ssh moses@192.168.56.1 "/home/moses/forsee/poweroff_vm.bash ' + vm_name + '"', shell=True)
            print "powered off vm ", vm_name, "..."
    except Exception, e:
            print "attempt to poweroff  VM", vm_name, str(e)

def revert_vm():
    print "reverting vm", vm_name
    try:
        status = subprocess.check_output('ssh moses@192.168.56.1 "bash /home/moses/forsee/list_running_vms.bash ' + vm_name + '"', shell=True)
        if vm_name in status:
            subprocess.check_output('ssh moses@192.168.56.1 "/home/moses/forsee/poweroff_revert_vm.bash  ' + vm_name + ' &"', shell=True)
        else: # just revert, no power off
            subprocess.check_output('ssh moses@192.168.56.1 "/home/moses/forsee/revert_vm.bash  ' + vm_name + ' &"', shell=True)
    except Exception, e:
        print "attempt to poweroff and revert VM", vm_name, "had a problem", str(e)



def poll_for_vm_readiness():

    #revert it and then start it
    revert_vm()
    start_vm()

    max_poll_time = 60 # secs.
    total_poll_time = 0
    poll_interval = 3 # secs
    print "Checking if vm", vm_name, "is ready .."
    while True:
        try:
            output = remote_command("ls")
            if "ps1" in output: #there are powershell scripts in the home directory
                #sys.exit(0)
                return

        except Exception, e:
            print "Polling vm for readiness. Total poll time", total_poll_time, "sec", str(e)
            time.sleep(poll_interval)
            total_poll_time  += poll_interval
            if total_poll_time > max_poll_time:
                print "After polling for ", max_poll_time," it seems like the vm", vm_name, "will not start. Aborting.."
                sys.exit(1) #do not remove yourself from the repo via forsee_exit() ince the VM is probably dead or something


def detect_possible_malware_vm_hijack():
    print "detecting_possible_malware_vm_hijack.."
    max_poll_time = 120 # secs.
    total_poll_time = 0
    poll_interval = 3 # secs

    while True: # I will poll for 60 seconds
        if POSSIBLE_MALWARE_VM_HIJACK == False: #to be set by remote_attempt_capture() after it completes
            print "POSSIBLE_MALWARE_VM_HIJACK is ", POSSIBLE_MALWARE_VM_HIJACK, ". Got is well signal  in ", total_poll_time, "secs"
            break
        time.sleep(poll_interval)
        total_poll_time += poll_interval
        if total_poll_time > max_poll_time:
            print "There seem to be a possible VM HIJACK on VM", vm_name, "on IP:", remote_vm_ip, "by malware", malware, "please investigate this malware. I am removing the sample from the malware HIVE to manual_triage HIVE. On aborting the Hypervisor will revert this VM"
            subprocess.check_output("mv " + path_to_malware + " " + manual_triage, shell=True)
            print "Aborting ..."
            forsee_exit(1)




def main():
    global path_to_malware, malware_repo
    if not os.path.isfile(local_dumps_folder + "/windbg.log"): #if a local extracted dumps does not exists

        poll_for_vm_readiness() #start the VM and wait for it to start

        if not was_captured(False) : #this will check if a .dmp has already being captured so no need to rerun the malware. False means we know, so just say its not captured.
            remote_deliver_run_capture()
        else:
            print ".dmp for ",malware," already exists in remote machine"

        if thread_reported_problem:
            print "it appears a thread reported a problem: ", thread_message
            print "Aborting .."
            subprocess.call("mv " + path_to_malware + " " + malware_crashed_folder + "/"+malware, shell=True)
            #revert snapshot of vm for next malware
            forsee_exit(1)

    print "About to start the forensic and static analysis modules"
    global ss, regs_dict, p, init_state, step_track, backtrace, backtrace_lines, active_states, stack_frame_no, min_bt_size_attained, bt_frame_track, ida, ida2, BUI_total_funcs



    #do the static analysis and forensic analysis in multi-threaded way
    global thread_crashed

    thread_crashed["thread2"] = True # on completion, thread should set this to False
    t2 = mythread("forensic_analysis", "thread2") #do_forensic_analysis()
    t2.setDaemon(True) #this enables the thread to die when my program exits
    t2.start()
    for my_thread in threading.enumerate():
        if my_thread is not threading.current_thread():
            my_thread.join()

    #release the vm for next malware
    release_vm()

    if any_thread_crashed():
        print "It appears one of the thread crashed during the static and forensic analysis stage, Aborting..."
        subprocess.call("mv " + path_to_malware + " " + malware_crashed_folder + "/"+malware, shell=True)
        #IPython.embed()
        forsee_exit(0)

    if thread_reported_problem:
        print "it appears a thread reported a problem  during the static and forensic analysis stage:", thread_message
        print "Aborting .."
        subprocess.call("mv " + path_to_malware + " " + malware_crashed_folder + "/"+malware, shell=True)
        forsee_exit(1)

    #IF IT MAKES IT PAST THIS POINT, the malware should give us results. Move the malware to the appropriate location and change the global variables of this location
    if check_if_multi_threaded():
        print "It appears the malware is not single threaded, but i will only process thread 0"
        subprocess.call("mv " + path_to_malware + " " + malware_multi_threaded_folder + "/"+malware, shell=True)
        malware_repo = malware_multi_threaded_folder
        path_to_malware = malware_multi_threaded_folder + "/" + malware
        #forsee_exit(1)
    else:
        #move malware to malware_ran_folder
        subprocess.call("mv " + path_to_malware + " " + malware_ran_folder +"/"+BUI_arch+"/"+malware, shell=True)
        malware_repo = malware_ran_folder + "/" + BUI_arch
        path_to_malware = malware_ran_folder + "/" + BUI_arch + "/" + malware







    ip = long("0x" + regs_dict[regs_map['ip']],16)





    #initialize the stepping data structure that tracks things like conditional jmps in the about-to-be-stepped block
    to_check = str(p.factory.block(init_state.addr).capstone)
    if "j"  in to_check and 'jmp' not in to_check:
        steping[0]['cond_jmps'] += 1

    active_states = [init_state]
    step_track = {'count': 0, 'prev_states':{}, 'max_path_id':0}
    state_info = {'addr':init_state.addr,'bt_frame': "0x" + stack_frame_no, 'path_id':0, 'min_bt_size_attained': min_bt_size_attained ,'parent': None, 'children':[], 'call_trace':[]}
    uid = hash(str(init_state.addr))
    step_track['prev_states'][uid] = state_info
    path_id = 0
    paths_info['lib_calls'][path_id] = []

    global BUI_reached_funcs



    #lets construct the call_trace
    call_trace =[]
    call_len = len(backtrace)
    frame_to_start = int(stack_frame_no,16)
    call_trace.append({hex(ip):{'block_count':1, 'ret_addr':backtrace[hex(int(stack_frame_no,16))]['ret_addr']}}) #for the first frame
    #print frame_to_start, call_len
    for frame_no in xrange(frame_to_start + 1, call_len):
        #print "frame ", frame_no, " addr: ", backtrace[hex(frame_no)]['ret_addr']
        func_ret_addr = backtrace[hex(frame_no)]['ret_addr']
        addr_inside_func = backtrace[hex(frame_no - 1)]['ret_addr']#The previous fxn's ret addr: since we cannot really know the address that called the function(from this context), but we can know just one of the addresses inside the fxn i.e where control will return inside the fxn
        call_trace.insert(0,{addr_inside_func:{'block_count':1, 'ret_addr':func_ret_addr}})

    step_track['prev_states'][uid]['call_trace'] = call_trace# call_trace is a list of dict
    #graph things
    graph_id = "0-0"
    cfa = "" #current func addr
    for key in call_trace[-1]:
        cfa = key.replace("L","")
    label = "IP:"+hex(ip).replace("L","")+"\nframe:"+stack_frame_no+"\nf: "+cfa+"\ncall_stack: "+str(len(call_trace))
    step_track['prev_states'][uid]['graph_label'] = {'graph_id':graph_id, 'parent_graph_id':graph_id, 'label':label,'cs':0,'syscalls':0,'child_list':[], 'legit_loops':0, 'sym_loops':0, 'frame-tran':'','steps':0,'addr':hex(ip)}
    label = graph_id +"\n"+ step_track['prev_states'][uid]['graph_label']['label']

    init_dot_graph()
    dot.node(graph_id, label, shape='Mdiamond')
    step_and_show(5000, BUI_restrict=True, limit=500)

def forsee_exit(code):
    print "removing workspace folder", workspace_folder
    subprocess.call("rm -r " + workspace_folder, shell=True)
    release_vm()
    sys.exit(code)
    subprocess.call("kill -9 " + str(os.getpid()), shell=True)# just incase sys.exit is too weak to kill this, lol

def release_vm():
    global vm_released
    if not vm_released:
        poweroff_vm() #shut it down to conserve RAM
        #puts the vm in the vm_ready pool for others
        subprocess.call("touch " + vm_ready_pool + "/" + remote_vm_ip, shell=True)
        vm_released = True

if __name__ == "__main__":
    main()
    #try:
        #main()
    #except Exception, e:
        #print "Exception wrapped aroung main(): ", str(e)
    forsee_exit(0)


#idc.Exit(0)
