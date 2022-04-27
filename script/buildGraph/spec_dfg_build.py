#! /usr/bin/env python
import sys  
import networkx as nx
import numpy as np
import angr
import argparse
import os
from collections import defaultdict
#import scipy.sparse as sp
import pickle
import json
import time
import glob
import threading
import sparse as sp #version 0.1.0


parser = argparse.ArgumentParser()
parser.add_argument('--target_program', type=str, default='debug', help='target_program type(poj/spec)')
parser.add_argument('--arch_t', type=str, default='x86', help='type of arch')
parser.add_argument('--output', type=str, default='./', help='output path')
parser.add_argument('--input', type=str, default='./', help='input path')
parser.add_argument('--comp_t', type=str, default='gcc', help='type of compiler')
parser.add_argument('--opti_t', type=str, default='O2', help='type of optimization')
parser.add_argument('--pro_class', type=str, default='0', help='program class')
parser.add_argument('--filename', type=str, default='0', help='program filename')
#python dfg_build.py --output=poj_data --comp_t=gcc --opti_t=O2 --pro_class=1 --pro_id=1020

child_dic = defaultdict(int)
father_dic = defaultdict(int)
pro_id='0'


def m_to_sparse(m):
    return sp.COO(m)

def m_to_dense(ms):
    return ms.todense()

# def load_cfg_arg():
    # path = '../angr/'+compiler+'_'+opti_t+'_test_data/'
    # cg_path = path+compiler+'_'+opti_t+'_test_cg/'+
    # result_path = path+compiler+'_'+opti_t+'_test_result/'
    # cg_arg_f = open(cg_path+'node_'+filename)
    # cg_adj_f = open(cg_path+'adj_'+filename)
    # cfg_arg_f = open(result_path+'arg_'+filename)
    # cfg_adj_f = open(result_path+'adj_'+filename)
    # bb_f = open(result_path+'bb_'+filename)

def dfg_remove(A, node_list):
    new_node_list = list(set(node_list))
    new_A = np.zeros((len(new_node_list),len(new_node_list)))
    addr_to_newi = {}
    oldi_to_newi = {}
    for i in range(len(new_node_list)):
        addr_to_newi[new_node_list[i]]=i
    
    for i in range(len(node_list)):
        oldi_to_newi[i]=addr_to_newi[node_list[i]]
    
    for i in range(len(A)):
        for j in range(len(A[0])):
            if A[i,j]==1:
                new_A[oldi_to_newi[i],oldi_to_newi[j]]=1
    #print('node_list',node_list,'\n',A)
    #print('new_node_list',new_node_list,'\n',new_A)
    return new_A, new_node_list

def get_bb_inst(block):
    #print(type(block.disassembly),str(block.disassembly))
    inst_list = []
    # for inst in block.disassembly.insns:
    #     print(type(inst.op_str),inst.op_str)
    #     inst_list.append(inst.op_str)
    inststr = str(block.disassembly)
    inst_list = inststr.split('\n')
    #print('inststr:',inststr,'inst_list:',inst_list)
    return inst_list


def get_cfg_data(cfg):
    func_list=[]
    for addr,func in cfg.kb.functions.items():
        graph_f = func.transition_graph
        i=0
        block_cnt=0
        node_list=[]
        for node in func.nodes():
            #print("node:",node,"type:",type(node),isinstance(node,angr.codenode.BlockNode))
            #print(dir(node))
            if isinstance(node,angr.codenode.BlockNode):
                node_list.append(i)
                block_cnt += 1
            i=i+1
        #print(len(list(func.nodes())),len(list(func.blocks)),len(np.array(nx.adjacency_matrix(graph_f).todense())))
        #print("node_list",node_list,len(list(func.blocks)),block_cnt)
        if (len(list(func.blocks)) != block_cnt) or (block_cnt==0):
            continue

        A=np.array(nx.adjacency_matrix(graph_f).todense())
        A_block = A[:,node_list]
        A_block = A_block[node_list,:]
        A_block = A_block.astype(np.int16)
        CFGAS = m_to_sparse(A_block) #turn to sparse matrix of A_block to save space

        bb_list=[]
        for block in func.blocks:
            if block.size>0:
                # print(block.instructions,end=" ",file=f_arg)
                # block.pp()
                inst_list = get_bb_inst(block)
                #print('bb:',inst_list)
                new_bb = {'bb_addr':block.instruction_addrs[0],'bb':inst_list}
                bb_list.append(new_bb)
            else:
                #print(0,end=" ",file=f_arg)
                new_bb = {'bb_addr':0,'bb':''}
                bb_list.append(new_bb)
        #print("\n",file=f_arg)
        if(len(bb_list) != block_cnt):
            print('[ERROR] len(bb_list) != block_cnt')
        
        new_cfg = {'addr':addr,'block_cnt':block_cnt,'cfg':CFGAS,'bb_list':bb_list,'dfg':None}
        func_list.append(new_cfg)
    return func_list

def get_cg_data(cfg):
    #cfg = b.analyses.CFGFast() 
    cg = cfg.functions.callgraph
    A=np.array(nx.adjacency_matrix(cg).todense())
    CGAS = m_to_sparse(A) #turn to sparse matrix
    cg_node_list = []
    print('CG node amount:',cg.number_of_nodes())
    for n in cg.nodes():
        cg_node_list.append(n)
    return CGAS, cg_node_list


def analyze(b, addr, progname, out_name):
    print(time.strftime('%d %H:%M:%S',time.localtime(time.time()))+'[DEBUG] analyze start',progname)
    f_node_name = out_name+"_dfg_arg"
    f_node = open(f_node_name,'w+')
    f_adj_name = out_name+"_dfg_adj"
    f_adj = open(f_adj_name,'wb+')
    f_cfg_name = out_name+"_cfg"

    cfg = b.analyses.CFGEmulated(resolve_indirect_jumps=False,context_sensitivity_level=1, keep_state=True,state_add_options=angr.sim_options.refs) 
    print(time.strftime('%d %H:%M:%S',time.localtime(time.time()))+'[DEBUG] cfg build finish',progname)
    func_list = get_cfg_data(cfg)
    print(time.strftime('%d %H:%M:%S',time.localtime(time.time()))+'[DEBUG] func_list build finish',len(func_list))

    CGAS, cg_node_list = get_cg_data(cfg)
    print(time.strftime('%d %H:%M:%S',time.localtime(time.time()))+'[DEBUG] cg build finish')


    for func in func_list:
        bb_addr_list = []
        for bb in func['bb_list']:
            bb_addr_list.append(bb['bb_addr'])

        #ddg = b.analyses.DDG(cfg,start=cfg.functions['main'].addr)
        ddg = b.analyses.DDG(cfg,start=func['addr'],call_depth=0,block_addrs=bb_addr_list)
        A=np.array(nx.adjacency_matrix(ddg.graph).todense())
        print(time.strftime('%d %H:%M:%S',time.localtime(time.time()))+'[DEBUG] DDG build finish',progname,func['addr'],len(A))
        

        #np.save(f_adj,AS)
        #print(ddg.graph.number_of_nodes(),file=f_node)
        dfg_node_list = []
        for n in ddg.graph.nodes():
            #print(n,file=f_node)
            #print(n,type(n.ins_addr),'\n')
            if isinstance(n.ins_addr,int):
                dfg_node_list.append(n.ins_addr)
            else:
                dfg_node_list.append(-1)
        #print('[DEBUG]',dfg_node_list,'\n',A)
        A,dfg_node_list = dfg_remove(A,dfg_node_list)
        AS = m_to_sparse(A) #turn to sparse matrix of A_block to save space
        new_dfg = {'DFGAS':AS,'dfg_node_list':dfg_node_list}
        func['dfg']=new_dfg
    new_sample = {'func_list':func_list, 'CGAS':CGAS, 'cg_node_list':cg_node_list}
    f=open(out_name+'_graph.pkl','wb')
    pickle.dump(new_sample, f, pickle.HIGHEST_PROTOCOL)


def analyze_dfg(b, addr, progname, out_name):
    print(time.strftime('%d %H:%M:%S',time.localtime(time.time()))+'[DEBUG] analyze start',progname)

    cfg = b.analyses.CFGEmulated(resolve_indirect_jumps=False,context_sensitivity_level=0, keep_state=True,state_add_options=angr.sim_options.refs)  #,call_depth=0
    print(time.strftime('%d %H:%M:%S',time.localtime(time.time()))+'[DEBUG] cfg build finish',progname)
    
    func_list = get_cfg_data(cfg)
    print(time.strftime('%d %H:%M:%S',time.localtime(time.time()))+'[DEBUG] func_list build finish',len(func_list))

    CGAS, cg_node_list = get_cg_data(cfg)
    print(time.strftime('%d %H:%M:%S',time.localtime(time.time()))+'[DEBUG] cg build finish')

    bb_addr_list = []
    for func in func_list:
        for bb in func['bb_list']:
            bb_addr_list.append(bb['bb_addr'])
    print('[DEBUG] program bb amount:',len(bb_addr_list))

    ddg = b.analyses.DDG(cfg,start=cfg.functions['main'].addr,block_addrs=bb_addr_list) #,call_depth=1
    #ddg = b.analyses.DDG(cfg,start=func['addr'],call_depth=0,block_addrs=bb_addr_list)
    A=np.array(nx.adjacency_matrix(ddg.graph).todense())
    print(time.strftime('%d %H:%M:%S',time.localtime(time.time()))+'[DEBUG] DDG build finish',progname,len(A))
    
    dfg_node_list = []
    for n in ddg.graph.nodes():
        if isinstance(n.ins_addr,int):
            dfg_node_list.append(n.ins_addr)
        else:
            dfg_node_list.append(-1)
    A,dfg_node_list = dfg_remove(A,dfg_node_list)
    print(time.strftime('%d %H:%M:%S',time.localtime(time.time()))+'[DEBUG] DDG remove same nodes',len(A))
    AS = m_to_sparse(A) #turn to sparse matrix of A_block to save space
    #new_dfg = {'DFGAS':AS,'dfg_node_list':dfg_node_list}

    new_sample = {'func_list':func_list, 'DFGAS':AS,'dfg_node_list':dfg_node_list, 'CGAS':CGAS, 'cg_node_list':cg_node_list}
    f=open(out_name+'_graph.pkl','wb')
    pickle.dump(new_sample, f, pickle.HIGHEST_PROTOCOL)
    print('FINISH:',out_name)
    #print(dfg_node_list)
    #check_dfg(dfg_node_list)

def analyze_dfg_for_sample(b, cfg, bench_id, data_path, binary_type, cfg_func_list):
    #"/sample_"+str(compile_tag)+'_'+str(bench_id)+'_'+str(func.deadlabel)+'_'+str(sample_id_index)+'_'+str(func_addr)+copy_tag[i]
    #sample_0_4_0_432_4105696_a.pkl
    
    last_loop_finish = -1
    data_list = glob.glob(data_path+"sample_"+str(binary_type)+"_"+str(bench_id)+"_*_*_*_a.pkl")
    data_list.sort()
    pre_data_lenth = 0
    while len(data_list) > pre_data_lenth:
        pre_data_lenth = len(data_list)
        for i in range(last_loop_finish+1,len(data_list)):
            print(data_list[i])
            compile_tag,bench_id,deadlabel,sample_id_index,func_addr,copy_tag = data_list[i].split('sample_')[-1].split('_')
            out_name = data_list[i].split('.')[0]
            func_addr = int(func_addr)

            if func_addr not in cfg_func_list:
                print('[ERROR] func',func_addr,'not in cfg')
                continue

            #ddg = b.analyses.DDG(cfg,start=cfg.functions['main'].addr,block_addrs=bb_addr_list) #,call_depth=1
            try:
                ddg = b.analyses.DDG(cfg,start=func_addr,call_depth=0)
                print(ddg.graph,type(ddg.graph),ddg.has_node)
                A=np.array(nx.adjacency_matrix(ddg.graph).todense())
            except:
                print('[ERROR] wrong, no ddg create',func_addr)
                continue

            
            #print(time.strftime('%d %H:%M:%S',time.localtime(time.time()))+'[DEBUG] DDG build finish',progname,len(A))
            
            dfg_node_list = []
            for n in ddg.graph.nodes():
                if isinstance(n.ins_addr,int):
                    dfg_node_list.append(n.ins_addr)
                else:
                    dfg_node_list.append(-1)
            A,dfg_node_list = dfg_remove(A,dfg_node_list)
            #print(time.strftime('%d %H:%M:%S',time.localtime(time.time()))+'[DEBUG] DDG remove same nodes',len(A))
            AS = m_to_sparse(A) #turn to sparse matrix of A_block to save space
            #new_dfg = {'DFGAS':AS,'dfg_node_list':dfg_node_list}

            new_sample = {'DFGAS':AS,'dfg_node_list':dfg_node_list,'DFG_addr':func_addr}
            f=open(out_name+'_dfg.pkl','wb')
            #pickle.dump(new_sample, f, pickle.HIGHEST_PROTOCOL)
            print('[DEBUG] dfg save to',out_name+'_dfg.pkl')

        print('[RUN] sample',len(data_list)-1,'finish (',data_list[-1],')')
        last_loop_finish = len(data_list)-1
        data_list = glob.glob(data_path0+"sample_"+str(binary_type)+"_"+str(bench_id)+"_*_*_*_a.pkl")
        data_list.sort()


def check_dfg(dfg_node_list):
    func_addr_in = 0
    func_addr_amount = 0 
    arg_f = open('../angr/gcc_o2_test_data/gcc_o2_test_result/arg_520.omnetpp_r')
    arg_line = arg_f.readline()
    while arg_line: #every func
        func_addr,bb_amount = map(int,arg_line.split())
        func_addr_amount += 1
        if (func_addr in dfg_node_list):
            func_addr_in += 1
        arg_line = arg_f.readline()
        arg_line = arg_f.readline()
        arg_line = arg_f.readline()
    print('[DEBUG] check dfg:',func_addr_in,'/',func_addr_amount)


class myThread (threading.Thread):
    def __init__(self, threadID, name, b, cfg, bench_id, data_path, binary_type, cfg_func_list):
        threading.Thread.__init__(self)
        self.threadID = threadID
        self.name = name       
        self.b = b
        self.cfg = cfg
        self.bench_id = bench_id #0-11
        self.data_path = data_path
        self.binary_type = binary_type
        self.cfg_func_list = cfg_func_list
        print('Thread create:', threadID, name, b, cfg, bench_id, data_path, binary_type)

    def run(self):
        analyze_dfg_for_sample(self.b, self.cfg,self.bench_id,self.data_path,self.binary_type,self.cfg_func_list)
        print ("Finish thread:" + self.name)

if __name__ == "__main__":
    arg = parser.parse_args()
    pro_class = arg.pro_class
    filename = arg.filename
    comp_t = arg.comp_t
    opti_t = arg.opti_t
    output_path = arg.output
    input_path = arg.input
    arch_t = arg.arch_t
    target_program = arg.target_program
    if target_program=="poj":
        in_path='/home/angr/workspace/POJ/'+input_path+'/'+pro_class+'/'+filename+'-'+comp_t+'-'+opti_t
        out_name = output_path+'/'+comp_t+'/'+opti_t+'/'+pro_class+'/'+filename #same path; different name with cfg
    elif target_program=="spec":
        in_path='/home/newdisk/gyx/SC/specBenchmark/'+comp_t+'_'+opti_t+'/'+filename+'/'+filename
        if opti_t=="o2":
            opti_t_out="O2"
        elif opti_t=="o3":
            opti_t_out="O3"
        else:
            print("Error opti_t.")
        out_name = output_path+'/'+comp_t+'_'+opti_t_out+'_'+filename #same path; different name with cfg
    else:
        in_path="./debug"
        out_name = "./debug_out" 
    print(out_name)


    proj = angr.Project(in_path, load_options={'auto_load_libs':False},default_analysis_mode='symbolic')

    data_file_list=["505.mcf_r","508.namd_r","510.parest_r","520.omnetpp_r","523.xalancbmk_r","544.nab_r","557.xz_r","526.blender_r","502.gcc_r","511.povray_r","538.imagick_r","541.leela_r"]
    for i in range(12):
        if filename == data_file_list[i]:
            bench_id = i
            break

    print('[PROG]',in_path) 
    main = proj.loader.main_object.get_symbol("main")

    #analyze_dfg(proj, main.rebased_addr,in_path.split('/')[-1],out_name)

    print(time.strftime('%d %H:%M:%S',time.localtime(time.time()))+'[DEBUG] analyze start',in_path.split('/')[-1])
    cfg = proj.analyses.CFGEmulated(resolve_indirect_jumps=False,context_sensitivity_level=0, keep_state=True,state_add_options=angr.sim_options.refs)  #,call_depth=0
    print(time.strftime('%d %H:%M:%S',time.localtime(time.time()))+'[DEBUG] cfg build finish',in_path.split('/')[-1])
    data_path0 = '/data_hdd/myself/guanxin/gpu02/poj_bench/pre_data/spec_nodfg_balance2/0/'
    data_path1 = '/data_hdd/myself/guanxin/gpu02/poj_bench/pre_data/spec_nodfg_balance2/1/'
    cfg_func_list = []
    for addr,func in cfg.kb.functions.items():
        cfg_func_list.append(addr)
    print('FUNC LIST:',cfg_func_list)

    if comp_t=='llvm' and opti_t=='o2':
        binary_type=0
    if comp_t=='llvm' and opti_t=='o3':
        binary_type=1
    if comp_t=='gcc' and opti_t=='o2':
        binary_type=4
    if comp_t=='gcc' and opti_t=='o3':
        binary_type=5
    
    #self, threadID, name, cfg, bench_id, data_path
    threads = []
    t_name = "Thread-0"
    t = myThread(0, t_name, proj, cfg, bench_id, data_path0, binary_type, cfg_func_list)
    threads.append(t)
    t_name = "Thread-1"
    t = myThread(1, t_name, proj, cfg, bench_id, data_path1, binary_type, cfg_func_list)
    threads.append(t)
    
    for i in range(len(threads)):
        threads[i].start()

    for i in range(len(threads)):
        threads[i].join()
                


