#! /usr/bin/env python
import sys  
import networkx as nx
import numpy as np
import angr
import argparse
import os
import time
from collections import defaultdict
import sparse as sp #version 0.1.0
import pickle
import json


parser = argparse.ArgumentParser()
parser.add_argument('--target_program', type=str, default='null', help='target_program type(poj/spec)')
parser.add_argument('--arch_t', type=str, default='x86', help='type of arch')
parser.add_argument('--output', type=str, default='./', help='output path')
parser.add_argument('--input', type=str, default='./', help='input path')
parser.add_argument('--comp_t', type=str, default='gcc', help='type of compiler')
parser.add_argument('--opti_t', type=str, default='O2', help='type of optimization')
parser.add_argument('--pro_class', type=str, default='0', help='program class')
parser.add_argument('--filename', type=str, default='0', help='program filename')
#python dfg_build.py --output=poj_data --comp_t=gcc --opti_t=O3 --pro_class=1 --filename=1984 --target_program=poj

child_dic = defaultdict(int)
father_dic = defaultdict(int)
func_list=[]
pro_id='0'

def m_to_sparse(m):
    return sp.COO(m)

def m_to_dense(ms):
    return ms.todense()

def analyze(b, addr, progname=None):
    print(time.strftime('%d %H:%M:%S',time.localtime(time.time()))+'[DEBUG] analyze start',progname)
    cfg = b.analyses.CFGEmulated(resolve_indirect_jumps=False,context_sensitivity_level=2, keep_state=True,state_add_options=angr.sim_options.refs) 
    print(time.strftime('%d %H:%M:%S',time.localtime(time.time()))+'[DEBUG] CFG build finish',progname)
    ddg = b.analyses.DDG(cfg,start=cfg.functions['main'].addr)
    A=np.array(nx.adjacency_matrix(ddg.graph).todense())
    print(time.strftime('%d %H:%M:%S',time.localtime(time.time()))+'[DEBUG] DDG build finish',progname,len(A))
    AS = sp.lil_matrix(A) #turn to sparse matrix of A_block to save space
    np.save(f_adj,AS)
    print(ddg.graph.number_of_nodes(),file=f_node)
    for n in ddg.graph.nodes():
        print(n,file=f_node)


def get_cfg_data(cfg):
    func_list=[]
    for addr,func in cfg.kb.functions.items():
        block_cnt=0
        for node in func.nodes():
            if isinstance(node,angr.codenode.BlockNode):
                block_cnt += 1
        if (len(list(func.blocks)) != block_cnt) or (block_cnt==0):
            continue
        func_list.append(addr)
    return func_list

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
    return new_A, new_node_list

def analyze_subgraph(b, addr, progname=None):
    print(time.strftime('%d %H:%M:%S',time.localtime(time.time()))+'[DEBUG] analyze start',progname)
    cfg = b.analyses.CFGFast() 
    func_list = get_cfg_data(cfg)
    #ddg = b.analyses.DDG(cfg,start=cfg.functions['main'].addr)
    print(time.strftime('%d %H:%M:%S',time.localtime(time.time()))+'[DEBUG] CFG_FAST finish',progname)
    func_dfg_list = []
    
    for func in func_list:
        startList=[]
        startList.append(func)
        cfg = b.analyses.CFGEmulated(starts=startList,resolve_indirect_jumps=False,context_sensitivity_level=0, keep_state=True,state_add_options=angr.sim_options.refs,call_depth=0)  #, call_depth=0
        #print(time.strftime('%d %H:%M:%S',time.localtime(time.time()))+'[DEBUG] CFG build for program',progname,'finish. startList =',startList)
        # debugFuncList=[]
        # for debugaddr,debugfunc in cfg.kb.functions.items():
        #     for node in debugfunc.nodes():
        #         if isinstance(node,angr.codenode.BlockNode):
        #             debugFuncList.append(node)
        # print(debugFuncList)
        # print('func cfg get.')
        
        ddg = b.analyses.DDG(cfg,start=func,call_depth=0)
        if (ddg.graph.size()<=0):
            print(time.strftime('%d %H:%M:%S',time.localtime(time.time()))+'[DEBUG] DDG for progname',progname,'build finish (func',func,' Null graph)')
            continue
        A=np.array(nx.adjacency_matrix(ddg.graph).todense())
        print(time.strftime('%d %H:%M:%S',time.localtime(time.time()))+'[DEBUG] DDG for progname',progname,'build finish (func',func,' #Node ',len(A),')')
        # np.save(f_adj,AS)
        # print(ddg.graph.number_of_nodes(),file=f_node)
        # for n in ddg.graph.nodes():
        #     print(n,file=f_node)
        dfg_node_list = []
        for n in ddg.graph.nodes():
            if isinstance(n.ins_addr,int):
                dfg_node_list.append(n.ins_addr)
            else:
                dfg_node_list.append(-1)
        A,dfg_node_list = dfg_remove(A,dfg_node_list)
        AS = m_to_sparse(A) #turn to sparse matrix of A_block to save space
        new_dfg = {'func_addr':func,'DFGAS':AS,'dfg_node_list':dfg_node_list}
        func_dfg_list.append(new_dfg)
        #print('DFG:',func,dfg_node_list)
    f=open(out_name+'_graph.pkl','wb')
    pickle.dump(func_dfg_list, f, pickle.HIGHEST_PROTOCOL)


if __name__ == "__main__":
    arg = parser.parse_args()
    pro_class = arg.pro_class
    filename = arg.filename
    comp_t = arg.comp_t
    opti_t = arg.opti_t
    output_path = arg.output
    arch_t = arg.arch_t
    target_program = arg.target_program
    if target_program=="poj":
        in_path='/workspace/SCIS/dataset/POJ/poj_data/binaryAllType/'+comp_t+'/'+opti_t+'/'+pro_class+'/'+filename
        #out_name = '/workspace/SCIS/dataset/POJ/poj_data/modelInput/'+comp_t+'/'+opti_t+'/'+pro_class+'/'+filename #same path; different name with cfg
        out_name = './debug_out'
    elif target_program=="spec":
        in_path='../../specBenchmark/'+comp_t+'_'+opti_t+'/'+filename+'/'+filename
        if opti_t=="o2":
            opti_t_out="O2"
        elif opti_t=="o3":
            opti_t_out="O3"
        else:
            print("Error opti_t.")
        out_name = output_path+'/'+comp_t+'_'+opti_t_out+'/'+filename #same path; different name with cfg
    else:
        in_path="./debug"
        out_name = "./debug" 
    print(out_name)
    print('in_path:',in_path)
    proj = angr.Project(in_path, load_options={'auto_load_libs':False},default_analysis_mode='symbolic')
       
    main = proj.loader.main_object.get_symbol("main")
    if target_program=="poj":
        f_node_name = out_name+"_dfg_arg"
        f_node = open(f_node_name,'w+')
        f_adj_name = out_name+"_dfg_adj"
        f_adj = open(f_adj_name,'wb+')
        analyze(proj, main.rebased_addr, filename)
    elif target_program=="spec":
        analyze_subgraph(proj, main.rebased_addr, comp_t+'_'+opti_t_out+'_'+filename)
    else: #debug
        analyze_subgraph(proj, main.rebased_addr, comp_t+'_'+opti_t_out+'_'+filename)
