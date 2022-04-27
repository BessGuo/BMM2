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

def analyze(b, addr, progname=None):
    print(time.strftime('%d %H:%M:%S',time.localtime(time.time()))+'[DEBUG] analyze start',progname)
    cfg = b.analyses.CFGEmulated(resolve_indirect_jumps=False,context_sensitivity_level=2, keep_state=True,state_add_options=angr.sim_options.refs) 
    print(time.strftime('%d %H:%M:%S',time.localtime(time.time()))+'[DEBUG] CFG build finish',progname)
    ddg = b.analyses.DDG(cfg,start=cfg.functions['main'].addr)

def analyze_dfg(b, progname=None):
    print(time.strftime('%d %H:%M:%S',time.localtime(time.time()))+'[DEBUG] analyze start',progname)
    cfg = b.analyses.CFGEmulated(resolve_indirect_jumps=False,context_sensitivity_level=2, keep_state=True,state_add_options=angr.sim_options.refs) 
    print(time.strftime('%d %H:%M:%S',time.localtime(time.time()))+'[DEBUG] CFG build finish',progname)
    ddg = b.analyses.DDG(cfg,start=cfg.functions['main'].addr)
    A=np.array(nx.adjacency_matrix(ddg.graph).todense())
    print(time.strftime('%d %H:%M:%S',time.localtime(time.time()))+'[DEBUG] DDG build finish',progname,len(A))

if __name__ == "__main__":
    # # ----- from poj_build_graph.py
    inpath = '/workspace/SCIS/dataset/POJ/poj_data/binaryAllType/gcc/O3/1/1984'
    proj = angr.Project(inpath, load_options={'auto_load_libs':True},default_analysis_mode='symbolic')
    analyze_dfg(proj,'debug-1984')

    # #------ from dfg_build.py
    # in_path = '/workspace/SCIS/dataset/POJ/poj_data/binaryAllType/gcc/O3/1/1984'
    # print('in_path:',in_path)
    # proj = angr.Project(in_path, load_options={'auto_load_libs':False},default_analysis_mode='symbolic')
       
    # main = proj.loader.main_object.get_symbol("main")
    # analyze(proj, main.rebased_addr, 'debug-1984')




                
    




    