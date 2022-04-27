import glob
import os

maxClassID = 104
binaryCnt = {}

for fileName in glob.glob('/home/newdisk/gyx/SCIS/dataset/POJ/poj_data/modelInput/gcc/O3/*'):
    binaryName = fileName.split('/')[-1]
    classId = int(binaryName.split('_')[2])
    
    if classId not in binaryCnt:
        binaryCnt[classId] = 1
    else:
        binaryCnt[classId] += 1

print(sorted(binaryCnt.items(),key=lambda kv:kv[0]))