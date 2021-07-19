# =============================================================================
# #Libraries
# =============================================================================
import glob #usa per importare dei file di testo
from os import system as cmd #usa per importare comandi dalla command line
import os
import shutil
import sys   #usa per avere dei breakpoint
import pyshark
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from collections import Counter
import copy

dataFrame = pd.read_pickle("PacketDataframe.pkl")
folder_image = "Image"

#Remove directory already created
try:
    shutil.rmtree(folder_image)
except:
    pass

try:
    os.mkdir(folder_image)
#If you have already created it Error
except OSError:
    print("Creation of the directory %s failed" % folder_image)
else:
    print("Successfully created the directory %s" % folder_image)
folder_image = "./Image/"


def bitRate(data, step_sec = 0.1):
    start = data.iloc[0]["time"]
    finish = data.iloc[-1]["time"]
    print("Start: ",start)
    print("Finish: ",finish)
    
    
    data["time"] -= data.iloc[0]["time"]
    start = data.iloc[0]["time"]
    finish = data.iloc[-1]["time"]
    
    print("Start: ",start)
    print("Finish: ",finish)
    
    step = finish/ step_sec
    finish = start + step_sec
    value = []
    print(step)
    for i in range(int(step)):
    
        #From Byte to bit
        val = np.sum(data[(data["time"]>=start) & (data["time"]<finish)]["length"]*8)
        if not np.isnan(val):
            value.append(val/step_sec)
        start = finish 
        finish = start + step_sec
        
    return value

# =============================================================================
# # Evaluate bitRate considering all the trace with 3 different sampling rate
# =============================================================================

plt.figure(figsize = (20, 10))

'''
plt.plot(list(map(lambda x: x/1e6, bitRate(dataFrame,1))), color = 'peru',marker="o",label = "avg 1sec")

plt.plot([ i*5 for i in range(1,len(list(map(lambda x: x/1e6, 
                                             bitRate(dataFrame,5))))+1)],list(map(lambda x: x/1e6, bitRate(dataFrame,5))), color = 'gold',marker="*",label = "avg 5sec")
plt.plot([ i*10 for i in range(1,len(list(map(lambda x: x/1e6, bitRate(dataFrame,10))))+1)],list(map(lambda x: x/1e6, bitRate(dataFrame,10))), 
         color = 'chartreuse',marker="v",label = "avg 10sec")
'''

plt.plot([ i*0.5 for i in range(1,len(list(map(lambda x: x/1e6, 
                                             bitRate(dataFrame,0.5))))+1)],list(map(lambda x: x/1e6, bitRate(dataFrame,0.5))), color = 'gold',marker="*",label = "avg 0.5sec")
plt.plot([ i*0.1 for i in range(1,len(list(map(lambda x: x/1e6, bitRate(dataFrame,0.1))))+1)],list(map(lambda x: x/1e6, bitRate(dataFrame,0.1))), 
         color = 'chartreuse',marker="v",label = "avg 0.1sec")
plt.plot([ i*0.05 for i in range(1,len(list(map(lambda x: x/1e6, bitRate(dataFrame,0.05))))+1)],list(map(lambda x: x/1e6, bitRate(dataFrame,0.05))), 
         color = 'peru',marker="o",label = "avg 0.05sec")


#plt.plot(list(map(lambda x: x/1e6, bitRate(dataFrame,10))), color = 'olivedrab',marker="o-")
plt.xlabel('Time(s)', fontsize = 20, labelpad = 10)
plt.ylabel('Mbps', fontsize = 20, labelpad = 10)
plt.title('Total bitrate', fontsize = 30, pad = 15)
plt.xticks(fontsize = 14)
plt.yticks(fontsize = 14)
plt.legend(fontsize=20,loc="best")
plt.savefig(folder_image +"BitRate different Averages")
plt.show()
