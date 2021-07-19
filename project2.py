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

# ==========================================================================================
# # GeoLocal Referenciation of the 5 sessions with the highest amount of traffic generated
# ==========================================================================================

from ip2geotools.databases.noncommercial import DbIpCity
import folium

def geo_infos(ip_src_list, ip_dst_list):

  src_geo_info = []
  dst_geo_info = []
  i = 0

  for j in range(len(ip_src_list)):
    try:
      src_response = DbIpCity.get(ip_src_list[j], api_key='free')
      dst_response = DbIpCity.get(ip_dst_list[j], api_key='free')
    except:
      continue
    if src_response.latitude == None or dst_response.latitude == None: 
      continue
    i +=1
    src_geo_info.append([src_response.latitude, src_response.longitude, src_response.region])
    dst_geo_info.append([dst_response.latitude, dst_response.longitude, dst_response.region])
    if i == 10: break

  return src_geo_info, dst_geo_info

data_couple = copy.deepcopy(dataFrame)
#Change your local IP with the one used to navigate on the Web
data_couple["IP_SRC"]= data_couple["IP_SRC"].replace({'192.168.43.28':'46.37.14.27'})
data_couple["IP_DST"] = data_couple["IP_DST"].replace({'192.168.43.28':'46.37.14.27'})
df_srcdst = list(zip(data_couple.IP_SRC, data_couple.IP_DST))

mostcommon_srcdst = Counter(df_srcdst).most_common(5)

list_src = []
list_dst = []

for i in range(len(mostcommon_srcdst)):
    list_src.append(mostcommon_srcdst[i][0][0]) #src pos 0
    list_dst.append(mostcommon_srcdst[i][0][1]) #dst pos 1

#src_geo, dst_geo = geo_infos(list(top_10_flows['ip_src']), list(top_10_flows['ip_dst']))

#Sigle Couple
src_geo, dst_geo = geo_infos(['185.86.84.30'],['46.37.14.27'])
#5 Couples
src_geo, dst_geo = geo_infos(list_src, list_dst)

src_geo = pd.DataFrame(src_geo, columns=['latitude', 'longitude', 'region'])
dst_geo = pd.DataFrame(dst_geo, columns=['latitude', 'longitude', 'region'])




flow_map = folium.Map([0, 0], zoom_start=2, tiles='Stamen Terrain')

for i in range(len(src_geo)):
  folium.Marker([src_geo.loc[i][0], src_geo.loc[i][1]], popup='<i>Mt. Hood Meadows</i>', 
                icon=folium.Icon(color='green')).add_to(flow_map)
  folium.Marker([dst_geo.loc[i][0], dst_geo.loc[i][1]], popup='<i>Mt. Hood Meadows</i>',  
                icon=folium.Icon(color='red')).add_to(flow_map)
  folium.PolyLine([(src_geo.loc[i][0], src_geo.loc[i][1]), (dst_geo.loc[i][0], dst_geo.loc[i][1])], 
                  color="blue", weight=1.5, opacity=1).add_to(flow_map)

flow_map.save(folder_image +"Map_top_5_flows.html")
#display(flow_map)
