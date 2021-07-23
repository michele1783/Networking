# -*- coding: utf-8 -*-
"""
Created on Fri Jul  2 13:36:33 2021

@author: Michele Luca Puzzo
"""

# =============================================================================
# #Libraries
# =============================================================================
import glob  # usa per importare dei file di testo
from os import system as cmd  # usa per importare comandi dalla command line
import os
import shutil
import sys  # usa per avere dei breakpoint
import pyshark
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
from matplotlib.pyplot import figure
import seaborn as sns
from collections import Counter
import copy
import seaborn as sns
import networkx as nx
import imblearn
from collections import Counter
from tqdm import tqdm
import pickle
import operator
import math
from sklearn import preprocessing
from sklearn.model_selection import train_test_split
from sklearn.svm import SVC
from sklearn.pipeline import make_pipeline
from sklearn.metrics import confusion_matrix

from sklearn.model_selection import GridSearchCV
from sklearn.metrics import classification_report

from sklearn.ensemble import RandomForestClassifier
from imblearn.over_sampling import SMOTE
from imblearn.over_sampling import ADASYN
from imblearn.over_sampling import RandomOverSampler


from sklearn.cluster import KMeans
from kneed import KneeLocator


from multiprocessing import Process, Manager
from os import system as cmd
import time

import folium

# =============================================================================
# Splitting .pcap File in 5 different pcap file
# =============================================================================

#all files with specific extension
list_pcap_file = glob.glob("./*.pcap")

print("Number of .pcap files: ", len(list_pcap_file))

file = list_pcap_file[0]
print(file)

# create directory
name_folder = "Splitting"

#Remove directory already created
shutil.rmtree(name_folder)

try:
    os.mkdir(name_folder)
#If you have already created it Error
except OSError:
    print("Creation of the directory %s failed" % name_folder)
else:
    print("Successfully created the directory %s" % name_folder)


# Editcap is a program that reads some or all of the captured packets from the infile,
# optionally converts them in various ways and writes the resulting packets to the
# capture outfile.


# -c Splits the packet output to different files based on uniform packet counts with
# a maximum of <packets per file> each
cmd("editcap -c 1000000 " + file + " " + name_folder + "/.pcap") #1000000 è il numero di pkts in cui voglio splittare la pkt trace. avrò 11 file nel file splitting, 11 piccole pcap trace


list_pcap_file = glob.glob("./Splitting/*.pcap")

print("Number of .pcap files: ", len(list_pcap_file))

file = list_pcap_file[0]
print(file)

#=========================================================================
# Capinfos is a program that reads one or more capture files and returns
# some or all available statistics (infos) of each <infile> in one of two types
# of output formats: long or table.
#===============================================================================

#*Options*
print("*OPTIONS :*")

print()
print()
#-c --> Number of Packets in the capture
cmd("capinfos -c "+file)
print()
print()
#-i --> The average data rate, in bits/sec, data bite rate
cmd("capinfos -i "+file)
print()
print()
#-z --> The average PACKET SIZE
cmd("capinfos -z "+file)
print()
print()


#-A --> Generate all infos
cmd("capinfos -A "+file)
print()
print()


# =============================================================================
# Info -Table Format
# =============================================================================

# generate a TAB delimited table form report
cmd("capinfos -T -m "+file+" >info.txt") #-T table format, #-m just ofr comma separated all the statistics
print()
print()

# To generate a CSV delimited table style report of all infos
# and write it to a text file called info.csv use:
cmd("capinfos -TmQ "+file+" >info.csv")
print()
print()

file_name = glob.glob("./Splitting/*.pcap")[0]
print("Working with: ", file_name)
pcap = pyshark.FileCapture(file_name)
#Create file pickle
def extract_Info_pckt(file_name): #nome del file del pcap trace: #lista_packet_ICMP

    pcap = pyshark.FileCapture(file_name) #reading pcap file

    title = ["Label DSCP", "header len", "ds_field","ds_field_ecn", "length",
          "Protocol" ,"flag_df", "flag_mf", "flag_rb", "fragment_offset", "ttl",
          "IP_SRC", "IP_DST","src_port", "dst_port","time"]
    #header_len circa 20 bytes
    #ds_len info about diferentiated service,priority of a packet in the network
    #ecn: explicit congestion notification, will know if there is congestion in that link
    #all the features come from IP layer tranne per src and dst port
    #protocol = 6 se tcp, 17 udp
    #ttl: how many hop remain for that specific pkt until reach the destination, se 0 link molto congestionato
    #time of capture that specific pkt


    total_info = []  # for each pkt i fil this list, will be a list of list and then will transform in  a dataframe
    print("Now I'm working on: " + file_name)
    print()


    i = 0
    dscp = []
    total_info.append(title) # total_info è la lista più esterna, values la lista per ogni pkt

    for packet in pcap:

        ### MAC Address verification ###
        #sorgente = pcap[0].eth.src

        #Creating an empty list where we collect info about the packet
        #Useful this format to create then a DataFrame

        values = []

        #print(packet.layers)
        #We extract onòy the packets from IP Level and only Version IPv4
        #if 'IP' in packet and packet.eth.src == sorgente:
        if 'IP' in packet : #we are just taking ip packet, exploit the dissectors available on tshark.
            #dissector= a zoom on each specific layer of the packet

            #Label
            values.append(packet.ip.dsfield_dscp) #we extract form each pkt the specific info that we want to add in our list
            dscp.append(packet.ip.dsfield_dscp)
            #Features

            #Header Length
            values.append(int(packet.ip.hdr_len))
            #Differentiated Service
            values.append(int(packet.ip.dsfield,16))
            #Explicit Congestion Notification
            values.append(packet.ip.dsfield_ecn)
            #Length of the Packet including the header
            values.append(int(packet.ip.len))
            #Number of Protocol (e.g. 6 = TCP, 17 = UDP, 1 = ICMP)
            values.append(int(packet.ip.proto))
            #Flag Do not Fragment
            values.append(packet.ip.flags_df)
            #Flag More Fragment
            values.append(packet.ip.flags_mf)
            #Flag Reserved - Must be 0
            values.append(packet.ip.flags_rb)
            #Fragment Offset
            values.append(packet.ip.frag_offset)
            #Time To Live
            values.append(int(packet.ip.ttl))


            #### Extraction of the Ip Source and Ip Destination###

            source = packet.ip.src
            values.append(source)

            destination = packet.ip.dst
            values.append(destination)

            #### Extraction of the Port ####
            if "UDP" in packet:
                values.append(packet.udp.srcport)
                values.append(packet.udp.dstport)

            elif "TCP" in packet :
                values.append(packet.tcp.srcport)
                values.append(packet.tcp.dstport)

            else:
                #Protocol as IP and ICMP e Ws.Short Port in src and dst will be set to -1
                values.append(-1) #dummy variable to recognize that pkt comes from different protocol
                values.append(-1)

            #if "ICMP" in packet:
            #    lista_packet_ICMP.append((packet.ip.dsfield_dscp, packet.icmp.type, packet.icmp.code))


            #Time will be used for the simulation
            time = float(packet.sniff_timestamp)
            values.append(time)

            #Update the number of pckts
            i += 1

            #Store all the caracteristics of a packet into the Totale list
            total_info.append(values)

    print("Now we have finished the analysis so we closed the file: " + file_name)
    pcap.close()

    print(len(total_info))
    #Creation of the data frame
    dataFrame = pd.DataFrame(total_info[1:],columns = total_info[0])

    return dataFrame

    # #We are saving the dataframe of Features Packets
    # with open('FeaturesDataFrame/' + title + '.pkl', 'wb') as f:
    #     pickle.dump(tot_dat, f)

    # print("Here we have analyzed this number of pckts: " + str(i))

    #Label Analysis
    # occ_label = dict(Counter(dscp))
    #print("DSCP occurrences",occ_label)


dataFrame = extract_Info_pckt(file_name) #create the file
print("Finish the reading part")
dataFrame.to_pickle("PacketDataframe.pkl") #save the pickle file
dataFrame = pd.read_pickle("PacketDataframe.pkl")  # read the file
print("Finish to read al pcap file")

#==========================================================================
#Parallel reading
#==========================================================================
def extract_Info_pckt(file_name ): #lista_packet_ICMP
    
    pcap = pyshark.FileCapture(file_name)

    title = ["Label DSCP", "headerLen", "ds_field","ds_field_ecn", "length", 
          "Protocol" ,"flag_df", "flag_mf", "flag_rb", "fragment_offset", "ttl", 
          "IP_SRC", "IP_DST","src_port", "dst_port","time"] 
    
    total_info = []
    print("Now I'm working on: " + file_name)
    print()
       
    
    i = 0
    dscp = []
    total_info.append(title)
    
    for packet in pcap:
        
        ### MAC Address verification ###
        #sorgente = pcap[0].eth.src
            
        #Creating an empty list where we collect info about the packet
        #Useful this format to create then a DataFrame
        
        values = []
        
        #print(packet.layers)
        #We extract onòy the packets from IP Level and only Version IPv4
        #if 'IP' in packet and packet.eth.src == sorgente:
        if 'IP' in packet :
            
            
            #Label
            values.append(packet.ip.dsfield_dscp)
            dscp.append(packet.ip.dsfield_dscp)
            #Features
            
            #Header Length
            values.append(int(packet.ip.hdr_len))
            #Differentiated Service
            values.append(int(packet.ip.dsfield,16))
            #Explicit Congestion Notification
            values.append(packet.ip.dsfield_ecn)
            #Length of the Packet including the header
            values.append(int(packet.ip.len))
            #Number of Protocol (e.g. 6 = TCP, 17 = UDP, 1 = ICMP)
            values.append(int(packet.ip.proto))
            #Flag Do not Fragment 
            values.append(packet.ip.flags_df)
            #Flag More Fragment
            values.append(packet.ip.flags_mf)
            #Flag Reserved - Must be 0
            values.append(packet.ip.flags_rb)
            #Fragment Offset
            values.append(packet.ip.frag_offset)
            #Time To Live
            values.append(int(packet.ip.ttl))
            
            
            #### Extraction of the Ip Source and Ip Destination###
            
            source = packet.ip.src
            values.append(source)
            
            destination = packet.ip.dst
            values.append(destination)
  
            #### Extraction of the Port ####
            if "UDP" in packet:
                values.append(packet.udp.srcport)
                values.append(packet.udp.dstport)

            elif "TCP" in packet :
                values.append(packet.tcp.srcport)
                values.append(packet.tcp.dstport)            
                
            else:
                #Protocol as IP and ICMP e Ws.Short avranno come porta -1
                values.append(-1)
                values.append(-1)
                
            #if "ICMP" in packet:
            #    lista_packet_ICMP.append((packet.ip.dsfield_dscp, packet.icmp.type, packet.icmp.code))
            
            
            #Time will be used for the simulation
            time = float(packet.sniff_timestamp)
            values.append(time)
             
            #Update the number of pckts
            i += 1
            
            #Store all the caracteristics of a packet into the Totale list
            total_info.append(values)
            
    print("Now we have finished the analysis so we closed the file: " + file_name)     
    pcap.close()
   
    print("# Packets \t",len(total_info)-1) #-1 fro the title list
    #Creation of the data frame
    dataFrame = pd.DataFrame(total_info[1:],columns = total_info[0])
    
    
    
    dataFrame.to_pickle(file_name + "_PacketDataframe.pkl")

if __name__ == "__main__":
    
    list_files = glob.glob("./*.pcap")
    
    print("# Files \t", len(list_files))
    pcap_analyzed = list_files[0]
    
    sub_dir = "SplitRead/"
    
    #Remove directory already created
    shutil.rmtree(sub_dir) 
    
    try:
        os.mkdir("./" + sub_dir)
    #If you have already created it Error
    except OSError:
        print("Creation of the directory %s failed" % sub_dir)
    else:
        print("Successfully created the directory %s" % sub_dir)
    
    #cmd('editcap -c 200000 ' + pcap_analyzed +" ./"+ sub_dir +"__mini.pcap")
    #cmd('editcap -c 100000 ' + pcap_analyzed +" ./"+ sub_dir +"__mini.pcap")
    cmd('editcap -c 50000 ' + pcap_analyzed +" ./"+ sub_dir +"__mini.pcap")
    #cmd('editcap -c 10000 ' + pcap_analyzed +" ./"+ sub_dir +"__mini.pcap")
    #cmd('editcap -c 1000000 ' + pcap_analyzed +" ./"+ sub_dir +"__mini.pcap")
    #cmd("complete PATH for wireshark...")
    
    print("Current Working Directory: "+ os.getcwd())
    
    #Change directory
    os.chdir("./"+sub_dir)
    
    print("New Working Directory: "+ os.getcwd())
    
    splitting_file = sorted(glob.glob("*.pcap"))
    
    print("# Splitted Files \t", len(list_files))
    
    manager = Manager()
    
    start_time = time.time()
    
    lista_process = []
    
    for i in range(len(splitting_file)):
        print("ok_")
        file = splitting_file[i]
        
        p1 = Process(target = extract_Info_pckt, args = (file,))
        
        lista_process.append(p1)
        
        p1.start()
        
    for process in lista_process:
        process.join()
        
    ### Finish ####
    
    print("Finish to read al pcap file")
    print("--- %s seconds ---" % (time.time() - start_time))

####################################################################################

folder_image = "Image"

# Remove directory already created
shutil.rmtree(folder_image)

try:
    os.mkdir(folder_image)
# If you have already created it Error
except OSError:
    print("Creation of the directory %s failed" % folder_image)
else:
    print("Successfully created the directory %s" % folder_image)
folder_image = "./Image/"


def bitRate(data, step_sec=0.1):
    start = data.iloc[0]["time"]
    finish = data.iloc[-1]["time"]
    print("Start: ", start)
    print("Finish: ", finish)

    data["time"] -= data.iloc[0]["time"]
    start = data.iloc[0]["time"]
    finish = data.iloc[-1]["time"]

    print("Start: ", start)
    print("Finish: ", finish)

    step = finish / step_sec
    finish = start + step_sec
    value = []
    print(step)
    for i in range(int(step)):

        # From Byte to bit
        val = np.sum(data[(data["time"] >= start) & (
            data["time"] < finish)]["length"]*8)
        if not np.isnan(val):
            value.append(val/step_sec)
        start = finish
        finish = start + step_sec

    return value

#=============================================================================
# TOP 6 Receiver from the IP with the highest amount of traffic
#=============================================================================

data_couple = dataFrame.groupby(["IP_SRC"])[['length']].agg('sum').sort_values(by=['length'], ascending=False).head(20)
indirizzi = data_couple.index
myip = indirizzi[0]
onlyMyIP = dataFrame[dataFrame["IP_SRC"] == myip]
data_couple = onlyMyIP.groupby(["IP_DST"])[['length']].agg('sum').sort_values(by=['length'], ascending=False).head(6)
grouped = onlyMyIP.groupby(["IP_DST"]).agg('sum').sort_values(by=['length'], ascending=False).head(6)
data_couple = onlyMyIP.groupby(["IP_DST"])


rowlength = int(grouped.shape[0]/2)   # fix up if odd number of groups
fig, axs = plt.subplots(figsize=(20,12),
                        nrows=2, ncols=rowlength,
                        gridspec_kw=dict(hspace=0.4))
plt.subplots_adjust(wspace=0.4)
fig.tight_layout()
targets = zip(grouped.index, axs.flatten())
for i, (key, ax) in enumerate(targets):
    print(key)
    #ax.plot(data_couple.get_group(key)["length"])
    ax.plot(bitRate(data_couple.get_group(key)),marker = "o")
    ax.set_title(key)
    ax.set_xlabel("T (decisec)")
    ax.set_ylabel("bit/sec")
    ax.set_xticks(np.arange(0, 36, 5))
    ax.set_yscale('log')
ax.legend()
fig.suptitle('TOP 6 receiver from ' + myip , fontsize=16)
plt.savefig(folder_image + "TOP 6 IP Dst")
plt.show()


#============================================================================
# TOP 5 DESTINATION based on the amount of byte received
#=============================================================================
data_couple = dataFrame.groupby(["IP_DST"])[['length']].agg('sum').sort_values(by=['length'], ascending=False).head(5)

plt.figure(figsize = (18, 12), dpi = 75)
#Remove my Ip too traffic generated
plt.barh(data_couple.index, data_couple['length']/1e6, color = sns.color_palette('plasma', 10))
plt.title('Top 5 destinations for received data', fontsize = 30, loc = 'center', pad = 15)
plt.ylabel('IP address', fontsize = 18, labelpad = 5)
plt.xlabel('Total volume of received data ($Mbit$)', fontsize = 20, labelpad = 15)
plt.xticks(fontsize = 14)
plt.yticks(fontsize = 14)
plt.savefig(folder_image +"TOP 5 Destination")
plt.show()

#=============================================================================
#TOP 5 SENDER based on the amount of byte sent
#=============================================================================
from matplotlib import pyplot
data_couple = dataFrame.groupby(["IP_SRC"])[['length']].agg('sum').sort_values(by=['length'], ascending=False).head(5)

plt.figure(figsize = (18, 12), dpi = 75)
#Remove my Ip too traffic generated
plt.barh(data_couple.index, data_couple['length']/1e6, color = sns.color_palette('plasma', 10))
plt.title('Top 5 destinations for sending data', fontsize = 30, loc = 'center', pad = 15)
plt.ylabel('IP address', fontsize = 18, labelpad = 5)
plt.xlabel('Total volume of sending data ($Mbit$)', fontsize = 20, labelpad = 15)
plt.xticks(np.arange(0, 200, step=20))

plt.yticks(fontsize = 14)
pyplot.xscale('log')


plt.savefig(folder_image +"TOP Sender")
plt.show()


from matplotlib import pyplot as plt1
import matplotlib.ticker

matplotlib.rcParams['xtick.minor.size'] = 0
matplotlib.rcParams['xtick.minor.width'] = 0

fig1, ax1 = plt1.subplots(figsize=(18,12))
ax1.barh(data_couple.index, data_couple['length']/1e6, color = sns.color_palette('plasma', 10))
ax1.set_title('Top 5 destinations for sending data', fontsize = 30, loc = 'center', pad = 15)
ax1.set_xscale('log')
#ax1.set_xticks(np.arange(10,700, step=20))
majors = [5,10, 20, 30, 40, 50, 60, 70, 100, 300, 500, 700]
ax1.xaxis.set_major_locator(matplotlib.ticker.FixedLocator(majors))
ax1.set_xlabel('Total volume of sending data ($Mbit$)', fontsize = 20, labelpad = 15)

ax1.xaxis.set_major_formatter(matplotlib.ticker.ScalarFormatter())

plt.show()


#==============================================================
#Top 10 protocol based on amount of byte
#================================================================

grouped_flows = dataFrame.groupby(['IP_SRC', 'IP_DST', 'Protocol', 'src_port', 'dst_port']).agg(
    tot_len=pd.NamedAgg(column='length', aggfunc='sum')).reset_index()

# grouped_flows["Protocol"] = grouped_flows["Protocol"].index.replace({1:"ICMP",6:"TCP",17:"UDP", 50:"ESP",4:"IPv4",89:"OSPFIGP",47:"Generic Routing Encapsulation",97:"Ethernet-within-IP Encapsulation",103:"Protocol Independent Multicast"})
lista = ["ICMP", "TCP", "UDP", "ESP", "IPv4",  "OSPFIGP",  "Gen. Routing Encaps",  "Eth-within-IP Encaps.",  "Protocol Ind. Multicast"]
prot = list(grouped_flows.Protocol.value_counts().index)
prot = [i for i in lista]

#replace({1: "ICMP", 6: "TCP", 17: "UDP", 50: "ESP", 4: "IPv4", 89: "OSPFIGP", 47: "Generic Routing Encapsulation", 97: "Ethernet-within-IP Encapsulation", 103: "Protocol Independent Multicast"})
# Protocol Frequencies

plt.figure(figsize=(16, 10), dpi=75)
plt.barh(prot, grouped_flows.Protocol.value_counts().values, color=sns.color_palette('viridis', 5))
plt.title('Protocols frequencies flows based',
          fontsize=30, loc='center', pad=15)
plt.xlabel('Frequency', fontsize=20, labelpad=15)
plt.ylabel('Protocol', fontsize=20, labelpad=15)
plt.xscale('log')
plt.xticks(fontsize=14)
plt.yticks(fontsize=14)
plt.savefig(folder_image + "Protocol Analysis")
plt.show()







#############################################################################
#                    Geo Referenciation#
#############################################################################

from ip2geotools.databases.noncommercial import DbIpCity


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
print(mostcommon_srcdst)

list_src = []
list_dst = []

for i in range(len(mostcommon_srcdst)):
    list_src.append(mostcommon_srcdst[i][0][0]) #src pos 0
    list_dst.append(mostcommon_srcdst[i][0][1]) #dst pos 1

#src_geo, dst_geo = geo_infos(list(top_10_flows['P_SRC']), list(top_10_flows['ip_dst']))

#Sigle Couple
#src_geo, dst_geo = geo_infos(['185.86.84.30'],['46.37.14.27'])
#5 Couples
src_geo, dst_geo = geo_infos(list_src, list_dst)

src_geo = pd.DataFrame(src_geo, columns=['latitude', 'longitude', 'region'])
dst_geo = pd.DataFrame(dst_geo, columns=['latitude', 'longitude', 'region'])

print(src_geo)
print(dst_geo)

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

sys.exit("ciao")



#=============================================================================
                                #Transport Layer Analysis : Port Number
#=============================================================================

def port_scan (x, dic):
    ''' scan through the ports and update the counter at each import file.
    save only the info for the well-known ports '''

    for port in x:
        if pd.isnull(port) == False:
            if int(port) < 65536:
                if port not in dic.keys():
                    dic[port] = 1
                else:
                    dic[port] += 1
    return(dic)

source_ports = {}
source_ports = port_scan(dataFrame["src_port"], source_ports)
dest_ports = {}
dest_ports = port_scan(dataFrame["dst_port"], dest_ports)


pd.DataFrame.from_dict(source_ports, orient = 'index').to_json('./source_ports.json')
pd.DataFrame.from_dict(dest_ports, orient = 'index').to_json('./dest_ports.json')


sports = pd.read_json('./source_ports.json')
dports = pd.read_json('./dest_ports.json')

sports = sports.reset_index()
dports = dports.reset_index()
sports = sports.rename(columns = {'index':'port', 0:'count'})
dports = dports.rename(columns = {'index':'port', 0:'count'})


sports = sports.sort_values(by = 'count', ascending = False)
dports = dports.sort_values(by = 'count', ascending = False)

plt.figure(figsize = (19, 10), dpi = 75)
plt.bar(x = list(map(str, list(sports.loc[sports['count']>15420,'port']))), color = 'darkred', height = list(sports.loc[sports['count'] > 15420,'count']), label = 'Src port', alpha = 0.7)
plt.bar(x = list(map(str, list(dports.loc[dports['count']>15420,'port']))), color = 'darkcyan', height = list(dports.loc[dports['count'] > 15420,'count']), label = 'Dst port', alpha = 0.7)
plt.legend(fontsize=20)
plt.yscale('log')
plt.title('Ports ', fontsize = 30, pad = 15)
plt.yticks(np.arange(1000,150000,20000))
plt.xlabel('Port number', fontsize = 20, labelpad = 15)
plt.ylabel('Count', fontsize = 20, labelpad = 15)
plt.savefig(folder_image +"Port Scanner")
plt.show()

#=======================================================================
#InterArrivalTime
#=======================================================================

def InterArrivalTime(data):
    val = np.array(data["time"])

    return np.diff(val)

data_protocol = copy.deepcopy(dataFrame[dataFrame["Protocol"].isin([6,17])])
data_protocol["Protocol"] = data_protocol["Protocol"].replace({1:"ICMP",6:"TCP",17:"UDP"})

print(Counter(data_protocol["Protocol"]))
#Inter arrival time

tcp_data = data_protocol[data_protocol["Protocol"]=="TCP"]
udp_data = data_protocol[data_protocol["Protocol"]=="UDP"]

inteArr_TCP= []
for elem in tcp_data.groupby(['IP_SRC', 'IP_DST', 'Protocol', 'src_port', 'dst_port']):
    #groupby tuple (key,dataframe)
    inteArr_TCP += InterArrivalTime(elem[1]).tolist()

inteArr_UDP = []
for elem in udp_data.groupby(['IP_SRC', 'IP_DST', 'Protocol', 'src_port', 'dst_port']):
    inteArr_UDP += InterArrivalTime(elem[1]).tolist()


val_ = inteArr_TCP + inteArr_UDP

label_TCP = [ "TCP" for i in range(len(inteArr_TCP))]
label_UDP =[ "UDP" for i in range(len(inteArr_UDP))]

lab_ = label_TCP + label_UDP

d = {'Protocol': lab_, 'IntArrTime': val_}
df = pd.DataFrame(data=d)
plt.figure(figsize = (20, 10))
plt.rcParams['ytick.labelsize'] = 14
df_ = df[df["IntArrTime"] <0.00001]
ax = sns.boxplot(x="Protocol", y="IntArrTime", data=df_)
ax.set_xlabel("")
ax.set_ylabel("Inter Arrival Time (sec)",fontsize=16)
plt.savefig(folder_image +"BoxPlot InterArrivalTime")
plt.show()


print("Mean InterArrivalTime TCP Session: %.5f"% np.mean(np.array(inteArr_TCP)[np.array(inteArr_TCP)<1]))

print("Mean InterArrivalTime UDP Session: %.5f"% np.mean(np.array(inteArr_UDP)[np.array(inteArr_UDP)<1]))

#==================================================================
#Evaluation of TTL
#=================================================================


data_couple=dataFrame["ttl"].value_counts().sort_index()
a = data_couple=dataFrame["ttl"].value_counts().sort_index()


primi=data_couple[0:21]


plt.bar(data_couple.index, data_couple.values, color='r')
plt.title('Number of pkts for each ttl', fontsize=30, loc='center', pad=15)
plt.ylabel('number of pkts', fontsize=15, labelpad=5)
plt.xlabel('time to live', fontsize=15, labelpad=15)
plt.xticks(fontsize=14)
plt.yticks(fontsize=14)
plt.yscale('log')
plt.savefig(folder_image + "Number of pkts for each ttl")
plt.show()


plt.bar(primi.index, primi.values, color='grey')
plt.title('Focus on pkts with small ttl', fontsize=30, loc='center', pad=15)
plt.ylabel('number of pkts', fontsize=15, labelpad=5)
plt.xlabel('time to live', fontsize=15, labelpad=15)
plt.xticks(fontsize=14)
plt.yticks(fontsize=14)

plt.savefig(folder_image + "Focus on pkts with small ttl")
plt.show()

somma = np.cumsum(list(a[:]))
indici = list(data_couple.index)
plt.plot(indici, somma)
plt.title('Cumulative sum of number of pkts', fontsize=30, loc='center', pad=15)
plt.ylabel('cumulative sum', fontsize=15, labelpad=5)
plt.xlabel('time to live', fontsize=15, labelpad=15)
plt.savefig(folder_image + "Nl")
plt.show()


#===============================================================================
#Topology of the network
#================================================================================

G=nx.DiGraph()
d = dataFrame.groupby(["IP_SRC","IP_DST"])[["length"]].agg('sum').sort_values(by=["length"],ascending= False)
D1 = d[:35].unstack().fillna(0)
indice = list(D1.index)
#print(list(D1.index))
#print(len(indice))
for j in range(len(indice)):
    a = D1.iloc[j]
    for i in range(len(D1.columns)):
        if a[i]>0:
            G.add_edge(indice[j], a.index[i][1], weight = a[i])


pos = nx.spring_layout(G)
plt.figure(3,figsize=(17,17))
nx.draw_networkx_edges(G, pos, width=1,arrowsize =13)
nx.draw_networkx_labels(G, pos, font_size=12, font_family="sans-serif")
nx.draw_networkx_nodes(G, pos, node_size=500, node_color = "lightgreen")
nx.draw_networkx_labels(G, pos, font_size=12, font_family="sans-serif")
labels = nx.get_edge_attributes(G,'weight')
nx.draw_networkx_edge_labels(G,pos,edge_labels=labels, alpha = 0.5, font_size = 8, label_pos = 0.5)
plt.show()


# ================================================================================
# SUPERVISED LEARNING
# ===============================================================================
list_pcap_file = glob.glob("./*.pcap")

print("Number of .pcap files: ", len(list_pcap_file))

file = list_pcap_file[0]
print(file)

# create directory
name_folder = "Splitting"

#Remove directory already created
shutil.rmtree(name_folder)

try:
    os.mkdir(name_folder)
#If you have already created it Error
except OSError:
    print("Creation of the directory %s failed" % name_folder)
else:
    print("Successfully created the directory %s" % name_folder)


# Editcap is a program that reads some or all of the captured packets from the infile,
# optionally converts them in various ways and writes the resulting packets to the
# capture outfile.


#cmd("editcap -i 6.7 " + file + " " + name_folder + "/.pcap")
cmd("editcap -c 1500000 " + file + " " + name_folder + "/.pcap")
file_name=glob.glob("./Splitting/*.pcap")[0]

print("Working with: ", file_name)

pcap=pyshark.FileCapture(file_name)

# Create file pickle
def extract_Info_pckt(file_name):  # nome del file del pcap trace: #lista_packet_ICMP

    pcap=pyshark.FileCapture(file_name)  # reading pcap file

    title=["Label DSCP", "header len", "ds_field", "ds_field_ecn", "length",
          "Protocol", "flag_df", "flag_mf", "flag_rb", "fragment_offset", "ttl",
          "IP_SRC", "IP_DST", "src_port", "dst_port", "time"]
    # header_len circa 20 bytes
    # ds_len info about diferentiated service,priority of a packet in the network
    # ecn: explicit congestion notification, will know if there is congestion in that link
    # all the features come from IP layer tranne per src and dst port
    # protocol = 6 se tcp, 17 udp
    # ttl: how many hop remain for that specific pkt until reach the destination, se 0 link molto congestionato
    # time of capture that specific pkt


    total_info=[]  # for each pkt i fil this list, will be a list of list and then will transform in  a dataframe
    print("Now I'm working on: " + file_name)
    print()


    i=0
    dscp=[]
    # total_info è la lista più esterna, values la lista per ogni pkt
    total_info.append(title)

    for packet in pcap:

        ### MAC Address verification ###
        # sorgente = pcap[0].eth.src

        # Creating an empty list where we collect info about the packet
        # Useful this format to create then a DataFrame

        values=[]

        # print(packet.layers)
        # We extract onòy the packets from IP Level and only Version IPv4
        # if 'IP' in packet and packet.eth.src == sorgente:
        # we are just taking ip packet, exploit the dissectors available on tshark.
        if 'IP' in packet:
            # dissector= a zoom on each specific layer of the packet

            # Label
            # we extract form each pkt the specific info that we want to add in our list
            values.append(packet.ip.dsfield_dscp)
            dscp.append(packet.ip.dsfield_dscp)
            # Features

            # Header Length
            values.append(int(packet.ip.hdr_len))
            # Differentiated Service
            values.append(int(packet.ip.dsfield, 16))
            # Explicit Congestion Notification
            values.append(packet.ip.dsfield_ecn)
            # Length of the Packet including the header
            values.append(int(packet.ip.len))
            # Number of Protocol (e.g. 6 = TCP, 17 = UDP, 1 = ICMP)
            values.append(int(packet.ip.proto))
            # Flag Do not Fragment
            values.append(packet.ip.flags_df)
            # Flag More Fragment
            values.append(packet.ip.flags_mf)
            # Flag Reserved - Must be 0
            values.append(packet.ip.flags_rb)
            # Fragment Offset
            values.append(packet.ip.frag_offset)
            # Time To Live
            values.append(int(packet.ip.ttl))


            #### Extraction of the Ip Source and Ip Destination###

            source=packet.ip.src
            values.append(source)

            destination=packet.ip.dst
            values.append(destination)

            #### Extraction of the Port ####
            if "UDP" in packet:
                values.append(packet.udp.srcport)
                values.append(packet.udp.dstport)

            elif "TCP" in packet:
                values.append(packet.tcp.srcport)
                values.append(packet.tcp.dstport)

            else:
                # Protocol as IP and ICMP e Ws.Short Port in src and dst will be set to -1
                # dummy variable to recognize that pkt comes from different protocol
                values.append(-1)
                values.append(-1)

            # if "ICMP" in packet:
            #    lista_packet_ICMP.append((packet.ip.dsfield_dscp, packet.icmp.type, packet.icmp.code))


            # Time will be used for the simulation
            time=float(packet.sniff_timestamp)
            values.append(time)

            # Update the number of pckts
            i += 1

            # Store all the caracteristics of a packet into the Totale list
            total_info.append(values)

    print("Now we have finished the analysis so we closed the file: " + file_name)
    pcap.close()

    print(len(total_info))
    # Creation of the data frame
    dataFrame=pd.DataFrame(total_info[1:], columns=total_info[0])

    return dataFrame

    # #We are saving the dataframe of Features Packets
    # with open('FeaturesDataFrame/' + title + '.pkl', 'wb') as f:
    #     pickle.dump(tot_dat, f)

    # print("Here we have analyzed this number of pckts: " + str(i))

    # Label Analysis
    # occ_label = dict(Counter(dscp))
    # print("DSCP occurrences",occ_label)


dataFrame=extract_Info_pckt(file_name)  # create the file
print("Finish the reading part")
dataFrame.to_pickle("PacketDataframe.pkl")  # save the pickle file

dataFrame=pd.read_pickle("PacketDataframe.pkl")  # read the file

df=dataFrame
df["Label DSCP"]=pd.to_numeric(df["Label DSCP"])

dscp_tab={0: "BE",
            8: "Priority",
            10: "Priority",
            12: "Priority",
            14: "Priority",
            16: "Immediate",
            18: "Immediate",
            20: "Immediate",
            22: "Immediate",
            24: "Flash voice",
            26: "Flash voice",
            28: "Flash voice",
            30: "Flash voice",
            32: "Flash Override",
            34: "Flash Override",
            36: "Flash Override",
            38: "Flash Override",
            40: "Critical voice RTP",
            46: "Critical voice RTP",
            48: "Internetwork control",
            56: "Network Control"
            }

df=df.replace({'Label DSCP': dscp_tab})
df=df.replace({'Label DSCP': {"Priority": "AF", "Immediate": "AF", "Flash voice": "AF",
                                "Flash Override": "AF", "Critical voice RTP": "EF",
                                "Internetwork control": "CS6", "Network Control": "CS6",
                                4: "NotKnown", 2: "NotKnown", 6: "NotKnown", 7: "NotKnown",
                                1: "NotKnown", 41: "EF", 42: "EF", 43: "EF", 44: "EF", 45: "EF"}})

print("DSCP Occurrences: \n")
print(Counter(df["Label DSCP"]).values)


# Following the paper proposed by Rossi(2010):
# Retrieve all info flows based

data_unique=df.drop_duplicates(["IP_DST", "dst_port"])

# all possible (IP_0,port_0)
flows_list=data_unique[["IP_DST", "dst_port"]].values.tolist()


dict_rows={}

for i in tqdm(range(len(flows_list))):
    # extract all packets received by each specific couple IP dst, port destination
    subdata=df[(df["IP_DST"] == flows_list[i][0]) &
                  (df["dst_port"] == flows_list[i][1])]

    # 20 is just the length of our vector when we change the values in a logaritmic scale
    # max 2**19 --> 524288 | This consideration depends on your dataset
    length=np.zeros(20)
    pkt=np.zeros(20)

    # At least 2 pkts received by this specific (IP_0,port_0)
    if subdata.shape[0] >= 2:

        # Check about the label, we want to be sure to analyze a couple with just 1 DSCP
        # The vector that represents this element will have just one label

        if Counter(subdata["Label DSCP"] == 1):

            dtu=subdata.drop_duplicates(["IP_SRC", "src_port"])

            list_couple_src=dtu[["IP_SRC", "src_port"]].values.tolist()

            for elem in list_couple_src:
                # Observe each element in the Neighborhood (N)
                finaldata=subdata[(subdata["IP_SRC"] == elem[0]) & (
                    subdata["src_port"] == elem[1])]

                # Number of packets
                # Ex: pck = 245, log_{2}(245) = 7.94 --> ceil()--> 8
                # The range considered is (2**7,2**8] = (128,256]
                length[math.ceil(
                    math.log(finaldata.shape[0])/math.log(2))] += 1

                # Packet length analysis --> Byte
                # extract each packet length
                for index, row in finaldata.iterrows():
                    pkt[math.ceil(math.log(row["length"])/math.log(2))] += 1

            dict_rows[(flows_list[i][0], flows_list[i][1])]=[list(
                Counter(subdata["Label DSCP"]).keys())[0], length/sum(length), pkt/sum(pkt)]

        else:
            # print("problem")
            break


# Save the data in a pickle file
with open('dictAnalysis.pkl', 'wb') as handle:
    pickle.dump(dict_rows, handle, protocol=pickle.HIGHEST_PROTOCOL)


# Reading data
dict_rows=pd.read_pickle("dictAnalysis.pkl")


# Fast check about DSCP Occurrences
check=[]
for k, val in dict_rows.items():
    check.append(val[0])

print("DSCP Check:\t", Counter(check).items())


# Create a dataframe extendind the data about packet length and number

data_pandas=[]
for k, val in dict_rows.items():
    obs=[]
    obs.append(val[0])
    obs.extend(val[1].tolist())
    obs.extend(val[2].tolist())
    data_pandas.append(obs)

# Columns
col=["Label"]
col.extend(["X"+str(i)for i in range(40)])
df_=pd.DataFrame.from_records(data_pandas, columns=col)
# Select just items with a string label and not numeric
df_=df_[df_["Label"].isin(['AF', 'BE', 'CS6', 'EF', 'NotKnown'])]
# Useful to encode the label, it will be exploited at the end of the classification
le=preprocessing.LabelEncoder()
df_["Label"]=le.fit_transform(df_["Label"])


# Extract X,Y
X=df_.iloc[:, 1:]
print(X)
Y=df_.iloc[:, 0]
print(Y)
oversample=SMOTE(sampling_strategy={0: int(sum(Y == 1)),
                                      3: int(sum(Y == 1)),
                                      2: int(sum(Y == 1)),
                                      4: int(sum(Y == 1))}, k_neighbors=2)

X_over, Y_over = oversample.fit_resample(X, Y)
# Divide in train and test
x_train, x_test, y_train, y_test=train_test_split(
    X_over, Y_over, test_size=0.3, random_state=0)
print()
print("Train: ", Counter(y_train))
print("Test: ", Counter(y_test))
print()

#oversample=SMOTE(sampling_strategy={0: int(sum(y_train == 1)),
 #                                     3: int(sum(y_train == 1)),
  #                                    2: int(sum(y_train == 1)),
   #                                   4: int(sum(y_train == 1))}, k_neighbors=2)

# oversample = ADASYN(sampling_strategy={0:int(sum(y_train==1)),
#                                        3:int(sum(y_train==1)),
#                                        2:int(sum(y_train==1)),
#                                        4:int(sum(y_train==1))}, n_neighbors=3)


# X_over, Y_over = ros.fit_resample(x_train, y_train)
# print(X_over)
# print(Y_over)
#X_over, Y_over=oversample.fit_resample(x_train, y_train)
#print(sorted(Counter(Y_over).items()))
clf=make_pipeline(SVC(gamma=1e-1, class_weight='balanced', C=1000))
#clf = RandomForestClassifier(max_depth=2, random_state=0)
#from sklearn.naive_bayes import MultinomialNB
#clf = MultinomialNB()

clf.fit(X_over, Y_over)
y_pred=clf.predict(x_test)


print(clf.score(x_test, y_test))

print("Our Prediction based on the DSCP label: ",
      Counter(le.inverse_transform(y_pred)))
print(classification_report(le.inverse_transform(
    y_test), le.inverse_transform(y_pred)))
print("Let's observe the confusion matrix ...")

# =============================================================================
# # CONFUSION MATRIX
# =============================================================================


def plot_confusion_matrix(df_confusion, title='Confusion matrix', cmap=plt.cm.gray_r):
    '''Confusion Matrix Evaluation'''

    plt.figure(figsize=(9, 9))
    plt.matshow(df_confusion, cmap=cmap, fignum=1)  # imshow

    for (i, j), z in np.ndenumerate(df_confusion):
        plt.text(j, i, '{:0.2f}'.format(z), ha='center', va='center',
                 bbox=dict(boxstyle='round', facecolor='white'))

    # plt.title(title)
    plt.colorbar()
    tick_marks=np.arange(len(df_confusion.columns))
    plt.xticks(tick_marks, df_confusion.columns, rotation=45, fontsize=13)
    plt.gca().xaxis.tick_bottom()
    plt.yticks(tick_marks, df_confusion.index, fontsize=13)
    plt.tight_layout()
    # plt.ylabel(df_confusion.index.name)
    # plt.xlabel(df_confusion.columns.name)
    plt.ylabel("True", fontsize=18)
    plt.xlabel("Predicted", fontsize=18)
    plt.grid(False)
    # plt.savefig("")
    plt.show()


labels=["BE", "NotKnown", "AF", "EF", "CS6"]
confmatrix=confusion_matrix(le.inverse_transform(y_test), le.inverse_transform(y_pred),
                              labels=labels)

df_confusion=pd.DataFrame(confmatrix, index=labels, columns=labels)
# Normalizing the matrix
df_conf_norm=df_confusion.div(df_confusion.sum(axis=1), axis=0)

plot_confusion_matrix(df_conf_norm)
sys.exit("error")
# =============================================================================
# #IMPROVEMENTS for your PROJECT
# =============================================================================
# 1) Dimensionality Reduction ? PCA or LDA
# 2) Adding other variables --> Such as InterArrival time between packets in a flow
# 3) Grid Search : (I'll give you snippet code for this part above ...)

# from sklearn.preprocessing import StandardScaler
# from sklearn.decomposition import PCA
# from sklearn.svm import SVC
# from sklearn.pipeline import Pipeline
# from sklearn.model_selection import GridSearchCV
# scaler1=StandardScaler()
# scaler1.fit(df_)
# feature_scaled = scaler1.transform(df_)
# pca1 = PCA(n_components=4)
# pca1.fit(feature_scaled)
# feature_scaled_pca = pca1.transform(feature_scaled)
# print(np.shape(feature_scaled_pca))
# pipe_steps = [('scaler', StandardScaler()), ('pca',PCA()), ('SupVM', SVC(kernel='rbf'))]





# Set the parameters by cross-validation
tuned_parameters=[{'kernel': ['rbf'], 'gamma': [1e-2, 5e-3],#linear, #0.001,
                     'C': [800,1000] },#900
                    {'kernel': ['sigmoid']}]


clf=GridSearchCV(
    SVC(class_weight='balanced'), tuned_parameters, cv=3)  # Cross-Validation 3

# clf.fit(x_train, y_train)
clf.fit(X_over, Y_over)

print("Best parameters set found on development set:")
print()
print(clf.best_params_)
print()

print("Detailed classification report:")
print()
print("The model is trained on the full development set.")
print("The scores are computed on the full evaluation set.")
print()

y_true, y_pred=y_test, clf.predict(x_test)

print("Label transforation: ", set(y_test),
      le.inverse_transform(list(set(y_test))))



# Precision = TP/(TP + FP)
# Recall = TP/(TP + FN) --> Sensitivity to predict a specific class


# Final Confusion Matrix after Grid Search
labels=["BE", "NotKnown", "AF", "EF", "CS6"]
confmatrix=confusion_matrix(le.inverse_transform(y_test), le.inverse_transform(y_pred),
                              labels=labels)

df_confusion=pd.DataFrame(confmatrix, index=labels, columns=labels)
# Normalizing the matrix
df_conf_norm=df_confusion.div(df_confusion.sum(axis=1), axis=0)

plot_confusion_matrix(df_conf_norm)
sys.exit("error")
