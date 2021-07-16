# -*- coding: utf-8 -*-
"""
Created on Fri Jul  2 13:36:33 2021

@author: Nichele Luca Puzzo
"""

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

#============================================================================= 
#Splitting .pcap File in 5 different pcap file
#=============================================================================

#all files with specific extension
list_pcap_file = glob.glob("./*.pcap")

print("Number of .pcap files: ", len(list_pcap_file))

file = list_pcap_file[0]
print(file)

#create directory
name_folder = "Splitting"

#Remove directory already created
#shutil.rmtree(name_folder) 

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


#Capinfos is a program that reads one or more capture files and returns 
#some or all available statistics (infos) of each <infile> in one of two types 
#of output formats: long or table.

# #*Options*
# print("*OPTIONS :*")

# print()
# print()
# #-c --> Number of Packets in the capture
# cmd("capinfos -c "+file)
# print()
# print()
# #-i --> The average data rate, in bits/sec, data bite rate
# cmd("capinfos -i "+file)
# print()
# print()
# #-z --> The average PACKET SIZE
# cmd("capinfos -z "+file)
# print()
# print()


#-A --> Generate all infos
cmd("capinfos -A "+file)
print()
print()


#=============================================================================
#Info -Table Format
#=============================================================================

#To generate a TAB delimited table form report
cmd("capinfos -T -m "+file+" >info.txt") #-T table format, #-m just ofr comma separated all the statistics
print()
print()

#To generate a CSV delimited table style report of all infos 
#and write it to a text file called info.csv use:
cmd("capinfos -TmQ "+file+" >info.csv")
print()
print()

file_name = glob.glob("./Splitting/*.pcap")[0]
print("Working with: ", file_name)
pcap = pyshark.FileCapture(file_name)
#Create file pickle
# def extract_Info_pckt(file_name): #nome del file del pcap trace: #lista_packet_ICMP
    
#     pcap = pyshark.FileCapture(file_name) #reading pcap file

#     title = ["Label DSCP", "header len", "ds_field","ds_field_ecn", "length", 
#           "Protocol" ,"flag_df", "flag_mf", "flag_rb", "fragment_offset", "ttl", 
#           "IP_SRC", "IP_DST","src_port", "dst_port","time"] 
#     #header_len circa 20 bytes
#     #ds_len info about diferentiated service,priority of a packet in the network
#     #ecn: explicit congestion notification, will know if there is congestion in that link
#     #all the features come from IP layer tranne per src and dst port
#     #protocol = 6 se tcp, 17 udp
#     #ttl: how many hop remain for that specific pkt until reach the destination, se 0 link molto congestionato 
#     #time of capture that specific pkt
    
    
    
#     total_info = []  # for each pkt i fil this list, will be a list of list and then will transform in  a dataframe
#     print("Now I'm working on: " + file_name)
#     print()
       
    
#     i = 0
#     dscp = []
#     total_info.append(title) # total_info è la lista più esterna, values la lista per ogni pkt
    
#     for packet in pcap:
        
#         ### MAC Address verification ###
#         #sorgente = pcap[0].eth.src
            
#         #Creating an empty list where we collect info about the packet
#         #Useful this format to create then a DataFrame
        
#         values = []
        
#         #print(packet.layers)
#         #We extract onòy the packets from IP Level and only Version IPv4
#         #if 'IP' in packet and packet.eth.src == sorgente:
#         if 'IP' in packet : #we are just taking ip packet, exploit the dissectors available on tshark. 
#             #dissector= a zoom on each specific layer of the packet          
            
#             #Label
#             values.append(packet.ip.dsfield_dscp) #we extract form each pkt the specific info that we want to add in our list 
#             dscp.append(packet.ip.dsfield_dscp)
#             #Features
            
#             #Header Length
#             values.append(int(packet.ip.hdr_len))
#             #Differentiated Service
#             values.append(int(packet.ip.dsfield,16))
#             #Explicit Congestion Notification
#             values.append(packet.ip.dsfield_ecn)
#             #Length of the Packet including the header
#             values.append(int(packet.ip.len))
#             #Number of Protocol (e.g. 6 = TCP, 17 = UDP, 1 = ICMP)
#             values.append(int(packet.ip.proto))
#             #Flag Do not Fragment 
#             values.append(packet.ip.flags_df)
#             #Flag More Fragment
#             values.append(packet.ip.flags_mf)
#             #Flag Reserved - Must be 0
#             values.append(packet.ip.flags_rb)
#             #Fragment Offset
#             values.append(packet.ip.frag_offset)
#             #Time To Live
#             values.append(int(packet.ip.ttl))
            
            
#             #### Extraction of the Ip Source and Ip Destination###
            
#             source = packet.ip.src
#             values.append(source)
            
#             destination = packet.ip.dst
#             values.append(destination)
  
#             #### Extraction of the Port ####
#             if "UDP" in packet:
#                 values.append(packet.udp.srcport)
#                 values.append(packet.udp.dstport)

#             elif "TCP" in packet :
#                 values.append(packet.tcp.srcport)
#                 values.append(packet.tcp.dstport)            
                
#             else:
#                 #Protocol as IP and ICMP e Ws.Short Port in src and dst will be set to -1
#                 values.append(-1) #dummy variable to recognize that pkt comes from different protocol
#                 values.append(-1)
                
#             #if "ICMP" in packet:
#             #    lista_packet_ICMP.append((packet.ip.dsfield_dscp, packet.icmp.type, packet.icmp.code))
            
            
#             #Time will be used for the simulation
#             time = float(packet.sniff_timestamp)
#             values.append(time)
             
#             #Update the number of pckts
#             i += 1
            
#             #Store all the caracteristics of a packet into the Totale list
#             total_info.append(values)
            
#     print("Now we have finished the analysis so we closed the file: " + file_name)     
#     pcap.close()
   
#     print(len(total_info))
#     #Creation of the data frame
#     dataFrame = pd.DataFrame(total_info[1:],columns = total_info[0])
    
#     return dataFrame
    
#     # #We are saving the dataframe of Features Packets
#     # with open('FeaturesDataFrame/' + title + '.pkl', 'wb') as f:
#     #     pickle.dump(tot_dat, f)
    
#     # print("Here we have analyzed this number of pckts: " + str(i))
    
#     #Label Analysis
#     # occ_label = dict(Counter(dscp))
#     #print("DSCP occurrences",occ_label)

  
# dataFrame = extract_Info_pckt(file_name)
# print("Finish the reading part")
# dataFrame.to_pickle("PacketDataframe.pkl")
dataFrame = pd.read_pickle("PacketDataframe.pkl")
folder_image = "Image"

#Remove directory already created
shutil.rmtree(folder_image) 

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
# # TOP 6 DESTINATION   
# =============================================================================

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
fig.tight_layout()
targets = zip(grouped.index, axs.flatten())
for i, (key, ax) in enumerate(targets):
    print(key)
    #ax.plot(data_couple.get_group(key)["length"])
    ax.plot(bitRate(data_couple.get_group(key)),marker = "o")
    ax.set_title(key)
    ax.set_xlabel("T (decisec)")
    ax.set_ylabel("bit/sec")
    ax.xticks(np.arange(0, 36, step=1))
    ax.set_yscale('log')
ax.legend()
fig.suptitle('TOP 6 IP Dst', fontsize=16)
plt.savefig(folder_image + "TOP 6 IP Dst")
plt.show()


# =============================================================================
# # TOP 5 DESTINATION   
# =============================================================================
data_couple = dataFrame.groupby(["IP_DST"])[['length']].agg('sum').sort_values(by=['length'], ascending=False).head(5)

plt.figure(figsize = (18, 12), dpi = 75)
#Remove my Ip too traffic generated
plt.barh(data_couple.index, data_couple['length']/1e3, color = sns.color_palette('plasma', 10))
plt.title('Top 5 destinations for received data', fontsize = 30, loc = 'center', pad = 15)
plt.ylabel('IP address', fontsize = 18, labelpad = 5)
plt.xlabel('Total volume of received data ($Kbit$)', fontsize = 20, labelpad = 15)
plt.xticks(fontsize = 14)
plt.yticks(fontsize = 14)
plt.savefig(folder_image +"TOP Destination")
plt.show()

# =============================================================================
# # TOP 5 SENDER
# =============================================================================
data_couple = dataFrame.groupby(["IP_SRC"])[['length']].agg('sum').sort_values(by=['length'], ascending=False).head(5)

plt.figure(figsize = (18, 12), dpi = 75)
#Remove my Ip too traffic generated
plt.barh(data_couple.index, data_couple['length']/1e3, color = sns.color_palette('plasma', 10))
plt.title('Top 5 destinations for sending data', fontsize = 30, loc = 'center', pad = 15)
plt.ylabel('IP address', fontsize = 18, labelpad = 5)
plt.xlabel('Total volume of sending data ($Kbit$)', fontsize = 20, labelpad = 15)
plt.xticks(fontsize = 14)
plt.yticks(fontsize = 14)
plt.savefig(folder_image +"TOP Sender")
plt.show()


#Top 10 protocol
data_couple = dataFrame.groupby(["Protocol"])[['length']].agg('sum').sort_values(by=['length'], ascending=False).head(10)




###############################################################################
sys.exit("error message")
