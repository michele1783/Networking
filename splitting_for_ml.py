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

list_pcap_file = glob.glob("./*.pcap")

print("Number of .pcap files: ", len(list_pcap_file))

file = list_pcap_file[0]
print(file)

#create directory
name_folder = "Splitting_2"

try:
    shutil.rmtree(name_folder)
except:
    pass

try:
    os.mkdir(name_folder)
#If you have already created it Error
except OSError:
    print("Creation of the directory %s failed" % name_folder)
else:
    print("Successfully created the directory %s" % name_folder)

# -c Splits the packet output to different files based on uniform packet counts with 
# a maximum of <packets per file> each
cmd("editcap -c 2500000 " + file + " " + name_folder + "/.pcap")

list_pcap_file = glob.glob("./Splitting/*.pcap")

print("Number of .pcap files: ", len(list_pcap_file))

file = list_pcap_file[0]
print(file)

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

file_name = glob.glob("./Splitting_2/*.pcap")[0]
print("Working with: ", file_name)
dataFrame = extract_Info_pckt(file_name)
dataFrame.to_pickle("PacketDataframeForMachineLearning.pkl")
