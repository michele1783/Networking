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
import sys   #usa per avere dei brakpoint

# ==========# 
#Reading .pcap File
# =============================================================================

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
    

#Editcap is a program that reads some or all of the captured packets from the infile, 
#optionally converts them in various ways and writes the resulting packets to the 
#capture outfile.


#-c Splits the packet output to different files based on uniform packet counts with 
#a maximum of <packets per file> each
cmd("editcap -c 1000000 " + file + " " + name_folder + "/.pcap") #1000000 è il numero di pkts in cui voglio splittare la pkt trace. avrò 11 file nel file splitting, 11 piccole pcap trace

print("Check on the amount of pkt in the last .pcap generated: ") #i pkt sono 11811 si generano quindi 12 file. voglio controllare quanti ce ne sono nell'ultimo

file_check = sorted(glob.glob(name_folder+"./*.pcap"))[-1]
cmd("capinfos -c "+file_check)
sys.exit("error message")