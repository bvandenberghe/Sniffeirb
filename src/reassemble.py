# -*- coding: utf-8 -*-
import time
from pymongo import Connection
from threading import Thread
import sys, os
from scapy.all import *
import array
import sys
from lianatree import *
from connect import connectMongo
import globals

#input : packets belonging to a single stream (TCP STREAM ONLY)
#output : stream payload reassembled
def reassemble_stream (src, dst, sport, dport):
	#print "debut"
	#start reassembling stream from datastream
	db = connectMongo(globals.sessionId)
	#db = connectMongo('sess_07-12-2012-160442')
	#get data from column stream for specified fields
	flow=db.stream.find_one({"proto": "TCP", "src": src, "dst": dst, "sport": sport, "dport": dport})
	#print "le flow ", flow, "\n"
    #create the twice chained list of packets
	liana=LianaTree()
	for pkt in flow['packets']:
		liana.feed(pkt)
	i=0
	dataTab=[]
	tempTab=[]
	while (i<len(liana.packets)):
		currentPacket=liana.packets[i]
		addedPacket=False
		dataTabTemp=dataTab
#		print "iteration ", i 
#		printDataTab(dataTab)
#		print "packet : ", currentPacket['id'], currentPacket['seq']

		for currentData in dataTabTemp:
			lastPacket=currentData[len(currentData)-1]
#			print "		debut boucle for, current data : ", lastPacket['id'], "\n"
			ind=0
	#		print "on test : " 
			for currentNext in lastPacket['next']:
#				print "			indice ",ind
				ind+=1
#				print "			boucle currentnext : ",currentNext, currentPacket['id']
				if currentNext==currentPacket['id']:
#					print "			on ajoute le packet  : ", currentPacket['id']
					newData=list(currentData)
					newData.append(currentPacket)
					dataTab.append(newData)
					addedPacket=True
		
		if addedPacket==False:	
#			print ' ajout dune racine : ', currentPacket['id'], "\n" 
			emptyData=[]
			emptyData.insert(0,currentPacket)
			dataTab.append(emptyData)					
		i+=1

#Suppression des chemins non terminé dans la table (qui ont aidé à la construction des autres chemins)
	dataTabTemp=list(dataTab)
	for data in dataTabTemp:
		pkt=data[len(data)-1]
		if pkt['next']!=[]:
			dataTab.remove(data)
		
			
			
#	print "###########################################################################\n"
	#printDataTab(dataTab)
#	print "###########################################################################\n"


#reconstruction de la payload
	payloads=[]
	count=0
	for data in dataTab:
		payloads.insert(count,"")
		for p in data:
			payloads[count]+=p['data']
		count+=1
		
#	for payload in payloads:
#		print payload, "\n#######################################!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"

	return payloads

def printDataTab(dataTab):
	for d in dataTab:
		for p in d:
			print p['id'],p['next']
		print "\n"




#reassemble_stream('82.113.152.80', '192.168.8.129', 80,44339)

