# -*- coding: utf-8 -*-
import time
from pymongo import Connection
from threading import Thread
import sys, os
from scapy.all import *
import array
import sys
from lianatree import *
from dataHandler.connect import *
import globals

#input : packets belonging to a single stream (TCP STREAM ONLY)
#output : stream payload reassembled
def reassemble_stream (src, dst, sport, dport):
	#start reassembling stream from datastream
	db = connectMongo()
	#get data from column stream for specified fields
	flow=db.stream.find_one({"proto": "TCP", "src": src, "dst": dst, "sport": sport, "dport": dport, "session":globals.sessionId})
	#create the twice chained list of packets
	liana=LianaTree()
	for pkt in flow['packets']:
		liana.feed(pkt)
	
	dataTab=pathBuilder(liana)
	dataTab=cleanDataTab(dataTab)

	smartFlow = rebuilding(dataTab)
	smartFlow=removeTwins(smartFlow)
#	splitDocuments(smartFlow)
	return smartFlow

#algorithm of the rebuilding of all possible paths
def pathBuilder(liana):
	i=0
	dataTab=[]
	#dataTab will contain several tables of packets
	while (i<len(liana.packets)):
		currentPacket=liana.packets[i]
		addedPacket=False
		dataTabTemp=dataTab
		for currentData in dataTabTemp:
			lastPacket=currentData[len(currentData)-1]
			ind=0
			#for each next of the current packet
			for currentNext in lastPacket['next']:
				ind+=1
				if currentNext==currentPacket['id']:
					#if the current packet is the next of another
					newData=list(currentData)
					newData.append(currentPacket)
					dataTab.append(newData)
					addedPacket=True
		
		if addedPacket==False:	
			emptyData=[]
			emptyData.insert(0,currentPacket)
			dataTab.append(emptyData)					
		i+=1
	return dataTab


#Cleaning all partial paths
def cleanDataTab(dataTab):
	dataTabTemp=list(dataTab)
	for data in dataTabTemp:
		pkt=data[len(data)-1]
		if pkt['next']!=[]:
			dataTab.remove(data)
	return dataTab

#remove duplicate payloads in the same lianatree
def removeTwins(smartFlow):
	seen = set()
	seen_add = seen.add
	return [ x for x in smartFlow if x['payload'] not in seen and not seen_add(x['payload'])]

#rebuilding the payload of all paths
def rebuilding(dataTab):
	payloads=[]
	count=0
	for data in dataTab:
		payloads.insert(count,{"payload":"","likely":100})
		for p in data:
			payloads[count]["payload"]+=p['data']
		count+=1
	return payloads

#print for debug
def printDataTab(dataTab):
	i=0
	for d in dataTab:
		print "index : ", i
		for p in d:
			print "id ", p['id'], "seq ",p['seq'],"next id", p['next']
		print "\n"
		i+=1

