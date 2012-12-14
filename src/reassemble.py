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
	#start reassembling stream from datastream
	db = connectMongo(globals.sessionId)
	#db = connectMongo('sess_07-12-2012-160442')
	#get data from column stream for specified fields
	flow=db.stream.find_one({"proto": "TCP", "src": src, "dst": dst, "sport": sport, "dport": dport})
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
	while (i<len(liana.packets)):
		currentPacket=liana.packets[i]
		addedPacket=False
		dataTabTemp=dataTab
		for currentData in dataTabTemp:
			lastPacket=currentData[len(currentData)-1]
			ind=0
			for currentNext in lastPacket['next']:
				ind+=1
				if currentNext==currentPacket['id']:
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




#Suppression des chemins non terminé dans la table (qui ont aidé à la construction des autres chemins)
#Cleaning all partial paths
def cleanDataTab(dataTab):
	dataTabTemp=list(dataTab)
	for data in dataTabTemp:
		pkt=data[len(data)-1]
		if pkt['next']!=[]:
			dataTab.remove(data)
	return dataTab

#remove duplicate payloads in a same lianatree
def removeTwins(smartFlow):
	i=0
	j=0
	while i < len(smartFlow):
		while j < len(smartFlow):
			if(i!=j and smartFlow[i]['payload'] == smartFlow[j]['payload']):
				smartFlow.pop(j)				
			j+=1
		i+=1
		j=0
	return smartFlow


#reconstruction de la payload
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
	for d in dataTab:
		for p in d:
			print p['id'],p['next']
		print "\n"

