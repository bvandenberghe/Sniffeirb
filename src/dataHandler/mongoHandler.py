#!/usr/bin/python
# -*- coding: utf-8 -*-
import bson
from scapy.all import *
from dataAnalysis.protocol import *
import globals
from dataHandler.connect import *

# methode .explain pour voir le nombre d'appel qui fait pour résoudre la requete 
# indexer les champs

#add or update data into the database
def insertPacket(pkt,db):
	proto=getProtocol(pkt)
	Type="unknown"
	if(IP in pkt):
		Type="IP"
		if(proto=="TCP" or proto =="UDP"):
			dport=pkt.dport
			sport=pkt.sport
		else:
			dport=""
			sport=""
		spec = {"src" : pkt[IP].src, "dst" : pkt[IP].dst, "dport" : dport, "sport" : sport, "proto" : proto, "type" : Type,"session":globals.sessionId}
		
		if(proto=="TCP"):
			data=bson.binary.Binary(str(pkt[TCP].payload))
			length=len(pkt[TCP].payload)
			if(data):
				db.stream.update(spec, { "$set": {"initTS" : getInitialisationTimestamp(db, pkt[IP].src, pkt[IP].dst, sport, dport)}, "$push" : {"packets" : { "flags" : pkt.sprintf("%TCP.flags%"), "ts" : pkt.time, "seq" : pkt.seq, "ack" : pkt.ack, "data" :  data, "dataLength" : length}}},upsert=True)
			else:
				db.stream.update(spec, { "$set": {"initTS" : getInitialisationTimestamp(db, pkt[IP].src, pkt[IP].dst, sport, dport)}, "$push" : {"packets" : { "flags" : pkt.sprintf("%TCP.flags%"), "ts" : pkt.time, "seq" : pkt.seq, "ack" : pkt.ack}}},upsert=True)
				
		elif(proto=="UDP"):
			data=bson.binary.Binary(str(pkt[UDP].payload))
			length=len(pkt[UDP].payload)
			if(data):
				db.stream.update(spec, { "$set": {"initTS" : getInitialisationTimestamp(db, pkt[IP].src, pkt[IP].dst, sport, dport)}, "$push" : {"packets" : { "flags" : pkt.sprintf("%UDP.flags%"), "ts" : pkt.time, "data" : data, "dataLength" : length }}},upsert=True)
			else:
				db.stream.update(spec, { "$set": {"initTS" : getInitialisationTimestamp(db, pkt[IP].src, pkt[IP].dst, sport, dport)}, "$push" : {"packets" : { "flags" : pkt.sprintf("%UDP.flags%"), "ts" : pkt.time,}}},upsert=True)

#delete all entries into mongodb relative at sniffeirb
def deleteAllArchives():
	'''connection = connectMongo()
	dbs=connection.database_names()
	for d in dbs:
		if d.startswith('sess_'):
			connection.drop_database(d)
	connection.disconnect()'''

#list all entries into mongodb relative at sniffeirb except the current one.
def getArchive():
	result=[]
	'''connection = connectMongo()
	dbs=connection.database_names()
	for d in dbs:
			if d.startswith('sess_'):
				result.append(d)
	connection.disconnect()'''
	return result

#delete a given archive
def deleteArchive(name):
	'''connection = connectMongo()
	connection.drop_database(name)
	connection.disconnect()'''

#delete a given archive
def loadArchive(name):
	globals.sessionId=str(name)

#initialisation timestamp is the min timestamp of all packets in the stream
def getInitialisationTimestamp(db, src, dst, sport, dport):
	stream=db.stream.find_one({"src": src, "dst": dst, "sport": sport, "dport": dport, "session":globals.sessionId})
	if stream==None:
		return None
	minimumTS=min(stream['packets'], key=lambda x:x['ts'])['ts']
	return minimumTS


