#!/usr/bin/python
# -*- coding: utf-8 -*-
from pymongo import Connection
from JsonDisplayHandler import getProtocol
from scapy.all import *


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
		spec = {"src" : pkt[IP].src, "dst" : pkt[IP].dst, "dport" : dport, "sport" : sport, "proto" : proto , "type" : Type}
		data=pkt.sprintf("%Raw.load%")
		if(proto=="TCP"):
			if(data!=""):
				db.stream.update(spec, { "$push" : {"packets" : { "flags" : "TODO", "ts" : pkt.time, "seq" : pkt.seq, "ack" : pkt.ack, "data" :  data}}},upsert=True)
			else:
				db.stream.update(spec, { "$push" : {"packets" : { "flags" : "TODO", "ts" : pkt.time, "seq" : pkt.seq, "ack" : pkt.ack}}},upsert=True)
				
		elif(proto=="UDP"):
			if(data!=""):
				db.stream.update(spec, { "$push" : {"packets" : { "flags" : "TODO", "ts" : pkt.time, "data" : data }}},upsert=True)
			else:
				db.stream.update(spec, { "$push" : {"packets" : { "flags" : "TODO", "ts" : pkt.time}}},upsert=True)
		#for p in db.stream.find():
		#	print p
