#!/usr/bin/python
# -*- coding: utf-8 -*-
import bson
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
		
		if(proto=="TCP"):
			data=bson.binary.Binary(str(pkt[TCP].payload))
			if(data):
				db.stream.update(spec, { "$push" : {"packets" : { "flags" : pkt.sprintf("%TCP.flags%"), "ts" : pkt.time, "seq" : pkt.seq, "ack" : pkt.ack, "data" :  data}}},upsert=True)
			else:
				db.stream.update(spec, { "$push" : {"packets" : { "flags" : pkt.sprintf("%TCP.flags%"), "ts" : pkt.time, "seq" : pkt.seq, "ack" : pkt.ack}}},upsert=True)
				
		elif(proto=="UDP"):
			data=bson.binary.Binary(str(pkt[UDP].payload))
			if(data):
				db.stream.update(spec, { "$push" : {"packets" : { "flags" : pkt.sprintf("%UDP.flags%"), "ts" : pkt.time, "data" : data }}},upsert=True)
			else:
				db.stream.update(spec, { "$push" : {"packets" : { "flags" : pkt.sprintf("%UDP.flags%"), "ts" : pkt.time}}},upsert=True)
		#for p in db.stream.find():
		#	print p
