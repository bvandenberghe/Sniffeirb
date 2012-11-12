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
		if(proto=="TCP"):
			db.stream.update(spec, { "$push" : {"packets" : { "flags" : "TODO", "ts" : pkt.time, "seq" : pkt.seq, "ack" : pkt.ack, "data" : pkt.sprintf("%Raw%") }}},upsert=True)
		elif(proto=="UDP"):
			db.stream.update(spec, { "$push" : {"packets" : { "flags" : "TODO", "ts" : pkt.time, "data" : pkt.sprintf("%Raw%") }}},upsert=True)
		#for p in db.stream.find():
		#	print p
