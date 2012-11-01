# -*- coding: utf-8 -*-
import json
import sys
from scapy.all import *

def packetListToJson(packetList, indexFrom, view):
	finalJson="["
	for (num,pkt) in enumerate(packetList):
		finalJson+=packetToJson(pkt, num+indexFrom, view)+", "
	if len(packetList)>0:
		finalJson=finalJson[:len(finalJson)-2]
	finalJson+="]"
	return finalJson
	

def packetToJson(pkt, pktNumber, view):
	#print vars(pkt)
	jsonToDisplay=None
	if(view=="global"):
		jsonToDisplay=getGlobalViewJsonFormat(pkt, pktNumber)
	if(jsonToDisplay==None):
		print "error, the view "+view+" has not been found"
		sys.exit()
	return json.dumps(jsonToDisplay,sort_keys=True)#, indent=4)
	
	
def getProtocol(pkt):
	protocol="other"
	if TCP in pkt:
		protocol="TCP"
	elif UDP in pkt:
		protocol="UDP"
	elif ICMP in pkt:
		protocol="ICMP"
	elif DNS in pkt:
		protocol="DNS"
	elif ARP in pkt:
		protocol="ARP"
	elif DHCP in pkt:
		protocol="DHCP"
	return protocol

def getGlobalViewJsonFormat(pkt, pktNumber):
	protocol=getProtocol(pkt)
	if(protocol=="TCP" or protocol =="UDP"):
		dport=pkt.dport
	else:
		dport=""
	return {"num":pktNumber, "src":pkt.sprintf("%IP.src%"), "dst":pkt.sprintf("%IP.dst%"), "size":pkt.sprintf("%IP.len%"), "protocol":protocol, "port":dport}		


