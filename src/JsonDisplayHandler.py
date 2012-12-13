# -*- coding: utf-8 -*-
import json
import sys
from scapy.all import *
from reassemble import reassemble_stream
from protocol import inspectStreamForProtocol


'''def packetListToJson(packetList, indexFrom, view):
	finalJson="["
	for (num,pkt) in enumerate(packetList):
		finalJson+=packetToJson(pkt, num+indexFrom, view)+", "
	if len(packetList)>0:
		finalJson=finalJson[:len(finalJson)-2]
	finalJson+="]"
	return finalJson
	'''

def packetToJson(pkt, view):
	#print vars(pkt)
	jsonToDisplay=None
	if(view=="global"):
		smartFlow=reassemble_stream(pkt['src'],pkt['dst'],pkt['sport'],pkt['dport'])
		media=inspectStreamForProtocol(smartFlow,pkt["sport"],pkt["dport"])
		jsonToDisplay={"initTS":pkt['initTS'], "src":pkt['src'], "dst":pkt['dst'], "sport":pkt['sport'], "dport":pkt['dport'], "proto":pkt['proto'],"media":media, "size" : getLianaTreeDataSize(smartFlow)}
	if(view=="data"):
		jsonToDisplay={"src":pkt['src'], "dst":pkt['dst'], "sport":pkt['sport'], "dport":pkt['dport'], "proto":pkt['proto'], "data" : pkt['data'].encode('string_escape')}
		
	if(jsonToDisplay==None):
		print "error, the view "+view+" has not been found"
		sys.exit()
	return json.dumps(jsonToDisplay,sort_keys=True)#, indent=4)


#give the sum of all datas in all the lianatrees
def getLianaTreeDataSize(smartFlow):	
	size=0
	for data in smartFlow:
		size+=len(data["payload"])
	return size
	
def getProtocol(pkt):
	protocol="other"
	if TCP in pkt:
		protocol="TCP"
	elif UDP in pkt:
		protocol="UDP"
	elif ICMP in pkt:
		protocol="ICMP"
	return protocol


