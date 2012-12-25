# -*- coding: utf-8 -*-
import json
import sys
from scapy.all import *
from flowBuilder.reassemble import *
from dataHandler.mongoHandler import *

'''def packetListToJson(packetList, indexFrom, view):
	finalJson="["
	for (num,stream) in enumerate(packetList):
		finalJson+=packetToJson(stream, num+indexFrom, view)+", "
	if len(packetList)>0:
		finalJson=finalJson[:len(finalJson)-2]
	finalJson+="]"
	return finalJson
	'''

def packetToJson(stream, view="data", size = 0):
	jsonToDisplay=None
	if(view=="global"):
		jsonToDisplay={"initTS":stream['initTS'], "src":stream['src'], "dst":stream['dst'], "sport":stream['sport'], "dport":stream['dport'], "proto":stream['proto'],"media":stream["media"], "size" : size}

	if(view=="data"):
		jsonToDisplay={"src":stream['src'], "dst":stream['dst'], "sport":stream['sport'], "dport":stream['dport'], "proto":stream['proto'], "data" : stream['data'].encode('string_escape'), "infos" : stream['infos']}
		
	if(jsonToDisplay==None):
		print "error, the view "+view+" has not been found"
		sys.exit()

	return json.dumps(jsonToDisplay,sort_keys=True)#, indent=4)



#send all names of previous sniffed session
def sendArchiveJSON():
	return json.JSONEncoder().encode(getArchive())

