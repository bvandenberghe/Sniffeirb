# -*- coding: utf-8 -*-
import json
import sys
class JsonDisplayHandler:
	
	@staticmethod
	def getFormatPacketFunction(view):
		if view == "global":
			return JsonDisplayHandler.packetToJson_global
		print "the view "+view+" has not been found"
		sys.exit()
	
	@staticmethod
	def packetListToJson(packetList, view):
		finalJson="["
		for pkt in packetList:
			finalJson+=JsonDisplayHandler.getFormatPacketFunction(view)(pkt)
		finalJson=finalJson[:len(finalJson)-2]
		finalJson+="]"
		return finalJson
		
	@staticmethod
	def packetToJson_global(pkt):
		jsonToDisplay={"num":"undefined", "src":pkt.src, "dst":pkt.dst, "size":"undefined", "protocol":"undefined", "port":"undefined"}
		return json.dumps(jsonToDisplay,sort_keys=True, indent=4)
		
