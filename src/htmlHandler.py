# -*- coding: utf-8 -*-
import globals
import re
import zlib


#cf http://www.w3.org/Protocols/rfc2616/rfc2616-sec4.html#sec4.4
def splitHTMLStream(data):
	streamsTab=[]
	while(True):
		if(re.search("^(HTTP/1.[0-1]|GET|POST)",data)!=None):
			mid=data.find("\r\n\r\n")
			if(mid!=None):
				httpHeader=data[:mid]
				body=data[mid+4:]
				regexp=re.search("Content-Length: ?([0-9]*)",httpHeader)
				if(regexp!=None):
					streamsTab.append({"header": httpHeader, "body":body[0:int(regexp.group(1))]})
					data=body[int(regexp.group(1)):]
				else:
					streamsTab.append({"header" : httpHeader, "body" : body})
			else:
				streamsTab.append({"header":None, "body":data})
				break
		else:
			break
		return streamsTab

		

#decode HTML
def decodeAndEscapeHTML(data):
	streamTab=splitHTMLStream(data)
	if streamTab==None:
		return []
	for a in streamTab:
		if a["header"].find("Content-Encoding: gzip\r\n"):
			tmp=a["body"]
			try:
				a["body"]=zlib.decompress(tmp, -zlib.MAX_WBITS)
			except zlib.error:
				#a["body"]=zlib.decompress(tmp)
				print "exception can't decompress gzip"
			print "Content encoding gzip trouve"
	return streamTab


