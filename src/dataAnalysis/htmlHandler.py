# -*- coding: utf-8 -*-
import globals
import re
import cgi
from io import BytesIO
import dataAnalysis.gzip_patched as gzip
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
		else:
			streamsTab.append({"header":None, "body":data})
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
			print "Content encoding gzip trouve"
			try:
				f = BytesIO(tmp)
				gf=gzip.GzipFile(fileobj=f)
				a["body"]=gf.read()
				#zlib.decompress(tmp, -zlib.MAX_WBITS)
				f.close()
				gf.close()
			except Exception, e:
				print "exception: can't decompress gzip"
				print e
	return streamTab


