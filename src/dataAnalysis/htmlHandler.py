# -*- coding: utf-8 -*-
import globals
import re
import cgi
from io import BytesIO
import dataAnalysis.gzip_patched as gzip
#cf http://www.w3.org/Protocols/rfc2616/rfc2616-sec4.html#sec4.4
def splitHTMLStream(data):
	streamsTab=[]
	print data[0:200]
	chain=data.split("\r\n\r\n")
	i=0
	j=0
	finalTab=[]
	newchain=[]
	#we create a new tab with header/body each 2 list element
	while i < len(chain):
		if re.match("^((?:HTTP/1\\.[0-2] [0-9]* [a-zA-Z ]*)|(?:GET|POST))",chain[i]):
			newchain.append(chain[j])
			newchain.append(chain[j+1])
			j+=2
			i+=2
		else:
			if i>0 and j>0:
				newchain[j-1]+=chain[i]
			i+=1
	i=0
	while i < len(newchain):
		if i+1>=len(newchain):
			finalTab.append({"header":newchain[i],"body":""})
		else:
			finalTab.append({"header":newchain[i],"body":newchain[i+1]})
			i+=2
	#print finalTab
	return finalTab
'''	
		regexp=re.findall("((?:HTTP/1\\.[0-2] [0-9]* [a-zA-Z ]*\\r\\n)(?:[a-zA-Z0-9\\-_;\\.,?/\\\\= \\t:]*(?:\\r\\n)?)*)\\r\\n\\r\\n((?:.*)(?:\\r\\n\\r\\n)(?=HTTP))",data)
		print regexp
		for (header,body) in regexp:
			
			streamsTab.append({"header":header,"body":body})
		return streamsTab
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
'''
		

#decode HTML
def decodeAndEscapeHTML(data):
	streamTab=splitHTMLStream(data)
	if streamTab==None:
		return []
	for a in streamTab:
		if a["header"].find("Content-Encoding: gzip\r\n"):
			a["body"]=a["body"][a["body"].find("\x1f\x8b"):]#because sometimes a few caracters at the begining keep gzip from working
			print "Content encoding gzip trouve"
			try:
				f = BytesIO(a["body"])
				gf=gzip.GzipFile(fileobj=f)
				a["body"]=gf.read()
				#zlib.decompress(tmp, -zlib.MAX_WBITS)
				f.close()
				gf.close()
			except Exception, e:
				print "exception: can't decompress gzip"
				print e
	return streamTab

def writeHTTPToFile(doc):
	if doc["header"].find("Content-Type: text/html"):
		f=open("view/temp/"+globals.sessionId+"doc"+str(globals.docNumber)+".html","w")
		f.write(doc["body"])
		f.close()
		

def getContentType(doc):
	regexp=re.search("Content-Type: ?([a-zA-Z0-9\\-/]*)",doc["header"])
	if regexp!=None:
		return regexp.group(0)
	return None

def getHTTPDoc(data, docNb):
	streamTab=splitHTMLStream(data)
	print streamTab
	docNb=int(docNb)
	if streamTab==None:
		return None 
	#for a in streamTab:
	if docNb>=len(streamTab):
		return None
	return streamTab[docNb]

