# -*- coding: utf-8 -*-
import globals

import sys
import os
import signal
import SimpleHTTPServer
import SocketServer
from JsonDisplayHandler import *
from string import Template
from flowBuilder.reassemble import *
from dataAnalysis.htmlHandler import *
from dataHandler.connect import connectMongo
from dataReceiver.sniffer import *
import commands

import cgi
TEMPLATE_PATH = "./view"


#sends all packets in buffer from indexFrom to indexTo
# if indexTo == -1, sends until the buffer ends
def getSniffedPackets(indexFrom,indexTo):
	db = connectMongo()
	#get data from column stream for specified fields
	nb=0
	finalJson="["
	for stream in db.stream.find({"proto": "TCP", "session":globals.sessionId}):
		if stream['initTS']!=None and stream['initTS']>indexFrom and (stream['initTS']<=indexTo or indexTo==-1):
			smartFlow=reassemble_stream(stream["src"], stream["dst"], stream["sport"], stream["dport"])
			lianaTreeSize=getLianaTreeDataSize(smartFlow)
			if lianaTreeSize!=0:
				stream["media"]=""
				for data in smartFlow:
					(mostProbableMedia,infos)=inspectStreamForMedia(data,stream["sport"],stream["dport"])
					if mostProbableMedia!="":
						stream["media"]=mostProbableMedia+" "+infos
					else:
						stream["media"]=""	
				finalJson+=packetToJson(stream, view="global",size=lianaTreeSize)+", "
				nb+=1
	if nb>0:
		finalJson=finalJson[:len(finalJson)-2]
	finalJson+="]"
	return finalJson

#def getPacketsData(src, dst, sport, dport):
def getPacketsData(src2, dst2):
	temp=src2.split(":")
	src=temp[0]
	sport=temp[1]
	temp=dst2.split(":")
	dst=temp[0]
	dport=temp[1]
	#print (src, sport, dst, dport)
	db = connectMongo()
	#get data from column stream for specified fields
	nb=0
	finalJson="["
	spec = {"proto": "TCP", "src" : src, "dst" : dst, "sport" : int(sport), "dport" : int(dport),"session" : globals.sessionId}
	stream=db.stream.find_one(spec)#, "sport" : sport, "dport" : dport})
	if stream!=None:
		smartFlow=reassemble_stream(stream["src"], stream["dst"], stream["sport"], stream["dport"])
		#for an update lianaTreeSize=getLianaTreeDataSize(smartFlow)
		print "taille", len(smartFlow)
		for data in smartFlow:
			ind = 0	
			(mostProbableMedia,infos)=inspectStreamForMedia(data,stream["sport"],stream["dport"])
			if mostProbableMedia.startswith("HTTP"):
				#streamTab=decodeAndEscapeHTML(data["payload"])
				streamTab=splitHTMLStream(data["payload"])
				count=0
	
				for doc in streamTab:
					stream['data']=""
					stream['data']+="Header :<br />"+cgi.escape(doc["header"])+"<br />Body :<br />"+cgi.escape(doc["body"])+"<br /><br />"
					globals.docNumber+=1
					count+=1
					ct=getContentType(doc)
					infos={}
					if ct!=None:
						infos["link"]=""	
						if ct.strip().startswith("image"):
							infos["type"]="image"
						else:
							infos["type"]="text"
							writeHTTPToFile(doc);
							#finalJson+="link:doc"+str(globals.docNumber)+".html"
							infos["link"]="temp/"+globals.sessionId+"doc"+str(globals.docNumber)+".html"
					else:
						infos["type"]="text"
						writeHTTPToFile(doc);
						#finalJson+="link:doc"+str(globals.docNumber)+".html"
						infos["link"]="temp/"+globals.sessionId+"doc"+str(globals.docNumber)+".html"
					stream["infos"]=infos
					finalJson+=packetToJson(stream,view="data")+", "
					nb+=1
			else:
				
				stream['data']=cgi.escape(data["payload"])
				infos={"link":"", "type":""}
				stream['infos']=infos
				finalJson+=packetToJson(stream,view="data")+", "
				nb+=1
			
	if nb>0:
		finalJson=finalJson[:len(finalJson)-2]
	finalJson+="]"
	
	return finalJson

def getDoc(src, dst, doc):
	temp=src.split(":")
	src=temp[0]
	sport=temp[1]
	temp=dst.split(":")
	dst=temp[0]
	dport=temp[1]
	#print (src, sport, dst, dport)
	db = connectMongo()
	#get data from column stream for specified fields
	nb=0
	spec = {"proto": "TCP", "src" : src, "dst" : dst, "sport" : int(sport), "dport" : int(dport),"session" : globals.sessionId}
	stream=db.stream.find_one(spec)#, "sport" : sport, "dport" : dport})
	if stream!=None:
		smartFlow=reassemble_stream(stream["src"], stream["dst"], stream["sport"], stream["dport"])
		#for an update lianaTreeSize=getLianaTreeDataSize(smartFlow)
		for data in smartFlow:
			(mostProbableMedia,infos)=inspectStreamForMedia(data,stream["sport"],stream["dport"])
			if mostProbableMedia.startswith("HTTP"):
				mydoc=getHTTPDoc(data["payload"],doc)
				#print mydoc
				if mydoc==None:
					return (None,None,None)
			#	print "header : "+str(mydoc["header"])+"\nfin"
				contentType=getContentType(mydoc)
				contentEncoding=getContentEncoding(mydoc)
				return (contentType,contentEncoding,mydoc["body"])
'''	if a["header"].find("Content-Encoding: gzip\r\n"):
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
	'''

#returns a file's template	
def get_page_template(page_name):
	fichier = open(page_name,'r')
	contenu = fichier.read()
	temp = Template(contenu)
	return temp

#used to parse HTTP GET parameters
def get_values_array(parameters):
	if parameters==None:
		return {}
	param=parameters.split('&')
	values={}
	for p in param:
		tmp=p.split('=')
		values[tmp[0]]=tmp[1]
	return values

class HTTPServerHandler(SimpleHTTPServer.SimpleHTTPRequestHandler):
	def do_GET(self):
		splitParams=self.path.split('?')
		self.path=splitParams[0]
		
		if(len(splitParams)>1):
			parameters=splitParams[1]
		else:
			parameters=None
			
		if self.path.endswith(".html"):
		
			self.send_response(200)
			self.send_header('Content-Type','text/html')
			self.end_headers()
			
			tmp=get_page_template(TEMPLATE_PATH+self.path)
			d = dict(plop='blabla')
			self.wfile.write(tmp.safe_substitute(d))
			
		elif self.path=="/" or self.path=="/sniffeirb.html":
		
			self.send_response(200)
			self.send_header('Content-Type','text/html')
			self.end_headers()
			
			tmp=get_page_template(TEMPLATE_PATH+"/"+"sniffeirb.html")
			sniffRunValue=globals.sniff_run
			if sniffRunValue==None:
				sniffRunValue=0
			d = dict(sniff_run=sniffRunValue)
			self.wfile.write(tmp.safe_substitute(d))
			
		elif self.path=='/start':
			self.send_response(200)
			self.send_header('Content-Type','application/json')
			self.end_headers()
			if globals.sniff_run==None or globals.sniff_run==0:
				print "Starting sniffer"
				#starting sniffer thread
				globals.sniff_run=1;
				globals.sniffer = SnifferThread("")
				globals.sniffer.start()
				self.wfile.write("1")#return true

		elif self.path=='/stop':
			self.send_response(200)
			self.send_header('Content-Type','application/json')
			self.end_headers()
			if globals.sniff_run==1:
				print "Stopping sniffer"
				#stopping sniffer thread
				globals.sniff_run=0;
				self.wfile.write("1")#return true
		
		elif self.path=='/sniffall':
		
			self.send_response(200)
			self.send_header('Content-Type','application/json')
			self.end_headers()

			self.wfile.write(getSniffedPackets(0,-1))
			
		elif self.path=='/getdata':
			self.send_response(200)
			self.send_header('Content-Type','application/json')
			self.end_headers()
			
			array=get_values_array(parameters)
			if(len(array)==2):
				f=open ("toto.txt", 'w')
				f.write(getPacketsData(array["src"],array["dst"]))
				f.write('----------------------\n')
				f.close()
				self.wfile.write(getPacketsData(array["src"],array["dst"]))
#			if(len(array)==4):
#				self.wfile.write(getPacketsData(array["src"],array["dst"],int(array["sport"]),int(array["dport"])))
			
		elif self.path=='/sniff':
			#for example, /sniff?from=0&to=3 sends packets from 0 to 3
			
			self.send_response(200)
			self.send_header('Content-Type','application/json')
			self.end_headers()
			
			array=get_values_array(parameters)
			
			if(len(array)>=2):
				indexFrom=array['from']
				indexTo=array['to']
			elif(len(array)==1):
				indexFrom=array['from']
				indexTo=-1
			else:
				indexFrom=0
				indexTo=1
			
			if len(array)<2:
				self.wfile.write("0")#code d'erreur
			else:
				self.wfile.write(getSniffedPackets(float(indexFrom),float(indexTo)))	

		elif self.path=='/getArchive':
			self.send_response(200)
			self.send_header('Content-Type','text/html')
			self.end_headers()
			self.wfile.write(sendArchiveJSON())

		elif self.path=='/deleteArchive':
			array=get_values_array(parameters)
			if len (array)==1:
				print array['idArchive']
				deleteArchive(array['idArchive'])
				self.send_response(200)
				self.send_header('Content-Type','text/html')
				self.end_headers()
			else :
				self.send_response(500)
				self.send_header('Content-Type','text/html')
				self.end_headers()
				self.wfile.write(array['idArchive'])
		
		elif self.path=='/loadArchive':
			array=get_values_array(parameters)
			if len (array)==1:
				print array['idArchive']
				loadArchive(array['idArchive'])
				self.send_response(200)
				self.send_header('Content-Type','text/html')
				self.end_headers()
			else :
				self.send_response(500)
				self.send_header('Content-Type','text/html')
				self.end_headers()
				self.wfile.write(array['idArchive'])
		elif self.path=='/getDoc':
			array=get_values_array(parameters)
			f=array["src"]
			t=array["dst"]
			doc=array["doc"]
			(contentType,contentEncoding,data)=getDoc(f,t,doc)
			self.send_response(200)
			print "content-type: "+str(contentType)+", content-encoding: "+str(contentEncoding)
			self.send_header('Content-Type',contentType)
			self.send_header('Content-Encoding',contentEncoding)
			self.end_headers()
			self.wfile.write(data)
		elif self.path=='/shutdown':
			self.send_response(200)
			self.send_header('Content-Type','text/html')
			self.end_headers()
			self.wfile.write("<html><body><center><h1>server shutdown</h1></center></body></html>")
			globals.sniff_run=0
			print "forcing program to quit ..."
			commands.getoutput('rm view/temp/*')
			os.killpg(os.getpgid(0),signal.SIGKILL)
		else:
			self.path=TEMPLATE_PATH+self.path
			SimpleHTTPServer.SimpleHTTPRequestHandler.do_GET(self)


