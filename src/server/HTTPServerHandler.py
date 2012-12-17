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

import cgi
TEMPLATE_PATH = "./view"


#fonction qui renvoie tous les packets du buffer du numéro indexFrom au numéro indexTo, si indexTo vaut -1 ça veux dire jusqu'à la fin
def getSniffedPackets(indexFrom,indexTo):
	db = connectMongo(globals.sessionId)
	#get data from column stream for specified fields
	nb=0
	finalJson="["
	for stream in db.stream.find({"proto": "TCP"}):
		if stream['initTS']!=None and stream['initTS']>indexFrom and (stream['initTS']<=indexTo or indexTo==-1):
			smartFlow=reassemble_stream(stream["src"], stream["dst"], stream["sport"], stream["dport"])
			lianaTreeSize=getLianaTreeDataSize(smartFlow)
			stream["media"]=""
			for data in smartFlow:
				(mostProbableMedia,infos)=inspectStreamForMedia(data,stream["sport"],stream["dport"])
				if mostProbableMedia!="":
					stream["media"]=mostProbableMedia+" "+infos
			
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
	db = connectMongo(globals.sessionId)
	#get data from column stream for specified fields
	nb=0
	finalJson="["
	spec = {"proto": "TCP", "src" : src, "dst" : dst, "sport" : int(sport), "dport" : int(dport)}
	stream=db.stream.find_one(spec)#, "sport" : sport, "dport" : dport})
	if stream!=None:
		smartFlow=reassemble_stream(stream["src"], stream["dst"], stream["sport"], stream["dport"])
		#pour la mise a jour lianaTreeSize=getLianaTreeDataSize(smartFlow)
		for data in smartFlow:
			streamTab=decodeAndEscapeHTML(data["payload"])
			stream['data']=""
			for a in streamTab:
				stream['data']+="Header :<br />"+cgi.escape(a["header"])+"<br />Body :<br />"+cgi.escape(a["body"])+"<br /><br />"
				finalJson+=packetToJson(stream,view="data")+", "
				nb+=1
	if nb>0:
		finalJson=finalJson[:len(finalJson)-2]
	finalJson+="]"
	return finalJson


#fonction qui renvoie le template d'un fichier	
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
			self.send_header('Content-type','text/html')
			self.end_headers()
			
			tmp=get_page_template(TEMPLATE_PATH+self.path)
			d = dict(plop='blabla')
			self.wfile.write(tmp.safe_substitute(d))
			
		elif self.path=="/" or self.path=="/sniffeirb.html":
		
			self.send_response(200)
			self.send_header('Content-type','text/html')
			self.end_headers()
			
			tmp=get_page_template(TEMPLATE_PATH+"/"+"sniffeirb.html")
			sniffRunValue=globals.sniff_run
			if sniffRunValue==None:
				sniffRunValue=0
			d = dict(sniff_run=sniffRunValue)
			self.wfile.write(tmp.safe_substitute(d))
			
		elif self.path=='/start':
			self.send_response(200)
			self.send_header('Content-type','application/json')
			self.end_headers()
			if globals.sniff_run==None or globals.sniff_run==0:
				print "on commence à sniffer"
				#démarrage du thread du sniffer
				globals.sniff_run=1;
				globals.sniffer = SnifferThread("")
				globals.sniffer.start()
				self.wfile.write("1")#return true

		elif self.path=='/stop':
			self.send_response(200)
			self.send_header('Content-type','application/json')
			self.end_headers()
			if globals.sniff_run==1:
				print "on arrete de sniffer"
				#arrêt du thread du sniffer
				globals.sniff_run=0;
				self.wfile.write("1")#return true
		
		elif self.path=='/sniffall':
		
			self.send_response(200)
			self.send_header('Content-type','application/json')
			self.end_headers()

			self.wfile.write(getSniffedPackets(0,-1))
			
		elif self.path=='/getdata':
			self.send_response(200)
			self.send_header('Content-type','application/json')
			self.end_headers()
			
			array=get_values_array(parameters)
			if(len(array)==2):
				self.wfile.write(getPacketsData(array["src"],array["dst"]))
#			if(len(array)==4):
#				self.wfile.write(getPacketsData(array["src"],array["dst"],int(array["sport"]),int(array["dport"])))
			
		elif self.path=='/sniff':
			#/sniff?from=0&to=3 renverra les paquets du numéro 0 au 3
			
			self.send_response(200)
			self.send_header('Content-type','application/json')
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
			
			#print "from :"+str(indexFrom)+"   to:"+str(indexTo)
			if len(array)<2:
				self.wfile.write("0")#code d'erreur
			else:
				#print "from "+ indexFrom+ "  to "+indexTo
				self.wfile.write(getSniffedPackets(float(indexFrom),float(indexTo)))	

		elif self.path=='/getArchive':
			self.send_response(200)
			self.send_header('Content-type','text/html')
			self.end_headers()
			self.wfile.write(sendArchiveJSON())

		elif self.path=='/deleteArchive':
			array=get_values_array(parameters)
			if len (array)==1:
				print array['idArchive']
				deleteArchive(array['idArchive'])
				self.send_response(200)
				self.send_header('Content-type','text/html')
				self.end_headers()
			else :
				self.send_response(500)
				self.send_header('Content-type','text/html')
				self.end_headers()
				self.wfile.write(array['idArchive'])
		
		elif self.path=='/loadArchive':
			array=get_values_array(parameters)
			if len (array)==1:
				print array['idArchive']
				loadArchive(array['idArchive'])
				self.send_response(200)
				self.send_header('Content-type','text/html')
				self.end_headers()
			else :
				self.send_response(500)
				self.send_header('Content-type','text/html')
				self.end_headers()
				self.wfile.write(array['idArchive'])
		
		
		elif self.path=='/shutdown':
			self.send_response(200)
			self.send_header('Content-type','text/html')
			self.end_headers()
			self.wfile.write("<html><body><center><h1>server shutdown</h1></center></body></html>")
			globals.sniff_run=0
			print "forcing program to quit ..."
			os.killpg(os.getpgid(0),signal.SIGKILL)
		else:
			self.path=TEMPLATE_PATH+self.path
			SimpleHTTPServer.SimpleHTTPRequestHandler.do_GET(self)


