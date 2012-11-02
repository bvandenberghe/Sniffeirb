# -*- coding: utf-8 -*-
from sniffeirb_globals import *
from sniffer import *
import sys
import os
import signal
import SimpleHTTPServer
import SocketServer
from JsonDisplayHandler import packetListToJson
from string import Template
TEMPLATE_PATH = "./view"

#fonction qui renvoie tous les packets du buffer du numéro indexFrom au numéro indexTo, si indexTo vaut -1 ça veux dire jusqu'à la fin
def getSniffedPackets(indexFrom,indexTo):
	global sniff_buffer
	buffSize=len(sniff_buffer)
	if(buffSize<indexTo or indexTo==-1):
		indexTo=buffSize
	tmp=packetListToJson(sniff_buffer[indexFrom:indexTo],indexFrom,"global")
	return tmp

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
	if len(param)==1:
		return {}
	values={}
	for p in param:
		tmp=p.split('=')
		values[tmp[0]]=tmp[1]
	#print values
	return values

class HTTPServerHandler(SimpleHTTPServer.SimpleHTTPRequestHandler):
	sniffer=None
	def do_GET(self):
		global sniff_run
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
			sniffRunValue=sniff_run
			if sniffRunValue==None:
				sniffRunValue=0
			d = dict(sniff_run=sniffRunValue)
			self.wfile.write(tmp.safe_substitute(d))
			
		elif self.path=='/start':
			self.send_response(200)
			self.send_header('Content-type','application/json')
			self.end_headers()
			if sniff_run==None or sniff_run==0:
				print "on commence à sniffer"
				#démarrage du thread du sniffer
				sniff_run=1;
				sniffer = SnifferThread("")
				sniffer.start()
				self.wfile.write("1")#return true

		elif self.path=='/stop':
			self.send_response(200)
			self.send_header('Content-type','application/json')
			self.end_headers()
			if sniff_run==1:
				print "on arrete de sniffer"
				#arrêt du thread du sniffer
				sniff_run=0;
				self.wfile.write("1")#return true
		
		elif self.path=='/sniffall':
		
			self.send_response(200)
			self.send_header('Content-type','application/json')
			self.end_headers()

			self.wfile.write(getSniffedPackets(0,-1))
			
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
				self.wfile.write(getSniffedPackets(int(indexFrom),int(indexTo)))
			
		elif self.path=='/shutdown':
			self.send_response(200)
			self.send_header('Content-type','text/html')
			self.end_headers()
			self.wfile.write("<html><body><center><h1>Server killed</h1></center></body></html>")
			print "forcing program to quit ..."
			os.killpg(os.getpgid(0),signal.SIGKILL)
		else:
			self.path=TEMPLATE_PATH+self.path
			SimpleHTTPServer.SimpleHTTPRequestHandler.do_GET(self)


