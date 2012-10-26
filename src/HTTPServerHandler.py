# -*- coding: utf-8 -*-
from sniffeirb_globals import *
import sys
import SimpleHTTPServer
import SocketServer
from JsonDisplayHandler import *
from string import Template
TEMPLATE_PATH = "./view"

#fonction qui renvoie tous les packets dans le buffer et vide le buffer
def getSniffedPackets(indexFrom,indexTo):
	buffSize=len(sniff_buffer)
	#if(buffSize<indexFrom or indexFrom<0):
	#	return ""
	if(buffSize<indexTo or indexTo==-1):
		indexTo=len(sniff_buffer)
	
	tmp=JsonDisplayHandler.packetListToJson(sniff_buffer[indexFrom:indexTo],"global")
	
	return tmp

#fonction qui renvoie le template d'un fichier	
def get_page_template(page_name):
	fichier = open(page_name,'r')
	contenu = fichier.read()
	temp = Template(contenu)
	return temp
	

class HTTPServerHandler(SimpleHTTPServer.SimpleHTTPRequestHandler):
	def do_GET(self):
		if self.path.endswith(".html"):
		
			self.send_response(200)
			self.send_header('Content-type','text/html')
			self.end_headers()
			
			tmp=get_page_template(TEMPLATE_PATH+self.path)
			d = dict(plop='blabla')
			self.wfile.write(tmp.safe_substitute(d))
			
		elif self.path=="/":
		
			self.send_response(200)
			self.send_header('Content-type','text/html')
			self.end_headers()
			
			tmp=get_page_template(TEMPLATE_PATH+"/"+"sniffeirb.html")
			d = dict(plop='blabla')
			self.wfile.write(tmp.safe_substitute(d))
			
		elif self.path=='/sniffall':
		
			self.send_response(200)
			self.send_header('Content-type','application/json')
			self.end_headers()
			
			self.wfile.write(getSniffedPackets(0,-1))
			
		elif self.path.startswith('/sniff'):
			#/sniff:0:3 renverra les paquets du numéro 0 au 3
			
			self.send_response(200)
			self.send_header('Content-type','application/json')
			self.end_headers()
			
			param=self.path.split(':')
			
			if(len(param)>2):
				indexTo=param[2]
			else:
				indexTo=-1
			
			if len(param)==1:
				indexFrom=0
			else:
				indexFrom=param[1]
				
			#print "from :"+str(indexFrom)+"   to:"+str(indexTo)
			if len(param)<2:
				self.wfile.write("[\"error, sniff needs at least 1 parameters\"]")
			else:
				self.wfile.write(getSniffedPackets(int(indexFrom),int(indexTo)))
			
		elif self.path=='/shutdown':
			print "Le serveur a été quitté"
			httpd.shutdown()
		else:
			self.path=TEMPLATE_PATH+self.path
			SimpleHTTPServer.SimpleHTTPRequestHandler.do_GET(self)


