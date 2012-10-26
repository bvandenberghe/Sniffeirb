#!/usr/bin/python
# -*- coding: utf-8 -*-
import SimpleHTTPServer
import SocketServer
import sys
from scapy.all import *
from string import Template
import sys
from sniffer import *
from sniffeirb_globals import *
PORT = 8080
HOST = "localhost"
TEMPLATE_PATH = "./view"

#gestion des paramètres du programme
if len(sys.argv)!=2:
	print 'serveur ouvert sur le port par defaut : ',PORT
else:
	PORT = int(sys.argv[1])
	print 'serveur ouvert sur le port ',PORT

#fonction qui renvoie tous les packets dans le buffer et vide le buffer
def new_sniffed_packets():
	tmp=""
	while len(sniff_buffer)>0:
		p=sniff_buffer.pop(0)
		tmp+=p.sprintf('{IP:%IP.src% -> %IP.dst%\n}')
	return tmp

#fonction qui renvoie le template d'un fichier	
def get_page_template(page_name):
	fichier = open(page_name,'r')
	contenu = fichier.read()
	temp = Template(contenu)
	return temp

#fonction d'exemple qui sert a rien
def func():
	""" sample function to be called via a URL"""
	pkts = sniff(count=10,prn=lambda x:x.sprintf("{IP:%IP.src% -> %IP.dst%\n}{Raw:%Raw.load%\n}"))
	return pkts

#handler du serveur HTTP
class CustomHandler(SimpleHTTPServer.SimpleHTTPRequestHandler):
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
		elif self.path=='/sniff':
			self.send_response(200)
			self.send_header('Content-type','text/html')
			self.end_headers()
			self.wfile.write(new_sniffed_packets())
		elif self.path=='/shutdown':
			print "Le serveur a été quitté"
			httpd.shutdown()
		else:
			self.path=TEMPLATE_PATH+self.path
			SimpleHTTPServer.SimpleHTTPRequestHandler.do_GET(self)

#démarrage du thread du serveur web
httpd = SocketServer.ThreadingTCPServer((HOST, PORT),CustomHandler)

#démarrage du thread du sniffer
sniffer = SnifferThread("")
sniffer.start()



httpd.serve_forever()

