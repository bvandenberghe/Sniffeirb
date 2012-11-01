#!/usr/bin/python
# -*- coding: utf-8 -*-

import sys


from sniffer import *
from sniffeirb_globals import *
from HTTPServerHandler import *
import webbrowser

PORT = 8080
HOST = "localhost"

#gestion des paramètres du programme
if len(sys.argv)!=2:
	print 'serveur ouvert sur le port par defaut : ',PORT
else:
	PORT = int(sys.argv[1])
	print 'serveur ouvert sur le port ',PORT


#démarrage du thread du serveur web
httpd = SocketServer.ThreadingTCPServer((HOST, PORT),HTTPServerHandler)
webbrowser.open('http://localhost:',PORT)
httpd.serve_forever()









	
