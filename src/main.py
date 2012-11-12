#!/usr/bin/python
# -*- coding: utf-8 -*-

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
import sys
import os
from sniffer import *
from sniffeirb_globals import *
from HTTPServerHandler import *
import webbrowser
import signal

PORT = 8080
HOST = "localhost"

# check if user have root privileges
if not os.geteuid()==0:
    sys.exit("\nNeed root privileges to run this program\n")

#gestion des paramètres du programme
if len(sys.argv)!=2:
	print 'serveur ouvert sur le port par defaut : ',PORT
else:
	PORT = int(sys.argv[1])
	print 'serveur ouvert sur le port ',PORT


try:
	#démarrage du thread du serveur web
	httpd = SocketServer.ThreadingTCPServer((HOST, PORT),HTTPServerHandler)
	webbrowser.open('http://localhost:'+str(PORT))
	httpd.serve_forever()
except KeyboardInterrupt:
	print "forcing program to quit..."
	os.killpg(os.getpgid(0),signal.SIGKILL)

