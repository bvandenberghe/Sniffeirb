#!/usr/bin/python
# -*- coding: utf-8 -*-

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
import sys
import os
from sniffer import *
import globals
from HTTPServerHandler import *
import webbrowser
import signal
from connect import *
import datetime

def printUsage():
	print'''
usage : '''+sys.argv[0]+''' [OPTIONS]

Web Interface :
	--web-interface (-wi) launch web interface
	--port (-p) <port> : change web interface port (8080 default)
	--nav (-n) : open the default web browser on http://localhost:PORT
Misc:
	--help (-h)  : print this help summary page.
	--sniff (-s) : launch sniffer
	--session (-S) <session_name>: use an already existing session
	'''


argSize=len(sys.argv)
if(argSize==1):
	printUsage()
	exit()

PORT = 8080
HOST = "localhost"
WEBINTERFACE=False
LAUNCHSNIFFER=False
LAUNCHBROWSER=False
i=1
globals.sessionId=str(datetime.datetime.now().strftime("sess_%d-%m-%Y-%H%M%S"))
while(i<argSize):
	if(sys.argv[i]=="-p" or sys.argv[i]=="--port"):
		if(argSize>i+1):
			PORT=int(sys.argv[i+1])
			i=i+1
		else:
			printUsage()
	elif(sys.argv[i]=="-wi" or sys.argv[i]=="--web-interface"):
		if not os.geteuid()==0:
  			print "\nWarning: need root privileges to start the sniffer from Web Interface\n"
		WEBINTERFACE=True
	elif(sys.argv[i]=="-s" or sys.argv[i]=="--sniff"):
		if not os.geteuid()==0:
  			sys.exit("\nNeed root privileges to use this option\n")
  		else:
			LAUNCHSNIFFER=True
	elif(sys.argv[i]=="-n" or sys.argv[i]=="--nav"):
		LAUNCHBROWSER=True
	elif(sys.argv[i]=="-h" or sys.argv[i]=="--help"):
		printUsage()
		exit()
	elif(sys.argv[i]=="-S" or sys.argv[i]=="--session"):
		globals.sessionId=str(sys.argv[i+1])
		i+=1
	else:
		print "argument: "+sys.argv[i]+" unknown"
		printUsage()
		exit()
	i=i+1



print "Session Name : "+str(globals.sessionId)
try:
	#démarrage du thread du serveur web
	if(LAUNCHSNIFFER):
		globals.sniff_run=1
		globals.sniffer = SnifferThread("")
		globals.sniffer.start()
		print "sniffing ..."
	if(WEBINTERFACE):
		httpd = SocketServer.ThreadingTCPServer((HOST, PORT),HTTPServerHandler,False)
		httpd.allow_reuse_address = True # Prevent 'cannot bind to address' errors on restart
		httpd.server_bind()     # Manually bind, to support allow_reuse_address
		httpd.server_activate() # (see above comment)
		if(LAUNCHBROWSER):
			print "navigateur ouvert à l'adresse http://localhost:"+str(PORT)
			webbrowser.open('http://localhost:'+str(PORT),new=2)
		httpd.serve_forever()
		print 'serveur ouvert sur le port ', PORT
		signal.pause()
except KeyboardInterrupt:
	print "Keyboard interruption detected"
	pass
finally:
	print "server shutting down ..."
	httpd.shutdown()
	print "program exiting ..." 
	globals.sniff_run=0
	exit()
'''
try:
	signal.pause()
except KeyboardInterrupt:
	os.killpg(os.getpgid(0),signal.SIGKILL)
'''

