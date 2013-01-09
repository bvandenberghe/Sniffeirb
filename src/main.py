#!/usr/bin/python
# -*- coding: utf-8 -*-

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)#disable scappy ipv6 warning
import sys
import os
from dataReceiver import sniffer
import globals
from server.HTTPServerHandler import *
import webbrowser
import signal
from dataHandler.connect import *
import datetime
from pymongo import Connection
from string import *

def readPcap():
	print "reading pcap file"
	if globals.PCAP :
		try :
			sniff(filter="!(host 127.0.0.1) and !(arp) and !(ip6)", prn=callback, store=0, offline=globals.PCAP)
		except scapy.error.Scapy_Exception :
			print "error pcap file "
				
def callback(pkt):
	insertPacket(pkt,globals.dbconnection)

def printUsage():
	print'''usage : '''+sys.argv[0]+''' [OPTIONS]

Web Interface :
	--web-interface (-wi) launch web interface
	--port (-p) <port> : change web interface port (8080 default)
	--nav (-n) : open the default web browser on http://localhost:PORT
Misc:
	--help (-h)  : print this help summary page.
	--sniff (-s) : launch sniffer
	--session (-S) <session_name>: use an already existing session
	--drop-database (-d)  : remove all already existing databases 
	--file (-f) <pcap_file_name> : launch the sniffer on given pcap file
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
globals.sessionId="sess"+str(datetime.datetime.now().strftime("_%d-%m-%Y-%H%M%S"))
while(i<argSize):
	if(sys.argv[i]=="-p" or sys.argv[i]=="--port"):
		if(argSize>i+1):
			PORT=int(sys.argv[i+1])
			i=i+1
		else:
			printUsage()
			
	elif(sys.argv[i]=="-f" or sys.argv[i]=="--file"):
		if(argSize>i+1):
			globals.PCAP=sys.argv[i+1]
			i=i+1
			if globals.PCAP :
				name1=rsplit(globals.PCAP,"/",1)
				name2= rsplit(name1[1], ".", 1)
				globals.sessionId=name2[0]+str(datetime.datetime.now().strftime("_%d-%m-%Y-%H%M%S"))
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

	elif(sys.argv[i]=="-d" or sys.argv[i]=="--drop-database"):
		deleteAllArchives()

	else:
		print "argument: "+sys.argv[i]+" unknown"
		printUsage()
		exit()
	i=i+1



print "Session Name : "+str(globals.sessionId)
try:
	globals.dbconnection=connectMongo()
	if globals.PCAP :
		readPcap()
	
	if(LAUNCHSNIFFER):
		globals.sniff_run=1
		globals.sniffer = SnifferThread("")
		globals.sniffer.start()
		print "Sniffing ..."
	if(WEBINTERFACE):
		try:
			httpd = SocketServer.ThreadingTCPServer((HOST, PORT),HTTPServerHandler,False)
			globals.serverThread=httpd
			httpd.allow_reuse_address = True # Prevent 'cannot bind to address' errors on restart
			httpd.server_bind()     # Manually bind, to support allow_reuse_address
			httpd.server_activate()
			if(LAUNCHBROWSER):
				print "Launching web browser..."
				webbrowser.open('http://localhost:'+str(PORT),new=2)
			print 'Web interface launched on http://localhost:', PORT
			httpd.serve_forever()
			signal.pause()
		except KeyboardInterrupt:
			print "Keyboard interruption detected"
			pass
		finally:
			print "Server shutting down ..."
			httpd.shutdown()
			print "Program exiting ..." 
			globals.sniff_run=0
			exit()
except KeyboardInterrupt:
	print "Keyboard interruption detected"
	pass
finally:
	globals.sniff_run=0
	exit()
'''
try:
	signal.pause()
except KeyboardInterrupt:
	os.killpg(os.getpgid(0),signal.SIGKILL)
'''

