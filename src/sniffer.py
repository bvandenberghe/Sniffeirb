# -*- coding: utf-8 -*-
import time
from threading import Thread
import sys, os
from scapy.all import *
import array
from sniffeirb_globals import *
import sys
from patchSniffScapy import *
from mongoHandler import *
from connect import *
#sniff et ecrit les nouveaux packets dans le buffer
class SnifferThread(Thread):
	def __init__ (self,filter):
		Thread.__init__(self)
		self.filter = filter
		self.db=connectMongo("idsession")
	def run(self):
		try:
			sniff2(filter="!(host 127.0.0.1) and !(arp) and !(ip6)", prn=self.callback, stopperTimeout=2, stopper=stopperCheck, store=0)
		except KeyboardInterrupt:
			print "sniffer thread exited ..."
			exit(0)
	def callback(self,pkt):
		#sniff_buffer.append(pkt)#'%TCP.payload%'
		insertPacket(pkt,self.db)
		
#condition to stop the sniffer	
def stopperCheck():
	global sniff_run
	#print sniff_run
	if sniff_run==0: 
		# Time to stop the sniffer ;)
		return True
	return False














