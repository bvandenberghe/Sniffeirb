# -*- coding: utf-8 -*-
import time
from threading import Thread
import sys, os
from scapy.all import *
from scapy.error import *
import array
import globals
import sys
from patchSniffScapy import *
from dataHandler.connect import connectMongo
from dataHandler.mongoHandler import *

#sniff et ecrit les nouveaux packets dans le buffer
class SnifferThread(Thread):
	def __init__ (self,filter):
		Thread.__init__(self)
		self.filter = filter

	def run(self):
			sniff2(filter="!(host 127.0.0.1) and !(arp) and !(ip6)", prn=self.callback, stopperTimeout=2, stopper=stopperCheck, store=0)
	def callback(self,pkt):
		insertPacket(pkt,globals.dbconnection)
		print "dans le call"		
#condition to stop the sniffer	
def stopperCheck():
	#print sniff_run
	if globals.sniff_run==0: 
		# Time to stop the sniffer ;)
		return True
	return False
















