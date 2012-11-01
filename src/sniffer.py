# -*- coding: utf-8 -*-
import time
from threading import Thread
import sys, os
from scapy.all import *
import array
import sniffeirb_globals as GLOBAL
	

#sniff et ecrit les nouveaux packets dans le buffer
class SnifferThread(Thread):
	def __init__ (self,filter):
		Thread.__init__(self)
		self.filter = filter
	def run(self):
		try:
			sniff2(filter="!(host 127.0.0.1) and !(arp) and !(ip6)", prn=self.callback, stopperTimeout=2, stopper=stopperCheck, store=0)
    		except KeyboardInterrupt:
        		exit(0)
	def callback(self,pkt):
		pkt.show()
		GLOBAL.sniff_buffer.append(pkt)#'%TCP.payload%'

#condition to stop the sniffer	
def stopperCheck():
	if GLOBAL.sniff_run!=1: 
		# Time to stop the sniffer
		return True
        return False














