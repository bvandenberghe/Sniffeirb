# -*- coding: utf-8 -*-
import time
from threading import Thread
import sys, os
from scapy.all import *
import array
import globals
import sys

#get Packets from specified IP and reassemble pages
#class ReassembleThread(Thread):
#	def __init__ (self,filter):
#		Thread.__init__(self)
#		self.filter = filter
#	def run(self):
#		try:
#			reassemble(IPdest)
#		except KeyboardInterrupt:
#			print "reassemble thread exited ..."
#			exit(0)
#	#def callback(self,pkt):
#		#sniff_buffer.append(pkt)#'%TCP.payload%'

def reassemble (IPdest):
	#get Packets from specified IP and put them in a new buffer
	reassemble_buff=[]
	for packet in sniff_buffer:
		ip=packet[IP]
		if ip.dst==IPdest:
			reassemble_buff.append(packet)
			print ("paquet appartenant a cette destination")
			
