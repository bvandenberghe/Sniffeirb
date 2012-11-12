# -*- coding: utf-8 -*-
import time
from pymongo import Connection
from threading import Thread
import sys, os
from scapy.all import *
import array
import globals
import sys

#get Packets from specified IP and reassemble pages
class ReassembleThread(Thread):
	def __init__ (self,filter):
		Thread.__init__(self)
		self.filter = filter
	def run(self):
		try:
			reassemble(IPdest)
		except KeyboardInterrupt:
			print "reassemble thread exited ..."
			exit(0)
	#def callback(self,pkt):
		#sniff_buffer.append(pkt)#'%TCP.payload%'
	def reassemble (src, dst, sport, dport):
	#start reassembling stream from datastream
		#connection to DB
		connection=Connection('localhost', 27017)
		db=connection['test']
		#get data from column stream for specified fields
		flow=stream.find_one({"type": "IP"}, {"src": src}, {"dst": dst}, {"sport": sport}, {"dport": dport})
		#sort by IP sequence number /!\ issue a warning if twice same ip sequence number and makes 2 != streams
		sorted(flow.packets, key=lambda packet: packet.seq)
		print(flow.packets)
