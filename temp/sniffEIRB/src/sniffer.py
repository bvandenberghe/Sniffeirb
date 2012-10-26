import time
from threading import Thread
from scapy.all import sniff
import array
from sniffeirb_globals import *

class SnifferThread(Thread):
	def __init__ (self,filter):
		Thread.__init__(self)
		self.filter = filter
	def run(self):
		sniff(prn=self.callback)
	def callback(self,pkt):
		sniff_buffer.append(pkt)#'%TCP.payload%'

