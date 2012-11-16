# -*- coding: utf-8 -*-
import time
from pymongo import Connection
from threading import Thread
import sys, os
from scapy.all import *
import array
import sys
from lianatree import *
from connect import connectMongo
import globals


def reassemble_stream (src, dst, sport, dport):
	#start reassembling stream from datastream

	db = connectMongo(globals.sessionId)
	#get data from column stream for specified fields
	flow=db.stream.find_one({"proto": "TCP", "src": src, "dst": dst, "sport": sport, "dport": dport})
	#sort by IP sequence number /!\ issue a warning if twice same ip sequence number and makes 2 != streams
	#packets=sorted(flow.packets, key=lambda packet: packet.seq)
	#print(packets)
	#print flow
	liana=LianaTree()
	for pkt in flow['packets']:
		liana.feed(pkt)
	#on reassemble en dedoublant pour chaque next double
	#cheetah's algorithm
	flow_tab = []
	data = [{'data': liana.packets[x]['data'], 'initseq': liana.packets[x]['seq'], 'nextseq': liana.packets[x]['nextseq']} for x in liana.packets if not liana.packets[x]['prev']]
	print data
	for d in data:
		test_bool = False
		for x in liana.packets:
			if d['nextseq']==liana.packets[x]['seq']:
				d['data']=d['data']+(liana.packets[x]['data'])
				d['nextseq']+=len(liana.packets[x]['data'])
				test_bool = True
				print "tour"+ str(x)
		if test_bool==False:
			break
	for d in data:
		print d
		print "###################################################################################################################################################\n"

# on ne supprime pas les données du liana tree ... quand tous les nextseq pointent sur des trucs vides : ceci est la condition d'arret 
# en debut de boucle, on place le flag à false
# si on fait quelquechose pendant une boucle on met le flag a vrai   
# sinon, à la fin de la boucle si le flag vaut false, on s'arrête		
		


#reassemble_stream('147.210.183.243', '172.20.0.42', 3128, 54896)

