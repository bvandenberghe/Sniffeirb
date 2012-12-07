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

#input : packets belonging to a single stream (TCP STREAM ONLY)
#output : stream payload reassembled
def reassemble_stream (src, dst, sport, dport):
	#print "debut"
	#start reassembling stream from datastream
	#db = connectMongo(globals.sessionId)
	db = connectMongo('sess_07-12-2012-160442')
	#get data from column stream for specified fields
	flow=db.stream.find_one({"proto": "TCP", "src": src, "dst": dst, "sport": sport, "dport": dport})
	#print "le flow ", flow, "\n"
    #create the twice chained list of packets
	liana=LianaTree()
	for pkt in flow['packets']:
		liana.feed(pkt)
		#print "pkt ", pkt
		#print "liana",  liana.packets , "\n"
	# - cheetah's algorithm -
	flow_tab = []
	firstPackets =[]
	#in firstPackets we put all packets likely to be first (because they don't have any previous packets into the lianatree)
	for x in liana.packets:
		if not liana.packets[x]['prev']:
			firstPackets = [{'data': liana.packets[x]['data'], 'initseq': liana.packets[x]['seq'], 'nextseq': liana.packets[x]['nextseq']}]
			print "\n\npremier paquet : ", liana.packets[x]

	# /!\ attention, ici on ne prend qu'une seule branche de l'arbre !!!!'
	for d in firstPackets:
		test_bool = False
		for x in liana.packets:
			if d['nextseq']==liana.packets[x]['seq']:
				d['data']=d['data']+(liana.packets[x]['data'])
				d['nextseq']+=len(liana.packets[x]['data'])
				test_bool = True
				print "tour"+ str(x)
		#if test_bool==False:
		#	break
	for d in firstPackets:
		print d
		print "###################################################################################################################################################\n"
	return firstPackets

# on ne supprime pas les données du liana tree ... quand tous les nextseq pointent sur des trucs vides : ceci est la condition d'arret 
# en debut de boucle, on place le flag à false
# si on fait quelquechose pendant une boucle on met le flag a vrai   
# sinon, à la fin de la boucle si le flag vaut false, on s'arrête		

reassemble_stream('82.113.152.80', '192.168.8.129', 80,44339)

