#!/usr/bin/python
# -*- coding: utf-8 -*-

from pymongo import Connection
connection = Connection('localhost', 27017)

db = connection['test-database']

flux = [{
"ipsrc" : "192.168.0.1",
"ipdst" : "192.168.0.2"
},
{"ipsrc" : "192.168.0.3",
"ipdst" : "192.168.0.4"}]
db.flux.insert(flux)

for post in db.flux.find({"ipsrc": "192.168.0.1"}):
	print post
