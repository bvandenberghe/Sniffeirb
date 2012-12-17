from pymongo import *
import globals
def connectMongo():
	try:
		connection = Connection('localhost', 27017)
		db = connection[globals.database_name]
		db.stream.create_index([("session", ASCENDING), ("src", ASCENDING), ("dst", ASCENDING), ("sport", ASCENDING), ("dport", ASCENDING)])	
	except Exception,e:
		print "error: can't connect to the mongo database "+globals.database_name
		print e
		exit(1)
	return db
