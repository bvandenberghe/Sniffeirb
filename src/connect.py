from pymongo import Connection

def connectMongo(database):
	try:
		connection = Connection('localhost', 27017)
		db = connection[database]
	except:
		print "error: can't connect to the mongo database"
		exit(1)
	return db
