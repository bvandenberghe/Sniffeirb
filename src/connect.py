from pymongo import Connection

def connectMongo(database):
	global db
	connection = Connection('localhost', 27017)
	db = connection[database]
	return db