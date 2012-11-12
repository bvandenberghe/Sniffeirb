from pymongo import Connection
from sniffeirb_globals import *

def connectMongo(database):
	global db
	connection = Connection('localhost', 27017)
	db = connection[database]
	return db
