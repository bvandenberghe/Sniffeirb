from pymongo import Connection
sniff_buffer = []
sniff_run = None
connection = Connection('localhost', 27017)
db = connection['test-database']
