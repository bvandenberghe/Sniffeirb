# -*- coding: utf-8 -*-
import globals
import re
import cgi
import zlib

#decode HTML
def decodeAndEscapeHTML(data):
	mid=data.find("\r\n\r\n")
	httpHeader=data[:mid]
	body=data[mid+4:]
	print "decodage du html"
	print httpHeader
	print body.encode("string_escape")
	if httpHeader.find("Content-Encoding: gzip\r\n"):
		tmp=body
		try:
			body=zlib.decompress(tmp, -zlib.MAX_WBITS)
		except zlib.error:
			body=zlib.decompress(tmp)
		print "Content encoding gzip trouve"
		body=zlib.decompress(body)
	
	return httpHeader+"\r\n"+cgi.escape(body)





