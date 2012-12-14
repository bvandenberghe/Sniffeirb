# -*- coding: utf-8 -*-
from protocol import inspectStreamForMedia

#Split a flow in several documents
def splitDocuments(smartFlow):

	stream["media"]=""
	
	for data in smartFlow:
		(mostProbableMedia,infos)=inspectStreamForMedia(data,stream["sport"],stream["dport"])

	for sf in smartFlow:
		print sf

