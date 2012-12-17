import scapy.all

#give the sum of all datas in all the lianatrees
def getLianaTreeDataSize(smartFlow):	
	size=0
	for data in smartFlow:
		size+=len(data["payload"])
	return size



class LianaTree:
    """
    Attributs : 
    - id
    - lien vers noeud suivant
    - data
    - TS
    - nextSeq
    - ack
    """

## VERIFIER SI ni suivant ni suiveur

    def __init__(self):
        self.curid = 0
#        self.initseqs = set()
        self.packets = {}
    
     #fill the linanaTree with packets and enhance the packet with additionnal information such as next and previous packets
    def feed(self, packet):
# DEAD CODE
#        if "S" in packet['flags']:
#            self.initseqs.add(packet['seq'])
#            print "debut feed ", self.initseqs
        # si flags syn a 1 je note le num de sequence
        if "data" in packet:
            pkt = {
                'id': self.curid,
                'seq': packet['seq'],
                'data': packet['data'],
                'nextseq': (packet['seq']+packet['dataLength']) % (2**32),
                'ts': packet['ts'],
                'ack': packet['ack'],
                'next': [],
				'prev': []
                }
            self.curid += 1

#            print "########################", (packet['data']),"#########"                      
            for x in self.packets:
#                print "########################""packet ini", self.packets                       
                if self.packets[x]['nextseq'] == pkt['seq']:
                    self.packets[x]['next'].append(pkt['id'])
                    pkt['prev'].append(self.packets[x]['id'])
                if self.packets[x]['seq'] == pkt['nextseq']:
                    pkt['next'].append(self.packets[x]['id'])
                    self.packets[x]['prev'].append(pkt['id'])
            self.packets[pkt['id']] = pkt



    
###########################
