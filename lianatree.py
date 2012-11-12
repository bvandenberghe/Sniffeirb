import scapy.all
import 

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
        self.initseqs = set()
        self.packets = {}
    
    def feed(self, packet):
        if "syn" in packet['flags']:
            self.initseqs.add(packet['seq'])
        # si flags syn a 1 je note le num de sequence
        if "data" in packet:
            pkt = {
                'id': self.curid,
                'seq': packet['seq'],
                'data': packet['data'],
                'nextseq': (packet['seq']+len(packet['data'])) % (2**32),
                'ts': packet.ts,
                'ack': packet.ack,
                'next': []
                }
            self.curid += 1
            for x in self.packets:
                if self.packets[x]['nextseq'] == pkt['seq']:
                    self.packets[x]['next'].append(pkt['id'])
                if self.packets[x]['seq'] == pkt['nextseq']:
                    pkt['next'].append(self.packets[x]['id'])
            self.packets[pkt['id']] = pkt



    
###########################
