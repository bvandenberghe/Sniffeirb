# -*- coding: utf-8 -*-

from snifferThread import *
from readerThread import *

class Sniffer:
    """Classe définissant le Sniffer ayant pour attributs:
       - sniffer_thread
       - reader_thread
       
       et pour méthoodes :
       - run_sniffing : lance le sniffage du reseau
       """

    def __init__(self):
        self.sniffer_thread = SnifferThread()
        self.reader_thread = ReaderThread()

    def run_sniffing()
