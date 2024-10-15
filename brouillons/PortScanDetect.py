import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from impacket import ImpactDecoder, ImpactPacket
import time