# TODO
# 1. Move ARP store into database and track more info
#   a. track when we last saw a MAC/IP
#   b. track if multiple MAC's are seen for a single IP
#   c. allow MAC lookup (so we can look up ourself)
# 2. Create central dispatch that launches multiple tasks
#   a. listening for MACs
#   b. actively requesting MACs (network scan)
# 3. Test variations
#   a. multiple interfaces
#   b. different OS

import sys
import socket
import binascii

import fcntl
import struct

try:
	import dpkt
except:
	sys.exit("ERROR: Failed to import dpkt https://code.google.com/p/dpkt/")	
try:
	import pcap
except:
	sys.exit("ERROR: Failed to import pycap http://code.google.com/p/pypcap")

known_ips = {}
ips = set()

ARP_PACKET_TYPE = 0x0806		# address resolution protocol
ARP_REQUEST = 0x0800
ETH_BROADCAST = 'ff:ff:ff:ff:ff:ff'

def ether_decode(p):
	return ':'.join(['%02x' % ord(x) for x in str(p)])

def add_known_ip(ip, mac):
	if known_ips.has_key(ip):
		print "Already know {}={}".format(ip, mac)
		return 0
	else:
		known_ips[ip] = mac
		return 1

def add_ip(ip):
	if ip in ips:
		print "Already seen {}".format(ip)
		return 0
	else:
		ips.add(ip)
		return 1

# TODO: Replace with stdlib
def eth_aton(buffer):
	sp = buffer.split(':')
	buffer = ''.join(sp)
	return binascii.unhexlify(buffer)
 
def arp_request(pcap, address):
	arp = dpkt.arp.ARP()
	# Senders hardware address (MAC):
	## @todo retrieve MAC of active device
	arp.sha = eth_aton('80:e6:50:0a:6f:98')
	# Sender's protocol address:
	# @todo Test with multiple active interfaces.
	arp.spa = socket.inet_aton(socket.gethostbyname(socket.gethostname()))
	# Target hardware address (unknown, hence our request):
	arp.tha = eth_aton('00:00:00:00:00:00')
	# Target protocol address:
	arp.tpa = socket.inet_aton(address)
	# Request to resolve ha given pa
	arp.op = dpkt.arp.ARP_OP_REQUEST

	eth = dpkt.ethernet.Ethernet()
	eth.src = arp.sha
	# Broadcast ARP request
	eth.dst = eth_aton('ff:ff:ff:ff:ff:ff')
	eth.data = arp
	eth.type = dpkt.ethernet.ETH_TYPE_ARP

	return pcap.sendpacket(str(eth))

# TODO: Make interface(s) configurable
print pcap.findalldevs()
interface = pcap.lookupdev()
local_net, local_mask = pcap.lookupnet(interface)
print "Listening on {}: {}/{}".format(interface, socket.inet_ntoa(local_net), socket.inet_ntoa(local_mask))

# Small snaplen as we only care about ARP packets
pc = pcap.pcap(name=interface, snaplen=256, promisc=True, immediate=True)

# TODO: Filter to see only arp packets (it seems to filter everything)
#pc.setfilter('2054')
#pc.setfilter(value="arp")

arp_request(pc, '10.0.0.1')

for ts, pkt in pc:
	packet = dpkt.ethernet.Ethernet(pkt)
	if (packet.type == ARP_PACKET_TYPE):
		if (packet.data.op == dpkt.arp.ARP_OP_REQUEST):
			# ARP Request
			print "ARP request for {} from {}.".format(socket.inet_ntoa(packet.data.tpa), socket.inet_ntoa(packet.data.spa))
			add_ip(socket.inet_ntoa(packet.data.spa))
			add_ip(socket.inet_ntoa(packet.data.tpa))
			print ips
		elif (packet.data.op == dpkt.arp.ARP_OP_REPLY):
			# ARP Reply
			print "ARP reply to {}, {}={}.".format(socket.inet_ntoa(packet.data.tpa), socket.inet_ntoa(packet.data.spa), ether_decode(packet.src))
			add_known_ip(ether_decode(packet.src), socket.inet_ntoa(packet.data.spa))
			for key in sorted(known_ips):
				print "{}: {}".format(known_ips[key], key)
