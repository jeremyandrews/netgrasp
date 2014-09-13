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
#
# Future:
# - Identify hardware manufacturer
#    http://www.macvendorlookup.com/mac-address-api

import sys
import socket
import binascii
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

ARP_REQUEST = 0x0800
ETH_BROADCAST = 'ff:ff:ff:ff:ff:ff'

class HardwareAddress:
	all_hardwareAddresses = {}

	def __init__(self, interface, ip):
		print "New IP {} on {}.".format(ip, interface)
		# A record of other IP addresses we've associated with
		# this MAC in the past.
		self.ip_history = [ip]

		# The IP address currently associated with this MAC.
		self.ip = ip

		# The interface that this hardware address was seen on.
		self.interface = interface

		# @todo: multi-dimensional array [interface][ip]
		self.__class__.all_hardwareAddresses[interface, ip] = self

		# The network it was seen on, default to any.
		self.network = '0.0.0.0/0'

		# The hardware address, default to broadcast.
		self.mac = 'ff:ff:ff:ff:ff:ff'

		# When we first saw activity from this IP.
		self.ip_activity_first = 0

		# When we last saw activity from this IP.
		self.ip_activity_last = 0

		# When we first confirmed this hardware address.
		self.mac_confirmed_first = 0

		# When we last confirmed this hardware address.
		self.mac_confirmed_last = 0

		# When we last requested confirmation.
		self.mac_request = 0

		# Flag indicating that this address is currently active.
		self.active = True

	@classmethod
	def isKnownIP(cls, interface, ip):
		return tuple([interface, ip]) in cls.all_hardwareAddresses

	@classmethod
	def ipSeen(cls, interface, ip):
		ha = cls.all_hardwareAddresses[interface, ip]
		ha.ip_activity_last = 0

	@classmethod
	def macSeen(cls, interface, ip, mac):
		ha = cls.all_hardwareAddresses[interface, ip]
		if (ha.mac != mac):
			ha.mac_confirmed_first = 0
			ha.mac = mac
			print "New MAC {} for {}.".format(mac, ip)
		ha.mac_confirmed_last = 0


def unpack_mac(p):
	return "%x:%x:%x:%x:%x:%x" % struct.unpack("BBBBBB", p)

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

def monitor_arp(hdr, data):
	ARP_PACKET_TYPE = 0x0806		# address resolution protocol
	packet = dpkt.ethernet.Ethernet(data)
	if (packet.type == ARP_PACKET_TYPE):
		''' Received ARP packet '''
		if (packet.data.op == dpkt.arp.ARP_OP_REQUEST):
			''' Process ARP Request packet '''
			# Check packet sender
			if (HardwareAddress.isKnownIP(interface, socket.inet_ntoa(packet.data.spa))):
				# We've seen this IP before.
				HardwareAddress.ipSeen(interface, socket.inet_ntoa(packet.data.spa))
			else:
				# This is our first time seeing this IP.
				HardwareAddress(interface, socket.inet_ntoa(packet.data.spa))
			# Check packet target
			if (HardwareAddress.isKnownIP(interface, socket.inet_ntoa(packet.data.tpa))):
				# We've seen this IP before.
				HardwareAddress.ipSeen(interface, socket.inet_ntoa(packet.data.tpa))
			else:
				# This is our first time seeing this IP.
				HardwareAddress(interface, socket.inet_ntoa(packet.data.tpa))			
		elif (packet.data.op == dpkt.arp.ARP_OP_REPLY):
			''' Process ARP Reply packet '''
			if (HardwareAddress.isKnownIP(interface, socket.inet_ntoa(packet.data.spa))):
				# We've seen this IP before.
				HardwareAddress.ipSeen(interface, socket.inet_ntoa(packet.data.spa))
			else:
				# This is our first time seeing this IP.
				HardwareAddress(interface, socket.inet_ntoa(packet.data.spa))
			HardwareAddress.macSeen(interface, socket.inet_ntoa(packet.data.spa), unpack_mac(packet.src))

			# In case we missed the original ARP Request
			if (HardwareAddress.isKnownIP(interface, socket.inet_ntoa(packet.data.tpa))):
				# We've seen this IP before.
				HardwareAddress.ipSeen(interface, socket.inet_ntoa(packet.data.tpa))
			else:
				# This is our first time seeing this IP.
				HardwareAddress(interface, socket.inet_ntoa(packet.data.tpa))

# TODO: Make interface(s) configurable
print pcap.findalldevs()
interface = pcap.lookupdev()
local_net, local_mask = pcap.lookupnet(interface)
print "Listening on {}: {}/{}".format(interface, socket.inet_ntoa(local_net), socket.inet_ntoa(local_mask))

# Small snaplen as we only care about ARP packets
pc = pcap.pcap(name=interface, snaplen=256, promisc=True, timeout_ms = 100, immediate=True)

pc.setfilter('arp')

# Loop infinitely and monitory arp packets
while True:
	pc.loop(1, monitor_arp)

#arp_request(pc, '10.0.0.1')