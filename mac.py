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
# - Be "smart" about reserved IPs
#    https://en.wikipedia.org/wiki/Reserved_IP_addresses

import sys
import socket
import binascii
import struct
import time
import threading

try:
	import dpkt
except:
	sys.exit("ERROR: Failed to import dpkt https://code.google.com/p/dpkt/")	
try:
	import pcap
except:
	sys.exit("ERROR: Failed to import pycap http://code.google.com/p/pypcap")

ARP_REQUEST = 0x0800
ETH_BROADCAST = 'ff:ff:ff:ff:ff:ff'

myMAC = 'ff:ff:ff:ff:ff:ff'
# @todo: support multiple IPs
myIP = socket.gethostbyname(socket.gethostname())

# @todo: don't use a global
pcap_instance = False

class HardwareAddress:
	all_hardwareAddresses = {}

	def __init__(self, interface, ip):
		print "PASSIVE: New IP {} on {}.".format(ip, interface)
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
		self.mac = ETH_BROADCAST

		# When we first saw activity from this IP.
		self.ip_activity_first = time.time()

		# When we last saw activity from this IP.
		self.ip_activity_last = time.time()

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
		ha.ip_activity_last = time.time()

	@classmethod
	def macSeen(cls, interface, ip, mac):
		ha = cls.all_hardwareAddresses[interface, ip]
		if (ha.mac != mac):
			ha.mac_confirmed_first = time.time()
			ha.mac = mac
			print "PASSIVE: New MAC {} for {}.".format(mac, ip)
		ha.mac_confirmed_last = time.time()

	@classmethod
	def getMAC(cls, interface, ip):
		if (HardwareAddress.isKnownIP(interface, ip)):
			ha = cls.all_hardwareAddresses[interface, ip]
			return ha.mac
		else:
			return ETH_BROADCAST


def unpack_mac(p):
	return "%x:%x:%x:%x:%x:%x" % struct.unpack("BBBBBB", p)

# TODO: Replace with stdlib
def eth_aton(buffer):
	sp = buffer.split(':')
	i = 0
	for value in sp:
		if (len(value) == 1):
			sp[i] = '0' + value
		i += 1
	buffer = ''.join(sp)
	return binascii.unhexlify(buffer)

class Sniffer(object):
	def start(self):
		sniff = threading.Thread(target=self.sniff_interface, args=(interface,))
		sniff.start()
		print "DEBUG: Started listener thread."

	def sniff_interface(self, interface):
		global pcap_instance
		# Small snaplen as we only care about ARP packets
		pc = pcap.pcap(name=interface, snaplen=256, promisc=True, timeout_ms = 100, immediate=True)
		pcap_instance = pc

		pc.setfilter('arp')

		# Loop infinitely and monitory arp packets
		while True:
			pc.loop(1, self.monitor_arp)

	def monitor_arp(self, hdr, data):
		global myMAC
		global myIP
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
					# Don't update ipSeen; this is only a request.
					#HardwareAddress.ipSeen(interface, socket.inet_ntoa(packet.data.tpa))
					pass
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
		if (myMAC == ETH_BROADCAST):
			myMAC = HardwareAddress.getMAC(interface, myIP)
			if (myMAC != ETH_BROADCAST):
				print "PASSIVE: Learned my MAC: {}".format(myMAC)

class Pinger(object):
	def start(self):
		global pcap_instance
		ping_loop = threading.Thread(target=self.ping_loop, args=(pcap_instance,))
		ping_loop.start()
		print "DEBUG: Started pinger thread."

	def ping_loop(self, pc):
		while True:
			time.sleep(15)
			all_addresses = HardwareAddress.all_hardwareAddresses
			for ha in all_addresses.itervalues():
				if (ha.mac == ETH_BROADCAST):
					self.arp_request(pc, ha.ip)

	def arp_request(self, pcap, address):
		global myMAC
		global myIP

		if (myMAC == ETH_BROADCAST):
			return False

		arp = dpkt.arp.ARP()
		# Senders hardware address (MAC):
		arp.sha = eth_aton(myMAC)
		# Sender's protocol address:
		# @todo Test with multiple active interfaces.
		arp.spa = socket.inet_aton(myIP)
		# Target hardware address (unknown, hence our request):
		arp.tha = eth_aton('00:00:00:00:00:00')
		# Target protocol address:
		arp.tpa = socket.inet_aton(address)
		# Request to resolve ha given pa
		arp.op = dpkt.arp.ARP_OP_REQUEST

		eth = dpkt.ethernet.Ethernet()
		eth.src = arp.sha
		# Broadcast ARP request
		eth.dst = eth_aton(ETH_BROADCAST)
		eth.data = arp
		eth.type = dpkt.ethernet.ETH_TYPE_ARP
		print "ACTIVE: Sent ARP to {}".format(address)

		return pcap.sendpacket(str(eth))


# TODO: Make interface(s) configurable
print pcap.findalldevs()
interface = pcap.lookupdev()
local_net, local_mask = pcap.lookupnet(interface)
print "Listening on {}: {}/{}".format(interface, socket.inet_ntoa(local_net), socket.inet_ntoa(local_mask))

listener = Sniffer()
listener.start()

pinger = Pinger()
pinger.start()

#sleep(3)
#aper = Arper()



#arp_request(pc, '10.0.0.1')