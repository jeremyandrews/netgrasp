========
NetGrasp
========
Netgrasp tracks IP and MAC address pairs seen on the network while it runs,
optionally generating notifications. For example, it can notify you when a new
device joins your network. It can also send daily and weekly emails summarizing
the devices using your network.

============
Installation
============
Run:
  sudo ./setup.py install

To start netgrasp:
  sudo netgraspctl start

To stop netgrasp:
  sudo netgraspctl stop

Finally, to control netgrasp:

 * netgraspctl -h
 * netgraspctl list -h
 * netgraspctl identify -h

For more information, review docs/README.md
