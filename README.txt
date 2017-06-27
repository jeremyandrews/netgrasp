========
NetGrasp
========
Netgrasp tracks IP and MAC address pairs seen on the network while it runs,
optionally generating notifications. For example, it can notify you when a new
device joins your network. It can also send daily and weekly emails summarizing
the devices using your network.

Netgrasp requires Python 2.

============
Installation
============
Run:
  pip install netgrasp

Or:
  sudo ./setup.py install

To configure netgrasp, save the configuration template to any of
the following paths, as preferred for your local configuration:
 * /etc/netgrasp.cfg
 * /usr/local/etc/netgrasp.cfg
 * ~/.netgrasp.cfg
 * ./netgrasp.cfg

For example:
  sudo netgrasp template > /usr/local/etc/netgrasp.cfg

Then edit the configuration file to suit your environment.


To start netgrasp:
  sudo netgrasp start

To stop netgrasp:
  sudo netgrasp stop

Some built-in documentation on using Netgrasp:
 * netgrasp -h
 * netgrasp list -h
 * netgrasp identify -h

Complete documentation can be found in docs/README.md:
  https://github.com/jeremyandrews/netgrasp/blob/master/docs/README.md
