**_Passive network observation tool._**

# Overview

Must be started as root. Will spawn another process and initiate pcap to listen
for MAC request and reply packets on the network. Root privilieges are dropped
as soon as possible during startup.
```
  sudo python2 ./netgrasp
```

Netgrasp tracks IP and MAC address pairs seen on the network while it runs,
optionally notifying you when a new device joins your network. It can also
provide daily summary digests detailing devices on your network.

## Dependencies
 * [dpkt](https://github.com/kbandla/dpkt) (`pip install dpkt`)
 * [pcap](https://github.com/dugsong/pypcap) (`pip install pypcap`)
 * sqlite3


# Configuration

Netgrasp will look for its configuration file at the following paths:
```
  /etc/netgrasp.cfg, /usr/local/etc/netgrasp.cfg, ~/.netgrasp.cfg, ./netgrasp.cfg
```

## [Listen]
In the Listen section, you must specify the interface Netgrasp should monitor. For example:
```
  interface = en0
```

You can optionally specify a timeout period (in seconds) after which a device is
considered to no longer be active. Different devices request updated arp
information at different intervals, but generally this should be over 1800
seconds to avoid false positives. For example:
```
  active_timeout = 7200
```

## [Security]
In the Security section, you must specify a non-root user ID and group ID under
which Netgrasp will run. Though you start the process as root, it drops root
privileges the moment it no longer needs them, instead becoming the user/group
configured here. By default it will change to uid/gid 1, which is typically the
Daemon user. For example:
```
  uid = 1
  gid = 1
```

Netgrasp will refuse to run as the root user, even if you configure the uid with
0 here.

## [Database]
Netgrasp maintains a record of all Arp packets and related analysis in an
Sqlite3 database file. In this section, you must specify where this database
should be written.  The database must be readable and writeable by the user you
specified in the Security section. For example:
```
  filename = /var/db/netgrasp/netgrasp.db
```

## [Logging]
If you want to see what's going on behind the scenes, you can increase the
logging level.  Setting the logging level to WARN notifies you of problems.
Setting the logging level to INFO notifies you of interesting things (such as
changes in state for devices on the network). Setting the logging level to DEBUG
will flood you with information. For example:
```
  level = INFO
```

By default, Netgrasp logs ever single ARP packet it sees. This allows useful
patterns to be identified, such as network scans. It is recommended you leave
this enabled to allow Netgrasp to be as useful as possible.

## [Email]
Netgrasp currently can send two different kinds of notification emails: alerts
and digests.  Alerts are as-they-happen notifications of things such as new
devices appearing on your network. Digests are regular summaries of activity on
your network.

In order for Netgrasp to send you notificaitons, you must properly configure an
smtp server that it can use. Notifications can be sent to multiple people in a
comma separated list. For example
```
  to = user1@example.com,user2@example.com,user3@example.com
  from = netgrasp@example.com
  smtp_hostname = example.com
  smtp_port = 465
  smtp_ssl = yes
  smtp_username = username
  smtp_password = password
```

The following alert types are supported:
* first_requested: the first time an IP address is requested on your network
* requested: any time an IP address is requested on your network
* first_seen: the first time an IP address is actively seen on your network
* first_seen_recently: when a stale IP address becomes active again
* seen: any time an IP address is actively seen on your network
* stale: any time an IP address hasn't been seen for more than active_timeout
  seconds
* network_scan: any time a device requests an abnormally large number of IPs

For example:
```
  alerts = first_seen_recently,first_seen,network_scan
```

The following digest types are supported:
* daily: a daily summary of network activity
* weekly: not yet implemented, will be a weekly summary of network activity

# Roadmap
* Improve digest
   * add time-based activity (# of devices seen per hour, per day)
* Add weekly digests
* Deliver alerts via Growl
   * [gntp](https://pythonhosted.org/gntp/)
   * [Growl](https://pypi.python.org/pypi/Growl)
* CLI netgraspcli command for performing real time tasks:
   * list active devices, with optional filters
   * list recent events, with optional filters
   * add customname to vendor and host
   * start/stop/restart netgrasp daemon
* Alert on anomalies
   * multiple IP's associated with a single MAC address
   * multiple MAC addresses associated with a single IP address
   * destination/source IP of 0.0.0.0, or other invalid IPs
   * [Reserved IP addresses](https://en.wikipedia.org/wiki/Reserved_IP_addresses)
* Add semi-active and active modes
   * semi-active pro-actively pings devices that haven't been seen a while,
     to determine if they've really gone offline (and to more quickly identify
     a device that's no longer on the network)
   * active pro-actively pings the entire network semi-regularly to quickly
     identify devices that we may not otherwise see via passive scanning
     devices
* Support listening on multiple interfaces
* Add cross-platform UI for configuration, alerting, and ongoing network
  monitoring
   * [Kivy](https://kivy.org)
   * [Python GUI Programming](https://wiki.python.org/moin/GuiProgramming)
