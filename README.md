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

Netgrasp can also be daemonized, running in the background:
```
  sudo python2 ./netgrasp -d
```

## Dependencies
 * Python 2
 * [dpkt](https://github.com/kbandla/dpkt) (`pip install dpkt`)
 * [pcap](https://github.com/dugsong/pypcap) (`pip install pypcap`)
 * sqlite3
 * (_OPTIONAL_) [ntfy](https://github.com/dschep/ntfy) (`pip install ntfy`)


# Configuration

Netgrasp will look for its configuration file at the following paths:
```
  /etc/netgrasp.cfg, /usr/local/etc/netgrasp.cfg, ~/.netgrasp.cfg, ./netgrasp.cfg
```

## [Listen]
In the Listen section, you must specify the interface Netgrasp should monitor. For example:
```
[Listen]
interface = en0
```

You can optionally specify a timeout period (in seconds) after which a device is
considered to no longer be active. Different devices request updated arp
information at different intervals, but generally this should be over 1800
seconds to avoid false positives. For example:
```
[Listen]
active_timeout = 7200
```

Alert emails and notifications are processed at regular intervals. You can tune
how frequently this happens by modifying the delay setting, specifying a value
in seconds. For example:
```
[Listen]
delay = 5
```

## [Security]
In the Security section, you must specify a non-root user name and group name
under which Netgrasp will run. Though you start the process as root, it drops
root privileges the moment it no longer needs them, instead becoming the
user/group configured here. By default it will change to the daemon user. For
example:
```
[Security]
user = daemon
group = daemon
```

Netgrasp will refuse to run as the root user, even if you configure the uid with
0 here.

## [Database]
Netgrasp maintains a record of all Arp packets and related analysis in an
Sqlite3 database file. In this section, you must specify where this database
should be written.  The database must be readable and writeable by the user you
specified in the Security section. For example:
```
[Database]
filename = /var/db/netgrasp/netgrasp.db
```

## [Logging]
If you want to see what's going on behind the scenes, you can increase the
logging level.  Setting the logging level to WARN notifies you of problems.
Setting the logging level to INFO notifies you of interesting things (such as
changes in state for devices on the network). Setting the logging level to DEBUG
will flood you with information. For example:
```
[Logging]
level = INFO
```

You can force Netgrasp to generate verbose logs by starting the program with the
-v flag. This causes Netgrasp to ignore the [Logging] level setting, and instead
to use DEBUG.
```
  sudo python2 ./netgrasp -v
```

If you choose to daemonize Netgrasp, the mast process pid gets written to a pid
file and logs are written to a log file. The paths to these files are configured
as follows:
```
[Logging]
pidfile = /var/run/netgrasp.pid
filename = /var/log/netgrasp.log
```

## [Email]
Netgrasp currently can send two different kinds of notification emails: alerts
and digests.  Alerts are as-they-happen notifications of things such as new
devices appearing on your network. Digests are regular summaries of activity on
your network.

In order for Netgrasp to send you notificaitons, you must properly configure an
smtp server that it can use. Notifications can be sent to multiple people in a
comma separated list. For example
```
[Email]
to = user1@example.com,user2@example.com,user3@example.com
from = netgrasp@example.com
smtp_hostname = example.com
smtp_port = 587
smtp_ssl = yes
smtp_username = username
smtp_password = password
```

The following alert types are supported:
* first_requested: the first time an IP address is requested on the network
* requested: any time an IP address is requested on the network
* first_seen: the first time an IP address is actively seen on the network
* first_seen_recently: when a stale IP address becomes active again
* seen: any time an IP address is actively seen on the network
* changed_ip: a known device has changed IPs
* duplicate_ip: multiple MACs with the same IP active on the network
* stale: any time an IP address hasn't been seen for more than active_timeout
  seconds
* network_scan: any time a device requests an abnormally large number of IPs

For example:
```
[Email]
alerts = first_seen_recently,first_seen,network_scan,duplicate_ip
```

The following digest types are supported:
* daily: a daily summary of network activity
* weekly: not yet implemented, will be a weekly summary of network activity

## [Notifications]
Netgrasp can also provide real-time notifiations on your desktop, using ntfy.
These are disabled by default as ntfy can be more difficult to install
correctly than other dependencies. Once installed, ntfy must be available to
the user that netgrasp runs under, as configured above in the Security section.
Netgrasp will refuse to start if you enable Notifications but don't make
ntfy available to it.

The same alert types that were available to email alerts are also available to
notifications.

For example:
```
[Notifications]
alerts = first_seen_recently,network_scan,changed_ip,duplicate_ip
```

# Roadmap
* CLI netgraspcli command for performing real time tasks:
   * start netgrasp daemon
* Alert on anomalies
   * multiple IP's associated with a single MAC address
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
* Localize MAC lookup
   * Currently we're using an online API
   * Determine licensing, and download online list, for example:
      * http://standards-oui.ieee.org/oui.txt
* Add cross-platform UI for configuration, alerting, and ongoing network
  monitoring
   * [Kivy](https://kivy.org)
   * [Python GUI Programming](https://wiki.python.org/moin/GuiProgramming)
* Identify unassociated mobile devices
   * [Why MAC Address Randomization is not Enough](http://papers.mathyvanhoef.com/asiaccs2016.pdf)
