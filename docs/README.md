**_Passive network observation tool._**

# Overview

Must be started as root. Will spawn another process and initiate pcap to listen
for MAC request and reply packets on the network. Root privilieges are dropped
as soon as possible during startup.

Netgrasp is started as follows:
```
  sudo netgrasp start
```

Netgrasp tracks IP and MAC address pairs seen on the network while it runs,
optionally notifying you when a new device joins your network. It can provide
daily summary digests detailing devices on your network. It can also be used
interactively to review devices and list events on your network.

## Dependencies
 * Python 2
 * Installed when you run `./setup.py install`:
   * [dpkt](https://github.com/kbandla/dpkt)
   * [pycap](https://github.com/dugsong/pypcap)
   * [daemonize](https://github.com/thesharp/daemonize)
 * sqlite3
 * (_OPTIONAL_) [pyzmail](http://www.magiksys.net/pyzmail/) (`pip install pyzmail`)
 * (_OPTIONAL_) [ntfy](https://github.com/dschep/ntfy) (`pip install ntfy`)

### Current limitations
 * Python 3 not supported
 * IPv6 not supported
 * Windows not supported

# Control
Once netgrasp has been started, you can control it with the following commands:
```
  netgrasp -h
  netgrasp list -h
  netgrasp identify -h
  netgrasp update -h
  netgrasp start -h
  netgrasp stop -h
  netgrasp restart -h
  netgrasp status -h
```

## Listing Devices
Use `netgrasp list` to list devices and related events on your network. By
default only currently active devices are show, but the `-a` flag can also show
inactive devices. The `-aa` flag shows all activity, not just the latest activity.

Lists can be filtered by MAC address (`--mac` or `-m`), IP address (`--ip` or
`-i`), vendor (`--vendor` or `-v`), hostname (`--hostname` or `-h`) or custom
name (`--custom` or `-c`). Filters can be arbitrarily combined.

By default devices are listed. Optionally use `--type event` to list events
instead.

### All currently active devices
`netgrasp list`

### All currently active Apple devices
`netgrasp list -v apple`

### All Apple devices that have ever been active on your network
`netgrasp list -av apple`

### All currently active devices with an IP containing 10.0
`netgrasp list -i 10.0`

### All records for all Apple devices ever active on your network
`netgrasp list -aav apple`

### All events related to currently active Apple devices
`netgrasp list -t event -v apple`

### All events related to all Apple devices
`netgrasp list -t event -av apple`

## Identifying Devices

Once devices are manually identified, the custom name you assign will be used
in listings, alerts and notifications. Custom names are attached to the MAC
address, as well as to the MAC and IP address pair.

Identifiation is a two-step process.

1. Find the ID associated with the device. (`netgrasp identify`)
1. Set a custom name for that ID. (`netgrasp identify --set`)

During step one, you can use the same filters documented earlier for listing
devices. For example:

### List IDs of all unidentified devices
`netgrasp identify`

### List IDs of all devices, even if already identified
`netgrasp identify -a`

### List IDs of all Apple devices
`netgrasp identify -av apple`

### Set custom name for ID
`netgrasp --set 4 "my iPhone"`

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
logging level.  Setting the logging level to WARNING notifies you of problems.
Setting the logging level to INFO notifies you of interesting things (such as
changes in state for devices on the network). Setting the logging level to DEBUG
will flood you with information. For example:
```
[Logging]
level = INFO
```

You can force Netgrasp to generate verbose logs by starting the program with the
-v flag. This causes Netgrasp to ignore the [Logging] level setting, and instead
to use DEBUG. You can do this with our without the -d (daemon) flag.
```
  sudo python2 netgrasp
```

By default, Netgrasp daemonizes itself, and the master processes pid gets
written to a pid file and logs are written to a log file. The paths to these
files are configured as follows:
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

In order for Netgrasp to send you notifications, you must properly configure an
smtp server that it can use. Notifications can be sent to multiple people in a
comma separated list of the format NAME|EMAIL, NAME|EMAIL where NAME is
optional. For example:
```
[Email]
enabled = yes
to = User 1|user1@example.com, User 2|user2@example.com, user3@example.com
from = Netgrasp|netgrasp@example.com
smtp_hostname = example.com
smtp_port = 587
smtp_mode = tls
smtp_username = username
smtp_password = password
```

Supported email modes: normal, ssl, tls

The following alert types are supported:

* seen_device: any time a device is seen on the network
* first_seen_device: the first time a device is seen on the network
* first_seen_device_recently: when a stale device becomes active again
* requested_ip: any time an IP address is requested on the network
* first_requested_ip: the first time an IP address is requested on the network
* first_requested_ip_recently: when a stale IP becomes active again
* seen_mac: any time a MAC address is seen on the network
* first_seen_mac: the first time a MAC address is seen on the network
* seen_ip: any time an IP address is seen on the network
* first_seen_ip: the first time an IP address is seen on the network
* seen_host: any time a hostname is seen on the network
* first_seen_host: the first time a hostname is seen on the network
* seen_vendor: a new device by a previously seen vendor seen on the network
* first_seen_vendor: a new device by a new vendor seen on the network
* device_stale: a device hasn't been seen for active_timeout seconds
* request_stale: a device hasn't been requested for active_timeout seconds
* changed_ip: a known device joins the network with a new IP address
* duplicate_ip: multiple active MAC addresses with the same IP address
* duplicate_mac: multiple active IP addresses with the same MAC address
* network_scan: a device has requested >50 IPs on the network
* ip_not_on_network: an ARP packet claims to have come from an IP not
  on monitored subnet
* src_mac_broadcast: an ARP packet claims to have come from 'ff:ff:ff:ff:ff:ff'
* requested_self: a device requested itself

For example:
```
[Email]
alerts = first_seen_device, first_seen_device_recently, network_scan, duplicate_ip, stale
```

The following digest types are supported:
* daily: a daily summary of network activity
* weekly: be a weekly summary of network activity

## [Notifications]
Netgrasp can also provide real-time notifiations on your desktop, using ntfy.
Once installed, ntfy must be available to the user that netgrasp runs under, as
configured above in the Security section.  Netgrasp will refuse to start if you
enable Notifications but don't make ntfy available to it.

The same alert types that were available to email alerts are also available to
notifications.

For example:
```
[Notifications]
enabled = true
alerts = first_seen_recently,network_scan,duplicate_ip,ip_not_on_network,stale
```
