from utils import debug
from utils import exclusive_lock
from utils import email
from utils import simple_timer
from utils import pretty
from config import config
from notify import notify
from database import database

import logging
import logging.handlers
import pwd
import sys
import os
import datetime
import time
import traceback

netgrasp_instance = None

BROADCAST = 'ff:ff:ff:ff:ff:ff'

ALERT_TYPES = ['first_requested', 'requested', 'first_seen_mac', 'first_seen_recently', 'seen', 'changed_ip', 'duplicate_ip', 'duplicate_mac', 'stale', 'network_scan', 'ip_not_on_network', 'src_mac_broadcast']
EVENT_REQUESTED_FIRST, EVENT_REQUESTED, EVENT_FIRST_SEEN_MAC, EVENT_SEEN_FIRST_RECENT, EVENT_SEEN, EVENT_CHANGED_IP, EVENT_DUPLICATE_IP, EVENT_DUPLICATE_MAC, EVENT_STALE, EVENT_SCAN, IP_NOT_ON_NETWORK, SRC_MAC_BROADCAST = ALERT_TYPES

DIGEST_TYPES = ['daily', 'weekly']

PROCESSED_ALERT         = 1
PROCESSED_DAILY_DIGEST  = 2
PROCESSED_WEEKLY_DIGEST = 4
PROCESSED_NOTIFICATION  = 8

DEFAULT_CONFIG    = ['/etc/netgrasp.cfg', '/usr/local/etc/netgrasp.cfg', '~/.netgrasp.cfg', './netgrasp.cnf']
DEFAULT_USER      = "daemon"
DEFAULT_GROUP     = "daemon"
DEFAULT_LOGLEVEL  = logging.INFO
DEFAULT_LOGFILE   = "/var/log/netgrasp.log"
DEFAULT_LOGFORMAT = "%(asctime)s [%(levelname)s/%(processName)s] %(message)s"
DEFAULT_PIDFILE   = "/var/run/netgrasp.pid"
DEFAULT_DBLOCK    = "/tmp/.netgrasp_database_lock"

class Netgrasp:
    def __init__(self, config):
        if config:
            self.config = config
        else:
            self.config = DEFAULT_CONFIG

    # Drop root permissions when no longer needed.
    def drop_root(self, ng):
        import grp

        os.setgroups([])
        os.setgid(grp.getgrnam(self.config.GetText('Security', 'group', DEFAULT_GROUP, False)).gr_gid)
        os.setuid(pwd.getpwnam(self.config.GetText('Security', 'user', DEFAULT_USER, False)).pw_uid)
        ng.debugger.info('running as user %s',  (self.debugger.whoami(),))

    # Determine if pid in pidfile is a running process.
    def is_running(self):
        import os
        import errno

        running = False
        if self.pidfile:
            if os.path.isfile(self.pidfile):
                f = open(self.pidfile)
                pid = int(f.readline())
                f.close()
                if pid > 0:
                    self.debugger.info("Found pidfile %s, contained pid %d", (self.pidfile, pid))
                    try:
                        os.kill(pid, 0)
                    except OSError as e:
                        if e.errno == errno.EPERM:
                            running = pid
                    else:
                        running = pid
        return running

# Simple, short text string used for heartbeat.
HEARTBEAT = 'nghb'
# Macimum seconds to process before returning to main loop
MAXSECONDS = 2

# This is our main program loop.
def main(*pcap):
    import netgrasp
    import multiprocessing

    ng = netgrasp.netgrasp_instance

    ng.debugger.info("main process running as user %s", (ng.debugger.whoami(),))

    if pcap:
        # We have daemonized and are not running as root.
        ng.pcap_instance, ng.interface, ng.network, ng.netmask = pcap
    else:
        # We are running in the foreground as root.
        pcap = get_pcap()
        ng.pcap_instance, ng.interface, ng.network, ng.netmask = pcap
        ng.drop_root(ng)

    # At this point we should no longer have/need root privileges.
    assert (os.getuid() != 0) and (os.getgid() != 0), 'Failed to drop root privileges, aborting.'

    ng.debugger.info("initiating wiretap process")
    parent_conn, child_conn = multiprocessing.Pipe()
    child = multiprocessing.Process(name="wiretap", target=wiretap, args=[ng.pcap_instance, child_conn])

    child.daemon = True
    child.start()
    if child.is_alive():
        ng.debugger.debug("initiated wiretap process")
    else:
        ng.debugger.debug("wiretap failed to start")

    try:
        ng.db = database.Database(ng.database_filename, ng.debugger)
        database.database_instance = ng.db
    except Exception as e:
        ng.debugger.critical("%s", (e,))
        ng.debugger.critical("failed to open or create %s (as user %s), exiting", (ng.database_filename, ng.whoami()))
    ng.db.lock = ng.config.GetText('Database', 'lockfile', DEFAULT_DBLOCK, False)
    ng.debugger.info("opened %s as user %s", (ng.database_filename, ng.debugger.whoami()))
    ng.db.cursor = ng.db.connection.cursor()
    # http://www.sqlite.org/wal.html
    ng.db.cursor.execute("PRAGMA journal_mode=WAL")

    create_database()
    update_database()

    ng.active_timeout = ng.config.GetInt("Listen", "active_timeout", 60 * 60 * 2, False)
    ng.delay = ng.config.GetInt("Listen", "delay", 15, False)
    if (ng.delay > 30):
        ng.delay = 30
    elif (ng.delay < 1):
        ng.delay = 1

    email.email_instance = email.Email(ng.config, ng.debugger)

    ng.garbage_collection = ng.config.GetBoolean("Database", "gcenabled", True, False)
    ng.oldest_arplog = datetime.timedelta(seconds=ng.config.GetInt("Database", "oldest_arplog", 60 * 60 * 24 * 7 * 2, False))
    ng.oldest_event = datetime.timedelta(seconds=ng.config.GetInt("Database", "oldest_event", 60 * 60 * 24 * 7 * 2, False))

    if child.is_alive():
        run = True
    else:
        ng.debugger.error("wiretap process gone away: %d", (child.exitcode,))
        run = False

    last_heartbeat = datetime.datetime.now()
    while run:
        try:
            now = datetime.datetime.now()
            ng.debugger.debug("top of master while loop: %s", (now,))

            parent_conn.send(HEARTBEAT)

            identify_macs()
            detect_stale_ips(ng.active_timeout)
            detect_netscans()
            #detect_anomalies(ng.active_timeout)
            send_notifications()
            send_email_alerts(ng.active_timeout)
            #send_email_digests()
            #garbage_collection(ng.garbage_collection, ng.oldest_arplog, ng.oldest_event)

            ng.debugger.debug("sleeping for %d seconds", (ng.delay,))
            time.sleep(ng.delay)

            heartbeat = False
            while parent_conn.poll():
                message = parent_conn.recv()
                if (message == HEARTBEAT):
                    heartbeat = True
            # It's possible to receive multiple heartbeats, but many or one is the same to us.
            if heartbeat:
                ng.debugger.debug("received heartbeat from wiretap process")
                last_heartbeat = now

            if not child.is_alive():
                ng.debugger.error("wiretap process gone away: %d", (child.exitcode,))
                run = False

            # If we haven't heard from the wiretap process in >1 minute, exit.
            time_to_exit = last_heartbeat + datetime.timedelta(minutes=3)
            if (now >= time_to_exit):
                run = False
                ng.debugger.error("No heartbeats from wiretap process for >3 minutes.")
        except Exception as e:
            ng.debugger.dump_exception("main() while loop caught exception")
    ng.debugger.critical("Exiting")

def get_pcap():
    import sys
    import socket
    assert os.getuid() == 0, 'Unable to initiate pcap, must be run as root.'

    try:
        import pcap
    except Exception as e:
        debug.debugger.error("fatal exception: %s", (e,))
        debug.debugger.critical("Fatal error: failed to import pcap, try: 'pip install pypcap', exiting")

    devices = pcap.findalldevs()
    if len(devices) <= 0:
      debug.debugger.critical("Fatal error: pcap identified no devices, try running tcpdump manually to debug.")

    interface = config.config_instance.GetText('Listen', 'interface', devices[0], False)
    local_net, local_mask = pcap.lookupnet(interface)

    try:
        pc = pcap.pcap(name=interface, snaplen=256, promisc=True, timeout_ms = 100, immediate=True)
        pc.setfilter('arp')
    except Exception as e:
        debug.debugger.critical("""Failed to invoke pcap. Fatal exception: %s, exiting.""" % e)

    debug.debugger_instance.warning("listening for arp traffic on %s: %s/%s", (interface, socket.inet_ntoa(local_net), socket.inet_ntoa(local_mask)))
    return [pc, interface, local_net, local_mask]

# Child process: wiretap, uses pcap to sniff arp packets.
def wiretap(pc, child_conn):
    import sys

    netgrasp_instance.debugger.debug('top of wiretap')

    try:
        import dpkt
    except Exception as e:
        netgrasp_instance.debugger.error("fatal exception: %s", (e,))
        netgrasp_instance.debugger.critical("failed to import dpkt, try: 'pip install dpkt', exiting")
    try:

        import pcap
    except Exception as e:
        netgrasp_instance.debugger.error("fatal exception: %s", (e,))
        netgrasp_instance.debugger.critical("failed to import pcap, try: 'pip install pypcap', exiting")

    assert (os.getuid() != 0) and (os.getgid() != 0), "Failed to drop root privileges, aborting."

    database_filename = config.config_instance.GetText("Database", "filename")

    try:
        db = database.Database(database_filename, netgrasp_instance.debugger)
        db.lock = config.config_instance.GetText('Database', 'lockfile', DEFAULT_DBLOCK, False)
    except Exception as e:
        netgrasp_instance.debugger.error("%s", (e,))
        netgrasp_instance.debugger.critical("failed to open or create %s (as user %s), exiting", (database_filename, netgrasp_instance.debugger.whoami()))
    netgrasp_instance.debugger.info("opened %s as user %s", (database_filename, netgrasp_instance.debugger.whoami()))
    db.cursor = db.connection.cursor()
    database.database_instance = db

    run = True
    last_heartbeat = datetime.datetime.now()
    while run:
        try:
            now = datetime.datetime.now()
            netgrasp_instance.debugger.debug("[%d] top of while loop: %s", (run, now))

            child_conn.send(HEARTBEAT)

            # Wait an arp packet, then loop again.
            pc.loop(1, received_arp, child_conn)

            heartbeat = False
            while child_conn.poll():
                message = child_conn.recv()
                if (message == HEARTBEAT):
                    heartbeat = True
            # It's possible to receive multiple heartbeats, but many or one is the same to us.
            if heartbeat:
                netgrasp_instance.debugger.debug("received heartbeat from main process")
                last_heartbeat = now

            # If we haven't heard from the main process in >1 minute, exit.
            time_to_exit = last_heartbeat + datetime.timedelta(minutes=3)
            if (now >= time_to_exit):
                run = False
        except Exception as e:
            netgrasp_instance.debugger.dump_exception("wiretap() while loop caught exception")
    netgrasp_instance.debugger.critical("No heartbeats from main process for >3 minutes, exiting.")

def ip_on_network(ip):
    try:
        import struct
        import socket

        ng = netgrasp_instance

        debugger = debug.debugger_instance
        debugger.debug("entering address_on_network(%s)", (ip,))

        numeric_ip = struct.unpack("<L", socket.inet_aton(ip))[0]
        cidr = sum([bin(int(x)).count("1") for x in socket.inet_ntoa(ng.netmask).split(".")])
        netmask = struct.unpack("<L", ng.network)[0] & ((2L<<int(cidr) - 1) - 1)
        return numeric_ip & netmask == netmask
    except:
        debugger.dump_exception("address_in_network() caught exception")

# Assumes we already have the database lock.
def log_event(did, ip, mac, event, have_lock = False):
    try:
        db = database.database_instance
        debugger = debug.debugger_instance
        debugger.debug("entering log_event(%s, %s, %s, %s, %s)", (did, ip, mac, event, have_lock))

        now = datetime.datetime.now()

        if have_lock:
            db.connection.execute("INSERT INTO event (mac, ip, did, timestamp, processed, event) VALUES(?, ?, ?, ?, ?, ?)", (mac, ip, did, now, 0, event))
        else:
            with exclusive_lock.ExclusiveFileLock(db.lock, 5, "log_event, " + event):
                db.connection.execute("INSERT INTO event (mac, ip, did, timestamp, processed, event) VALUES(?, ?, ?, ?, ?, ?)", (mac, ip, did, now, 0, event))
                db.connection.commit()
    except Exception as e:
        debugger.dump_exception("log_event() caught exception")

def ip_is_mine(ip):
    try:
        import socket
        debugger = debug.debugger_instance
        debugger.debug("entering ip_is_mine(%s)", (ip,))

        return (ip == socket.gethostbyname(socket.gethostname()))
    except Exception as e:
        debugger.dump_exception("ip_is_mine() caught exception")

def ip_has_changed(did):
    try:
        debugger = debug.debugger_instance
        db = database.database_instance

        debugger.debug("entering ip_has_changed(%s)", (did,))

        db.cursor.execute("SELECT DISTINCT iid FROM activity WHERE did = ? ORDER BY updated DESC LIMIT 2", (did))
        iids = db.cursor.fetchall()
        #debugger.debug("ips: %s", (ips,))
        if iids and len(iids) == 2:
            db.cursor.execute("SELECT address FROM ip WHERE iid IN(?, ?)", (iids[0], iids[1]))
            ips = db_cursor.fetchall()
            if ips:
                ip_a = ips[0]
                ip_b = ips[1]
                debugger.debug("ips: %s, %s", (ip_a, ip_b))

                if ip_a != ip_b:
                    debugger.info("ip for did %s changed from %s to %s", (did, ip_a[0], ip_b[0]))
                    return True
                else:
                    debugger.debug("ip for did %s has not changed from %s", (did, ip_a[0]))
                    return False
            else:
                debugger.info("[%d] failed to load ips for iids: %s, %s", (did, iids[0], iids[1]))
                return False
        else:
            debugger.debug("ip for did %s has not changed", (did,))
            return False

    except Exception as e:
        debugger.dump_exception("ip_has_changed() caught exception")

# Database definitions.
def create_database():
    try:
        from utils import exclusive_lock
        debugger = debug.debugger_instance
        db = database.database_instance

        debugger.debug('Creating database tables, if not already existing.')

        # PRAGMA index_list(TABLE)
        with exclusive_lock.ExclusiveFileLock(db.lock, 5, "create_database"):
            # Create state table.
            db.cursor.execute("""
              CREATE TABLE IF NOT EXISTS state(
                id INTEGER PRIMARY KEY,
                key VARCHAR UNIQUE,
                value TEXT
              )
            """)

            # Record of all MAC addresses ever actively seen.
            db.cursor.execute("""
              CREATE TABLE IF NOT EXISTS mac(
                mid INTEGER PRIMARY KEY,
                address TEXT,
                created TIMESTAMP,
                self NUMERIC
              )
            """)
            db.cursor.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_address ON mac (address)")

            # Record of all IP addresses ever actively seen.
            db.cursor.execute("""
              CREATE TABLE IF NOT EXISTS ip(
                iid INTEGER PRIMARY KEY,
                mid INTEGER,
                address TEXT,
                created TIMESTAMP,
              )
            """)
            db.cursor.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_mid_address ON ip (mid, address)")

            # Cache DNS lookups.
            db.cursor.execute("""
              CREATE TABLE IF NOT EXISTS host(
                hid INTEGER PRIMARY KEY,
                iid INTEGER,
                hostname TEXT,
                customname TEXT
		created TIMESTAMP,
		updated TIMESTAMP,
              )
            """)
            db.cursor.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_iid ON host (iid)")

            # Record of all devices ever actively seen.
            db.cursor.execute("""
              CREATE TABLE IF NOT EXISTS device(
                did INTEGER PRIMARY KEY,
                mid INTEGER,
                iid INTEGER,
                hid INTEGER,
                created TIMESTAMP,
                updated TIMESTAMP,
              )
            """)
            db.cursor.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_mid_iid ON device (mid, iid)")

            # Record of device activity.
            db.cursor.execute("""
              CREATE TABLE IF NOT EXISTS activity(
                aid INTEGER PRIMARY KEY,
                did INTEGER,
                iid INTEGER,
                interface TEXT,
                network TEXT,
                created TIMESTAMP,
                updated TIMESTAMP,
                counter NUMERIC,
                active NUMERIC,
              )
            """)
            db.cursor.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_did_iid ON device (did, iid)")

            # Record of all IP addresses ever requested.
            db.cursor.execute("""
              CREATE TABLE IF NOT EXISTS request(
                rid INTEGER PRIMARY KEY,
                did INTEGER,
                ip TEXT,
                interface TEXT,
                network TEXT,
                created TIMESTAMP,
                updated TIMESTAMP,
                counter NUMERIC,
                active NUMERIC,
              )
            """)

            # Create arplog table.
            db.cursor.execute("""
              CREATE TABLE IF NOT EXISTS arp(
                aid INTEGER PRIMARY KEY,
                did INT,
                src_mac TEXT,
                src_ip TEXT,
                rid INT,
                dst_mac TEXT,
                dst_ip TEXT,
                interface TEXT,
                network TEXT,
                timestamp TIMESTAMP
              )
            """)
            db.cursor.execute("CREATE INDEX IF NOT EXISTS idx_srcip_timestamp_request ON arplog (src_ip, timestamp, request)")
            db.cursor.execute("CREATE INDEX IF NOT EXISTS idx_srcmac_timestamp ON arplog (src_mac, timestamp)")
            db.cursor.execute("CREATE INDEX IF NOT EXISTS idx_dstdid_srcdid_timestamp ON arplog (dst_did, src_did, timestamp)")

            # Create event table.
            db.cursor.execute("""
              CREATE TABLE IF NOT EXISTS event(
                eid INTEGER PRIMARY KEY,
                mac TEXT,
                ip TEXT,
                did INTEGER,
                interface TEXT,
                network TEXT,
                timestamp TIMESTAMP,
                processed NUMERIC,
                event TEXT
              )
            """)
            db.cursor.execute("CREATE INDEX IF NOT EXISTS idx_event_timestamp_processed ON event (event, timestamp, processed)")
            db.cursor.execute("CREATE INDEX IF NOT EXISTS idx_timestamp_processed ON event (timestamp, processed)")
            # PRAGMA index_list(event)

            # Create vendor table.
            db.cursor.execute("""
              CREATE TABLE IF NOT EXISTS vendor(
                vid INTEGER PRIMARY KEY,
                mac TEXT,
                vendor TEXT,
                customname TEXT
              )
            """)
            db.cursor.execute("CREATE INDEX IF NOT EXISTS idx_mac ON vendor (mac)")

            # Create host table.
            db.cursor.execute("""
              CREATE TABLE IF NOT EXISTS host(
                hid INTEGER PRIMARY KEY,
                did INTEGER,
                vid INTEGER,
                mac TEXT,
                ip TEXT,
                timestamp TIMESTAMP,
                hostname TEXT,
                customname TEXT
              )
            """)
            db.cursor.execute("CREATE INDEX IF NOT EXISTS idx_ip_mac ON host (ip, mac)")
            db.cursor.execute("CREATE INDEX IF NOT EXISTS idx_mac_hostname ON host (mac, hostname)")
            db.cursor.execute("CREATE INDEX IF NOT EXISTS idx_did_hostname ON host (did, hostname)")
            db.cursor.execute("CREATE INDEX IF NOT EXISTS idx_did_customname ON host (did, customname)")
            db.cursor.execute("CREATE INDEX IF NOT EXISTS idx_did_hid ON host (did, hid)")
            db.connection.commit()
    except Exception as e:
        debugger.dump_exception("create_database() caught exception")

def update_database():
    try:
        from utils import exclusive_lock
        debugger = debug.debugger_instance
        db = database.database_instance

        # Update #1: add did column to seen table, populate
        try:
            db.cursor.execute("SELECT did FROM seen LIMIT 1")
        except Exception as e:
            debugger.debug("%s", (e,))
            debugger.info("applying update #1 to database: adding did column to seen, populating")
            with exclusive_lock.ExclusiveFileLock(db.lock, 5, "update_database"):
                db.cursor.execute("ALTER TABLE seen ADD COLUMN did INTEGER")
                # Prior to this we assumed a new IP was a new device.
                db.cursor.execute("SELECT DISTINCT ip, mac FROM seen")
                rows = db.cursor.fetchall()
                did = 1
                for row in rows:
                    ip, mac = row
                    db.cursor.execute("UPDATE seen SET did = ? WHERE ip = ? AND mac = ?", (did, ip, mac))
                    did += 1
                db.connection.commit()

        # Update #2: add did column to host table, populate
        try:
            db.cursor.execute("SELECT did FROM host LIMIT 1")
        except Exception as e:
            debugger.debug("%s", (e,))
            debugger.info("applying update #2 to database: adding did column to host, populating")
            with exclusive_lock.ExclusiveFileLock(db.lock, 5, "update_database"):
                db.cursor.execute("ALTER TABLE host ADD COLUMN did INTEGER")
                # Use did to match devices when their IP changes.
                # This was a bad update; it gets fixed properly in #4
                db.connection.commit()

        # Update #3: add did column to event table, populate
        try:
            db.cursor.execute("SELECT did FROM event LIMIT 1")
        except Exception as e:
            debugger.debug("%s", (e,))
            debugger.info("applying update #3 to database: adding did column to event, populating")
            with exclusive_lock.ExclusiveFileLock(db.lock, 5, "update_database"):
                db.cursor.execute("ALTER TABLE event ADD COLUMN did INTEGER")
                # Use did to match devices when their IP changes.
                db.cursor.execute("SELECT DISTINCT did, ip, mac FROM seen")
                rows = db.cursor.fetchall()
                for row in rows:
                    did, ip, mac = row
                    db.cursor.execute("UPDATE event SET did = ? WHERE ip = ? AND mac = ?", (did, ip, mac))
                db.connection.commit()

            db.cursor.execute("SELECT COUNT(did) FROM event WHERE did IS NOT NULL;")
            count_did = db.cursor.fetchone()
            db.cursor.execute("SELECT COUNT(did) FROM event WHERE did IS NULL;")
            count_nodid = db.cursor.fetchone()
            if count_did and count_nodid:
                debugger.info("Updated event table, set ? dids, did not set ? dids", (count_did[0], count_nodid[0]))
            else:
                debugger.error("Failed to update event table")

        # Update #4: add src_did, dst_did columns to arplog table, populate
        try:
            db.cursor.execute("SELECT src_did FROM arplog LIMIT 1")
        except Exception as e:
            debugger.debug("%s", (e,))
            debugger.info("applying update #4 to database: adding src_did, dst_did columns to arplog, populating")
            with exclusive_lock.ExclusiveFileLock(db.lock, 5, "update_database"):
                db.cursor.execute("ALTER TABLE arplog ADD COLUMN src_did INTEGER")
                db.cursor.execute("ALTER TABLE arplog ADD COLUMN dst_did INTEGER")

                # Populate src_did.
                db.cursor.execute("SELECT src_ip, src_mac FROM arplog GROUP BY src_ip, src_mac")
                rows = db.cursor.fetchall()
                for row in rows:
                    ip, mac = row
                    did = get_did(ip, mac)
                    db.cursor.execute("UPDATE arplog SET src_did = ? WHERE src_ip = ? AND src_mac = ?", (did, ip, mac))
                debugger.info("Populated arplog.src_did.")

                # Populate dst_did.
                db.cursor.execute("SELECT dst_ip, dst_mac FROM arplog GROUP BY dst_ip, dst_mac")
                rows = db.cursor.fetchall()
                for row in rows:
                    ip, mac = row
                    did = get_did(ip, mac)
                    db.cursor.execute("UPDATE arplog SET dst_did = ? WHERE dst_ip = ? AND dst_mac = ?", (did, ip, mac))
                debugger.info("Populated arplog.dst_did.")

                # Fix host table.
                db.cursor.execute("SELECT hid, ip, mac FROM host");
                hosts = db.cursor.fetchall()
                if hosts:
                    for host in hosts:
                        hid, ip, mac = host
                        db.cursor.execute("UPDATE host SET did = ? WHERE hid = ?", (get_did(ip, mac), hid))

                db.connection.commit()

        # Update #5: add timestamp column to host table
        try:
            db.cursor.execute("SELECT timestamp FROM host LIMIT 1")
        except Exception as e:
            debugger.debug("%s", (e,))
            debugger.info("applying update #5 to database: adding timestamp column to host")
            with exclusive_lock.ExclusiveFileLock(db.lock, 5, "update_database"):
                db.cursor.execute("ALTER TABLE host ADD COLUMN timestamp TIMESTAMP")

    except Exception as e:
        debugger.dump_exception("update_database() caught exception")

# We've sniffed an arp packet off the wire.
def received_arp(hdr, data, child_conn):
    try:
        import socket
        import struct
        import dpkt

        from utils import exclusive_lock

        debugger = debug.debugger_instance
        db = database.database_instance

        packet = dpkt.ethernet.Ethernet(data)
        src_ip = socket.inet_ntoa(packet.data.spa)
        src_mac = "%x:%x:%x:%x:%x:%x" % struct.unpack("BBBBBB", packet.src)

        dst_ip = socket.inet_ntoa(packet.data.tpa)
        dst_mac = "%x:%x:%x:%x:%x:%x" % struct.unpack("BBBBBB", packet.dst)

        seen, requested, did, rid = (True, True, None, None)
        if (src_mac == BROADCAST):
            seen = False
            debugger.info("Ignoring arp source of %s [%s], destination %s [%s]", (src_ip, src_mac, dst_ip, dst_mac))
            log_event(src_ip, src_mac, SRC_MAC_BROADCAST)

        if not ip_on_network(src_ip):
            seen = False
            debugger.info("IP not on network, source of %s [%s], dst %s [%s]", (src_ip, src_mac, dst_ip, dst_mac))
            log_event(src_ip, src_mac, IP_NOT_ON_NETWORK)

        if (dst_ip == src_ip) or (dst_mac == src_mac):
            requested = False
            debugger.info("requesting self %s [%s], ignoring", (src_ip, src_mac))
            log_event(src_ip, src_mac, EVENT_REQUESTED_SELF)

        # ARP REQUEST
        if (packet.data.op == dpkt.arp.ARP_OP_REQUEST):
            debugger.debug('ARP REQUEST from [%s] %s (%s) to [%s] %s (%s)', (src_did, src_ip, src_mac, dst_did, dst_ip, dst_mac))
            if seen:
                did = device_seen(src_ip, src_mac)
            if requested:
                rid = device_request(dst_ip, dst_mac)

        # ARP REPLY
        elif (packet.data.op == dpkt.arp.ARP_OP_REPLY):
            debugger.debug('ARP REPLY from [%s] %s (%s) to [%s] %s (%s)', (src_did, src_ip, src_mac, dst_did, dst_ip, dst_mac))
            if seen:
                did = device_seen(src_ip, src_mac)

        with exclusive_lock.ExclusiveFileLock(db.lock, 5, "received_arp, arp"):
            db.cursor.execute("INSERT INTO arp (did, rid, src_mac, src_ip, dst_mac, dst_ip, timestamp) VALUES(?, ?, ?, ?, ?, ?, ?)", (did, rid, src_mac, src_ip, dst_did, dst_mac, dst_ip, now))
            debugger.debug("inserted into arp")
            db.connection.commit()

    except Exception as e:
        debugger.dump_exception("received_arp() caught exception")

def device_seen(ip, mac):
    try:
        import datetime

        debugger = debug.debugger_instance
        db = database.database_instance

        debugger.debug("entering ip_seen(%s, %s)", (ip, mac))

        now = datetime.datetime.now()

        seen_mac, first_seen_mac, seen_ip, first_seen_ip, first_seen_host, seen_host, first_seen_device = (False, False, False, False, False, False, False)

        # Get ID for MAC, creating if necessary.
        db.cursor.execute("SELECT mid FROM mac WHERE address = ?", (mac,))
        seen = db.cursor.fetchone()
        if seen:
            mid = seen[0]
            debugger.debug("existing mac %s [%d]", (mac, mid))
            seen_mac = True
        else:
            with exclusive_lock.ExclusiveFileLock(db.lock, 6, "device_seen, new mac"):
                db.cursor.execute("INSERT INTO mac (address, created, self) VALUES(?, ?, ?)", (mac, now, ip_is_mine(ip)))
                first_seen_mac = True
                db.connection.commit()
            mid = db.cursor.lastrowid
            debugger.info("new mac %s [%d]", (mac, mid))

        # Get ID for IP, creating if necessary.
        db.cursor.execute("SELECT ip.iid FROM ip WHERE ip.mid = ? AND ip.address = ?", (mid, ip))
        seen = db.cursor.fetchone()
        if seen:
            iid = seen[0]
            debugger.debug("existing ip %s [%d]", (ip, iid))
            seen_ip = True
        else:
            with exclusive_lock.ExclusiveFileLock(db.lock, 6, "device_seen, new ip"):
                db.cursor.execute("INSERT INTO ip (mid, address, created) VALUES(?, ?, ?)", (mid, ip, now))
                first_seen_ip = True
                db.connection.commit()
            iid = db.cursor.lastrowid
            debugger.info("new ip %s [%d]", (ip, iid))

        # Get ID for Hostname, creating if necessary.
        db.cursor.execute("SELECT host.hid, host.hostname, host.customname FROM host WHERE host.iid = ?", (iid,))
        seen = db.cursor.fetchone()
        if seen:
            hid, hostname, customname = seen
            debugger.debug("existing host %s (%s) [%d]", (hostname, customname, hid))
            seen_host = True
        else:
            hostname = dns_lookup(ip)
            with exclusive_lock.ExclusiveFileLock(db.lock, 6, "device_seen, new host"):
                db.cursor.execute("INSERT INTO host (iid, hostname, customname, created, updated) VALUES(?, ?, ?, ?, ?)", (iid, hostname, None, now, now))

                db.connection.commit()
            first_seen_host = True
            hid = db.cursor.lastrowid
            debugger.info("new hostname %s [%d]", (hostname, hid))

        # Get ID for Device, creating if necessary.
        db.cursor.execute("SELECT device.did FROM device WHERE device.mid = ? AND device.iid = ?", (mid, did))
        seen = db.cursor.fetchone()
        if seen:
            did = seen[0]
            debugger.debug("existing device %s (%s) [%d]", (ip, mac, did))
        else:
            # The IP may have changed for this Device.
            db.cursor.execute("SELECT device.did FROM device WHERE device.mid = ? AND device.hid = ?", (mid, hid))
            seen = db.cursor.fetchone()
            if seen:
                did = seen[0]
                debugger.debug("existing device %s (%s) [%d] (new ip)", (ip, mac, did))
                with exclusive_lock.ExclusiveFileLock(db.lock, 6, "device_seen, update device (new ip)"):
                    db.cursor.execute("UPDATE device SET iid = ?, updated = ? WHERE did = ?", (iid, now, did))
                    log_event(did, ip, mac, EVENT_SEEN_DEVICE, True)
                    log_event(did, ip, mac, EVENT_CHANGED_IP, True)
                    db.connection.commit()
            else:
                with exclusive_lock.ExclusiveFileLock(db.lock, 6, "device_seen, new device"):
                    db.cursor.execute("INSERT INTO device (mid, iid, hid, created, updated) VALUES(?, ?, ?, ?, ?)", (mid, iid, hid, now, now))
                    db.connection.commit()
                first_seen_device = True
                did = db.cursor.lastrowid
                debugger.info("new device %s (%s) [%d]", (ip, mac, did))

        # Finally, log activity.
        db.cursor.execute("SELECT activity.aid FROM activity WHERE activity.did = ? AND activity.active = 1", (did,))
        seen = db.cursor.fetchone()

        with exclusive_lock.ExclusiveFileLock(db.lock, 6, "device_seen, log activity"):
            if seen:
                aid = seen[0]
                db.cursor.execute("UPDATE activity SET updated = ?, iid = ?, counter = counter + 1 WHERE aid = ?", (now, iid, aid))
                log_event(did, ip, mac, EVENT_SEEN_DEVICE, True)
            else:
                # @TODO interface, network
                db.cursor.execute("INSERT INTO activity (did, iid, interface, network, created, updated, counter, active) VALUES(?, ?, ?, ?, ?, ?, ?, ?)", (did, iid, None, None, now, now, 1, 1))
                log_event(did, ip, mac, EVENT_FIRST_SEEN_RECENTLY_DEVICE)

            # We delayed logging these events until we know the device id (did).
            if seen_mac:
                log_event(did, ip, mac, EVENT_SEEN_MAC, True)
            if first_seen_mac:
                log_event(did, ip, mac, EVENT_FIRST_SEEN_MAC, True)
            if seen_ip:
                log_event(did, ip, mac, EVENT_SEEN_IP)
            if first_seen_ip:
                log_event(did, ip, mac, EVENT_FIRST_SEEN_IP, True)
            if seen_host:
                log_event(did, ip, mac, EVENT_SEEN_HOST)
            if first_seen_host:
                log_event(did, ip, mac, EVENT_FIRST_SEEN_HOST)
            if first_seen_device:
                log_event(did, ip, mac, EVENT_FIRST_SEEN_DEVICE, True)
            db.connection.commit()

        return did

    except Exception as e:
        debugger.dump_exception("device_seen() caught exception")

def device_request(ip, mac):
    try:
        from utils import exclusive_lock
        import datetime

        debugger = debug.debugger_instance
        db = database.database_instance

        debugger.debug("entering ip_request(%s, %s)", (ip, mac))

        now = datetime.datetime.now()

        mid, iid, did = get_ids(ip, mac)

        # Log request.
        db.cursor.execute("SELECT request.rid, request.active FROM request WHERE request.ip = ?", (ip,))
        seen = db.cursor.fetchone()
        rid, active = (False, False)
        if seen:
            rid, active = seen
            if active:
                with exclusive_lock.ExclusiveFileLock(db.lock, 6, "device_seen, update device activity"):
                    db.cursor.execute("UPDATE request SET updated = ?, ip = ?, counter = counter + 1 WHERE rid = ?", (now, ip, aid))
                    log_event(did, ip, mac, EVENT_REQUEST_DEVICE, True)
                    db.connection.commit()

        if not seen or not active:
            with exclusive_lock.ExclusiveFileLock(db.lock, 6, "device_seen, new device activity"):
                # @TODO interface, network
                db.cursor.execute("INSERT INTO request (did, ip, interface, network, created, updated, counter, active) VALUES(?, ?, ?, ?, ?, ?, ?, ?)", (did, ip, None, None, now, now, 1, 1))
                if rid:
                    log_event(did, ip, mac, EVENT_FIRST_REQUEST_RECENTLY_DEVICE, True)
                else:
                    log_event(did, ip, mac, EVENT_FIRST_REQUEST_DEVICE, True)
                db.connection.commit()

        return did

    except Exception as e:
        debugger.dump_exception("device_request() caught exception")

def get_ids(ip, mac):
    try:
        debugger = debug.debugger_instance
        debugger.debug("entering get_ids(%s, %s)", (ip, mac))

        # Check if we know this MAC.
        if mac != BROADCAST:
            db.cursor.execute("SELECT mid FROM mac WHERE address = ?", (mac,))
            seen = db.cursor.fetchone()
            if seen:
                mid = seen[0]
            else:
                mid = None
        else:
            mid = None

        # Check if we know this IP.
        if mid:
            db.cursor.execute("SELECT ip.iid FROM ip WHERE ip.mid = ? AND ip.address = ?", (mid, ip))
            seen = db.cursor.fetchone()
            if seen:
                iid = seen[0]
            else:
                iid = None
        else:
            iid = None

        # Check if we know this Host.
        if iid:
            db.cursor.execute("SELECT host.hid, host.hostname, host.customname FROM host WHERE host.iid = ?", (iid,))
            seen = db.cursor.fetchone()
            if seen:
                hid, hostname, customname = seen
            else:
                hid = None
        else:
            hid = None

        # Check if we know this Device.
        if mid and iid:
            db.cursor.execute("SELECT device.did FROM device WHERE device.mid = ? AND device.iid = ?", (mid, did))
            seen = db.cursor.fetchone()
            if seen:
                did = seen[0]
                debugger.debug("existing device %s (%s) [%d]", (ip, mac, did))
            else:
                did = None
        else:
            did = None
        if not did and mid and hid:
            db.cursor.execute("SELECT device.did FROM device WHERE device.mid = ? AND device.hid = ?", (mid, hid))
            seen = db.cursor.fetchone()
            if seen:
                did = seen[0]
                debugger.debug("existing device %s (%s) [%d] (new ip)", (ip, mac, did))
            else:
                did = None

        return (mid, iid, did)

    except Exception as e:
        debugger.dump_exception("get_ids() caught exception")

def first_seen(did):
    try:
        debugger = debug.debugger_instance
        debugger.debug("entering first_seen(did)", (did,))
        db = database.database_instance

        db.cursor.execute("SELECT timestamp FROM activity WHERE did = ? AND timestamp NOT NULL ORDER BY timestamp ASC LIMIT 1", (did,))
        active = db.cursor.fetchone()
        if active:
            active = active[0]

        if active:
            return active
        else:
            return False
    except Exception as e:
        debugger.dump_exception("first_seen() caught exception")

def first_seen_recently(did):
    try:
        debugger = debug.debugger_instance
        debugger.debug("entering last_seen_recently(%s)", (did,))
        db = database.database_instance

        db.cursor.execute('SELECT timestamp FROM activity WHERE did = ? AND timestamp NOT NULL ORDER BY timestamp DESC LIMIT 1', (did,))
        recent = db.cursor.fetchone()
        if recent:
            recent = recent[0]

        if recent:
            return recent
        else:
            return False
    except Exception as e:
        debugger.dump_exception("first_seen_recently() caught exception")

def last_seen(did):
    try:
        debugger = debug.debugger_instance
        debugger.debug("entering last_seen(%s)", (did,))
        db = database.database_instance

        db.cursor.execute('SELECT updated FROM activity WHERE did=? AND updated NOT NULL ORDER BY updated DESC LIMIT 1', (did,))
        active = db.cursor.fetchone()
        if active:
            return active[0]
        else:
            return False
    except Exception as e:
        debugger.dump_exception("last_seen() caught exception")

def previously_seen(did):
    try:
        debugger = debug.debugger_instance
        debugger.debug("entering previously_seen(%s)", (did,))
        db = database.database_instance

        db.cursor.execute('SELECT updated FROM activity WHERE did=? AND updated NOT NULL AND active != 1 ORDER BY updated DESC LIMIT 1', (did,))
        previous = db.cursor.fetchone()
        if previous:
            return previous[0]
        else:
            return False
    except Exception as e:
        debugger.dump_exception("previously_seen() caught exception")

def first_requested(did):
    try:
        debugger = debug.debugger_instance
        debugger.debug("entering first_requested(%s)", (did,))
        db = database.database_instance

        db.cursor.execute('SELECT created FROM request WHERE did=? AND created NOT NULL ORDER BY created ASC LIMIT 1', (did,))
        active = db.cursor.fetchone()
        if active:
            return active[0]
        else:
            return False
    except Exception as e:
        debugger.dump_exception("first_requested() caught exception")

def last_requested(did):
    try:
        debugger = debug.debugger_instance
        debugger.debug("entering last_requested(%s)", (did,))
        db = database.database_instance

        db.cursor.execute('SELECT updated FROM request WHERE did=? AND updated NOT NULL ORDER BY updated DESC LIMIT 1', (did,))
        last = db.cursor.fetchone()
        if last:
            return last[0]
        else:
            return False
    except Exception as e:
        debugger.dump_exception("last_requested() caught exception")

def time_seen(did):
    try:
        debugger = debug.debugger_instance
        debugger.debug("entering time_seen(%s)", (did,))
        db = database.database_instance

        db.cursor.execute('SELECT timestamp, updated FROM activity WHERE did=? AND updated NOT NULL ORDER BY updated DESC LIMIT 1', (did,))
        active = db.cursor.fetchone()
        if active:
            firstSeen, lastSeen = active
            return lastSeen - firstSeen
        else:
            return False
    except Exception as e:
        debugger.dump_exception("time_seen() caught exception")

def previous_ip(did):
    try:
        debugger = debug.debugger_instance
        debugger.debug("entering previous_ip(%s)", (did,))
        db = database.database_instance

        previous_ip = None
        db.cursor.execute("SELECT DISTINCT iid FROM activity WHERE did = ? ORDER BY updated DESC LIMIT 2", (did, ip))
        ips = db.curosr.fetchall()
        if ips and len(ips) == 2:
            db.cursor.execute("SELECT address FROM ip WHERE iid = ?", (ips[1]))
            previous_ip = db.cursor.fetchone()
        if previous_ip:
            return previous_ip[0]
        else:
            return None

    except Exception as e:
        debugger.dump_exception("previous_ip() caught exception")

def devices_with_ip(ip):
    try:
        debugger = debug.debugger_instance
        debugger.debug("entering devices_with_ip(%s)", (ip,))
        db = database.database_instance

        devices = None
        db.cursor.execute("SELECT iid FROM ip WHERE address = ?", (ip,))
        ids = db.cursor.fetchall()
        if ids:
            db.cursor.execute("SELECT did FROM activity WHERE iid IN ("+ ",".join("?"*len(ids)) + ")", ids)
            devices = db.cursor.fetchall()
        if devices:
            return devices
        else:
            return None

    except Exception as e:
        debugger.dump_exception("devices_with_ip() caught exception")

def devices_with_mac(mac):
    try:
        debugger = debug.debugger_instance
        debugger.debug("entering devices_with_mac(%s)", (mac,))
        db = database.database_instance

        devices = None
        db.cursor.execute("SELECT ip.iid FROM ip LEFT JOIN mac ON mac.mid = ip.mid WHERE mac.address = ?", (mac,))
        ids = db.cursor.fetchall()
        if ids:
            db.cursor.execute("SELECT did FROM activity WHERE iid IN ("+ ",".join("?"*len(ids)) + ")", ids)
            devices = db.cursor.fetchall()
        if devices:
            return devices
        else:
            return None

    except Exception as e:
        debugger.dump_exception("devices_with_mac() caught exception")

def devices_requesting_ip(ip):
    try:
        debugger = debug.debugger_instance
        debugger.debug("entering devices_requesting_ip(%s, %s)", (ip,))
        db = database.database_instance

        # @TODO: do we consistently have a did here?
        db.cursor.execute("SELECT did FROM request WHERE ip = ? AND active = 1 GROUP BY did ORDER BY created DESC", (ip,))
        devices = db.cursor.fetchall()
        if devices:
            return devices
        else:
            return None

    except Exception as e:
        debugger.dump_exception("devices_requesting_ip() caught exception")

# Mark IP/MAC pairs as no longer active if we've not seen ARP activity for >active_timeout seconds
def detect_stale_ips(timeout):
    try:
        from utils import exclusive_lock

        debugger = debug.debugger_instance
        db = database.database_instance

        debugger.debug("entering detect_stale_ips()")
        stale = datetime.datetime.now() - datetime.timedelta(seconds=timeout)

        # Mark no-longer active devices stale.
        db.cursor.execute("SELECT aid, did, iid FROM activity WHERE active = 1 AND updated < ?", (stale,))
        rows = db.cursor.fetchall()
        if rows:
            with exclusive_lock.ExclusiveFileLock(db.lock, 5, "detect_stale_ips, activity"):
                for row in rows:
                    aid, did, iid = row
                    db.cursor.execute("SELECT ip.address, mac.address FROM ip LEFT JOIN mac ON ip.mid = mac.mid WHERE iid = ? LIMIT 1", (iid,))
                    address = db.cursor.fetchone()
                    if address:
                        ip, mac = address
                        log_event(did, ip, mac, EVENT_STALE, True)
                        debugger.info("%s [%s] is no longer active)", (ip, mac))
                    else:
                        debugger.error("aid(%d) did(%d) is no longer active, no ip/mac found)", (aid, did))
                    db.cursor.execute("UPDATE activity SET active = 0 WHERE aid = ?", (aid,))
                db.connection.commit()

        # Mark no-longer active requests stale.
        db.cursor.execute("SELECT rid, did, ip FROM request WHERE active = 1 AND updated < ?", (stale,))
        rows = db.cursor.fetchall()
        if rows:
            with exclusive_lock.ExclusiveFileLock(db.lock, 5, "detect_stale_ips, request"):
                for row in rows:
                    rid, did, ip = row
                    log_event(did, ip, None, EVENT_STALE_REQUEST, True)
                    debugger.info("%s (%d) is no longer active)", (ip, did))
                    db.cursor.execute("UPDATE request SET active = 0 WHERE rid = ?", (rid,))
                db.connection.commit()

    except Exception as e:
        debugger.dump_exception("detect_stale_ips() caught exception")

def detect_netscans():
    try:
        from utils import exclusive_lock

        debugger = debug.debugger_instance
        db = database.database_instance

        debugger.debug("entering detect_netscans()")
        now = datetime.datetime.now()

        minutes_ago = now - datetime.timedelta(minutes=5)
        db.cursor.execute("SELECT COUNT(DISTINCT(dst_ip)) AS count, did, src_ip, src_mac FROM arp WHERE request=1 AND timestamp>=? GROUP BY did HAVING count > 50", (minutes_ago,))
        scans = db.cursor.fetchall()
        if scans:
            for scan in scans:
                count, did = scan
                db.cursor.execute("SELECT eid FROM event WHERE did = ? AND event = ? AND timestamp > ?", (did, EVENT_SCAN, minutes_ago))
                already_detected = db.cursor.fetchone()
                if not already_detected:
                    log_event(did, src_ip, src_mac, EVENT_SCAN)
                    debugger.info("Detected network scan by %s [%s]", (src_ip, src_mac))

    except Exception as e:
        debugger.dump_exception("detect_netscans() caught exception")

# @TODO: FIXME
def detect_anomalies(timeout):
    try:
        from utils import exclusive_lock

        debugger = debug.debugger_instance
        db = database.database_instance

        debugger.debug("entering detect_anomalies()")
        now = datetime.datetime.now()
        stale = datetime.datetime.now() - datetime.timedelta(seconds=timeout)

        # Multiple MACs with the same IP.
        db.cursor.execute("SELECT COUNT(DISTINCT(mac)) as count, ip FROM seen WHERE active = 1 AND mac != ? GROUP BY ip HAVING count > 1 ORDER BY ip DESC", (BROADCAST,))
        duplicates = db.cursor.fetchall()
        if duplicates:
            for duplicate in duplicates:
                count, ip = duplicate
                db.cursor.execute("SELECT ip, mac, sid, did FROM seen WHERE ip = ? AND active = 1 AND mac != ?", (ip, BROADCAST))
                details = db.cursor.fetchall()
                for detail in details:
                    ip, mac, sid, did = detail
                    db.cursor.execute("SELECT eid FROM event WHERE mac=? AND ip=? AND event=? AND timestamp>?", (mac, ip, EVENT_DUPLICATE_IP, stale))
                    already_detected = db.cursor.fetchone()
                    if not already_detected or not already_detected[0]:
                        log_event(ip, mac, EVENT_DUPLICATE_IP)
                        debugger.info("Detected multiple MACs with same IP %s [%s]", (ip, mac))

        # Multiple IPs with the same MAC.
        db.cursor.execute("SELECT COUNT(DISTINCT(ip)) as count, mac FROM seen WHERE active = 1 AND mac != ? GROUP BY mac HAVING count > 1 ORDER BY mac DESC", (BROADCAST,))
        duplicates = db.cursor.fetchall()
        if duplicates:
            for duplicate in duplicates:
                count, mac = duplicate
                db.cursor.execute("SELECT ip, mac, sid, did FROM seen WHERE mac = ? AND active = 1", (mac,))
                details = db.cursor.fetchall()
                for detail in details:
                    ip, mac, sid, did = detail
                    db.cursor.execute("SELECT eid FROM event WHERE mac=? AND ip=? AND event=? AND timestamp>?", (mac, ip, EVENT_DUPLICATE_MAC, stale))
                    already_detected = db.cursor.fetchone()
                    if not already_detected or not already_detected[0]:
                        log_event(ip, mac, EVENT_DUPLICATE_MAC)
                        debugger.info("Detected multiple IPs with same MAC %s [%s]", (ip, mac))
    except Exception as e:
        debugger.dump_exception("detect_anomalies() caught exception")

def send_notifications():
    try:
        from utils import exclusive_lock

        debugger = debug.debugger_instance
        db = database.database_instance
        notifier = notify.notify_instance

        debugger.debug("entering send_notifications()")

        if not notifier.enabled:
            debugger.debug("notifications disabled")
            return False

        if not notifier.alerts:
            debugger.debug("no notification alerts configured")
            return False

        import ntfy

        day = datetime.datetime.now() - datetime.timedelta(days=1)
        timer = simple_timer.Timer()

        # only send notifications for configured events
        db.cursor.execute("SELECT eid, did, mac, ip, timestamp, event, processed FROM event WHERE NOT (processed & 8) AND event IN ("+ ",".join("?"*len(notifier.alerts)) + ")", notifier.alerts)

        rows = db.cursor.fetchall()
        if rows:
            counter = 0
            max_eid = 0
            for row in rows:
                eid, did, mac, ip, timestamp, event, processed = row
                debugger.debug("processing event %d for %s [%s] at %s", (eid, ip, mac, timestamp))

                if eid > max_eid:
                    max_eid = eid

                if event in notifier.alerts:
                    debugger.info("event %s [%d] in %s, generating notification alert", (event, eid, notifier.alerts))
                    firstSeen = first_seen(did)
                    lastSeen = first_seen_recently(did)
                    previouslySeen = previously_seen(did)
                    title = """Netgrasp alert: %s""" % (event)
                    body = """%s with IP %s [%s], seen %s, previously seen %s, first seen %s""" % (pretty.name_did(did), ip, mac, pretty.time_ago(lastSeen), pretty.time_ago(previouslySeen), pretty.time_ago(firstSeen))
                    ntfy.notify(body, title)
                else:
                    debugger.debug("event %s [%d] NOT in %s", (event, eid, notifier.alerts))

                if (timer.elapsed() > MAXSECONDS):
                    debugger.debug("processing notifications >%d seconds, aborting", (MAXSECONDS,))
                    with exclusive_lock.ExclusiveFileLock(db.lock, 5, "send_notifications, aborting"):
                        db.cursor.execute("UPDATE event SET processed=processed + ? WHERE eid <= ? AND NOT (processed & ?)", (PROCESSED_NOTIFICATION, max_eid, PROCESSED_NOTIFICATION))
                        db.connection.commit()
                    return

            with exclusive_lock.ExclusiveFileLock(db.lock, 5, "send_notifications"):
                db.cursor.execute("UPDATE event SET processed=processed + ? WHERE eid <= ? AND NOT (processed & ?)", (PROCESSED_NOTIFICATION, max_eid, PROCESSED_NOTIFICATION))
                db.connection.commit()

    except Exception as e:
        debugger.dump_exception("send_notifications() caught exception")

TALKED_TO_LIMIT = 50
def send_email_alerts(timeout):
    try:
        from utils import exclusive_lock

        debugger = debug.debugger_instance
        db = database.database_instance
        emailer = email.email_instance

        debugger.debug("entering send_email_alerts()")

        if not emailer.enabled:
            debugger.debug("email disabled")
            return False

        if not emailer.alerts:
            debugger.debug("no email alerts configured")
            return False

        day = datetime.datetime.now() - datetime.timedelta(days=1)

        db.cursor.execute("SELECT eid, did, mac, ip, timestamp, event, processed FROM event WHERE NOT (processed & 1) AND event IN ("+ ",".join("?"*len(emailer.alerts)) + ")", emailer.alerts)
        rows = db.cursor.fetchall()
        if rows:
            max_eid = 0
            processed_events = 0
            duplicate_macs = []
            duplicate_ips = []
            for row in rows:
                eid, did, mac, ip, timestamp, event, processed = row
                debugger.debug("processing event %d for %s [%s] at %s", (eid, ip, mac, timestamp))

                if eid > max_eid:
                    max_eid = eid
                processed_events += 1

                # only send emails for configured events
                if event in emailer.alerts:
                    if event == EVENT_DUPLICATE_MAC:
                        if mac in duplicate_macs:
                            debugger.debug("event %s [%d], notification email already sent", (event, eid))
                            continue
                        else:
                            debugger.debug("event %s [%d], first time seeing %s", (event, eid, mac))
                            duplicate_macs.append(mac)
                    elif event == EVENT_DUPLICATE_IP:
                        if ip in duplicate_macs:
                            debugger.debug("event %s [%d], notification email already sent", (event, eid))
                            continue
                        else:
                            debugger.debug("event %s [%d], first time seeing %s", (event, eid, ip))
                            duplicate_ips.append(ip)

                    debugger.info("event %s [%d] in %s, generating notification email", (event, eid, emailer.alerts))
                    # get more information about this entry ...
                    db.cursor.execute("SELECT activity.active, activity.counter, vendor.vendor, vendor.customname, host.hostname, host.customname FROM activity LEFT JOIN vendor ON activity.mid = vendor.mid LEFT JOIN host ON activity.iid = host.iid WHERE activity.did = ? ORDER BY updated DESC LIMIT 1", (did,))
                    info = db.cursor.fetchone()
                    if not info:
                        debugger.warning("Event for ip %s [%s] that we haven't seen", (ip, mac))
                        continue

                    active, counter, vendor, vendor_customname, hostname, host_customname = info
                    firstSeen = first_seen(did)
                    firstRequested = first_requested(did)
                    lastSeen = last_seen(did)
                    timeSeen = time_seen(did)
                    previouslySeen = previously_seen(did)
                    lastRequested = last_requested(did)

                    db.cursor.execute("SELECT rid, dst_ip, dst_mac FROM arp WHERE did = ? AND timestamp >= ? GROUP BY rid LIMIT ?", (did, day, TALKED_TO_LIMIT))
                    peers = db.cursor.fetchall()
                    talked_to_text = ""
                    talked_to_html = ""
                    talked_to_count = 0
                    if peers:
                        db.cursor.execute("SELECT COUNT(DISTINCT rid) FROM arp WHERE src_did = ?", (did,))
                        peer_count = db.cursor.fetchone()
                        talked_to_count = peer_count[0]
                        for peer in peers:
                            dst_did, dst_ip, dst_mac = peer
                            talked_to_text += """\n - %s (%s)""" % (pretty.name_did(dst_did), dst_ip)
                            talked_to_html += """<li>%s (%s)</li>""" % (pretty.name_did(dst_did), dst_ip)

                    devices = devices_with_ip(ip)
                    devices_with_ip_text = ""
                    devices_with_ip_html = ""
                    if devices:
                        for device in devices:
                            list_did, list_ip, list_mac = device
                            devices_with_ip_text += """\n - %s (%s)""" % (pretty.name_did(list_did), list_mac)
                            devices_with_ip_html += """<li>%s (%s)</li>""" % (pretty.name_did(list_did), list_mac)

                    devices = devices_with_mac(mac)
                    devices_with_mac_text = ""
                    devices_with_mac_html = ""
                    if devices:
                        for device in devices:
                            list_did, list_ip, list_mac = device
                            devices_with_mac_text += """\n - %s (%s)""" % (pretty.name_did(list_did), list_ip)
                            devices_with_mac_html += """<li>%s (%s)</li>""" % (pretty.name_did(list_did), list_ip)

                    devices = devices_requesting_ip(ip, timeout)
                    devices_requesting_ip_text = ""
                    devices_requesting_ip_html = ""
                    if devices:
                        for device in devices:
                            list_did, list_ip, list_mac = device
                            devices_requesting_ip_text += """\n - %s (%s)""" % (pretty.name_did(list_did), list_ip)
                            devices_requesting_ip_html += """<li>%s (%s)</li>""" % (pretty.name_did(list_did), list_ip)

                    emailer.MailSend(event, dict(
                        name=pretty.name_did(did),
                        ip=ip,
                        mac=mac,
                        event_id=eid,
                        vendor=vendor,
                        vendor_custom=vendor_customname,
                        hostname=hostname,
                        hostname_custom=host_customname,
                        first_seen=pretty.time_ago(firstSeen),
                        last_seen=pretty.time_ago(lastSeen),
                        recently_seen_count=counter,
                        time_seen=pretty.time_elapsed(timeSeen),
                        previously_seen=pretty.time_ago(previouslySeen),
                        first_requested=pretty.time_ago(firstRequested),
                        last_requested=pretty.time_ago(lastRequested),
                        previous_ip=previous_ip(did, ip),
                        devices_with_ip_text=devices_with_ip_text,
                        devices_with_ip_html=devices_with_ip_html,
                        devices_with_mac_text=devices_with_mac_text,
                        devices_with_mac_html=devices_with_mac_html,
                        devices_requesting_ip_text=devices_requesting_ip_text,
                        devices_requesting_ip_html=devices_requesting_ip_html,
                        active_boolean=active,
                        talked_to_count=talked_to_count,
                        talked_to_list_text=talked_to_text,
                        talked_to_list_html=talked_to_html,
                        event=event
                        ))
                else:
                    debugger.debug("event %s [%d] NOT in %s", (event, eid, emailer.alerts))

            with exclusive_lock.ExclusiveFileLock(db.lock, 5, "send_email_alerts"):
                db.cursor.execute("UPDATE event SET processed=processed + ? WHERE eid <= ? AND NOT (processed & ?)", (PROCESSED_ALERT, max_eid, PROCESSED_ALERT))
                db.connection.commit()
            debugger.debug("send_email_alerts: processed %d events", (processed_events,))

    except Exception as e:
        debugger.dump_exception("send_email_alerts() caught exception")

# Finds new MAC addresses and assigns them a name.
def identify_macs():
    try:
        from utils import exclusive_lock

        debugger = debug.debugger_instance
        db = database.database_instance

        debugger.debug("entering identify_macs()")

        import re
        import httplib

        # @TODO: Review query, simplify?
        db.cursor.execute("SELECT device.mid, mac.address, ip.address FROM device LEFT JOIN activity ON device.did = activity.did LEFT JOIN vendor ON device.mid = vendor.mid LEFT JOIN mac ON vendor.mid = mac.mid LEFT JOIN ip ON device.iid = ip.iid WHERE activity.active = 1 AND vendor.mid IS NULL")
        rows = db.cursor.fetchall()
        for row in rows:
            mid, mac, ip = row
            if not re.match("[0-9a-f]{2}([-:])[0-9a-f]{2}(\\1[0-9a-f]{2}){4}$", mac.lower()):
                fixed_mac = []
                pieces = mac.split(":")
                if not pieces:
                    pieces = mac.split("-")
                for piece in pieces:
                    if len(piece) == 1:
                        piece = "0"+piece
                    fixed_mac.append(piece)
                fixed_mac = ":".join(fixed_mac)
                mac = fixed_mac
            debugger.debug("Looking up vendor for %s [%s]", (ip, mac))
            http = httplib.HTTPConnection("api.macvendors.com", 80)
            url = """/%s""" % mac
            http.request("GET", url)
            response = http.getresponse()
            with exclusive_lock.ExclusiveFileLock(db.lock, 5, "identify_macs, vendor"):
                if response.status == 200 and response.reason == "OK":
                    vendor = response.read()
                    debugger.info("Identified %s [%s] as %s", (ip, mac, vendor))
                    db.cursor.execute("INSERT INTO vendor (mid, vendor) VALUES (?, ?)", (mid, vendor))
                else:
                    debugger.info("Failed identify vendor for [%s]", (mid,))
                    db.cursor.execute("INSERT INTO vendor (mid, vendor) VALUES (?, 'unknown')", (mid,))
                db.connection.commit()

        # @TODO restore functionality
        # @TODO consider retrieving actual TTL from DNS -- for now refresh active devices every 5 mins
#        ttl = datetime.datetime.now() - datetime.timedelta(minutes=5)
#        db.cursor.execute("SELECT host.hid, seen.did, seen.mac, seen.ip FROM seen LEFT JOIN host ON seen.did = host.did WHERE seen.lastSeen NOT NULL AND seen.active = 1 AND (host.timestamp IS NULL OR host.timestamp < ?) LIMIT 50", (ttl,))
#        rows = db.cursor.fetchall()
#        for row in rows:
#            hid, did, mac, ip = row
#            hostname = dns_lookup(ip)
#            now = datetime.datetime.now()
#            with exclusive_lock.ExclusiveFileLock(db.lock, 5, "identify_macs, hostname"):
#                if hid:
#                    debugger.debug("Refreshing hostname %s for %s", (hostname, ip))
#                    db.cursor.execute("UPDATE host SET hostname = ?, timestamp = ? WHERE hid = ?", (hostname, now, hid))
#                else:
#                    debugger.debug("Caching hostname %s for ip %s", (hostname, ip))
#                    db.cursor.execute("INSERT INTO host (did, mac, ip, hostname, timestamp) VALUES (?, ?, ?, ?, ?)", (did, mac, ip, hostname, now))
#                db.connection.commit()
    except Exception as e:
        debugger.dump_exception("identify_macs() caught exception")

def dns_lookup(ip):
    try:
        import socket

        debugger = debug.debugger_instance

        debugger.debug("entering dns_lookup(%s)", (ip,))
        try:
            hostname, aliaslist, ipaddrlist = socket.gethostbyaddr(ip)
            debugger.debug("hostname(%s), aliaslist(%s), ipaddrlist(%s)", (hostname, aliaslist, ipaddrlist))
            return hostname

        except Exception as e:
            hostname = "unknown"
            debugger.debug("dns_lookup() socket.gethostbyaddr(%s) failed, hostname = %s: %s", (ip, hostname, e))
            return hostname

    except Exception as e:
        debugger.dump_exception("dns_lookup() caught exception")

# @TODO Restore functionality
# Generates daily and weekly email digests.
def send_email_digests():
    try:
        from utils import exclusive_lock

        debugger = debug.debugger_instance
        db = database.database_instance
        emailer = email.email_instance

        debugger.debug("entering send_email_digests()")

        if not emailer.enabled:
            return False

        if not emailer.digest:
            debugger.debug("no digests configured")
            return False

        timer = simple_timer.Timer()
        now = datetime.datetime.now()

        digests = ["daily", "weekly"]
        for digest in digests:
            if (timer.elapsed() > MAXSECONDS):
                debugger.debug("processing digests >%d seconds, aborting digest", (MAXSECONDS,))
                return

            if (digest == "daily"):
                timestamp_string = "daily_digest_timestamp"
                future_digest_timestamp = now + datetime.timedelta(days=1)
                time_period = now - datetime.timedelta(days=1)
                time_period_description = "24 hours"
                previous_time_period = now - datetime.timedelta(days=2)
            elif (digest == "weekly"):
                timestamp_string = "weekly_digest_timestamp"
                future_digest_timestamp = now + datetime.timedelta(weeks=1)
                time_period = now - datetime.timedelta(weeks=1)
                time_period_description = "7 days"
                previous_time_period = now - datetime.timedelta(weeks=2)

            next_digest_timestamp = db.get_state(timestamp_string, "", True)
            if not next_digest_timestamp:
                # first time here, schedule a digest for appropriate time in future
                db.set_state(timestamp_string, future_digest_timestamp)
                next_digest_timestamp = future_digest_timestamp

            if now < next_digest_timestamp:
                # it's not yet time to send this digest
                continue

            # time to send a digest
            debugger.info("Sending %s digest", (digest,))
            db.set_state(timestamp_string, future_digest_timestamp)

            if (digest == "daily"):
                # PROCESSED_DAILY_DIGEST  = 2
                db.cursor.execute("SELECT DISTINCT did, mac, ip FROM event WHERE NOT (processed & 2) AND timestamp>=? AND timestamp<=? AND event = 'requested'", (time_period, now))
                requested = db.cursor.fetchall()
                db.cursor.execute("SELECT DISTINCT did, mac, ip FROM event WHERE NOT (processed & 2) AND timestamp>=? AND timestamp<=? AND event = 'seen'", (time_period, now))
                seen = db.cursor.fetchall()
            elif (digest == "weekly"):
                # PROCESSED_WEEKLY_DIGEST = 4
                db.cursor.execute("SELECT DISTINCT did, mac, ip FROM event WHERE NOT (processed & 4) AND timestamp>=? AND timestamp<=? AND event = 'requested'", (time_period, now))
                requested = db.cursor.fetchall()
                db.cursor.execute("SELECT DISTINCT did, mac, ip FROM event WHERE NOT (processed & 4) AND timestamp>=? AND timestamp<=? AND event = 'seen'", (time_period, now))
                seen = db.cursor.fetchall()

            db.cursor.execute("SELECT DISTINCT did, mac, ip FROM event WHERE timestamp>=? AND timestamp<=? AND event = 'seen'", (previous_time_period, time_period))
            seen_previous = db.cursor.fetchall()

            new = set(seen) - set(seen_previous)
            gone_away = set(seen_previous) - set(seen)

            noisy = []
            some_new = False
            active_devices_text = ""
            active_devices_html = ""
            for unique_seen in seen:
                did, mac, ip = unique_seen
                db.cursor.execute("SELECT COUNT(DISTINCT(dst_ip)) FROM arp WHERE request=1 AND src_ip=? AND timestamp>=? AND timestamp <=?", (ip, time_period, now))
                requests = db.cursor.fetchone()
                if (requests[0] > 10):
                    noisy.append((mac, ip, requests[0], pretty.name_did(did)))
                if unique_seen in new:
                    active_devices_text += """\n - %s (%s)*""" % (pretty.name_did(did), ip)
                    active_devices_html += """<li>%s (%s)*</li>""" % (pretty.name_did(did), ip)
                    some_new = True
                else:
                    active_devices_text += """\n - %s (%s)""" % (pretty.name_did(did), ip)
                    active_devices_html += """<li>%s (%s)</li>""" % (pretty.name_did(did), ip)
            if some_new:
                new_devices_text = "* = not active in the previous " + time_period_description
            else:
                new_devices_text = ""

            noisy_devices_intro = ""
            noisy_devices_text = ""
            noisy_devices_html = ""
            if noisy:
                noisy_devices_intro = "The following devices requested 10 or more IPs:"
                for noise in noisy:
                    noisy_devices_text += """\n - %s (%s) requested %d IP addresses""" % (noise[3], noise[1], noise[2])
                    noisy_devices_html += """<li>%s (%s) requested %d IP addresses""" % (noise[3], noise[1], noise[2])
                    if (noise[2] > 50):
                        noisy_devices_text += " (network scan?)"
                    noisy_devices_html += "</li>"

            gone_devices_intro = ""
            gone_devices_text = ""
            gone_devices_html = ""
            if gone_away:
                gone_devices_intro = """The following IPs were not active, but were active the previous %s:""" % (time_period_description)
                for gone in gone_away:
                    did, mac, ip = gone
                    gone_devices_text += """\n - %s (%s)""" % (pretty.name_did(did), ip)
                    gone_devices_html += """<li>%s (%s)</li>""" % (pretty.name_did(did), ip)

            device_breakdown_text = ""
            device_breakdown_html = ""
            if (digest == "daily"):
                range = 24
                while (range > 0):
                    lower = now - datetime.timedelta(hours=range)
                    range = range - 1
                    upper = now - datetime.timedelta(hours=range)
                    db.cursor.execute("SELECT DISTINCT mac, ip FROM event WHERE event = 'seen' AND timestamp>=? AND timestamp<?", (lower, upper))
                    distinct = db.cursor.fetchall()
                    device_breakdown_text += """\n - %s: %d""" % (lower.strftime("%I %p, %x"), len(distinct))
                    device_breakdown_html += """<li>%s: %d</li>""" % (lower.strftime("%I %p, %x"), len(distinct))
            elif (digest == "weekly"):
                range = 7
                while (range > 0):
                    lower = now - datetime.timedelta(days=range)
                    range = range - 1
                    upper = now - datetime.timedelta(days=range)
                    db.cursor.execute("SELECT DISTINCT mac, ip FROM event WHERE event = 'seen' AND timestamp>=? AND timestamp<?", (lower, upper))
                    distinct = db.cursor.fetchall()
                    device_breakdown_text += """\n - %s: %d""" % (lower.strftime("%A, %x"), len(distinct))
                    device_breakdown_html += """<li>%s: %d</li>""" % (lower.strftime("%A, %x"), len(distinct))

            if (digest == "daily"):
                db.cursor.execute("SELECT MAX(eid) FROM event WHERE timestamp<=? AND NOT (processed & 2)", (now,))
                processed_type = PROCESSED_DAILY_DIGEST
            elif (digest == "weekly"):
                db.cursor.execute("SELECT MAX(eid) FROM event WHERE timestamp<=? AND NOT (processed & 4)", (now,))
                processed_type = PROCESSED_WEEKLY_DIGEST
            max_eid = db.cursor.fetchone()
            if max_eid and max_eid[0]:
                with exclusive_lock.ExclusiveFileLock(db.lock, 5, "send_email_digests"):
                    db.cursor.execute("UPDATE event SET processed=processed + ? WHERE eid <= ? AND NOT (processed & ?)", (processed_type, max_eid[0], processed_type))

                    db.connection.commit()

            debugger.info("Sending %s digest", (digest,))

            emailer.MailSend('digest', dict(
                type=digest,
                time_period=time_period_description,
                active_devices_count=len(seen),
                active_devices_text=active_devices_text,
                active_devices_html=active_devices_html,
                new_devices_text=new_devices_text,
                ips_requested=len(requested),
                noisy_devices_intro=noisy_devices_intro,
                noisy_devices_text=noisy_devices_text,
                noisy_devices_html=noisy_devices_html,
                gone_devices_intro=gone_devices_intro,
                gone_devices_text=gone_devices_text,
                gone_devices_html=gone_devices_html,
                device_breakdown_text=device_breakdown_text,
                device_breakdown_html=device_breakdown_html
                ))
    except Exception as e:
        debugger.dump_exception("send_email_digests() caught exception")

# @TODO Restore functionality
def garbage_collection(enabled, oldest_arplog, oldest_event):
    try:
        from utils import exclusive_lock

        debugger = debug.debugger_instance
        db = database.database_instance

        debugger.debug("entering garbage_collection()")

        if not enabled:
            debugger.debug("garbage collection disabled")
            return

        garbage_collection_string = "garbage collection"

        now = datetime.datetime.now()
        next_garbage_collection = db.get_state(garbage_collection_string, "", True)

        if not next_garbage_collection:
            # perform first garbage collection now
            next_garbage_collection = now

        if now < next_garbage_collection:
            # it's not yet time to send this digest
            return False

        debugger.info("performing garbage collection")
        # schedule next garbage collection
        db.set_state(garbage_collection_string, now + datetime.timedelta(days=1))

        with exclusive_lock.ExclusiveFileLock(db.lock, 5, "garbage_collection"):
            # Purge old arplog entries.
            db.cursor.execute("SELECT COUNT(*) FROM arplog WHERE timestamp < ?", (now - oldest_arplog,))
            arplog_count = db.cursor.fetchone()
            db.cursor.execute("DELETE FROM arplog WHERE timestamp < ?", (now - oldest_arplog,))
            # Purge old event entries.
            db.cursor.execute("SELECT COUNT(*) FROM event WHERE timestamp < ?", (now - oldest_event,))
            event_count = db.cursor.fetchone()
            db.cursor.execute("DELETE FROM event WHERE timestamp < ?", (now - oldest_event,))
            db.connection.commit()

        debugger.debug("deleted %d arplog entries older than %s", (arplog_count[0], now - oldest_arplog))
        debugger.debug("deleted %d event entries older than %s", (event_count[0], now - oldest_event))
    except Exception as e:
        debugger.dump_exception("garbage_collection() caught exception")


#################
#################
#################

def _init(verbose, daemonize, mode = debug.FILE):
    try:
        import logging

        # Get a logger and config parser.
        logger = logging.getLogger(__name__)
        formatter = logging.Formatter(DEFAULT_LOGFORMAT)

        if mode == debug.FILE and os.getuid() != 0:
            # We're going to fail, so write to stderr.
            debugger = debug.Debugger()
        else:
            debugger = debug.Debugger(verbose, logger, mode)
        configuration = config.Config(debugger)

        debug.debugger_instance = debugger
        config.config_instance = configuration

        # Start logger, reading relevant configuration.
        if daemonize:
            try:
                debugger.handler = logging.FileHandler(configuration.GetText('Logging', 'filename', DEFAULT_LOGFILE))
            except Exception as e:
                debugger.critical("Fatal exception setting up log handler: %s", (e,))
        else:
            if mode == debug.FILE:
                debugger.handler = logging.StreamHandler()

        if mode == debug.FILE:
            debugger.handler.setFormatter(formatter)
            logger.addHandler(debugger.handler)

        if verbose:
            debugger.setLevel(logging.DEBUG)
            debugger.warning("[Logging] level forced to DEBUG, started with -v flag.")
        else:
            logger.setLevel(configuration.GetText('Logging', 'level', DEFAULT_LOGLEVEL, False))
        debugger.info('loaded configuration file: %s', (configuration.found,))

        return (debugger, configuration)
    except Exception as e:
        debugger.dump_exception("_init() caught exception")

def start():
    ng = netgrasp_instance
    ng.debugger, ng.config = _init(ng.verbose, ng.daemonize)

    if not ng.daemonize:
        ng.debugger.info("Output forced to stderr, started with --foreground flag.")

    keep_fds=[ng.debugger.handler.stream.fileno()]

    try:
        import sqlite3
    except Exception as e:
        ng.debugger.error("fatal exception: %s", (e,))
        ng.debugger.critical("failed to import sqlite3 (as user %s), try 'pip install sqlite3', exiting", (ng.debugger.whoami()))
    ng.debugger.info("successfuly imported sqlite3")
    try:
        import dpkt
    except Exception as e:
        ng.debugger.error("fatal exception: %s", (e,))
        ng.debugger.critical("failed to import dpkt (as user %s), try 'pip install dpkt', exiting", (ng.debugger.whoami()))
    ng.debugger.info("successfuly imported dpkt")
    if ng.daemonize:
        try:
            import daemonize
        except Exception as e:
            ng.debugger.error("fatal exception: %s", (e,))
            ng.debugger.critical("failed to import daemonize (as user %s), try 'pip install daemonize', exiting", (ng.debugger.whoami()))
        ng.debugger.info("successfuly imported daemonize")

    notify.notify_instance = notify.Notify(ng.debugger, ng.config)

    ng.database_filename = ng.config.GetText('Database', 'filename')

    if ng.daemonize:
        ng.pidfile = ng.config.GetText('Logging', 'pidfile', DEFAULT_PIDFILE, False)
        username = ng.config.GetText('Security', 'user', DEFAULT_USER, False)
        groupname = ng.config.GetText('Security', 'group', DEFAULT_GROUP, False)
        ng.debugger.info("daemonizing app=netgrasp, pidfile=%s, user=%s, group=%s, verbose=True", (ng.pidfile, username, groupname))
        try:
            daemon = daemonize.Daemonize(app="netgrasp", pid=ng.pidfile, privileged_action=get_pcap, user=username, group=groupname, action=main, keep_fds=keep_fds, logger=ng.debugger.logger, verbose=True)
            daemon.start()
        except Exception as e:
            ng.debugger.critical("Failed to daemonize: %s, exiting", (e,))
    else:
        main()
