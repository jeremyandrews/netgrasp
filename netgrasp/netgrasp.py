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

ALERT_TYPES = ['first_requested', 'requested', 'first_seen', 'first_seen_recently', 'seen', 'changed_ip', 'duplicate_ip', 'duplicate_mac', 'stale', 'network_scan']
EVENT_REQUESTED_FIRST, EVENT_REQUESTED, EVENT_SEEN_FIRST, EVENT_SEEN_FIRST_RECENT, EVENT_SEEN, EVENT_CHANGED_IP, EVENT_DUPLICATE_IP, EVENT_DUPLICATE_MAC, EVENT_STALE, EVENT_SCAN = ALERT_TYPES
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
        pc = pcap[0]
    else:
        # We are running in the foreground as root.
        pcap = get_pcap()
        pc = pcap[0]
        ng.drop_root(ng)

    # At this point we should no longer have/need root privileges.
    assert (os.getuid() != 0) and (os.getgid() != 0), 'Failed to drop root privileges, aborting.'

    ng.debugger.info("initiating wiretap process")
    parent_conn, child_conn = multiprocessing.Pipe()
    child = multiprocessing.Process(name="wiretap", target=wiretap, args=[pc, child_conn])
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
            detect_anomalies(ng.active_timeout)
            send_notifications()
            send_email_alerts()
            send_email_digests()
            garbage_collection(ng.garbage_collection, ng.oldest_arplog, ng.oldest_event)

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
            ng.debugger.dump_exception("main() while loop FIXME")
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
    return [pc]

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
            netgrasp_instance.debugger.dump_exception("wiretap() while loop FIXME")
    netgrasp_instance.debugger.critical("No heartbeats from main process for >3 minutes, exiting.")

def ip_seen(src_ip, src_mac, dst_ip, dst_mac, request):
    try:
        from utils import exclusive_lock
        import datetime

        debugger = debug.debugger_instance
        db = database.database_instance

        debugger.debug("entering ip_seen(%s, %s, %s, %s, %d)", (src_ip, src_mac, dst_ip, dst_mac, request))

        now = datetime.datetime.now()

        with exclusive_lock.ExclusiveFileLock(db.lock, 5, "ip_seen, arplog"):
            db.cursor.execute("INSERT INTO arplog (src_mac, src_ip, dst_mac, dst_ip, request, timestamp) VALUES(?, ?, ?, ?, ?, ?)", (src_mac, src_ip, dst_mac, dst_ip, request, now))
            debugger.debug("inserted into arplog")
            db.connection.commit()

        # @TODO Research and see if we should be treating these another way.
        if (src_ip == "0.0.0.0" or src_mac == BROADCAST):
            debugger.info("Ignoring IP source of %s [%s], dst %s [%s]", (src_ip, src_mac, dst_ip, dst_mac))
            return False

        # Check if we've seen this IP, MAC pair before.
        active, lastSeen, lastRequested, counter, sid, did, changed_ip = [False, False, False, 0, 0, 0, False]
        debugger.debug("ip_seen query 1")
        db.cursor.execute("SELECT active, lastSeen, lastRequested, counter, sid, did FROM seen WHERE ip=? AND mac=? ORDER BY lastSeen DESC LIMIT 1", (src_ip, src_mac))
        result = db.cursor.fetchone()
        if result:
            active, lastSeen, lastRequested, counter, sid, did = result

        if not result:
            # Check if we've seen this MAC, hostname pair before, it may have gotten assigned a new IP.
            # In the event of the same IP and a different hostname, we treat this like a different device
            # (though it's likely a vm, jail, or alias). @TODO Revisit this.
            hostname = dns_lookup(src_ip)
            debugger.debug("ip_seen query 2")
            db.cursor.execute("SELECT seen.active, seen.lastSeen, seen.lastRequested, seen.counter, seen.sid, seen.did FROM seen LEFT JOIN host ON seen.mac = host.mac WHERE seen.mac = ? AND host.hostname = ? ORDER BY seen.lastSeen DESC LIMIT 1", (src_mac, hostname))
            result = db.cursor.fetchone()
            if result:
                active, lastSeen, lastRequested, counter, sid, did = result
                changed_ip = True

        if not result:
            # Check if we've seen this IP be requested before.
            debugger.debug("ip_seen query 3")
            db.cursor.execute("SELECT active, lastSeen, lastRequested, counter, sid, did FROM seen WHERE ip=? AND mac=? ORDER BY lastSeen DESC LIMIT 1", (src_ip, BROADCAST))
            result = db.cursor.fetchone()
            if result:
                active, lastSeen, lastRequested, counter, sid, did = result

        log_event(src_ip, src_mac, EVENT_SEEN)
        if changed_ip:
            debugger.info("[%s] (%s) has a new ip [%s]", (did, src_mac, src_ip))
            log_event(src_ip, src_mac, EVENT_CHANGED_IP)
        if active:
            if lastSeen:
                # has been active recently
                debugger.debug("%s (%s) is active", (src_ip, src_mac))
                with exclusive_lock.ExclusiveFileLock(db.lock, 5, "ip_seen, update seen"):
                    db.cursor.execute("UPDATE seen set ip=?, mac=?, lastSeen=?, counter=?, active=1 WHERE sid=?", (src_ip, src_mac, now, counter + 1, sid))
                    db.connection.commit()
            else:
                # has not been active recently, but was requested recently
                if first_seen(src_ip, src_mac):
                    # First time we've seen IP since it was stale.
                    log_event(src_ip, src_mac, EVENT_SEEN_FIRST_RECENT)
                    the_event = EVENT_SEEN_FIRST_RECENT
                    lastSeen = last_seen(src_ip, src_mac)
                    if lastSeen:
                        timeSince = datetime.datetime.now() - lastSeen
                        debugger.info("[%s] %s (%s) is active again (after %s)", (did, src_ip, src_mac, timeSince))
                    else:
                        debugger.warning("We've seen a packet %s [%s] with a firstSeen (%s) but no lastSeen -- this shouldn't happen.", (src_ip, src_mac, first_seen(src_ip, src_mac)))
                else:
                    # First time we've actively seen this IP.
                    log_event(src_ip, src_mac, EVENT_SEEN_FIRST)
                    log_event(src_ip, src_mac, EVENT_SEEN_FIRST_RECENT)
                    the_event = EVENT_SEEN_FIRST
                    debugger.info("[%s] %s (%s) is active, first time seeing", (did, src_ip, src_mac))

                # @TODO properly handle multiple active occurences of the same IP
                with exclusive_lock.ExclusiveFileLock(db.lock, 5, "ip_seen, update seen 2"):
                    db.cursor.execute("UPDATE seen set ip=?, mac=?, firstSeen=?, lastSeen=?, counter=?, active=1 WHERE sid=?", (src_ip, src_mac, now, now, counter + 1, sid))
                    db.connection.commit()
        else:
            if did:
                # First time we've seen this IP recently.
                log_event(src_ip, src_mac, EVENT_SEEN_FIRST_RECENT)
                the_event = EVENT_SEEN_FIRST_RECENT
                debugger.info("[%s] %s (%s) is active, first time seeing recently", (did, src_ip, src_mac))
            else:
                # First time we've seen this IP.
                db.cursor.execute("SELECT MAX(did) + 1 FROM seen")
                row = db.cursor.fetchone()
                if row:
                    did = row[0]
                else:
                    did = 1
                if not did:
                    debugger.debug('Did was None, setting to 1')
                    did = 1
                log_event(src_ip, src_mac, EVENT_SEEN_FIRST)
                log_event(src_ip, src_mac, EVENT_SEEN_FIRST_RECENT)
                the_event = EVENT_SEEN_FIRST
                debugger.info("[%s] %s (%s) is active, first time seeing", (did, src_ip, src_mac))
            with exclusive_lock.ExclusiveFileLock(db.lock, 5, "ip_seen, update seen 3"):
                db.cursor.execute("INSERT INTO seen (did, mac, ip, firstSeen, lastSeen, counter, active, self) VALUES(?, ?, ?, ?, ?, 1, 1, ?)", (did, src_mac, src_ip, now, now, ip_is_mine(src_ip)))
                db.connection.commit()
    except Exception as e:
        debugger.dump_exception("ip_seen() FIXME")

def ip_request(ip, mac, src_ip, src_mac):
    try:
        from utils import exclusive_lock
        import datetime

        debugger = debug.debugger_instance
        db = database.database_instance

        debugger.debug("entering ip_request(%s, %s, %s, %s)", (ip, mac, src_ip, src_mac))
        now = datetime.datetime.now()

        if ((ip == src_ip) or (mac == src_mac)):
            debugger.debug("requesting self, ignoring")
            return

        active = False
        lastRequested = False
        db.cursor.execute("SELECT active, lastRequested, sid, did FROM seen WHERE ip=? AND mac=? AND active=1", (ip, mac))
        requested = db.cursor.fetchone()
        if requested:
            active, lastRequested, sid, did = requested
        else:
            if (mac == BROADCAST):
                # Maybe we already have seen a request for this address
                db.cursor.execute("SELECT active, lastRequested, sid, did FROM seen WHERE ip=? AND mac=? AND active=1", (ip, BROADCAST))
                requested = db.cursor.fetchone()
                if requested:
                    active, lastRequested, sid, did = requested
                else:
                    # Maybe the IP has been seen already
                    db.cursor.execute("SELECT active, lastRequested, sid, did FROM seen WHERE ip=? AND active=1", (ip,))
                    requested = db.cursor.fetchone()
                    if requested:
                        active, lastRequested, sid, did = requested

        log_event(ip, mac, EVENT_REQUESTED)
        if active:
            # Update:
            with exclusive_lock.ExclusiveFileLock(db.lock, 5, "ip_request, update seen"):
                db.cursor.execute("UPDATE seen set lastRequested=? WHERE sid=?", (now, sid))
                db.connection.commit()
            debugger.debug("%s (%s) requested", (ip, mac))
        else:
            # First time we've seen a request for this IP.
            log_event(ip, mac, EVENT_REQUESTED_FIRST)
            with exclusive_lock.ExclusiveFileLock(db.lock, 5, "ip_request, insert into seen"):
                db.cursor.execute("INSERT INTO seen (mac, ip, did, firstRequested, lastRequested, counter, active, self) VALUES(?, ?, ?, ?, ?, 1, 1, ?)", (mac, ip, get_did(ip, mac), now, now, ip_is_mine(ip)))
                db.connection.commit()
            debugger.info("%s (%s) requested, first time seeing", (ip, mac))
    except Exception as e:
        debugger.dump_exception("ip_request() FIXME")

# Assumes we already have the database lock.
def log_event(ip, mac, event, have_lock = False):
    try:
        db = database.database_instance
        debugger = debug.debugger_instance
        debugger.debug("entering log_event(%s, %s, %s)", (ip, mac, event))

        now = datetime.datetime.now()

        if have_lock:
            db.connection.execute("INSERT INTO event (mac, ip, timestamp, processed, event) VALUES(?, ?, ?, ?, ?)", (mac, ip, now, 0, event))
        else:
            with exclusive_lock.ExclusiveFileLock(db.lock, 5, "log_event, " + event):
                db.connection.execute("INSERT INTO event (mac, ip, timestamp, processed, event) VALUES(?, ?, ?, ?, ?)", (mac, ip, now, 0, event))
                db.connection.commit()
    except Exception as e:
        debugger.dump_exception("log_event() FIXME")

def ip_is_mine(ip):
    try:
        import socket
        debugger = debug.debugger_instance
        debugger.debug("entering ip_is_mine(%s)", (ip,))

        return (ip == socket.gethostbyname(socket.gethostname()))
    except Exception as e:
        debugger.dump_exception("ip_is_mine() FIXME")

# Database definitions.
def create_database():
    try:
        from utils import exclusive_lock
        debugger = debug.debugger_instance
        db = database.database_instance

        debugger.debug('Creating database tables, if not already existing.')

        with exclusive_lock.ExclusiveFileLock(db.lock, 5, "create_database"):
            # Create state table.
            db.cursor.execute("""
              CREATE TABLE IF NOT EXISTS state(
                id INTEGER PRIMARY KEY,
                key VARCHAR UNIQUE,
                value TEXT
              )
            """)

            # Create seen table.
            db.cursor.execute("""
              CREATE TABLE IF NOT EXISTS seen(
                sid INTEGER PRIMARY KEY,
                did INTEGER,
                mac TEXT,
                ip TEXT,
                interface TEXT,
                network TEXT,
                firstSeen TIMESTAMP,
                firstRequested TIMESTAMP,
                lastSeen TIMESTAMP,
                lastRequested TIMESTAMP,
                counter NUMERIC,
                active NUMERIC,
                self NUMERIC
              )
            """)
            db.cursor.execute("CREATE INDEX IF NOT EXISTS idx_ip_mac_firstSeen ON seen (ip, mac, firstSeen)")
            db.cursor.execute("CREATE INDEX IF NOT EXISTS idx_ip_mac_lastSeen ON seen (ip, mac, lastSeen)")
            db.cursor.execute("CREATE INDEX IF NOT EXISTS idx_ip_mac_firstRequested ON seen (ip, mac, firstRequested)")
            db.cursor.execute("CREATE INDEX IF NOT EXISTS idx_ip_mac_lastRequested ON seen (ip, mac, lastRequested)")
            db.cursor.execute("CREATE INDEX IF NOT EXISTS idx_active_lastSeen ON seen (active, lastSeen)")
            db.cursor.execute("CREATE INDEX IF NOT EXISTS idx_ip_mac_active ON seen (ip, mac, active)")
            db.cursor.execute("CREATE INDEX IF NOT EXISTS idx_mac_did ON seen (mac, did)")
            # PRAGMA index_list(seen)

            # Create arplog table.
            db.cursor.execute("""
              CREATE TABLE IF NOT EXISTS arplog(
                aid INTEGER PRIMARY KEY,
                src_mac TEXT,
                src_ip TEXT,
                dst_mac TEXT,
                dst_ip TEXT,
                request NUMERIC,
                interface TEXT,
                network TEXT,
                timestamp TIMESTAMP
              )
            """)
            db.cursor.execute("CREATE INDEX IF NOT EXISTS idx_srcip_timestamp_request ON arplog (src_ip, timestamp, request)")

            # Create event table.
            db.cursor.execute("""
              CREATE TABLE IF NOT EXISTS event(
                eid INTEGER PRIMARY KEY,
                mac TEXT,
                ip TEXT,
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
                mac TEXT,
                ip TEXT,
                hostname TEXT,
                customname TEXT
              )
            """)
            db.cursor.execute("CREATE INDEX IF NOT EXISTS idx_ip_mac ON host (ip, mac)")
            db.cursor.execute("CREATE INDEX IF NOT EXISTS idx_mac_hostname ON host (mac, hostname)")
            db.connection.commit()
    except Exception as e:
        debugger.dump_exception("create_database() FIXME")

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
            debugger.debug("applying update #1 to database: adding did column to seen, populating")
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
    except Exception as e:
        debugger.dump_exception("update_database() FIXME")

# We've sniffed an arp packet off the wire.
def received_arp(hdr, data, child_conn):
    try:
        import socket
        import struct
        import dpkt

        debugger = debug.debugger_instance

        packet = dpkt.ethernet.Ethernet(data)
        src_ip = socket.inet_ntoa(packet.data.spa)
        src_mac = "%x:%x:%x:%x:%x:%x" % struct.unpack("BBBBBB", packet.src)
        dst_ip = socket.inet_ntoa(packet.data.tpa)
        dst_mac = "%x:%x:%x:%x:%x:%x" % struct.unpack("BBBBBB", packet.dst)

        if (packet.data.op == dpkt.arp.ARP_OP_REQUEST):
            debugger.debug('ARP request from %s (%s) to %s (%s)', (src_ip, src_mac, dst_ip, dst_mac))
            ip_seen(src_ip, src_mac, dst_ip, dst_mac, True)
            ip_request(dst_ip, dst_mac, src_ip, src_mac)
        elif (packet.data.op == dpkt.arp.ARP_OP_REPLY):
            debugger.debug('ARP reply from %s (%s) to %s (%s)', (src_ip, src_mac, dst_ip, dst_mac))
            ip_seen(src_ip, src_mac, dst_ip, dst_mac, False)
    except Exception as e:
        debugger.dump_exception("received_arp() FIXME")

# Determine appropriate device id for IP, MAC pair.
def get_did(ip, mac):
    try:
        debugger = debug.debugger_instance
        debugger.debug("entering get_did(%s, %s)", (ip, mac))
        db = database.database_instance

        db.cursor.execute("SELECT did FROM seen WHERE ip=? AND mac=? ORDER BY did DESC LIMIT 1", (ip, mac))
        did = db.cursor.fetchone()
        if did:
            did = did[0]
        if not did:
            hostname = dns_lookup(ip)
            db.cursor.execute("SELECT seen.did FROM seen LEFT JOIN host ON seen.mac = host.mac WHERE seen.mac = ? AND host.hostname = ? ORDER BY seen.did DESC LIMIT 1", (mac, hostname))
            did = db.cursor.fetchone()
            if did:
                did = did[0]

        if not did:
            db.cursor.execute("SELECT did FROM seen WHERE ip=? AND mac=? ORDER BY did DESC LIMIT 1", (ip, BROADCAST))
            did = db.cursor.fetchone()
            if did:
                did = did[0]

        if did:
            debugger.debug("matched did for %s [%s]: %d", (ip, mac, did))
            return did
        else:
            db.cursor.execute("SELECT MAX(did) + 1 FROM seen")
            did = db.cursor.fetchone()
            if did:
                did = did[0]
            if not did:
                did = 1
            debugger.debug("no matching did for %s [%s], new: %d", (ip, mac, did))
            return did
    except Exception as e:
        debugger.dump_exception("get_did() FIXME")

def first_seen(ip, mac):
    try:
        debugger = debug.debugger_instance
        debugger.debug("entering first_seen(%s, %s)", (ip, mac))
        db = database.database_instance

        did = get_did(ip, mac)
        db.cursor.execute("SELECT firstSeen FROM seen WHERE did = ? AND firstSeen NOT NULL ORDER BY firstSeen ASC LIMIT 1", (did,))
        active = db.cursor.fetchone()
        if active:
            active = active[0]

        if active:
            return active
        else:
            return False
    except Exception as e:
        debugger.dump_exception("first_seen() FIXME")

def first_seen_recently(ip, mac):
    try:
        debugger = debug.debugger_instance
        debugger.debug("entering last_seen_recently(%s, %s)", (ip, mac))
        db = database.database_instance

        did = get_did(ip, mac)
        db.cursor.execute('SELECT firstSeen FROM seen WHERE did = ? AND firstSeen NOT NULL ORDER BY firstSeen DESC LIMIT 1', (did,))
        recent = db.cursor.fetchone()
        if recent:
            recent = recent[0]

        if recent:
            return recent
        else:
            return False
    except Exception as e:
        debugger.dump_exception("first_seen_recently() FIXME")

def last_seen(ip, mac):
    try:
        debugger = debug.debugger_instance
        debugger.debug("entering last_seen(%s, %s)", (ip, mac))
        db = database.database_instance

        did = get_did(ip, mac)
        db.cursor.execute('SELECT lastSeen FROM seen WHERE did=? AND lastSeen NOT NULL ORDER BY lastSeen DESC LIMIT 1', (did,))
        active = db.cursor.fetchone()
        if active:
            return active[0]
        else:
            return False
    except Exception as e:
        debugger.dump_exception("last_seen() FIXME")

def previously_seen(ip, mac):
    try:
        debugger = debug.debugger_instance
        debugger.debug("entering previously_seen(%s, %s)", (ip, mac))
        db = database.database_instance

        did = get_did(ip, mac)
        db.cursor.execute('SELECT lastSeen FROM seen WHERE did=? AND lastSeen NOT NULL AND active != 1 ORDER BY lastSeen DESC LIMIT 1', (did,))
        previous = db.cursor.fetchone()
        if previous:
            return previous[0]
        else:
            return False
    except Exception as e:
        debugger.dump_exception("previously_seen() FIXME")

def first_requested(ip, mac):
    try:
        debugger = debug.debugger_instance
        debugger.debug("entering first_requested(%s, %s)", (ip, mac))
        db = database.database_instance

        did = get_did(ip, mac)
        db.cursor.execute('SELECT firstRequested FROM seen WHERE did=? AND firstRequested NOT NULL ORDER BY firstRequested ASC LIMIT 1', (did,))
        active = db.cursor.fetchone()
        if active:
            return active[0]
        else:
            return False
    except Exception as e:
        debugger.dump_exception("first_requested() FIXME")

def last_requested(ip, mac):
    try:
        debugger = debug.debugger_instance
        debugger.debug("entering last_requested(%s, %s)", (ip, mac))
        db = database.database_instance

        did = get_did(ip, mac)
        db.cursor.execute('SELECT lastRequested FROM seen WHERE did=? AND lastRequested NOT NULL ORDER BY lastRequested DESC LIMIT 1', (did,))
        last = db.cursor.fetchone()
        if last:
            return last[0]
        else:
            return False
    except Exception as e:
        debugger.dump_exception("last_requested() FIXME")

# Mark IP/MAC pairs as no longer active if we've not seen ARP activity for >active_timeout seconds
def detect_stale_ips(timeout):
    try:
        from utils import exclusive_lock

        debugger = debug.debugger_instance
        db = database.database_instance

        debugger.debug("entering detect_stale_ips()")
        stale = datetime.datetime.now() - datetime.timedelta(seconds=timeout)

        db.cursor.execute("SELECT sid, mac, ip, firstSeen, lastSeen FROM seen WHERE active = 1 AND lastSeen < ?", (stale,))
        rows = db.cursor.fetchall()
        if rows:
            with exclusive_lock.ExclusiveFileLock(db.lock, 5, "detect_stale_ips"):
                for row in rows:
                    sid, mac, ip, firstSeen, lastSeen = row
                    if (firstSeen and lastSeen):
                        timeActive = lastSeen - firstSeen
                    else:
                        timeActive = "unknown"
                    log_event(ip, mac, EVENT_STALE, True)
                    debugger.info("%s [%s] is no longer active (was active for %s)", (ip, mac, timeActive))
                    db.cursor.execute("UPDATE seen SET active = 0 WHERE sid=?", (sid,))
                db.connection.commit()
    except Exception as e:
        debugger.dump_exception("detect_stale_ips() FIXME")

def detect_netscans():
    try:
        from utils import exclusive_lock

        debugger = debug.debugger_instance
        db = database.database_instance

        debugger.debug("entering detect_netscans()")
        now = datetime.datetime.now()

        minutes_ago = now - datetime.timedelta(minutes=5)
        db.cursor.execute("SELECT COUNT(DISTINCT(dst_ip)) AS count, src_mac, src_ip FROM arplog WHERE request=1 AND timestamp>=? GROUP BY src_ip HAVING count > 50", (minutes_ago,))
        scans = db.cursor.fetchall()
        if scans:
            for scan in scans:
                count, src_mac, src_ip = scan
                db.cursor.execute("SELECT eid FROM event WHERE mac=? AND ip=? AND event=? AND timestamp>?", (src_mac, src_ip, EVENT_SCAN, minutes_ago))
                already_detected = db.cursor.fetchone()
                if not already_detected or not already_detected[0]:
                    log_event(src_ip, src_mac, EVENT_SCAN)
                    debugger.info("Detected network scan by %s [%s]", (src_ip, src_mac))
    except Exception as e:
        debugger.dump_exception("detect_netscans() FIXME")

def detect_anomalies(timeout):
    try:
        from utils import exclusive_lock

        debugger = debug.debugger_instance
        db = database.database_instance

        debugger.debug("entering detect_anomalies()")
        now = datetime.datetime.now()
        stale = datetime.datetime.now() - datetime.timedelta(seconds=timeout)

        # Multiple MACs with the same IP.
        db.cursor.execute("SELECT COUNT(*) as count, ip FROM seen WHERE active = 1 AND mac != ? GROUP BY ip HAVING count > 1", (BROADCAST,))
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
        db.cursor.execute("SELECT COUNT(*) as count, mac FROM seen WHERE active = 1 AND mac != ? GROUP BY mac HAVING count > 1", (BROADCAST,))
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
        debugger.dump_exception("detect_anomalies() FIXME")

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
        db.cursor.execute("SELECT eid, mac, ip, timestamp, event, processed FROM event WHERE NOT (processed & 8) AND event IN ("+ ",".join("?"*len(notifier.alerts)) + ")", notifier.alerts)

        rows = db.cursor.fetchall()
        if rows:
            counter = 0
            max_eid = 0
            for row in rows:
                eid, mac, ip, timestamp, event, processed = row
                debugger.debug("processing event %d for %s [%s] at %s", (eid, ip, mac, timestamp))

                if eid > max_eid:
                    max_eid = eid

                if event in notifier.alerts:
                    debugger.info("event %s [%d] in %s, generating notification alert", (event, eid, notifier.alerts))
                    firstSeen = first_seen(ip, mac)
                    lastSeen = first_seen_recently(ip, mac)
                    previouslySeen = previously_seen(ip, mac)
                    title = """Netgrasp alert: %s""" % (event)
                    body = """%s with IP %s [%s], seen %s, previously seen %s, first seen %s""" % (pretty.name_ip(ip, mac), ip, mac, pretty.pretty_date(lastSeen), pretty.pretty_date(previouslySeen), pretty.pretty_date(firstSeen))
                    ntfy.notify(body, title)
                else:
                    debugger.debug("event %s [%d] NOT in %s", (event, eid, notifier.alerts))

                if (timer.elapsed() > MAXSECONDS):
                    debugger.debug("processing notifications >%d seconds, aborting", (MAXSECONDS,))
                    with exclusive_lock.ExclusiveFileLock(db.lock, 5, "send_notifications, aborting"):
                        db.cursor.execute("UPDATE event SET processed=processed+? WHERE eid<=? AND NOT (processed & ?)", (PROCESSED_NOTIFICATION, max_eid, PROCESSED_NOTIFICATION))
                        db.connection.commit()
                    return

            with exclusive_lock.ExclusiveFileLock(db.lock, 5, "send_notifications"):
                db.cursor.execute("UPDATE event SET processed=processed+? WHERE eid<=? AND NOT (processed & ?)", (PROCESSED_NOTIFICATION, max_eid, PROCESSED_NOTIFICATION))
                db.connection.commit()
    except Exception as e:
        debugger.dump_exception("send_notifications() FIXME")

def send_email_alerts():
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

        db.cursor.execute("SELECT eid, mac, ip, timestamp, event, processed FROM event WHERE NOT (processed & 1) AND event IN ("+ ",".join("?"*len(emailer.alerts)) + ")", emailer.alerts)
        rows = db.cursor.fetchall()
        if rows:
            max_eid = 0
            processed_events = 0
            for row in rows:
                eid, mac, ip, timestamp, event, processed = row
                debugger.debug("processing event %d for %s [%s] at %s", (eid, ip, mac, timestamp))

                if eid > max_eid:
                    max_eid = eid
                processed_events += 1

                # only send emails for configured events
                if event in emailer.alerts:
                    debugger.info("event %s [%d] in %s, generating notification email", (event, eid, emailer.alerts))
                    # get more information about this entry ...
                    db.cursor.execute("SELECT s.active, s.self, v.vendor, v.customname, h.hostname, h.customname FROM seen s LEFT JOIN vendor v ON s.mac = v.mac LEFT JOIN host h ON s.mac = h.mac AND s.ip = h.ip WHERE s.mac=? AND s.ip=? ORDER BY lastSeen DESC", (mac, ip))
                    info = db.cursor.fetchone()
                    if not info:
                        debugger.warning("Event for ip %s [%s] that we haven't seen", (ip, mac))
                        continue

                    active, self, vendor, vendor_customname, hostname, host_customname = info
                    firstSeen = first_seen(ip, mac)
                    firstRequested = first_requested(ip, mac)
                    lastSeen = last_seen(ip, mac)
                    previouslySeen = previously_seen(ip, mac)
                    lastRequested = last_requested(ip, mac)
                    subject = """Netgrasp alert: %s""" % (event)
                    body = """IP %s [%s]\n  Vendor: %s\nCustom name: %s\n  Hostname: %s\n  Custom host name: %s\n  First seen: %s\n  Most recently seen: %s\n  Previously seen: %s\n  First requested: %s\n  Most recently requested: %s\n  Currently active: %d\n  Self: %d\n""" % (ip, mac, vendor, vendor_customname, hostname, host_customname, pretty.pretty_date(firstSeen), pretty.pretty_date(lastSeen), pretty.pretty_date(previouslySeen), pretty.pretty_date(firstRequested), pretty.pretty_date(lastRequested), active, self)
                    db.cursor.execute("SELECT DISTINCT dst_ip, dst_mac FROM arplog WHERE src_mac=? AND timestamp>=?", (mac, day))
                    results = db.cursor.fetchall()
                    if results:
                        body += """\nIn the last day, this device talked to:"""
                    for peer in results:
                        body += """\n - %s (%s)""" % (peer[0], pretty.name_ip(peer[0], peer[1]))
                    emailer.MailSend(subject, "iso-8859-1", (body, "us-ascii"))
                else:
                    debugger.debug("event %s [%d] NOT in %s", (event, eid, emailer.alerts))

            with exclusive_lock.ExclusiveFileLock(db.lock, 5, "send_email_alerts"):
                db.cursor.execute("UPDATE event SET processed=processed+? WHERE eid<=? AND NOT (processed & ?)", (PROCESSED_ALERT, max_eid, PROCESSED_ALERT))
                db.connection.commit()
            debugger.debug("send_email_alerts: processed %d events", (processed_events,))
    except Exception as e:
        debugger.dump_exception("send_email_alerts() FIXME")

# Finds new MAC addresses and assigns them a name.
def identify_macs():
    try:
        from utils import exclusive_lock

        debugger = debug.debugger_instance
        db = database.database_instance

        debugger.debug("entering identify_macs()")

        import re
        import httplib

        db.cursor.execute("SELECT s.mac, s.ip FROM seen s LEFT JOIN vendor v ON s.mac = v.mac WHERE s.active = 1 AND v.mac IS NULL")
        rows = db.cursor.fetchall()
        for row in rows:
            raw_mac, ip = row
            if re.match("[0-9a-f]{2}([-:])[0-9a-f]{2}(\\1[0-9a-f]{2}){4}$", raw_mac.lower()):
                mac = raw_mac
            else:
                mac = []
                pieces = raw_mac.split(":")
                if not pieces:
                    pieces = row_mac.split("-")
                for piece in pieces:
                    if len(piece) == 1:
                        piece = "0"+piece
                    mac.append(piece)
                mac = ":".join(mac)
            debugger.debug("Looking up vendor for %s [%s]", (ip, raw_mac))
            http = httplib.HTTPConnection("api.macvendors.com", 80)
            url = """/%s""" % mac
            http.request("GET", url)
            response = http.getresponse()
            with exclusive_lock.ExclusiveFileLock(db.lock, 5, "identify_macs, vendor"):
                if response.status == 200 and response.reason == "OK":
                    vendor = response.read()
                    debugger.info("Identified %s [%s] as %s", (ip, raw_mac, vendor))
                    db.cursor.execute("INSERT INTO vendor (mac, vendor) VALUES (?, ?)", (raw_mac, vendor))
                else:
                    debugger.info("Failed identify vendor for [%s]", (raw_mac,))
                    db.cursor.execute("INSERT INTO vendor (mac, vendor) VALUES (?, 'unknown')", (raw_mac,))
                db.connection.commit()

        db.cursor.execute("SELECT s.mac, s.ip FROM seen s LEFT JOIN host h ON s.mac = h.mac AND s.ip = h.ip WHERE s.active = 1 AND h.mac IS NULL")
        rows = db.cursor.fetchall()
        for row in rows:
            mac, ip = row
            hostname = dns_lookup(ip)
            with exclusive_lock.ExclusiveFileLock(db.lock, 5, "identify_macs, hostname"):
                db.cursor.execute("INSERT INTO host (mac, ip, hostname) VALUES (?, ?, ?)", (mac, ip, hostname))
                db.connection.commit()
    except Exception as e:
        debugger.dump_exception("identify_macs() FIXME")

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
        debugger.dump_exception("dns_lookup() FIXME")

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
                db.cursor.execute("SELECT DISTINCT mac, ip FROM event WHERE NOT (processed & 2) AND timestamp>=? AND timestamp<=? AND event = 'requested'", (time_period, now))
                requested = db.cursor.fetchall()
                db.cursor.execute("SELECT DISTINCT mac, ip FROM event WHERE NOT (processed & 2) AND timestamp>=? AND timestamp<=? AND event = 'seen'", (time_period, now))
                seen = db.cursor.fetchall()
            elif (digest == "weekly"):
                # PROCESSED_WEEKLY_DIGEST = 4
                db.cursor.execute("SELECT DISTINCT mac, ip FROM event WHERE NOT (processed & 4) AND timestamp>=? AND timestamp<=? AND event = 'requested'", (time_period, now))
                requested = db.cursor.fetchall()
                db.cursor.execute("SELECT DISTINCT mac, ip FROM event WHERE NOT (processed & 4) AND timestamp>=? AND timestamp<=? AND event = 'seen'", (time_period, now))
                seen = db.cursor.fetchall()

            db.cursor.execute("SELECT DISTINCT mac, ip FROM event WHERE timestamp>=? AND timestamp<=? AND event = 'seen'", (previous_time_period, time_period))
            seen_previous = db.cursor.fetchall()

            new = set(seen) - set(seen_previous)
            gone = set(seen_previous) - set(seen)

            subject = """Netgrasp %s digest""" % (digest)
            body = """In the past %s, %d IPs were active:""" % (time_period_description, len(seen))
            noisy = []
            some_new = False
            for ip in seen:
                db.cursor.execute("SELECT COUNT(DISTINCT(dst_ip)) FROM arplog WHERE request=1 AND src_ip=? AND timestamp>=? AND timestamp <=?", (ip[1], time_period, now))
                requests = db.cursor.fetchone()
                if (requests[0] > 10):
                    noisy.append((ip[0], ip[1], requests[0], pretty.name_ip(ip[0], ip[1])))
                if ip in new:
                    body += """\n - %s* (%s)""" % (ip[1], pretty.name_ip(ip[0], ip[1]))
                    some_new = True
                else:
                    body += """\n - %s (%s)""" % (ip[1], pretty.name_ip(ip[0], ip[1]))
            if some_new:
                body+= """\n* = not active in the previous %s""" % (time_period_description)

            body += """\n\n%d unique IPs requested.""" % (len(requested),)

            if noisy:
                body += """\n\nThe following devices requested 10 or more IPs on the network:"""
                for noise in noisy:
                    body += """\n - %s (%s) requested %d IP addresses""" % (noise[1], noise[3], noise[2])
                    if (noise[2] > 50):
                        body += " (network scan?)"

            if gone:
                body += """\n\nThe following IPs were not active, but were active the previous %s:""" % (time_period_description)
                for ip in gone:
                    body += """\n - %s (%s)""" % (ip[1], pretty.name_ip(ip[0], ip[1]))

            if (digest == "daily"):
                body += "\n\nActive devices per hour during the past day:"
                range = 24
                while (range > 0):
                    lower = now - datetime.timedelta(hours=range)
                    range = range - 1
                    upper = now - datetime.timedelta(hours=range)
                    db.cursor.execute("SELECT DISTINCT mac, ip FROM event WHERE event = 'seen' AND timestamp>=? AND timestamp<?", (lower, upper))
                    distinct = db.cursor.fetchall()
                    body += """\n - %s: %d""" % (lower.strftime("%I %p, %x"), len(distinct))
            elif (digest == "weekly"):
                body += "\n\nActive devices per day during the past week:"
                range = 7
                while (range > 0):
                    lower = now - datetime.timedelta(days=range)
                    range = range - 1
                    upper = now - datetime.timedelta(days=range)
                    db.cursor.execute("SELECT DISTINCT mac, ip FROM event WHERE event = 'seen' AND timestamp>=? AND timestamp<?", (lower, upper))
                    distinct = db.cursor.fetchall()
                    body += """\n - %s: %d""" % (lower.strftime("%A, %x"), len(distinct))

            if (digest == "daily"):
                db.cursor.execute("SELECT MAX(eid) FROM event WHERE timestamp<=? AND NOT (processed & 2)", (now,))
                processed_type = PROCESSED_DAILY_DIGEST
            elif (digest == "weekly"):
                db.cursor.execute("SELECT MAX(eid) FROM event WHERE timestamp<=? AND NOT (processed & 4)", (now,))
                processed_type = PROCESSED_WEEKLY_DIGEST
            max_eid = db.cursor.fetchone()
            if max_eid and max_eid[0]:
                with exclusive_lock.ExclusiveFileLock(db.lock, 5, "send_email_digests"):
                    db.cursor.execute("UPDATE event SET processed=processed+? WHERE eid<=? AND NOT (processed & ?)", (processed_type, max_eid[0], processed_type))

                    db.connection.commit()

            debugger.info("Sending %s digest", (digest,))
            emailer.MailSend(subject, "iso-8859-1", (body, "us-ascii"))
    except Exception as e:
        debugger.dump_exception("send_email_digests() FIXME")

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
        debugger.dump_exception("garbage_collection() FIXME")


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
        debugger.dump_exception("_init() FIXME")

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
