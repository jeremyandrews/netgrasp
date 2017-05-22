from utils import debug
from utils import exclusive_lock
from utils import email
from config import config
from notify import notify
from database import database

import logging
import logging.handlers
import pwd
import sys
import os
import datetime

#import fcntl
#import signal
#import ConfigParser
#import io
#import struct
#from email.utils import parseaddr

import time

netgrasp_instance = None

BROADCAST = 'ff:ff:ff:ff:ff:ff'

ALERT_TYPES = ['first_requested', 'requested', 'first_seen', 'first_seen_recently', 'seen', 'changed_ip', 'duplicate_ip', 'duplicate_mac', 'stale', 'network_scan']
DIGEST_TYPES = ['daily', 'weekly']

EVENT_SEEN              = 'seen'
EVENT_SEEN_FIRST        = 'first_seen'
EVENT_SEEN_FIRST_RECENT = 'first_seen_recently'
EVENT_CHANGED_IP        = 'changed_ip'
EVENT_REQUESTED         = 'requested'
EVENT_REQUESTED_FIRST   = 'first_requested'
EVENT_STALE             = 'stale'
EVENT_SCAN              = 'network_scan'
EVENT_DUPLICATE_IP      = 'duplicate_ip'
EVENT_DUPLICATE_MAC     = 'duplicate_mac'

PROCESSED_ALERT         = 1
PROCESSED_DAILY_DIGEST  = 2
PROCESSED_WEEKLY_DIGEST = 4
PROCESSED_NOTIFICATION  = 8

DEFAULT_CONFIG    = ['/etc/netgraspd.cfg', '/usr/local/etc/netgraspd.cfg', '~/.netgraspd.cfg', './netgraspd.cnf']
DEFAULT_USER      = "daemon"
DEFAULT_GROUP     = "daemon"
DEFAULT_LOGLEVEL  = logging.INFO
DEFAULT_LOGFILE   = "netgraspd.log"
DEFAULT_LOGFORMAT = "%(asctime)s [%(levelname)s/%(processName)s] %(message)s"
DEFAULT_PIDFILE   = "netgraspd.pid"
DEFAULT_DBLOCK    = "/tmp/.database_lock"

class Netgrasp:
    def __init__(self, config, verbose = False, daemonize = True):
        self.verbose = verbose
        self.daemonize = daemonize

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

class Timer:
    def __init__(self):
        self.start = time.time()

    def elapsed(self):
        return time.time() - self.start

# Simple, short text string used for heartbeat.
HEARTBEAT = 'nghb'
# Maximum rows to process before giving up lock
MAXPROCESS = 100
# Macimum seconds to process before returning to main loop
MAXSECONDS = 5

# This is our main program loop.
def main(ng, *pcap):
    import multiprocessing
    ng.debugger.info("main process running as user %s", (ng.debugger.whoami(),))

    if pcap:
        # We have daemonized and are not running as root.
        pc = pcap[0]
        ng._database_lock = ExclusiveFileLock(ng.config.GetText('Database', 'lockfile', DEFAULT_DBLOCK, False))
    else:
        # We are running in the foreground as root.
        pcap = get_pcap()
        pc = pcap[0]
        ng.drop_root(ng)
        ng._database_lock = multiprocessing.Lock()

    # At this point we should no longer have/need root privileges.
    assert (os.getuid() != 0) and (os.getgid() != 0), 'Failed to drop root privileges, aborting.'

    parent_conn, child_conn = multiprocessing.Pipe()
    child = multiprocessing.Process(name="wiretap", target=wiretap, args=[pc, child_conn, ng._database_lock])
    child.daemon = True
    child.start()

    try:
        ng.db = database.Database(ng.database_filename, ng.debugger)
        database.database_instance = ng.db
    except Exception as e:
        ng.debugger.critical("%s", (e,))
        ng.debugger.critical("failed to open or create %s (as user %s), exiting", (ng.database_filename, ng.whoami()))
    ng.db.lock = ng._database_lock
    ng.debugger.info("opened %s as user %s", (ng.database_filename, ng.debugger.whoami()));
    ng.db.cursor = ng.db.connection.cursor()
    # http://www.sqlite.org/wal.html
    ng.db.cursor.execute("PRAGMA journal_mode=WAL")

    create_database(ng.db, ng.debugger)
    update_database(ng.db, ng.debugger)

    ng.active_timeout = ng.config.GetInt("Listen", "active_timeout", 60 * 60 * 2, False)
    ng.delay = ng.config.GetInt("Listen", "delay", 15, False)
    if (ng.delay > 30):
        ng.delay = 30
    elif (ng.delay < 1):
        ng.delay = 1

    ng.email = email.Email(ng.config, ng.debugger)

    run = True
    last_heartbeat = datetime.datetime.now()
    while run:
        now = datetime.datetime.now()
        ng.debugger.debug("top of master while loop: %s", (now,))

        parent_conn.send(HEARTBEAT)
        heartbeat = False
        while parent_conn.poll():
            message = parent_conn.recv()
            if (message == HEARTBEAT):
                heartbeat = True
        # It's possible to receive multiple heartbeats, but many or one is the same to us.
        if heartbeat:
            ng.debugger.debug("received heartbeat from wiretap process")
            last_heartbeat = now

        try:
            ng.debugger.debug("sleeping for %d seconds", (ng.delay,))
            time.sleep(ng.delay)
            identify_macs(ng.debugger, ng.db)
            detect_stale_ips(ng.debugger, ng.db, ng.active_timeout)
            detect_netscans(ng.debugger, ng.db)
            detect_anomalies(ng.debugger, ng.db, ng.active_timeout)
            send_notifications(ng.debugger, ng.db, ng.notify)
            send_email_alerts(ng.debugger, ng.db, ng.email)
            send_email_digests(ng.debugger, ng.db, ng.email)
            garbage_collection(ng.debugger, ng.db, ng.config)
        except Exception as e:
            ng.debugger.error("FIXME: %s", (e,))

        # If we haven't heard from the wiretap process in >1 minute, exit.
        time_to_exit = last_heartbeat + datetime.timedelta(minutes=1)
        if (now >= time_to_exit):
            run = False
    ng.debugger.critical("No heartbeats from wiretap process for >1 minute, exiting.")

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
def wiretap(pc, child_conn, database_lock):
    import sys

    debugger = debug.debugger_instance

    if netgrasp_instance.daemonize:
        # We use a lock file when daemonized, as this allows netgraspctl to coordinate
        # with the daemon. Over-write the master-process handler with our own.
        database_lock = ExclusiveFileLock(config.config_instance.GetText("Database", "lockfile", DEFAULT_DBLOCK, False))

    try:
        import dpkt
    except Exception as e:
        debugger.error("fatal exception: %s", (e,))
        debugger.critical("failed to import dpkt, try: 'pip install dpkt', exiting")
    try:

        import pcap
    except Exception as e:
        debugger.error("fatal exception: %s", (e,))
        debugger.critical("failed to import pcap, try: 'pip install pypcap', exiting")

    assert (os.getuid() != 0) and (os.getgid() != 0), "Failed to drop root privileges, aborting."

    database_filename = config.config_instance.GetText("Database", "filename")

    try:
        db = database.Database(database_filename, debugger)
    except Exception as e:
        debugger.error("%s", (e,))
        debugger.critical("failed to open or create %s (as user %s), exiting", (database_filename, logger.whoami()))
    debugger.info("opened %s as user %s", (database_filename, debugger.whoami()));
    db.cursor = db.connection.cursor()

    run = True
    last_heartbeat = datetime.datetime.now()
    while run:
        now = datetime.datetime.now()
        debugger.debug("[%d] top of while loop: %s", (run, now))

        child_conn.send(HEARTBEAT)

        heartbeat = False
        while child_conn.poll():
            message = child_conn.recv()
            if (message == HEARTBEAT):
                heartbeat = True
        # It's possible to receive multiple heartbeats, but many or one is the same to us.
        if heartbeat:
            debugger.debug("received heartbeat from main process")
            last_heartbeat = now

        # Wait an arp packet, then loop again.
        pc.loop(1, received_arp, child_conn)

        # If we haven't heard from the main process in >1 minute, exit.
        time_to_exit = last_heartbeat + datetime.timedelta(minutes=1)
        if (now >= time_to_exit):
            run = False
    debugger.critical("No heartbeats from main process for >1 minute, exiting.")

def ip_seen(src_ip, src_mac, dst_ip, dst_mac, request):
    debugger.debug('entering ip_seen(%s, %s, %s, %s, %d)', src_ip, src_mac, dst_ip, dst_mac, request)
    now = datetime.datetime.now()

    ng.db.database_lock.acquire()
    ng.db.cursor.execute('INSERT INTO arplog (src_mac, src_ip, dst_mac, dst_ip, request, timestamp) VALUES(?, ?, ?, ?, ?, ?)', (src_mac, src_ip, dst_mac, dst_ip, request, now))
    ng.db.connection.commit()
    ng.db.database_lock.release()
    debugger.debug('inserted into arplog')

    # @TODO Research and see if we should be treating these another way.
    if (src_ip == '0.0.0.0' or src_mac == ng.BROADCAST):
        debugger.info('Ignoring IP source of %s [%s], dst %s [%s]', src_ip, src_mac, dst_ip, dst_mac);
        return False

    # Check if we've seen this IP, MAC pair before.
    active, lastSeen, lastRequested, counter, sid, did, changed_ip = [False, False, False, 0, 0, 0, False]
    debugger.debug('ip_seen query 1')
    ng.db.cursor.execute('SELECT active, lastSeen, lastRequested, counter, sid, did FROM seen WHERE ip=? AND mac=? ORDER BY lastSeen DESC LIMIT 1', (src_ip, src_mac))
    result = ng.db.cursor.fetchone()
    if result:
        active, lastSeen, lastRequested, counter, sid, did = result

    if not result:
        # Check if we've seen this MAC, hostname pair before, it may have gotten assigned a new IP.
        # In the event of the same IP and a different hostname, we treat this like a different device
        # (though it's likely a vm, jail, or alias). @TODO Revisit this.
        hostname = dns_lookup(src_ip)
        debugger.debug('ip_seen query 2')
        ng.db.cursor.execute("SELECT seen.active, seen.lastSeen, seen.lastRequested, seen.counter, seen.sid, seen.did FROM seen LEFT JOIN host ON seen.mac = host.mac WHERE seen.mac = ? AND host.hostname = ? ORDER BY seen.lastSeen DESC LIMIT 1", (src_mac, hostname))
        result = ng.db.cursor.fetchone()
        if result:
            active, lastSeen, lastRequested, counter, sid, did = result
            changed_ip = True

    if not result:
        # Check if we've seen this IP be requested before.
        debugger.debug('ip_seen query 3')
        ng.db.cursor.execute('SELECT active, lastSeen, lastRequested, counter, sid, did FROM seen WHERE ip=? AND mac=? ORDER BY lastSeen DESC LIMIT 1', (src_ip, ng.BROADCAST))
        result = ng.db.cursor.fetchone()
        if result:
            active, lastSeen, lastRequested, counter, sid, did = result

    ng.db.database_lock.acquire()
    log_event(src_ip, src_mac, ng.EVENT_SEEN)
    if changed_ip:
        log_event(src_ip, src_mac, ng.EVENT_CHANGED_IP)
        debugger.info('[%d] (%s) has a new ip [%s]', did, src_mac, src_ip)
    if active:
        if lastSeen:
            # has been active recently
            debugger.debug('%s (%s) is active', src_ip, src_mac)
            ng.db.cursor.execute('UPDATE seen set ip=?, mac=?, lastSeen=?, counter=?, active=1 WHERE sid=?', (src_ip, src_mac, now, counter + 1, sid))
        else:
            # has not been active recently, but was requested recently
            if first_seen(src_ip, src_mac):
                # First time we've seen IP since it was stale.
                log_event(src_ip, src_mac, ng.EVENT_SEEN_FIRST_RECENT)
                lastSeen = last_seen(src_ip, src_mac)
                if lastSeen:
                    timeSince = datetime.datetime.now() - lastSeen
                    debugger.info('[%d] %s (%s) is active again (after %s)', did, src_ip, src_mac, timeSince)
                else:
                    logger.warning("We've seen a packet %s [%s] with a firstSeen (%s) but no lastSeen -- this shouldn't happen.", (src_ip, src_mac, first_seen(src_ip, src_mac)))
            else:
                # First time we've actively seen this IP.
                log_event(src_ip, src_mac, ng.EVENT_SEEN_FIRST)
                log_event(src_ip, src_mac, ng.EVENT_SEEN_FIRST_RECENT)
                debugger.info('[%d] %s (%s) is active, first time seeing', did, src_ip, src_mac)

            # @TODO properly handle multiple active occurences of the same IP
            ng.db.cursor.execute('UPDATE seen set ip=?, mac=?, firstSeen=?, lastSeen=?, counter=?, active=1 WHERE sid=?', (src_ip, src_mac, now, now, counter + 1, sid))
    else:
        if did:
            # First time we've seen this IP recently.
            log_event(src_ip, src_mac, ng.EVENT_SEEN_FIRST_RECENT)
            debugger.info('[%d] %s (%s) is active, first time seeing recently', did, src_ip, src_mac)
        else:
            # First time we've seen this IP.
            ng.db.cursor.execute("SELECT MAX(did) + 1 FROM seen")
            row = fetchone()
            if row:
                did = row
            else:
                did = 1
            log_event(src_ip, src_mac, ng.EVENT_SEEN_FIRST)
            log_event(src_ip, src_mac, ng.EVENT_SEEN_FIRST_RECENT)
            debugger.info('[%d] %s (%s) is active, first time seeing', did, src_ip, src_mac)
        # BUG HERE - one of these variables isn't available?
        ng.db.cursor.execute('INSERT INTO seen (did, mac, ip, firstSeen, lastSeen, counter, active, self) VALUES(?, ?, ?, ?, ?, 1, 1, ?)', (did, src_mac, src_ip, now, now, ip_is_mine(src_ip)))
    ng.db.connection.commit()
    ng.db.database_lock.release()

def ip_request(ip, mac, src_ip, src_mac):
    debugger.debug('entering ip_request(%s, %s, %s, %s)', ip, mac, src_ip, src_mac)
    now = datetime.datetime.now()

    if ((ip == src_ip) or (mac == src_mac)):
        debugger.debug('requesting self, ignoring')
        return

    active = False
    lastRequested = False
    ng.db.cursor.execute('SELECT active, lastRequested, sid FROM seen WHERE ip=? AND mac=? AND active=1', (ip, mac))
    requested = ng.db.cursor.fetchone()
    if requested:
        active = requested[0]
        lastRequested = requested[1]
        sid = requested[2]
    else:
        if (mac == ng.BROADCAST):
            # Maybe we already have seen a request for this address
            ng.db.cursor.execute('SELECT active, lastRequested, sid FROM seen WHERE ip=? AND mac=? AND active=1', (ip, ng.BROADCAST))
            requested = ng.db.cursor.fetchone()
            if requested:
                active = requested[0]
                lastRequested = requested[1]
                sid = requested[2]
            else:
                # Maybe the IP has been seen already
                ng.db.cursor.execute('SELECT active, lastRequested, sid FROM seen WHERE ip=? AND active=1', (ip,))
                requested = ng.db.cursor.fetchone()
                if requested:
                    active = requested[0]
                    lastRequested = requested[1]
                    sid = requested[2]

    ng.database_lock.acquire()
    log_event(ip, mac, ng.EVENT_REQUESTED)
    if active:
        # Update:
        ng.db.cursor.execute('UPDATE seen set lastRequested=? WHERE sid=?', (now, sid))
        debugger.debug('%s (%s) requested', ip, mac)
    else:
        # First time we've seen a request for this IP.
        log_event(ip, mac, ng.EVENT_REQUESTED_FIRST)
        ng.db.cursor.execute("INSERT INTO seen (mac, ip, firstRequested, lastRequested, counter, active, self) VALUES(?, ?, ?, ?, 1, 1, ?)", (mac, ip, now, now, ip_is_mine(ip)))
        debugger.info('%s (%s) requested, first time seeing', ip, mac)
    ng.db.connection.commit()
    ng.database_lock.release()

# Assumes we already have the database lock.
def log_event(ip, mac, event):
    now = datetime.datetime.now()
    ng.db.connection.execute('INSERT INTO event (mac, ip, timestamp, processed, event) VALUES(?, ?, ?, ?, ?)', (mac, ip, now, 0, event))

def ip_is_mine(ip):
    import socket
    return (ip == socket.gethostbyname(socket.gethostname()))

# Database definitions.
def create_database(db, debugger):
    db.lock.acquire()
    debugger.debug('Creating database tables, if not already existing.')

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
    db.connection.commit()
    db.lock.release()

def update_database(db, debugger):
    # Update #1: add did column to seen table, populate
    try:
        db.cursor.execute("SELECT did FROM seen LIMIT 1")
    except Exception as e:
        debugger.debug("%s", (e,))
        debugger.debug("applying update #1 to database: adding did column to seen, populating")
        db.lock.acquire()
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
        db.release()

# We've sniffed an arp packet off the wire.
def received_arp(hdr, data, child_conn):
    import socket

    debugger = debug.debugger_instance

    try:
        packet = dpkt.ethernet.Ethernet(data)
        src_ip = socket.inet_ntoa(packet.data.spa)
        src_mac = "%x:%x:%x:%x:%x:%x" % struct.unpack("BBBBBB", packet.src)
        dst_ip = socket.inet_ntoa(packet.data.tpa)
        dst_mac = "%x:%x:%x:%x:%x:%x" % struct.unpack("BBBBBB", packet.dst)
        if (packet.data.op == dpkt.arp.ARP_OP_REQUEST):
            debugger.debug('ARP request from %s (%s) to %s (%s)', src_ip, src_mac, dst_ip, dst_mac)
            ip_seen(src_ip, src_mac, dst_ip, dst_mac, True)
            ip_request(dst_ip, dst_mac, src_ip, src_mac)
        elif (packet.data.op == dpkt.arp.ARP_OP_REPLY):
            ip_seen(src_ip, src_mac, dst_ip, dst_mac, False)
            debugger.debug('ARP reply from %s (%s) to %s (%s)', src_ip, src_mac, dst_ip, dst_mac)
    except Exception as e:
        debugger.Error("FIXME: %s", (e,))

def pretty_date(time):
    if not time:
        return "never"
    now = datetime.datetime.now()
    diff = now - time
    second_diff = diff.seconds
    day_diff = diff.days

    if day_diff < 0:
        return ''

    if day_diff == 0:
        if second_diff < 10:
            return "just now"
        if second_diff < 60:
            return str(second_diff) + " seconds ago"
        if second_diff < 120:
            return "a minute ago"
        if second_diff < 3600:
            return str(second_diff / 60) + " minutes ago"
        if second_diff < 7200:
            return "an hour ago"
        if second_diff < 86400:
            return str(second_diff / 3600) + " hours ago"
    if day_diff == 1:
        return "yesterday"
    if day_diff < 7:
        return str(day_diff) + " days ago"
    if day_diff < 31:
        return str(day_diff / 7) + " weeks ago"
    if day_diff < 365:
        return str(day_diff / 30) + " months ago"
    return str(day_diff / 365) + " years ago"

# Determine appropriate device id for IP, MAC pair.
def get_did(ip, mac):
    ng.database.cursor.execute('SELECT did FROM seen WHERE ip=? AND mac=? ORDER BY did DESC LIMIT 1', (ip, mac))
    did = ng.database.cursor.fetchone()
    if not did:
        hostname = dns_lookup(ip)
        ng.database.cursor.execute("SELECT seen.did FROM seen LEFT JOIN host ON seen.mac = host.mac WHERE seen.mac = ? AND host.hostname = ? ORDER BY seen.did DESC LIMIT 1", (src_mac, hostname))
        did = ng.database.cursor.fetchone()
    if not did:
        ng.database.cursor.execute('SELECT did FROM seen WHERE ip=? AND mac=? ORDER BY did DESC LIMIT 1', (ip, ng.BROADCAST,))
        did = ng.database.cursor.fetchone()

    if did:
        return did[0]
    else:
        return False

def first_seen(ip, mac):
    did = get_did(ip, mac)
    ng.database.cursor.execute('SELECT firstSeen FROM seen WHERE did = ? AND firstSeen NOT NULL ORDER BY firstSeen ASC LIMIT 1', (did,))
    active = ng.database.cursor.fetchone()
    if active:
        return active[0]
    else:
        return False

def first_seen_recently(ip, mac):
    did = get_did(ip, mac)
    ng.database.cursor.execute('SELECT firstSeen FROM seen WHERE did = ? AND firstSeen NOT NULL ORDER BY firstSeen DESC LIMIT 1', (did,))
    recent = ng.database.cursor.fetchone()
    if recent:
        return recent[0]
    else:
        return False

def last_seen(ip, mac):
    did = get_did(ip, mac)
    ng.database.cursor.execute('SELECT lastSeen FROM seen WHERE did=? AND lastSeen NOT NULL ORDER BY lastSeen DESC LIMIT 1', (did,))
    active = ng.database.cursor.fetchone()
    if active:
        return active[0]
    else:
        return False

def previously_seen(ip, mac):
    did = get_did(ip, mac)
    ng.database.cursor.execute('SELECT lastSeen FROM seen WHERE did=? AND lastSeen NOT NULL AND active != 1 ORDER BY lastSeen DESC LIMIT 1', (did,))
    previous = ng.database.cursor.fetchone()
    if previous:
        return previous[0]
    else:
        return False

def first_requested(ip, mac):
    did = get_did(ip, mac)
    ng.database.cursor.execute('SELECT firstRequested FROM seen WHERE did=? AND firstRequested NOT NULL ORDER BY firstRequested ASC LIMIT 1', (did,))
    active = ng.database.cursor.fetchone()
    if active:
        return active[0]
    else:
        return False

def last_requested(ip, mac):
    did = get_did(ip, mac)
    ng.database.cursor.execute('SELECT lastRequested FROM seen WHERE did=? AND lastRequested NOT NULL ORDER BY lastRequested DESC LIMIT 1', (did,))
    last = ng.database.cursor.fetchone()
    if last:
        return last[0]
    else:
        return False

# Mark IP/MAC pairs as no longer active if we've not seen ARP activity for >active_timeout seconds
def detect_stale_ips(debugger, db, timeout):
    debugger.debug("entering detect_stale_ips()")
    stale = datetime.datetime.now() - datetime.timedelta(seconds=timeout)

    db.cursor.execute("SELECT sid, mac, ip, firstSeen, lastSeen FROM seen WHERE active = 1 AND lastSeen < ?", (stale,))
    rows = db.cursor.fetchall()
    if rows:
        db.lock.acquire()

    for row in rows:
        sid, mac, ip, firstSeen, lastSeen = row
        if (firstSeen and lastSeen):
            timeActive = lastSeen - firstSeen
        else:
            timeActive = "unknown"
        log_event(ip, mac, EVENT_STALE)
        debugger.info("%s [%s] is no longer active (was active for %s)", ip, mac, timeActive)
        db.cursor.execute("UPDATE seen SET active = 0 WHERE sid=?", (sid,))

    if rows:
        db.connection.commit()
        db.lock.release()

def detect_netscans(debugger, db):
    debugger.debug("entering detect_netscans()")
    now = datetime.datetime.now()

    three_minutes_ago = now - datetime.timedelta(minutes=3)
    db.cursor.execute("SELECT COUNT(DISTINCT(dst_ip)) AS count, src_mac, src_ip FROM arplog WHERE request=1 AND timestamp>=? GROUP BY src_ip HAVING count > 50", (three_minutes_ago,))
    scans = db.cursor.fetchall()
    if scans:
        db.lock.acquire()
    for scan in scans:
        count, src_mac, src_ip = scan
        db.cursor.execute("SELECT eid FROM event WHERE mac=? AND ip=? AND event=? AND timestamp>?", (src_mac, src_ip, EVENT_SCAN, three_minutes_ago))
        already_detected = db.cursor.fetchone()
        if not already_detected:
            db.cursor.execute("INSERT INTO event (mac, ip, timestamp, processed, event) VALUES(?, ?, ?, 0, ?)", (src_mac, src_ip, now, EVENT_SCAN))
            debugger.info("Detected network scan by %s [%s]", src_ip, src_mac)
    if scans:
        db.connection.commit()
        db.lock.release()

def detect_anomalies(debugger, db, timeout):
    debugger.debug("entering detect_anomalies()")
    now = datetime.datetime.now()
    stale = datetime.datetime.now() - datetime.timedelta(seconds=timeout)

    # Multiple MAC's with the same IP.
    db.cursor.execute("SELECT COUNT(*) as count, ip FROM seen WHERE active = 1 AND mac != ? GROUP BY ip HAVING count > 1", (BROADCAST,))
    duplicates = db.cursor.fetchall()
    if duplicates:
        db.lock.acquire()
    for duplicate in duplicates:
        count, ip = duplicate
        db.cursor.execute("SELECT ip, mac, sid, did FROM seen WHERE ip = ? AND active = 1;", (ip,))
        details = db.cursor.fetchall()
        for detail in details:
            ip, mac, sid, did = detail
            db.cursor.execute("SELECT eid FROM event WHERE mac=? AND ip=? AND event=? AND timestamp>?", (mac, ip, EVENT_DUPLICATE_IP, stale))
            already_detected = db.cursor.fetchone()
            if not already_detected:
                db.cursor.execute("INSERT INTO event (mac, ip, timestamp, processed, event) VALUES(?, ?, ?, 0, ?)", (mac, ip, now, EVENT_DUPLICATE_IP))
                debugger.info("Detected multiple MACs with same IP %s [%s]", ip, mac)
    if duplicates:
        db.connection.commit()
        db.lock.release()

    # Multiple IP's with the same MAC.
    db.cursor.execute("SELECT COUNT(*) as count, mac FROM seen WHERE active = 1 AND mac != ? GROUP BY mac HAVING count > 1", (BROADCAST,))
    duplicates = db.cursor.fetchall()
    if duplicates:
        db.lock.acquire()
    for duplicate in duplicates:
        count, mac = duplicate
        db.cursor.execute("SELECT ip, mac, sid, did FROM seen WHERE mac = ? AND active = 1;", (mac,))
        details = db.cursor.fetchall()
        for detail in details:
            ip, mac, sid, did = detail
            db.cursor.execute("SELECT eid FROM event WHERE mac=? AND ip=? AND event=? AND timestamp>?", (mac, ip, EVENT_DUPLICATE_MAC, stale))
            already_detected = db.cursor.fetchone()
            if not already_detected:
                db.cursor.execute("INSERT INTO event (mac, ip, timestamp, processed, event) VALUES(?, ?, ?, 0, ?)", (mac, ip, now, EVENT_DUPLICATE_MAC))
                debugger.info("Detected multiple IPs with same MAC %s [%s]", ip, mac)
    if duplicates:
        db.connection.commit()
        db.lock.release()

def send_notifications(debugger, db, notify):
    debugger.debug("entering send_notifications()")

    if not notify.enabled:
        debugger.debug("notifications disabled")
        return False

    if not notify.alerts:
        debugger.debug("no notification alerts configured")
        return False

    import ntfy
    timer = Timer()

    day = datetime.datetime.now() - datetime.timedelta(days=1)
    db.cursor.execute("SELECT eid, mac, ip, timestamp, event, processed FROM event WHERE NOT (processed & 8) AND event IN ("+ ",".join("?"*len(notify.alerts)) + ")", notify.alerts)

    rows = db.cursor.fetchall()
    if rows:
        db.lock.acquire()

    counter = 0
    for row in rows:
        eid, mac, ip, timestamp, event, processed = row
        # Give up the lock occasionally while processing a large number of rows, allowing the
        # wiretap process to work if needed, avoiding potential timeout.
        counter = counter + 1
        if (counter > MAXPROCESS):
            debugger.debug("updated 100 events, releasing/regrabbing lock")
            db.connection.commit()
            db.lock.release()
            if (timer.elapsed() > MAXSECONDS):
                # We've been processing notifications too long, quit for now and come back later.
                debugger.debug("processing notifications >%d seconds, quitting for now", MAXSECONDS)
                return
            counter = 0
            db.lock.acquire()

        debugger.debug("processing event %d for %s [%s] at %s", eid, ip, mac, timestamp)

        # only send notifications for configured events
        if event in notify.alerts:
            debugger.info("event %s [%d] in %s, generating notification alert", event, eid, notify.alerts)
            firstSeen = first_seen(ip, mac)
            lastSeen = first_seen_recently(ip, mac)
            previouslySeen = previously_seen(ip, mac)
            title = """Netgrasp alert: %s""" % (event)
            body = """%s with IP %s [%s], seen %s, previously seen %s, first seen %s""" % (name_ip(mac, ip), ip, mac, pretty_date(lastSeen), pretty_date(previouslySeen), pretty_date(firstSeen))
            ntfy.notify(body, title)
            notify.cursor.execute("UPDATE event SET processed = ? WHERE eid = ?", (processed + 8, eid))
        else:
            debugger.debug("event %s [%d] NOT in %s", event, eid, notify.alerts)
    if rows:
        db.connection.commit()
        db.lock.release()

def send_email_alerts(debugger, db, email):
    debugger.debug("entering send_email_alerts()")

    if not email.enabled:
        debugger.debug("email disabled")
        return False

    if not email.alerts:
        debugger.debug("no email alerts configured")
        return False

    day = datetime.datetime.now() - datetime.timedelta(days=1)

    timer = Timer()

    db.cursor.execute("SELECT eid, mac, ip, timestamp, event, processed FROM event WHERE NOT (processed & 1)");
    rows = db.cursor.fetchall()
    if rows:
        db.lock.acquire()

    counter = 0
    for row in rows:
        eid, mac, ip, timestamp, event, processed = row
        # Give up the lock occasionally while processing a large number of rows, allowing the
        # wiretap process to work if needed, avoiding potential timeout.
        counter = counter + 1
        if (counter > MAXPROCESS):
            debugger.debug("updated 100 events, releasing/regrabbing lock")
            db.connection.commit()
            db.lock.release()
            if (timer.elapsed() > MAXSECONDS):
                # We've been processing alerts too long, quit for now and come back later.
                debugger.debug("processing email alerts >%d seconds, quitting for now", (MAXSECONDS,))
                return
            counter = 0
            db.lock.acquire()

        debugger.debug("processing event %d for %s [%s] at %s", (eid, ip, mac, timestamp))
        alerted = True
        # only send emails for configured events
        if event in email.alerts:
            debugger.info("event %s [%d] in %s, generating notification email", (event, eid, email.alerts))
            # get more information about this entry ...
            db.cursor.execute("SELECT s.active, s.self, v.vendor, v.customname, h.hostname, h.customname FROM seen s LEFT JOIN vendor v ON s.mac = v.mac LEFT JOIN host h ON s.mac = h.mac AND s.ip = h.ip WHERE s.mac=? AND s.ip=? ORDER BY lastSeen DESC", (mac, ip))
            info = db.cursor.fetchone()
            if not info:
                db.connection.commit()
                db.lock.release()
                logger.warning("Event for ip %s [%s] that we haven't seen", (ip, mac))
                return
            active, self, vendor, vendor_customname, hostname, host_customname = info
            firstSeen = first_seen(ip, mac)
            firstRequested = first_requested(ip, mac)
            lastSeen = last_seen(ip, mac)
            previouslySeen = previously_seen(ip, mac)
            lastRequested = last_requested(ip, mac)
            subject = """Netgrasp alert: %s""" % (event)
            body = """IP %s [%s]\n  Vendor: %s\nCustom name: %s\n  Hostname: %s\n  Custom host name: %s\n  First seen: %s\n  Most recently seen: %s\n  Previously seen: %s\n  First requested: %s\n  Most recently requested: %s\n  Currently active: %d\n  Self: %d\n""" % (ip, mac, vendor, vendor_customname, hostname, host_customname, pretty_date(firstSeen), pretty_date(lastSeen), pretty_date(previouslySeen), pretty_date(firstRequested), pretty_date(lastRequested), active, self)
            db.cursor.execute("SELECT DISTINCT dst_ip, dst_mac FROM arplog WHERE src_mac=? AND timestamp>=?", (mac, day))
            results = db.cursor.fetchall()
            if results:
                body += """\nIn the last day, this device talked to:"""
            for peer in results:
                body += """\n - %s (%s)""" % (peer[0], name_ip(peer[1], peer[0]))
            email.MailSend(subject, "iso-8859-1", (body, "us-ascii"))
        else:
            debugger.debug("event %s [%d] NOT in %s", (event, eid, email.alerts))
        if alerted:
            db.cursor.execute("UPDATE event SET processed = ? WHERE eid = ?", (processed + 1, eid))

    if rows:
        db.connection.commit()
        db.lock.release()

# Finds new MAC addresses and assigns them a name.
def identify_macs(debugger, db):
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
        debugger.debug("Looking up vendor for %s [%s]", ip, raw_mac)
        http = httplib.HTTPConnection("api.macvendors.com", 80)
        url = """/%s""" % mac
        http.request("GET", url)
        response = http.getresponse()
        ng.db.lock.acquire()
        if response.status == 200 and response.reason == "OK":
            vendor = response.read()
            debugger.info("Identified %s [%s] as %s", ip, raw_mac, vendor)
            db.cursor.execute("INSERT INTO vendor (mac, vendor) VALUES (?, ?)", (raw_mac, vendor))
        else:
            debugger.info("Failed identify vendor for [%s]", raw_mac)
            db.cursor.execute("INSERT INTO vendor (mac, vendor) VALUES (?, 'unknown')", (raw_mac,))
        db.connection.commit()
        db.lock.release()

    db.cursor.execute("SELECT s.mac, s.ip FROM seen s LEFT JOIN host h ON s.mac = h.mac AND s.ip = h.ip WHERE s.active = 1 AND h.mac IS NULL")
    rows = db.cursor.fetchall()
    for row in rows:
        mac, ip = row
        hostname = dns_lookup(ip)
        db.lock.acquire()
        db.cursor.execute("INSERT INTO host (mac, ip, hostname) VALUES (?, ?, ?)", (mac, ip, hostname))
        db.connection.commit()
        db.lock.release()

def dns_lookup(ip):
    import socket
    debugger.debug("entering gethostbyaddr(%s)", (ip,))
    try:
        hostname, aliaslist, ipaddrlist = socket.gethostbyaddr(ip)
        debugger.debug("hostname(%s), aliaslist(%s), ipaddrlist(%s)", (hostname, aliaslist, ipaddrlist))
    except Exception as e:
        debugger.debug("gethostbyaddr failed: %s", (e,))
        hostname = "unknown"
        debugger.debug("hostname(%s)", (hostname,))
    return hostname

# Provides a human-friendly name for a mac-ip pair.
def name_ip(mac, ip):
    debugger.debug('entering name_ip(%s, %s)', (mac, ip))
    if (mac == ng.BROADCAST):
        db.cursor.execute("SELECT h.mac, h.ip, h.customname, h.hostname, v.customname, v.vendor FROM host h LEFT JOIN vendor v ON h.mac = v.mac WHERE h.ip=?", (ip,))
    else:
        db.cursor.execute("SELECT h.mac, h.ip, h.customname, h.hostname, v.customname, v.vendor FROM host h LEFT JOIN vendor v ON h.mac = v.mac WHERE h.ip=? AND h.mac=?", (ip, mac))
    detail = db.cursor.fetchone()
    if not detail:
        return detail
    if detail[2]:
        return detail[2]
    elif detail[3] and (detail[3] != 'unknown'):
        return detail[3]
    elif detail[4]:
        return detail[4]
    elif detail[5]:
        return """%s device""" % (detail[5])
    else:
        return detail[0]

# Generates daily and weekly email digests.
def send_email_digests(debugger, db, email):
    debugger.debug("entering send_email_digests()")

    if not email.enabled:
        return False

    if not email.digest:
        debugger.debug("no digests configured")
        return False

    timer = Timer()
    now = datetime.datetime.now()

    digests = ["daily", "weekly"]
    for digest in digests:
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
                noisy.append((ip[0], ip[1], requests[0], name_ip(ip[0], ip[1])))
            if ip in new:
                body += """\n - %s* (%s)""" % (ip[1], name_ip(ip[0], ip[1]))
                some_new = True
            else:
                body += """\n - %s (%s)""" % (ip[1], name_ip(ip[0], ip[1]))
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
                body += """\n - %s (%s)""" % (ip[1], name_ip(ip[0], ip[1]))

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
            db.cursor.execute("SELECT eid, processed FROM event WHERE timestamp>=? AND timestamp<=? AND NOT (processed & 2)", (time_period, now))
            alerted = PROCESSED_DAILY_DIGEST
        elif (digest == "weekly"):
            db.cursor.execute("SELECT eid, processed FROM event WHERE timestamp>=? AND timestamp<=? AND NOT (processed & 4)", (time_period, now))
            alerted = PROCESSED_WEEKLY_DIGEST
        rows = db.cursor.fetchall()
        db.lock.acquire()
        counter = 0
        for row in rows:
            eid, processed = row
            # Give up the lock occasionally while processing a large number of rows, allowing the
            # wiretap process to work if needed, avoiding potential timeout.
            counter = counter + 1
            if (counter > MAXPROCESS):
                debugger.debug("updated 100 events, releasing/regrabbing lock")
                db.connection.commit()
                db.lock.release()
                if (timer.elapsed() > MAXSECONDS):
                    # We've been processing events for too long, quit for now and come back later.
                    debugger.debug("processing events >%d seconds, quitting for now", (MAXSECONDS,))
                    return
                counter = 0
                db.lock.acquire()
            db.cursor.execute("UPDATE event SET processed=? WHERE eid=?", (processed + alerted, eid))
        db.connection.commit()
        db.lock.release()

        debugger.info("Sending %s digest", (digest,))
        email.MailSend(subject, "iso-8859-1", (body, "us-ascii"))

def garbage_collection(debugger, db, config):
    debugger.debug("entering garbage_collection()")

    if not config.GetBoolean("Database", "gcenabled", True, False):
        debugger.debug("garbage collection disabled")

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

    oldest_arplog = now - datetime.timedelta(seconds=config.GetInt("Database", "oldest_arplog", 60 * 60 * 24 * 7 * 2, False))
    oldest_event = now - datetime.timedelta(seconds=config.GetInt("Database", "oldest_event", 60 * 60 * 24 * 7 * 2, False))

    db.lock.acquire()
    # Purge old arplog entries.
    db.cursor.execute("SELECT COUNT(*) FROM arplog WHERE timestamp < ?", (oldest_arplog,))
    arplog_count = db.cursor.fetchone()
    db.cursor.execute("DELETE FROM arplog WHERE timestamp < ?", (oldest_arplog,))
    # Purge old event entries.
    db.cursor.execute("SELECT COUNT(*) FROM event WHERE timestamp < ?", (oldest_event,))
    event_count = db.cursor.fetchone()
    db.cursor.execute("DELETE FROM event WHERE timestamp < ?", (oldest_event,))
    db.connection.commit()
    db.lock.release()
    debugger.debug("deleted %d arplog entries older than %s", (arplog_count[0], oldest_arplog))
    debugger.debug("deleted %d event entries older than %s", (event_count[0], oldest_event))


#################
#################
#################

def _init(verbose, daemonize):
    import logging

    # Get a logger and config parser.
    logger = logging.getLogger(__name__)
    formatter = logging.Formatter(DEFAULT_LOGFORMAT)

    if os.getuid() != 0:
        # We're going to fail, so write to stderr.
        debugger = debug.Debugger()
    else:
        debugger = debug.Debugger(verbose, logger, debug.FILE)
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
        debugger.handler = logging.StreamHandler()

    debugger.handler.setFormatter(formatter)
    logger.addHandler(debugger.handler)

    if verbose:
        debugger.setLevel(logging.DEBUG)
        debugger.warning("[Logging] level forced to DEBUG, started with -v flag.")
    else:
        logger.setLevel(configuration.GetText('Logging', 'level', DEFAULT_LOGLEVEL, False))
    debugger.info('loaded configuration file: %s', configuration.found)

    if not daemonize:
        debugger.warning("Output forced to stderr, started with --foreground flag.")

    return (debugger, configuration)
    

def start():
    ng = netgrasp_instance
    ng.debugger, ng.config = _init(ng.verbose, ng.daemonize)

    keep_fds=[ng.debugger.handler.stream.fileno()]

    if os.getuid() != 0:
        ng.debugger.critical("netgrasp must be run as root (currently running as %s), exiting", ng.debugger.whoami())

    try:
        import sqlite3
    except Exception as e:
        ng.debugger.error("fatal exception: %s", e)
        ng.debugger.critical("failed to import sqlite3 (as user %s), try 'pip install sqlite3', exiting", (ng.debugger.whoami()))
    ng.debugger.info("successfuly imported sqlite3")
    try:
        import dpkt
    except Exception as e:
        ng.debugger.error("fatal exception: %s", e)
        ng.debugger.critical("failed to import dpkt (as user %s), try 'pip install dpkt', exiting", (ng.debugger.whoami()))
    ng.debugger.info("successfuly imported dpkt")
    if ng.daemonize:
        try:
            import daemonize
        except Exception as e:
            ng.debugger.error("fatal exception: %s", e)
            ng.debugger.critical("failed to import daemonize (as user %s), try 'pip install daemonize', exiting", (ng.debugger.whoami()))
        ng.debugger.info("successfuly imported daemonize")

    ng.notify = notify.Notify(ng.debugger, ng.config)

    ng.database_filename = ng.config.GetText('Database', 'filename')

    if ng.daemonize:
        pidfile = ng.config.GetText('Logging', 'pidfile', DEFAULT_PIDFILE, False)
        username = ng.config.GetText('Security', 'user', DEFAULT_USER, False)
        groupname = ng.config.GetText('Security', 'group', DEFAULT_GROUP, False)
        try:
            daemon = daemonize.Daemonize(app="netgraspd", pid=pidfile, privileged_action=get_pcap, user=username, group=groupname, action=main, keep_fds=keep_fds, logger=debugger.logger, verbose=True)
            daemon.start()
        except Exception as e:
            ng.debugger.critical("Failed to daemonize: %s, exiting", (e,))
    else:
        main(ng)
