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
import os
import datetime
import time

netgrasp_instance = None

BROADCAST = 'ff:ff:ff:ff:ff:ff'

ALERT_TYPES = ['requested_ip', 'first_requested_ip', 'first_requested_ip_recently', 'seen_device', 'first_seen_device',
               'first_seen_device_recently', 'seen_mac', 'first_seen_mac', 'seen_ip', 'first_seen_ip', 'seen_host',
               'first_seen_host', 'seen_vendor', 'first_seen_vendor', 'device_stale', 'request_stale', 'changed_ip',
               'duplicate_ip', 'duplicate_mac', 'network_scan', 'ip_not_on_network', 'src_mac_broadcast',
               'requested_self']

EVENT_REQUEST_IP, EVENT_FIRST_REQUEST_IP, EVENT_FIRST_REQUEST_RECENTLY_IP, EVENT_SEEN_DEVICE, EVENT_FIRST_SEEN_DEVICE, EVENT_FIRST_SEEN_DEVICE_RECENTLY, EVENT_SEEN_MAC, EVENT_FIRST_SEEN_MAC, EVENT_SEEN_IP, EVENT_FIRST_SEEN_IP, EVENT_SEEN_HOST, EVENT_FIRST_SEEN_HOST, EVENT_SEEN_VENDOR, EVENT_FIRST_SEEN_VENDOR, EVENT_STALE, EVENT_REQUEST_STALE, EVENT_CHANGED_IP, EVENT_DUPLICATE_IP, EVENT_DUPLICATE_MAC, EVENT_SCAN, EVENT_IP_NOT_ON_NETWORK, EVENT_SRC_MAC_BROADCAST, EVENT_REQUESTED_SELF = ALERT_TYPES

DIGEST_TYPES = ['daily', 'weekly']

PROCESSED_ALERT         = 1
PROCESSED_DAILY_DIGEST  = 2
PROCESSED_WEEKLY_DIGEST = 4
PROCESSED_NOTIFICATION  = 8

DEFAULT_CONFIG    = ['/etc/netgrasp.cfg', '/usr/local/etc/netgrasp.cfg', '~/.netgrasp.cfg', './netgrasp.cfg']
DEFAULT_USER      = "daemon"
DEFAULT_GROUP     = "daemon"
DEFAULT_LOGLEVEL  = logging.INFO
DEFAULT_LOGFILE   = "/var/log/netgrasp.log"
DEFAULT_LOGFORMAT = "%(asctime)s [%(levelname)s/%(processName)s] %(message)s"
DEFAULT_PIDFILE   = "/var/run/netgrasp.pid"
DEFAULT_DBLOCK    = "/tmp/.netgrasp_database_lock"


class Netgrasp(object):
    def __init__(self, config_filename=None):
        self.config = config_filename or DEFAULT_CONFIG

        self.listen = {}
        self.security = {}
        self.database = {}
        self.logging = {}
        self.email = {}
        self.notification = {}

        self.pcap = {}

    def _load_debugger(self):
        # We've not yet loaded configuration, so log to stdout.
        self.logger = logging.getLogger(__name__)
        self.debugger = debug.Debugger(self.verbose, self.logger, debug.PRINT)
        self.debugger.handler = logging.StreamHandler()
        formatter = logging.Formatter(DEFAULT_LOGFORMAT)
        self.debugger.handler.setFormatter(formatter)
        self.logger.addHandler(self.debugger.handler)

    def _enable_debugger(self):
        if self.daemonize:
            try:
                self.debugger.handler = logging.FileHandler(self.logging["filename"])
            except Exception as e:
                self.debugger.error("fatal exception: %s", (e,))
                self.debugger.critical("failed to open log file %s for writing (as user %s), exiting", (self.logging["filename"], self.debugger.whoami()))
        else:
            self.debugger.handler = logging.StreamHandler()
        formatter = logging.Formatter(DEFAULT_LOGFORMAT)
        self.debugger.handler.setFormatter(formatter)
        self.logger.addHandler(self.debugger.handler)
        self.logger.setLevel(self.logging["level"])

    def _load_configuration(self):
        self.configuration = config.Config(self.debugger, filename=self.config)

        # Load listen parameters.
        self.listen["interface"] = self.configuration.GetText("Listen", "interface", None, False)
        self.listen["active_timeout"] = self.configuration.GetInt("Listen", "active_timeout", 60 * 60 * 2, False)
        delay = self.configuration.GetInt("Listen", "delay", 15, False)
        if delay > 30:
            delay = 30
        elif delay < 1:
            delay = 1
        self.listen["delay"] = delay

        # Load security parameters.
        self.security["user"] = self.configuration.GetText("Security", "user", DEFAULT_USER, False)
        self.security["group"] = self.configuration.GetText("Security", "group", DEFAULT_GROUP, False)

        # Load database parameters.
        self.database["filename"] = self.configuration.GetText("Database", "filename", None, False)
        self.database["lock"] = self.configuration.GetText("Database", "lockfile", DEFAULT_DBLOCK, False)
        self.database["gcenabled"] = self.configuration.GetBoolean("Database", "gcenabled", True, False)
        if self.database["gcenabled"]:
            self.database["oldest_arp"] = datetime.timedelta(seconds=self.configuration.GetInt("Database", "oldest_arp", 60 * 60 * 24 * 7 * 2, False))
            self.database["oldest_event"] = datetime.timedelta(seconds=self.configuration.GetInt("Database", "oldest_event", 60 * 60 * 24 * 7 * 2, False))

        # Load logging parameters.
        self.logging["filename"] = self.configuration.GetText('Logging', 'filename', DEFAULT_LOGFILE)
        self.logging["pidfile"] = self.configuration.GetText('Logging', 'pidfile', DEFAULT_PIDFILE, False)
        if self.verbose:
            self.logging["level"] = logging.DEBUG
            self.debugger.debug("log level forced to verbose")
        else:
            self.logging["level"] = self.configuration.GetText('Logging', 'level', DEFAULT_LOGLEVEL, False)

        # Load email parameters.
        self.email["enabled"] = self.configuration.GetBoolean("Email", "enabled", False, False)
        if self.email["enabled"]:
            self.email["to"] = self.configuration.GetEmailList("Email", "to", None)
            self.email["from"] = self.configuration.GetEmailList("Email", "from", None)
            self.email["hostname"] = self.configuration.GetText("Email", "smtp_hostname", None)
            self.email["port"] = self.configuration.GetInt("Email", "smtp_port", 587)
            self.email["mode"] = self.configuration.GetText("Email", "smtp_mode", None)
            self.email["username"] = self.configuration.GetText("Email", "smtp_username", None)
            self.email["password"] = self.configuration.GetText("Email", "smtp_password", None)
            self.email["alerts"] = self.configuration.GetTextList("Email", "alerts", None, False)
            self.email["digests"] = self.configuration.GetTextList("Email", "digests", None, False)

        # Load notification parameters.
        self.notification["enabled"] = self.configuration.GetBoolean("Notification", "enabled", False, False)
        if self.notification["enabled"]:
            self.notification["alerts"] = self.configuration.GetTextList("Notification", "alerts", None, False)

    def _include_dependencies(self):
        try:
            import sqlite3
        except Exception as e:
            self.debugger.error("fatal exception: %s", (e,))
            self.debugger.critical("failed to import sqlite3 (as user %s), try 'pip install sqlite3', exiting", (self.debugger.whoami()))
        self.debugger.info("successfuly imported sqlite3")

        try:
            import dpkt
        except Exception as e:
            self.debugger.error("fatal exception: %s", (e,))
            self.debugger.critical("failed to import dpkt (as user %s), try 'pip install dpkt', exiting", (self.debugger.whoami()))
        self.debugger.info("successfuly imported dpkt")

        if self.daemonize:
            try:
                import daemonize
            except Exception as e:
                self.debugger.error("fatal exception: %s", (e,))
                self.debugger.critical("failed to import daemonize (as user %s), try 'pip install daemonize', exiting", (self.debugger.whoami()))
            self.debugger.info("successfuly imported daemonize")

        if self.email["enabled"]:
            try:
                import pyzmail
            except Exception as e:
                self.debugger.error("fatal exception: %s", (e,))
                self.debugger.critical("failed to import pyzmail (as user %s), try: 'pip install pyzmail' or disable [Email], exiting.", (self.debugger.whoami(),))
            self.debugger.info('successfuly imported pyzmail')

        if self.notification["enabled"]:
            try:
                import ntfy
            except Exception as e:
                self.debugger.error("fatal exception: %s", e)
                self.debugger.critical("failed to import ntfy (as user %s), try 'pip install ntfy', exiting", (self.debugger.whoami()))
            self.debugger.info('successfuly imported ntfy')

    # Drop root permissions when no longer needed.
    def drop_root(self, ng):
        import grp

        os.setgroups([])
        os.setgid(grp.getgrnam(ng.security["group"]).gr_gid)
        os.setuid(pwd.getpwnam(ng.security["user"]).pw_uid)
        ng.debugger.info('running as user %s',  (self.debugger.whoami(),))

    # Determine if pid in pidfile is a running process.
    def is_running(self):
        import errno

        running = False
        if self.logging["pidfile"]:
            if os.path.isfile(self.logging["pidfile"]):
                f = open(self.logging["pidfile"])
                pid_string = f.readline()
                f.close()
                if pid_string:
                    pid = int(pid_string)
                else:
                    pid = 0
                if pid > 0:
                    self.debugger.info("Found pidfile %s, contained pid %d", (self.logging["pidfile"], pid))
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
    import multiprocessing

    from update import update

    ng = netgrasp_instance

    ng.debugger.info("main process running as user %s", (ng.debugger.whoami(),))

    if not pcap:
        # We are running in the foreground as root.
        get_pcap()
        ng.drop_root(ng)

    # At this point we should no longer have/need root privileges.
    assert (os.getuid() != 0) and (os.getgid() != 0), 'Failed to drop root privileges, aborting.'

    ng.email["instance"] = email.Email()
    ng.notification["instance"] = notify.Notify()

    ng.debugger.info("initiating wiretap process")
    parent_conn, child_conn = multiprocessing.Pipe()
    child = multiprocessing.Process(name="wiretap", target=wiretap, args=[ng.pcap["instance"], child_conn])

    child.daemon = True
    child.start()
    if child.is_alive():
        ng.debugger.debug("initiated wiretap process")
    else:
        ng.debugger.debug("wiretap failed to start")

    try:
        ng.db = database.Database()
    except Exception:
        ng.debugger.dump_exception("main() caught exception creating database")
        ng.debugger.critical("failed to open or create %s (as user %s), exiting", (ng.database["filename"], ng.debugger.whoami()))
    ng.debugger.info("opened %s as user %s", (ng.database["filename"], ng.debugger.whoami()))
    ng.db.cursor = ng.db.connection.cursor()
    # http://www.sqlite.org/wal.html
    ng.db.cursor.execute("PRAGMA journal_mode=WAL")

    try:
        ng.db.cursor.execute("SELECT value FROM state WHERE key = 'schema_version'")
        schema_version = ng.db.cursor.fetchone()
        if schema_version:
            version = schema_version[0]
        else:
            version = 0

        if update.needed(version):
            ng.debugger.critical("schema updates are required, run 'netgrasp update'")

    except:
        version = 0

    create_database()

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

            detect_stale_ips()
            detect_netscans()
            detect_anomalies()
            send_notifications()
            send_email_alerts()
            send_email_digests()
            garbage_collection()
            refresh_dns_cache()

            ng.debugger.debug("sleeping for %d seconds", (ng.listen["delay"],))
            time.sleep(ng.listen["delay"])

            heartbeat = False
            while parent_conn.poll():
                message = parent_conn.recv()
                if message == HEARTBEAT:
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
            if now >= time_to_exit:
                run = False
                ng.debugger.error("No heartbeats from wiretap process for >3 minutes.")
        except Exception:
            ng.debugger.dump_exception("main() while loop caught exception")

    ng.debugger.critical("Exiting")


def get_pcap():
    import socket

    assert os.getuid() == 0, 'Unable to initiate pcap, must be run as root.'

    ng = netgrasp_instance

    try:
        import pcap
    except Exception as e:
        ng.debugger.error("fatal exception: %s", (e,))
        ng.debugger.critical("Fatal error: failed to import pcap, try: 'pip install pypcap', exiting")

    devices = pcap.findalldevs()
    if len(devices) <= 0:
      ng.debugger.critical("Fatal error: pcap identified no devices, try running tcpdump manually to debug.")

    ng.pcap["network"], ng.pcap["netmask"] = pcap.lookupnet(ng.listen["interface"])

    try:
        ng.pcap["instance"] = pcap.pcap(name=ng.listen["interface"], snaplen=256, promisc=True, timeout_ms = 100, immediate=True)
        ng.pcap["instance"].setfilter('arp')
    except Exception as e:
        ng.debugger.critical("""Failed to invoke pcap. Fatal exception: %s, exiting.""" % e)

    ng.debugger.warning("listening for arp traffic on %s: %s/%s", (ng.listen["interface"], socket.inet_ntoa(ng.pcap["network"]), socket.inet_ntoa(ng.pcap["netmask"])))
    return ng.pcap


# Child process: wiretap, uses pcap to sniff arp packets.
def wiretap(pc, child_conn):
    ng = netgrasp_instance
    ng.debugger.debug('top of wiretap')

    try:
        import dpkt
    except Exception as e:
        ng.debugger.error("fatal exception: %s", (e,))
        ng.debugger.critical("failed to import dpkt, try: 'pip install dpkt', exiting")
    try:

        import pcap
    except Exception as e:
        ng.debugger.error("fatal exception: %s", (e,))
        ng.debugger.critical("failed to import pcap, try: 'pip install pypcap', exiting")

    assert (os.getuid() != 0) and (os.getgid() != 0), "Failed to drop root privileges, aborting."

    try:
        ng.db = database.Database()
    except Exception as e:
        ng.debugger.error("%s", (e,))
        ng.debugger.critical("failed to open or create %s (as user %s), exiting", (ng.database["filename"], ng.debugger.whoami()))

    ng.debugger.info("opened %s as user %s", (ng.database["filename"], ng.debugger.whoami()))
    ng.db.cursor = ng.db.connection.cursor()

    run = True
    last_heartbeat = datetime.datetime.now()
    while run:
        try:
            now = datetime.datetime.now()
            ng.debugger.debug("[%d] top of while loop: %s", (run, now))

            child_conn.send(HEARTBEAT)

            # Wait an arp packet, then loop again.
            pc.loop(1, received_arp, child_conn)

            heartbeat = False
            while child_conn.poll():
                message = child_conn.recv()
                if message == HEARTBEAT:
                    heartbeat = True
            # It's possible to receive multiple heartbeats, but many or one is the same to us.
            if heartbeat:
                ng.debugger.debug("received heartbeat from main process")
                last_heartbeat = now

            # If we haven't heard from the main process in >1 minute, exit.
            time_to_exit = last_heartbeat + datetime.timedelta(minutes=3)
            if now >= time_to_exit:
                run = False
        except Exception:
            ng.debugger.dump_exception("wiretap() while loop caught exception")
    ng.debugger.critical("No heartbeats from main process for >3 minutes, exiting.")


def ip_on_network(ip):
    ng = netgrasp_instance

    try:
        import struct
        import socket

        ng.debugger.debug("entering address_on_network(%s)", (ip,))

        numeric_ip = struct.unpack("<L", socket.inet_aton(ip))[0]
        cidr = sum([bin(int(x)).count("1") for x in socket.inet_ntoa(ng.pcap["netmask"]).split(".")])
        netmask = struct.unpack("<L", ng.pcap["network"])[0] & ((2L<<int(cidr) - 1) - 1)
        return numeric_ip & netmask == netmask

    except:
        ng.debugger.dump_exception("address_in_network() caught exception")


# Assumes we already have the database lock.
def log_event(mid, iid, did, rid, event, have_lock = False):
    ng = netgrasp_instance

    try:
        ng.debugger.debug("entering log_event(%s, %s, %s, %s, %s, %s)", (mid, iid, did, rid, event, have_lock))

        # Only log events for which there are subscribers.
        if (ng.email["enabled"] and event in ng.email["alerts"]) \
            or (ng.notification["enabled"] and event in ng.notification["alerts"]):
            if have_lock:
                _log_event(mid, iid, did, rid, event)
            else:
                with exclusive_lock.ExclusiveFileLock(ng, 5, "log_event, " + event):
                    _log_event(mid, iid, did, rid, event)
                    ng.db.connection.commit()
        else:
            ng.debugger.debug("log_event: ignoring %s event, no subscribers", (event,))

    except Exception:
        ng.debugger.dump_exception("log_event() caught exception")


def _log_event(mid, iid, did, rid, event):
    ng = netgrasp_instance

    try:
        now = datetime.datetime.now()

        ng.db.connection.execute("INSERT INTO event (mid, iid, did, rid, timestamp, processed, type) VALUES(?, ?, ?, ?, ?, ?, ?)", (mid, iid, did, rid, now, 0, event))

    except Exception:
        ng.debugger.dump_exception("_log_event() caught exception")


def ip_is_mine(ip):
    ng = netgrasp_instance

    try:
        import socket
        ng.debugger.debug("entering ip_is_mine(%s)", (ip,))

        return ip == socket.gethostbyname(socket.gethostname())
    except Exception:
        ng.debugger.dump_exception("ip_is_mine() caught exception")


def ip_has_changed(did):
    ng = netgrasp_instance

    try:
        ng.debugger.debug("entering ip_has_changed(%s)", (did,))

        ng.db.cursor.execute("SELECT DISTINCT iid FROM activity WHERE did = ? ORDER BY updated DESC LIMIT 2", (did))
        iids = ng.db.cursor.fetchall()
        #debugger.debug("ips: %s", (ips,))
        if iids and len(iids) == 2:
            ng.db.cursor.execute("SELECT address FROM ip WHERE iid IN(?, ?)", (iids[0], iids[1]))
            ips = ng.db.cursor.fetchall()
            if ips:
                ip_a = ips[0]
                ip_b = ips[1]
                ng.debugger.debug("ips: %s, %s", (ip_a, ip_b))

                if ip_a != ip_b:
                    ng.debugger.info("ip for did %s changed from %s to %s", (did, ip_a[0], ip_b[0]))
                    return True
                else:
                    ng.debugger.debug("ip for did %s has not changed from %s", (did, ip_a[0]))
                    return False
            else:
                ng.debugger.info("[%d] failed to load ips for iids: %s, %s", (did, iids[0], iids[1]))
                return False
        else:
            ng.debugger.debug("ip for did %s has not changed", (did,))
            return False

    except Exception:
        ng.debugger.dump_exception("ip_has_changed() caught exception")


# Database definitions.
def create_database():
    ng = netgrasp_instance

    try:
        ng.debugger.debug("Creating database tables, if not already existing.")

        # PRAGMA index_list(TABLE)
        with exclusive_lock.ExclusiveFileLock(ng, 5, "create_database"):
            # Create state table.
            ng.db.cursor.execute("""
              CREATE TABLE IF NOT EXISTS state(
                id INTEGER PRIMARY KEY,
                key VARCHAR UNIQUE,
                value TEXT
              )
            """)
            # @TODO make this dynamic, define globally netgrasp and schema versions
            ng.db.cursor.execute("INSERT OR IGNORE INTO state (key, value) VALUES('schema_version', 1)")

            # Record of all MAC addresses ever actively seen.
            ng.db.cursor.execute("""
              CREATE TABLE IF NOT EXISTS mac(
                mid INTEGER PRIMARY KEY,
                vid TEXT,
                address TEXT,
                created TIMESTAMP,
                self NUMERIC
              )
            """)
            ng.db.cursor.execute("CREATE UNIQUE INDEX IF NOT EXISTS idxmac_address ON mac (address)")
            ng.db.cursor.execute("CREATE INDEX IF NOT EXISTS idxmac_vid ON mac (vid)")

            # Record of all vendors ever actively seen.
            ng.db.cursor.execute("""
              CREATE TABLE IF NOT EXISTS vendor(
                vid INTEGER PRIMARY KEY,
                name VARCHAR UNIQUE,
                created TIMESTAMP
              )
            """)

            # Record of all IP addresses ever actively seen.
            ng.db.cursor.execute("""
              CREATE TABLE IF NOT EXISTS ip(
                iid INTEGER PRIMARY KEY,
                mid INTEGER,
                address TEXT,
                created TIMESTAMP
              )
            """)
            ng.db.cursor.execute("CREATE UNIQUE INDEX IF NOT EXISTS idxip_mid_iid ON ip (mid, iid)")
            ng.db.cursor.execute("CREATE INDEX IF NOT EXISTS idxip_address_mid_created ON ip (address, mid, created)")
            ng.db.cursor.execute("CREATE INDEX IF NOT EXISTS idxip_mid_iid ON ip (mid, iid)")

            # Cache DNS lookups.
            ng.db.cursor.execute("""
              CREATE TABLE IF NOT EXISTS host(
                hid INTEGER PRIMARY KEY,
                iid INTEGER,
                name TEXT,
                custom_name TEXT,
		created TIMESTAMP,
		updated TIMESTAMP
              )
            """)
            ng.db.cursor.execute("CREATE UNIQUE INDEX IF NOT EXISTS idxhost_iid ON host (iid)")
            ng.db.cursor.execute("CREATE INDEX IF NOT EXISTS idxhost_name ON host (name)")
            ng.db.cursor.execute("CREATE INDEX IF NOT EXISTS idxhost_custom ON host (custom_name)")
            ng.db.cursor.execute("CREATE INDEX IF NOT EXISTS idxhost_updated ON host (updated)")

            # Record of all devices ever actively seen.
            ng.db.cursor.execute("""
              CREATE TABLE IF NOT EXISTS device(
                did INTEGER PRIMARY KEY,
                mid INTEGER,
                iid INTEGER,
                hid INTEGER,
                vid INTEGER,
                created TIMESTAMP,
                updated TIMESTAMP
              )
            """)
            ng.db.cursor.execute("CREATE UNIQUE INDEX IF NOT EXISTS idxdevice_mid_iid ON device (mid, iid)")
            ng.db.cursor.execute("CREATE INDEX IF NOT EXISTS idxdevice_hid_mid_did ON device (hid, mid, did)")
            ng.db.cursor.execute("CREATE INDEX IF NOT EXISTS idxdevice_vid ON device (vid)")
            ng.db.cursor.execute("CREATE INDEX IF NOT EXISTS idxdevice_updated ON device (updated)")

            # Record of device activity.
            ng.db.cursor.execute("""
              CREATE TABLE IF NOT EXISTS activity(
                aid INTEGER PRIMARY KEY,
                did INTEGER,
                iid INTEGER,
                interface TEXT,
                network TEXT,
                created TIMESTAMP,
                updated TIMESTAMP,
                counter NUMERIC,
                active NUMERIC
              )
            """)
            ng.db.cursor.execute("CREATE INDEX IF NOT EXISTS idxactivity_active_did ON activity (active, did)")
            ng.db.cursor.execute("CREATE INDEX IF NOT EXISTS idxactivity_did_iid ON activity (did, iid)")
            ng.db.cursor.execute("CREATE INDEX IF NOT EXISTS idxactivity_did_active_counter ON activity (did, active, counter)")
            ng.db.cursor.execute("CREATE INDEX IF NOT EXISTS idxactivity_active_updated ON activity (active, updated)")

            # Record of all IP addresses ever requested.
            ng.db.cursor.execute("""
              CREATE TABLE IF NOT EXISTS request(
                rid INTEGER PRIMARY KEY,
                did INTEGER,
                ip TEXT,
                interface TEXT,
                network TEXT,
                created TIMESTAMP,
                updated TIMESTAMP,
                counter NUMERIC,
                active NUMERIC
              )
            """)
            ng.db.cursor.execute("CREATE INDEX IF NOT EXISTS idxrequest_active_updated ON request (active, updated)")
            ng.db.cursor.execute("CREATE INDEX IF NOT EXISTS idxrequest_updated ON request (updated)")
            ng.db.cursor.execute("CREATE INDEX IF NOT EXISTS idxrequest_active_ip ON request (active, ip)")
            ng.db.cursor.execute("CREATE INDEX IF NOT EXISTS idxrequest_did_created ON request (did, created)")

            # Create arp table.
            ng.db.cursor.execute("""
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
            ng.db.cursor.execute("CREATE INDEX IF NOT EXISTS idxarp_srcip_timestamp_rid ON arp (src_ip, timestamp, rid)")
            ng.db.cursor.execute("CREATE INDEX IF NOT EXISTS idxarp_rid_srcip ON arp (rid, src_ip)")

            # Create event table.
            ng.db.cursor.execute("""
              CREATE TABLE IF NOT EXISTS event(
                eid INTEGER PRIMARY KEY,
                mid INTEGER,
                iid INTEGER,
                did INTEGER,
                rid INTEGER,
                interface TEXT,
                network TEXT,
                timestamp TIMESTAMP,
                processed NUMERIC,
                type VARCHAR
              )
            """)
            ng.db.cursor.execute("CREATE INDEX IF NOT EXISTS idxevent_type_timestamp_processed ON event (type, timestamp, processed)")
            ng.db.cursor.execute("CREATE INDEX IF NOT EXISTS idxevent_timestamp_processed ON event (timestamp, processed)")
            # PRAGMA index_list(event)

            # Update internal sqlite3 table and index statistics every time we restart.
            ng.db.cursor.execute("ANALYZE")

            ng.db.connection.commit()
    except Exception:
        ng.debugger.dump_exception("create_database() caught exception")


# We've sniffed an arp packet off the wire.
def received_arp(hdr, data, child_conn):
    ng = netgrasp_instance

    try:
        import socket
        import struct
        import dpkt

        from utils import exclusive_lock

        ng.debugger.debug("entering received_arp")

        now = datetime.datetime.now()

        packet = dpkt.ethernet.Ethernet(data)
        src_ip = socket.inet_ntoa(packet.data.spa)
        src_mac = "%x:%x:%x:%x:%x:%x" % struct.unpack("BBBBBB", packet.src)

        dst_ip = socket.inet_ntoa(packet.data.tpa)
        dst_mac = "%x:%x:%x:%x:%x:%x" % struct.unpack("BBBBBB", packet.dst)

        seen, requested, mid, iid, did, rid, src_mac_broadcast, ip_not_on_network, requested_self = (True, True, None, None, None, None, False, False, False)
        if src_mac == BROADCAST:
            seen = False
            ng.debugger.info("Ignoring arp source of %s [%s], destination %s [%s]", (src_ip, src_mac, dst_ip, dst_mac))
            src_mac_broadcast = True

        if not ip_on_network(src_ip):
            seen = False
            ng.debugger.info("IP not on network, source of %s [%s], dst %s [%s]", (src_ip, src_mac, dst_ip, dst_mac))
            ip_not_on_network = True

        if (dst_ip == src_ip) or (dst_mac == src_mac):
            requested = False
            ng.debugger.info("requesting self %s [%s], ignoring", (src_ip, src_mac))
            requested_self = True

        # ARP REQUEST
        if packet.data.op == dpkt.arp.ARP_OP_REQUEST:
            ng.debugger.debug('ARP REQUEST from %s [%s] to %s [%s]', (src_ip, src_mac, dst_ip, dst_mac))
            if seen:
                mid, iid, did = device_seen(src_ip, src_mac)
            if requested:
                rid = device_request(dst_ip, dst_mac)

        # ARP REPLY
        elif packet.data.op == dpkt.arp.ARP_OP_REPLY:
            ng.debugger.debug('ARP REPLY from %s [%s] to %s [%s]', (src_ip, src_mac, dst_ip, dst_mac))
            if seen:
                mid, iid, did = device_seen(src_ip, src_mac)

        with exclusive_lock.ExclusiveFileLock(ng, 5, "received_arp, arp"):
            ng.db.cursor.execute("INSERT INTO arp (did, rid, src_mac, src_ip, dst_mac, dst_ip, timestamp) VALUES(?, ?, ?, ?, ?, ?, ?)", (did, rid, src_mac, src_ip, dst_mac, dst_ip, now))
            ng.debugger.debug("inserted into arp (%s, %s, %s, %s, %s, %s, %s)", (did, rid, src_mac, src_ip, dst_mac, dst_ip, now))
            if src_mac_broadcast:
                log_event(mid, iid, did, rid, EVENT_SRC_MAC_BROADCAST, True)
            if ip_not_on_network:
                log_event(mid, iid, did, rid, EVENT_IP_NOT_ON_NETWORK, True)
            if requested_self:
                log_event(mid, iid, did, rid, EVENT_REQUESTED_SELF, True)
            ng.db.connection.commit()

    except Exception:
        ng.debugger.dump_exception("received_arp() caught exception")


def device_seen(ip, mac):
    ng = netgrasp_instance

    try:
        import datetime

        ng.debugger.debug("entering device_seen(%s, %s)", (ip, mac))

        now = datetime.datetime.now()

        rid, seen_mac, first_seen_mac, seen_ip, first_seen_ip, first_seen_host, seen_host, first_seen_device, seen_vendor, first_seen_vendor = (None, False, False, False, False, False, False, False, False, False)

        # Get ID for MAC, creating if necessary.
        ng.db.cursor.execute("SELECT mid, vid FROM mac WHERE address = ?", (mac,))
        seen = ng.db.cursor.fetchone()
        if seen:
            mid, vid = seen
            ng.debugger.debug("existing mac %s [%d, %d]", (mac, mid, vid))
            seen_mac = True
        else:
            vendor = mac_lookup(mac)
            ng.db.cursor.execute("SELECT vendor.vid FROM vendor WHERE vendor.name = ?", (vendor,))
            seen = ng.db.cursor.fetchone()
            if seen:
                vid = seen[0]
                ng.debugger.debug("existing vendor %s [%d]", (vendor, vid))
                seen_vendor = True
            else:
                with exclusive_lock.ExclusiveFileLock(ng, 6, "device_seen, new vendor"):
                    ng.db.cursor.execute("INSERT INTO vendor (name, created) VALUES(?, ?)", (vendor, now))

                    ng.db.connection.commit()
                first_seen_vendor = True
                vid = ng.db.cursor.lastrowid
                ng.debugger.info("new vendor %s [%d]", (vendor, vid))

            with exclusive_lock.ExclusiveFileLock(ng, 6, "device_seen, new mac"):
                ng.db.cursor.execute("INSERT INTO mac (vid, address, created, self) VALUES(?, ?, ?, ?)", (vid, mac, now, ip_is_mine(ip)))
                first_seen_mac = True
                ng.db.connection.commit()
            mid = ng.db.cursor.lastrowid
            ng.debugger.info("new mac %s [%d]", (mac, mid))

        # Get ID for IP, creating if necessary.
        ng.db.cursor.execute("SELECT ip.iid FROM ip WHERE ip.mid = ? AND ip.address = ?", (mid, ip))
        seen = ng.db.cursor.fetchone()
        if seen:
            iid = seen[0]
            ng.debugger.debug("existing ip %s [%d]", (ip, iid))
            seen_ip = True
        else:
            with exclusive_lock.ExclusiveFileLock(ng, 6, "device_seen, new ip"):
                ng.db.cursor.execute("INSERT INTO ip (mid, address, created) VALUES(?, ?, ?)", (mid, ip, now))
                first_seen_ip = True
                ng.db.connection.commit()
            iid = ng.db.cursor.lastrowid
            ng.debugger.info("new ip %s [%d]", (ip, iid))

        # Get ID for Hostname, creating if necessary.
        ng.db.cursor.execute("SELECT host.hid, host.name, host.custom_name FROM host WHERE host.iid = ?", (iid,))
        seen = ng.db.cursor.fetchone()
        if seen:
            hid, host_name, custom_name = seen
            ng.debugger.debug("existing host %s (%s) [%d]", (host_name, custom_name, hid))
            seen_host = True
        else:
            host_name = dns_lookup(ip)
            with exclusive_lock.ExclusiveFileLock(ng, 6, "device_seen, new host"):
                ng.db.cursor.execute("INSERT INTO host (iid, name, custom_name, created, updated) VALUES(?, ?, ?, ?, ?)", (iid, host_name, None, now, now))
                ng.db.connection.commit()
            first_seen_host = True
            hid = ng.db.cursor.lastrowid
            ng.debugger.info("new hostname %s [%d]", (host_name, hid))

        # Get ID for Device, creating if necessary.
        ng.db.cursor.execute("SELECT device.did FROM device WHERE device.mid = ? AND device.iid = ?", (mid, iid))
        seen = ng.db.cursor.fetchone()
        if seen:
            did = seen[0]
            ng.debugger.debug("existing device %s (%s) [%d]", (ip, mac, did))
        else:
            # The IP may have changed for this Device.
            ng.db.cursor.execute("SELECT device.did FROM device WHERE device.mid = ? AND device.hid = ?", (mid, hid))
            seen = ng.db.cursor.fetchone()
            if seen:
                did = seen[0]
                ng.debugger.debug("existing device %s (%s) [%d] (new ip)", (ip, mac, did))
                with exclusive_lock.ExclusiveFileLock(ng, 6, "device_seen, update device (new ip)"):
                    ng.db.cursor.execute("UPDATE device SET iid = ?, updated = ? WHERE did = ?", (iid, now, did))
                    log_event(mid, iid, did, rid, EVENT_SEEN_DEVICE, True)
                    log_event(mid, iid, did, rid, EVENT_CHANGED_IP, True)
                    ng.db.connection.commit()
            else:
                with exclusive_lock.ExclusiveFileLock(ng, 6, "device_seen, new device"):
                    ng.db.cursor.execute("INSERT INTO device (mid, iid, hid, vid, created, updated) VALUES(?, ?, ?, ?, ?, ?)", (mid, iid, hid, vid, now, now))
                    ng.db.connection.commit()
                first_seen_device = True
                did = ng.db.cursor.lastrowid
                ng.debugger.info("new device %s (%s) [%d]", (ip, mac, did))

        # Finally, log activity.
        ng.db.cursor.execute("SELECT activity.aid FROM activity WHERE activity.did = ? AND activity.active = 1", (did,))
        seen = ng.db.cursor.fetchone()

        with exclusive_lock.ExclusiveFileLock(ng, 6, "device_seen, log activity"):
            if seen:
                aid = seen[0]
                ng.db.cursor.execute("UPDATE activity SET updated = ?, iid = ?, counter = counter + 1 WHERE aid = ?", (now, iid, aid))
                log_event(mid, iid, did, rid, EVENT_SEEN_DEVICE, True)
            else:
                # @TODO interface, network
                ng.db.cursor.execute("INSERT INTO activity (did, iid, interface, network, created, updated, counter, active) VALUES(?, ?, ?, ?, ?, ?, ?, ?)", (did, iid, None, None, now, now, 1, 1))
                if not first_seen_device:
                    log_event(mid, iid, did, rid, EVENT_FIRST_SEEN_DEVICE_RECENTLY, True)

            # We delayed logging these events until we know the device id (did).
            if seen_mac:
                log_event(mid, iid, did, rid, EVENT_SEEN_MAC, True)
            if first_seen_mac:
                log_event(mid, iid, did, rid, EVENT_FIRST_SEEN_MAC, True)
            if seen_ip:
                log_event(mid, iid, did, rid, EVENT_SEEN_IP, True)
            if first_seen_ip:
                log_event(mid, iid, did, rid, EVENT_FIRST_SEEN_IP, True)
            if seen_host:
                log_event(mid, iid, did, rid, EVENT_SEEN_HOST, True)
            if first_seen_host:
                log_event(mid, iid, did, rid, EVENT_FIRST_SEEN_HOST, True)
            if seen_vendor:
                log_event(mid, iid, did, rid, EVENT_SEEN_VENDOR, True)
            if first_seen_vendor:
                log_event(mid, iid, did, rid, EVENT_FIRST_SEEN_VENDOR, True)
            if first_seen_device:
                log_event(mid, iid, did, rid, EVENT_FIRST_SEEN_DEVICE, True)
            ng.db.connection.commit()

        return mid, iid, did

    except Exception:
        ng.debugger.dump_exception("device_seen() caught exception")


def device_request(ip, mac):
    ng = netgrasp_instance

    try:
        from utils import exclusive_lock
        import datetime

        ng.debugger.debug("entering device_request(%s, %s)", (ip, mac))

        now = datetime.datetime.now()

        mid, iid, did = get_ids(ip, mac)

        # Log request.
        ng.db.cursor.execute("SELECT request.rid, request.active FROM request WHERE request.ip = ? ORDER BY updated DESC LIMIT 1", (ip,))
        seen = ng.db.cursor.fetchone()
        if seen:
            rid, active = seen
            if active:
                with exclusive_lock.ExclusiveFileLock(ng, 6, "device_request, update device request"):
                    ng.db.cursor.execute("UPDATE request SET updated = ?, ip = ?, counter = counter + 1 WHERE rid = ?", (now, ip, rid))
                    log_event(mid, iid, did, rid, EVENT_REQUEST_IP, True)
                    ng.db.connection.commit()
                return rid

        with exclusive_lock.ExclusiveFileLock(ng, 6, "device_request, new device request"):
            # @TODO interface, network
            ng.db.cursor.execute("INSERT INTO request (did, ip, interface, network, created, updated, counter, active) VALUES(?, ?, ?, ?, ?, ?, ?, ?)", (did, ip, None, None, now, now, 1, 1))
            rid = ng.db.cursor.lastrowid
            if seen:
                log_event(mid, iid, did, rid, EVENT_FIRST_REQUEST_RECENTLY_IP, True)
            else:
                log_event(mid, iid, did, rid, EVENT_FIRST_REQUEST_IP, True)
            ng.db.connection.commit()

        return rid

    except Exception:
        ng.debugger.dump_exception("device_request() caught exception")


def get_mac(ip):
    ng = netgrasp_instance

    try:
        ng.debugger.debug("entering get_mac(%s)", (ip,))

        ng.db.cursor.execute("SELECT mac.address FROM mac LEFT JOIN ip ON ip.mid = mac.mid WHERE ip.address = ?", (ip,))
        mac = ng.db.cursor.fetchone()
        if mac:
            return mac[0]
        else:
            return None

    except Exception:
        ng.debugger.dump_exception("get_mac() caught exception")


def get_ids(ip, mac):
    ng = netgrasp_instance

    try:
        ng.debugger.debug("entering get_ids(%s, %s)", (ip, mac))

        # Check if we know this MAC.
        if mac != BROADCAST:
            ng.db.cursor.execute("SELECT mid FROM mac WHERE address = ?", (mac,))
            seen = ng.db.cursor.fetchone()
            if seen:
                mid = seen[0]
            else:
                mid = None
        else:
            # Look the MAC up in our arp cache.
            ng.db.cursor.execute("SELECT mid FROM ip WHERE address = ? ORDER BY created DESC LIMIT 1", (ip,))
            seen = ng.db.cursor.fetchone()
            if seen:
                mid = seen[0]
            else:
                mid = None

        # Check if we know this IP.
        if mid:
            ng.db.cursor.execute("SELECT ip.iid FROM ip WHERE ip.mid = ? AND ip.address = ?", (mid, ip))
            seen = ng.db.cursor.fetchone()
            if seen:
                iid = seen[0]
            else:
                iid = None
        else:
            iid = None

        # Check if we know this Host.
        if iid:
            ng.db.cursor.execute("SELECT host.hid, host.name, host.custom_name FROM host WHERE host.iid = ?", (iid,))
            seen = ng.db.cursor.fetchone()
            if seen:
                hid, host_name, custom_name = seen
            else:
                hid = None
        else:
            hid = None

        # Check if we know this Device.
        if mid and iid:
            ng.db.cursor.execute("SELECT device.did FROM device WHERE device.mid = ? AND device.iid = ?", (mid, iid))
            seen = ng.db.cursor.fetchone()
            if seen:
                did = seen[0]
                ng.debugger.debug("existing device %s (%s) [%d]", (ip, mac, did))
            else:
                did = None
        else:
            did = None
        if not did and mid and hid:
            ng.db.cursor.execute("SELECT device.did FROM device WHERE device.mid = ? AND device.hid = ?", (mid, hid))
            seen = ng.db.cursor.fetchone()
            if seen:
                did = seen[0]
                ng.debugger.debug("existing device %s (%s) [%d] (new ip)", (ip, mac, did))
            else:
                did = None

        ng.debugger.debug("mid(%s) iid(%s) did(%s)", (mid, iid, did))
        return mid, iid, did

    except Exception:
        ng.debugger.dump_exception("get_ids() caught exception")


def get_details(did):
    ng = netgrasp_instance

    try:
        ng.debugger.debug("entering get_details(%s)", (did,))

        ng.db.cursor.execute("SELECT activity.active, activity.counter, ip.address, mac.address, host.name, host.custom_name, vendor.name FROM activity LEFT JOIN device ON activity.did = device.did LEFT JOIN host ON device.hid = host.hid LEFT JOIN ip ON device.iid = ip.iid LEFT JOIN mac ON device.mid = mac.mid LEFT JOIN vendor ON device.vid = vendor.vid WHERE device.did = ? ORDER BY activity.updated DESC LIMIT 1", (did,))
        info = ng.db.cursor.fetchone()
        if info:
            active, counter, ip, mac, host_name, custom_name, vendor = info
            return active, counter, ip, mac, host_name, custom_name, vendor
        else:
            ng.debugger.warning("unknown device %d", (did,))
            return False

    except Exception:
        ng.debugger.dump_exception("get_details() caught exception")


def first_seen(did):
    ng = netgrasp_instance

    try:
        ng.debugger.debug("entering first_seen(did)", (did,))

        ng.db.cursor.execute("SELECT created FROM activity WHERE did = ? AND created NOT NULL ORDER BY created ASC LIMIT 1", (did,))
        active = ng.db.cursor.fetchone()
        if active:
            active = active[0]

        if active:
            return active
        else:
            return False

    except Exception:
        ng.debugger.dump_exception("first_seen() caught exception")


def first_seen_recently(did):
    ng = netgrasp_instance

    try:
        ng.debugger.debug("entering last_seen_recently(%s)", (did,))

        ng.db.cursor.execute('SELECT created FROM activity WHERE did = ? AND created NOT NULL ORDER BY created DESC LIMIT 1', (did,))
        recent = ng.db.cursor.fetchone()
        if recent:
            recent = recent[0]

        if recent:
            return recent
        else:
            return False

    except Exception:
        ng.debugger.dump_exception("first_seen_recently() caught exception")


def last_seen(did):
    ng = netgrasp_instance

    try:
        ng.debugger.debug("entering last_seen(%s)", (did,))

        ng.db.cursor.execute('SELECT updated FROM activity WHERE did=? AND updated NOT NULL ORDER BY updated DESC LIMIT 1', (did,))
        active = ng.db.cursor.fetchone()
        if active:
            return active[0]
        else:
            return False

    except Exception:
        ng.debugger.dump_exception("last_seen() caught exception")


def previously_seen(did):
    ng = netgrasp_instance

    try:
        ng.debugger.debug("entering previously_seen(%s)", (did,))

        ng.db.cursor.execute('SELECT updated FROM activity WHERE did=? AND updated NOT NULL AND active != 1 ORDER BY updated DESC LIMIT 1', (did,))
        previous = ng.db.cursor.fetchone()
        if previous:
            return previous[0]
        else:
            return False

    except Exception:
        ng.debugger.dump_exception("previously_seen() caught exception")


def first_requested(did):
    ng = netgrasp_instance

    try:
        ng.debugger.debug("entering first_requested(%s)", (did,))

        ng.db.cursor.execute('SELECT created FROM request WHERE did=? AND created NOT NULL ORDER BY created ASC LIMIT 1', (did,))
        active = ng.db.cursor.fetchone()
        if active:
            return active[0]
        else:
            return False

    except Exception:
        ng.debugger.dump_exception("first_requested() caught exception")


def last_requested(did):
    ng = netgrasp_instance

    try:
        ng.debugger.debug("entering last_requested(%s)", (did,))

        ng.db.cursor.execute('SELECT updated FROM request WHERE did=? AND updated NOT NULL ORDER BY updated DESC LIMIT 1', (did,))
        last = ng.db.cursor.fetchone()
        if last:
            return last[0]
        else:
            return False

    except Exception:
        ng.debugger.dump_exception("last_requested() caught exception")


def time_seen(did):
    ng = netgrasp_instance

    try:
        ng.debugger.debug("entering time_seen(%s)", (did,))

        ng.db.cursor.execute('SELECT created, updated FROM activity WHERE did=? ORDER BY updated DESC LIMIT 1', (did,))
        active = ng.db.cursor.fetchone()
        if active:
            created, updated = active
            ng.debugger.debug("did(%d) created(%s) updated(%s)", (did, created, updated))
            return updated - created
        else:
            return False

    except Exception:
        ng.debugger.dump_exception("time_seen() caught exception")


def previous_ip(did):
    ng = netgrasp_instance

    try:
        ng.debugger.debug("entering previous_ip(%s)", (did,))

        prev_ip = None
        ng.db.cursor.execute("SELECT DISTINCT iid FROM activity WHERE did = ? ORDER BY updated DESC LIMIT 2", (did,))
        ips = ng.db.cursor.fetchall()
        if ips and len(ips) == 2:
            ng.db.cursor.execute("SELECT address FROM ip WHERE iid = ?", (ips[1]))
            prev_ip = ng.db.cursor.fetchone()
        if prev_ip:
            return prev_ip[0]
        else:
            return None

    except Exception:
        ng.debugger.dump_exception("previous_ip() caught exception")


def active_devices_with_ip(ip):
    ng = netgrasp_instance

    try:
        ng.debugger.debug("entering active_devices_with_ip(%s)", (ip,))

        devices = None
        ng.db.cursor.execute("SELECT iid FROM ip WHERE address = ?", (ip,))
        ids = ng.db.cursor.fetchall()
        if ids:
            iids = []
            for iid in ids:
                iids.append(iid[0])
            ng.db.cursor.execute("SELECT DISTINCT activity.did, ip.address, mac.address FROM activity LEFT JOIN ip ON activity.iid = ip.iid LEFT JOIN mac ON ip.mid = mac.mid WHERE active = 1 AND activity.iid IN ("+ ",".join("?"*len(iids)) + ")", iids)
            devices = ng.db.cursor.fetchall()

        if devices:
            dids = []
            for device in devices:
                _did, _ip, _mac = device
                dids.append((_did, _ip, _mac))
            return dids
        else:
            return None

    except Exception:
        ng.debugger.dump_exception("active_devices_with_ip() caught exception")


def active_devices_with_mac(mac):
    ng = netgrasp_instance

    try:
        ng.debugger.debug("entering active_devices_with_mac(%s)", (mac,))

        devices = None
        ng.db.cursor.execute("SELECT ip.iid FROM mac LEFT JOIN ip ON mac.mid = ip.mid WHERE mac.address = ?", (mac,))
        ids = ng.db.cursor.fetchall()
        if ids:
            iids = []
            for iid in ids:
                iids.append(iid[0])
            ng.db.cursor.execute("SELECT DISTINCT activity.did, ip.address, mac.address FROM activity LEFT JOIN ip ON activity.iid = ip.iid LEFT JOIN mac ON ip.mid = mac.mid WHERE active = 1 AND activity.iid IN ("+ ",".join("?"*len(iids)) + ")", iids)
            devices = ng.db.cursor.fetchall()

        if devices:
            dids = []
            for device in devices:
                _did, _ip, _mac = device
                dids.append((_did, _ip, _mac))
            return dids
        else:
            return None

    except Exception:
        ng.debugger.dump_exception("active_devices_with_mac() caught exception")


def devices_requesting_ip(ip, timeout):
    ng = netgrasp_instance

    try:
        ng.debugger.debug("entering devices_requesting_ip(%s, %s)", (ip, timeout))

        stale = datetime.datetime.now() - datetime.timedelta(seconds=timeout)

        dids = []
        ng.db.cursor.execute("SELECT dst_ip FROM arp WHERE src_ip = ? AND rid IS NOT NULL AND timestamp < ? GROUP BY src_ip ORDER BY timestamp DESC", (ip, stale))
        ips = ng.db.cursor.fetchall()
        if ips:
            for dst_ip in ips:
                dst_mac = get_mac(dst_ip[0])
                _mid, _iid, _did = get_ids(dst_ip[0], dst_mac)
                dids.append((_did, dst_ip, dst_mac))

        ng.debugger.debug("did, dst_ip, dst_mac(%s)", (dids,))
        return dids

    except Exception:
        ng.debugger.dump_exception("devices_requesting_ip() caught exception")


# Mark IP/MAC pairs as no longer active if we've not seen ARP activity for >active_timeout seconds
def detect_stale_ips():
    ng = netgrasp_instance

    try:
        ng.debugger.debug("entering detect_stale_ips()")
        stale = datetime.datetime.now() - datetime.timedelta(seconds=ng.listen["active_timeout"])

        # Mark no-longer active devices stale.
        ng.db.cursor.execute("SELECT aid, did, iid FROM activity WHERE active = 1 AND updated < ?", (stale,))
        rows = ng.db.cursor.fetchall()
        if rows:
            with exclusive_lock.ExclusiveFileLock(ng, 5, "detect_stale_ips, activity"):
                for row in rows:
                    aid, did, iid = row
                    ng.db.cursor.execute("SELECT ip.address, mac.mid, mac.address FROM ip LEFT JOIN mac ON ip.mid = mac.mid WHERE iid = ? LIMIT 1", (iid,))
                    address = ng.db.cursor.fetchone()
                    if address:
                        ip, mid, mac = address
                        log_event(mid, iid, did, None, EVENT_STALE, True)
                        ng.debugger.info("%s [%s] is no longer active", (ip, mac))
                    else:
                        ng.debugger.error("aid(%d) did(%d) is no longer active, no ip/mac found)", (aid, did))
                    ng.db.cursor.execute("UPDATE activity SET active = 0 WHERE aid = ?", (aid,))
                ng.db.connection.commit()

        # Mark no-longer active requests stale.
        ng.db.cursor.execute("SELECT rid, did, ip FROM request WHERE active = 1 AND updated < ?", (stale,))
        rows = ng.db.cursor.fetchall()
        if rows:
            with exclusive_lock.ExclusiveFileLock(ng, 5, "detect_stale_ips, request"):
                for row in rows:
                    rid, did, ip = row
                    mid, iid = (None, None)
                    log_event(mid, iid, did, rid, EVENT_REQUEST_STALE, True)
                    ng.debugger.info("%s (%d) is no longer active)", (ip, did))
                    ng.db.cursor.execute("UPDATE request SET active = 0 WHERE rid = ?", (rid,))
                ng.db.connection.commit()

    except Exception:
        ng.debugger.dump_exception("detect_stale_ips() caught exception")


def detect_netscans():
    ng = netgrasp_instance

    try:
        ng.debugger.debug("entering detect_netscans()")
        now = datetime.datetime.now()
        stale = datetime.datetime.now() - datetime.timedelta(seconds=ng.listen["active_timeout"]) - datetime.timedelta(minutes=10)

        ng.db.cursor.execute("SELECT COUNT(DISTINCT arp.dst_ip) AS count, arp.src_ip, arp.src_mac FROM arp LEFT JOIN request ON arp.rid = request.rid WHERE request.active = 1 GROUP BY arp.src_ip HAVING count > 50")
        scans = ng.db.cursor.fetchall()
        if scans:
            ng.debugger.debug("scans in progress (count, src ip, src mac): %s", (scans,))
            for scan in scans:
                count, src_ip, src_mac = scan
                mid, iid, did = get_ids(src_ip, src_mac)
                ng.db.cursor.execute("SELECT eid FROM event WHERE did = ? AND type = ? AND timestamp > ?", (did, EVENT_SCAN, stale))
                already_detected = ng.db.cursor.fetchone()
                if not already_detected:
                    # logging rid doesn't make sense, as there's 1 rid per IP requested.
                    log_event(mid, iid, did, None, EVENT_SCAN)
                    ng.debugger.info("network scan by %s [%s]", (src_ip, src_mac))

    except Exception:
        ng.debugger.dump_exception("detect_netscans() caught exception")


def detect_anomalies():
    ng = netgrasp_instance

    try:
        ng.debugger.debug("entering detect_anomalies()")
        stale = datetime.datetime.now() - datetime.timedelta(seconds=ng.listen["active_timeout"])

        # Multiple MACs with the same IP.
        ng.db.cursor.execute("SELECT COUNT(activity.iid) AS count, ip.address FROM activity LEFT JOIN ip ON activity.iid = ip.iid WHERE activity.active = 1 GROUP BY activity.iid HAVING count > 1 ORDER BY ip.iid ASC")
        duplicates = ng.db.cursor.fetchall()
        ng.debugger.debug("duplicate ips: %s", (duplicates,))
        if duplicates:
            for duplicate in duplicates:
                count, ip = duplicate
                ng.db.cursor.execute("SELECT ip.mid, ip.iid, activity.did FROM activity LEFT JOIN ip ON activity.iid = ip.iid WHERE ip.address = ? AND active = 1", (ip,))
                dupes = ng.db.cursor.fetchall()
                ng.debugger.debug("dupes: %s", (dupes,))
                for dupe in dupes:
                    mid, iid, did = dupe
                    ng.db.cursor.execute("SELECT eid FROM event WHERE mid = ? AND type = ? AND timestamp > ?", (mid, EVENT_DUPLICATE_IP, stale))
                    already_detected = ng.db.cursor.fetchone()
                    if already_detected:
                        break
                    log_event(mid, iid, did, None, EVENT_DUPLICATE_IP)
                    ng.debugger.info("multiple MACs with same IP: mid=%d, iid=%d", (mid, iid))

        # Multiple IPs with the same MAC.
        ng.db.cursor.execute("SELECT COUNT(ip.mid) AS count, ip.mid FROM activity LEFT JOIN ip ON activity.iid = ip.iid WHERE activity.active = 1 GROUP BY ip.mid HAVING count > 1 ORDER BY ip.mid ASC")
        duplicates = ng.db.cursor.fetchall()
        ng.debugger.debug("duplicate macs: %s", (duplicates,))
        if duplicates:
            for duplicate in duplicates:
                count, mid = duplicate
                ng.db.cursor.execute("SELECT ip.mid, ip.iid, activity.did FROM activity LEFT JOIN ip ON activity.iid = ip.iid WHERE ip.mid = ? AND active = 1", (mid,))
                dupes = ng.db.cursor.fetchall()
                ng.debugger.debug("dupes: %s", (dupes,))
                for dupe in dupes:
                    mid, iid, did = dupe
                    ng.db.cursor.execute("SELECT eid FROM event WHERE iid = ? AND type = ? AND timestamp > ?", (iid, EVENT_DUPLICATE_MAC, stale))
                    already_detected = ng.db.cursor.fetchone()
                    ng.debugger.debug("already_detected: %s", (already_detected,))
                    if already_detected:
                        break
                    log_event(mid, iid, did, None, EVENT_DUPLICATE_MAC)
                    ng.debugger.info("multiple IPs with same MAC: mid=%d, iid=%d", (mid, iid))

    except Exception:
        ng.debugger.dump_exception("detect_anomalies() caught exception")


def send_notifications():
    ng = netgrasp_instance

    try:
        ng.debugger.debug("entering send_notifications()")

        if not ng.notification["enabled"]:
            ng.debugger.debug("notifications disabled")
            return False

        if not ng.notification["alerts"]:
            ng.debugger.debug("no notification alerts configured")
            return False

        import ntfy

        timer = simple_timer.Timer()

        # only send notifications for configured events
        ng.db.cursor.execute("SELECT eid, mid, iid, did, timestamp, type, processed FROM event WHERE NOT (processed & 8) AND type IN ("+ ",".join("?"*len(ng.notification["alerts"])) + ")", ng.notification["alerts"])

        rows = ng.db.cursor.fetchall()
        if rows:
            max_eid = 0
            for row in rows:
                eid, mid, iid, did, timestamp, event, processed = row

                if eid > max_eid:
                    max_eid = eid

                if event in ng.notification["alerts"]:
                    details = get_details(did)
                    if not details:
                        ng.debugger.warning("invalid device %d, unable to generate notification")
                        continue
                    active, counter, ip, mac, host_name, custom_name, vendor = details

                    ng.debugger.info("event %s [%d] in %s, generating notification alert",
                                     (event, eid, ng.notification["alerts"]))
                    frstseen = first_seen(did)
                    lastseen = first_seen_recently(did)
                    prevseen = previously_seen(did)
                    title = """Netgrasp alert: %s""" % event
                    body = """%s with IP %s [%s], seen %s, previously seen %s, first seen %s""" % \
                           (pretty.name_did(did), ip, mac, pretty.time_ago(lastseen), pretty.time_ago(prevseen),
                            pretty.time_ago(frstseen))
                    ntfy.notify(body, title)
                else:
                    ng.debugger.debug("event %s [%d] NOT in %s", (event, eid, ng.notification["alerts"]))

                if timer.elapsed() > MAXSECONDS:
                    ng.debugger.debug("processing notifications >%d seconds, aborting", (MAXSECONDS,))
                    with exclusive_lock.ExclusiveFileLock(ng, 5, "send_notifications, aborting"):
                        ng.db.cursor.execute("UPDATE event SET processed=processed + ? WHERE eid <= ? AND NOT (processed & ?)",
                                             (PROCESSED_NOTIFICATION, max_eid, PROCESSED_NOTIFICATION))
                        ng.db.connection.commit()
                    return

            with exclusive_lock.ExclusiveFileLock(ng, 5, "send_notifications"):
                ng.db.cursor.execute("UPDATE event SET processed=processed + ? WHERE eid <= ? AND NOT (processed & ?)",
                                     (PROCESSED_NOTIFICATION, max_eid, PROCESSED_NOTIFICATION))
                ng.db.connection.commit()

    except Exception:
        ng.debugger.dump_exception("send_notifications() caught exception")

TALKED_TO_LIMIT = 50

def send_email_alerts():
    ng = netgrasp_instance

    try:
        ng.debugger.debug("entering send_email_alerts()")

        if not ng.email["enabled"]:
            ng.debugger.debug("email disabled")
            return False

        if not ng.email["alerts"]:
            ng.debugger.debug("no email alerts configured")
            return False

        day = datetime.datetime.now() - datetime.timedelta(days=1)

        ng.db.cursor.execute("SELECT eid, mid, iid, did, timestamp, type, processed FROM event WHERE NOT (processed & 1) AND type IN ("+ ",".join("?"*len(ng.email["alerts"])) + ")", ng.email["alerts"])
        rows = ng.db.cursor.fetchall()
        if rows:
            max_eid = 0
            processed_events = 0
            duplicate_macs = []
            duplicate_ips = []
            for row in rows:
                eid, mid, iid, did, timestamp, event, processed = row
                ng.debugger.debug("processing event %d for iid[%d] mid[%d] at %s", (eid, iid, mid, timestamp))

                if eid > max_eid:
                    max_eid = eid
                processed_events += 1

                # only send emails for configured events
                if event in ng.email["alerts"]:
                    details = get_details(did)
                    if not details:
                        ng.debugger.warning("invalid device %d, unable to generate alert")
                        continue
                    active, counter, ip, mac, host_name, custom_name, vendor = details

                    if event == EVENT_DUPLICATE_MAC:
                        if mac in duplicate_macs:
                            ng.debugger.debug("event %s [%d], notification email already sent", (event, eid))
                            continue
                        else:
                            ng.debugger.debug("event %s [%d], first time seeing %s", (event, eid, mac))
                            duplicate_macs.append(mac)
                    elif event == EVENT_DUPLICATE_IP:
                        if ip in duplicate_macs:
                            ng.debugger.debug("event %s [%d], notification email already sent", (event, eid))
                            continue
                        else:
                            ng.debugger.debug("event %s [%d], first time seeing %s", (event, eid, ip))
                            duplicate_ips.append(ip)

                    ng.debugger.info("event %s [%d] in %s, generating notification email", (event, eid, ng.email["alerts"]))
                    frstseen = first_seen(did)
                    frstrequ = first_requested(did)
                    lastseen = last_seen(did)
                    timeseen = time_seen(did)
                    prevseen = previously_seen(did)
                    lastrequ = last_requested(did)

                    ng.db.cursor.execute("SELECT dst_ip, dst_mac FROM arp WHERE src_ip = ? AND timestamp >= ? GROUP BY dst_ip LIMIT ?", (ip, day, TALKED_TO_LIMIT))
                    peers = ng.db.cursor.fetchall()
                    talked_to_list = []
                    talked_to_count = 0
                    if peers:
                        talked_to_count = len(peers)
                        for peer in peers:
                            dst_ip, dst_mac = peer
                            dst_mid, dst_iid, dst_did = get_ids(dst_ip, dst_mac)
                            ng.debugger.debug("ip, mac, mid, iid, did: %s, %s, %s, %s, %s", (dst_ip, dst_mac, dst_mid, dst_iid, dst_did))
                            talked_to_list.append("""%s (%s)""" % (pretty.name_did(dst_did, dst_ip), dst_ip))

                    if talked_to_count == TALKED_TO_LIMIT:
                      ng.db.cursor.execute("SELECT COUNT(DISTINCT dst_ip) AS count FROM arp WHERE src_ip = ? AND timestamp >= ?", (ip, day))
                      proper_count = ng.db.cursor.fetchone()
                      if proper_count:
                          talked_to_count = proper_count[0]

                    devices = active_devices_with_ip(ip)
                    devices_with_ip = []
                    if devices:
                        for device in devices:
                            list_did, list_ip, list_mac = device
                            devices_with_ip.append("""%s [%s]""" % (pretty.name_did(list_did), list_mac))

                    devices = active_devices_with_mac(mac)
                    devices_with_mac = []
                    if devices:
                        for device in devices:
                            list_did, list_ip, list_mac = device
                            devices_with_mac.append("""%s (%s)""" % (pretty.name_did(list_did), list_ip))

                    devices = devices_requesting_ip(ip, ng.listen["active_timeout"])
                    devices_requesting = []
                    if devices:
                        for device in devices:
                            list_did, list_ip, list_mac = device
                            devices_requesting.append("""%s (%s)""" % (pretty.name_did(list_did), list_ip))

                    email.MailSend(event, 'alert', dict(
                        name=pretty.name_did(did),
                        ip=ip,
                        mac=mac,
                        event_id=eid,
                        vendor=vendor,
                        hostname=host_name,
                        custom_name=custom_name,
                        first_seen=pretty.time_ago(frstseen),
                        last_seen=pretty.time_ago(lastseen),
                        recently_seen_count=counter,
                        time_seen=pretty.time_elapsed(timeseen),
                        previously_seen=pretty.time_ago(prevseen),
                        first_requested=pretty.time_ago(frstrequ),
                        last_requested=pretty.time_ago(lastrequ),
                        previous_ip=previous_ip(did),
                        devices_with_ip=devices_with_ip,
                        devices_with_mac=devices_with_mac,
                        devices_requesting=devices_requesting,
                        active_boolean=active,
                        talked_to_count=talked_to_count,
                        talked_to_list=talked_to_list,
                        event=event
                        ))
                else:
                    ng.debugger.debug("event %s [%d] NOT in %s", (event, eid, ng.email["alerts"]))

            with exclusive_lock.ExclusiveFileLock(ng, 5, "send_email_alerts"):
                ng.db.cursor.execute("UPDATE event SET processed=processed + ? WHERE eid <= ? AND NOT (processed & ?)", (PROCESSED_ALERT, max_eid, PROCESSED_ALERT))
                ng.db.connection.commit()
            ng.debugger.debug("send_email_alerts: processed %d events", (processed_events,))

    except Exception:
        ng.debugger.dump_exception("send_email_alerts() caught exception")


# Identify vendor associated with MAC.
def mac_lookup(mac):
    ng = netgrasp_instance

    try:
        ng.debugger.debug("entering mac_lookup(%s)", (mac,))

        import re
        import httplib

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
        ng.debugger.debug("Looking up vendor for %s", (mac,))
        http = httplib.HTTPConnection("api.macvendors.com", 80)
        url = """/%s""" % mac
        http.request("GET", url)
        response = http.getresponse()

        if response.status == 200 and response.reason == "OK":
            vendor = response.read()
            ng.debugger.debug("identified %s as %s", (mac, vendor))
        else:
            vendor = None
            ng.debugger.info("failed to identify %s", (mac,))

        return vendor

    except Exception:
        ng.debugger.dump_exception("mac_lookup() caught exception")


def refresh_dns_cache():
    ng = netgrasp_instance

    # @TODO consider retrieving actual TTL from DNS -- for now refresh active devices regularly
    try:
        ng.debugger.debug("entering refresh_dns_cache")

        ttl = datetime.datetime.now() - datetime.timedelta(minutes=15)
        ng.db.cursor.execute("SELECT host.hid, host.name, activity.did, mac.address, ip.address FROM activity LEFT JOIN ip ON activity.iid = ip.iid LEFT JOIN host ON activity.iid = host.iid LEFT JOIN mac ON ip.mid = mac.mid WHERE activity.active = 1 AND host.updated < ? LIMIT 10", (ttl,))
        rows = ng.db.cursor.fetchall()
        for row in rows:
            hid, old_name, did, mac, ip = row
            name = dns_lookup(ip)
            now = datetime.datetime.now()
            with exclusive_lock.ExclusiveFileLock(ng, 5, "refresh_dns_cache"):
                ng.debugger.debug("Refreshing hostname from '%s' to '%s' for %s", (old_name, name, ip))
                ng.db.cursor.execute("UPDATE host SET name = ?, updated = ? WHERE hid = ?", (name, now, hid))
                ng.db.connection.commit()

    except Exception:
        ng.debugger.dump_exception("refresh_dns_cache() caught exception")


def dns_lookup(ip):
    ng = netgrasp_instance

    try:
        import socket

        ng.debugger.debug("entering dns_lookup(%s)", (ip,))
        try:
            host_name, aliaslist, ipaddrlist = socket.gethostbyaddr(ip)
            ng.debugger.debug("host_name(%s), aliaslist(%s), ipaddrlist(%s)", (host_name, aliaslist, ipaddrlist))
            return host_name

        except Exception as e:
            host_name = "unknown"
            ng.debugger.debug("dns_lookup() socket.gethostbyaddr(%s) failed, host_name = %s: %s", (ip, host_name, e))
            return host_name

    except Exception:
        ng.debugger.dump_exception("dns_lookup() caught exception")


# Generates daily and weekly email digests.
def send_email_digests():
    ng = netgrasp_instance

    try:
        ng.debugger.debug("entering send_email_digests()")

        if not ng.email["enabled"]:
            ng.debugger.debug("email disabled")
            return False

        if not ng.email["digests"]:
            ng.debugger.debug("no digests configured")
            return False

        timer = simple_timer.Timer()
        now = datetime.datetime.now()

        # @TODO make sure we validate available digests
        for digest in ng.email["digests"]:
            if timer.elapsed() > MAXSECONDS:
                ng.debugger.debug("processing digests >%d seconds, aborting digest", (MAXSECONDS,))
                return

            if digest == "daily":
                timestamp_string = "daily_digest_timestamp"
                future_digest_timestamp = now + datetime.timedelta(days=1)
                time_period = now - datetime.timedelta(days=1)
                time_period_description = "24 hours"
                previous_time_period = now - datetime.timedelta(days=2)
            elif digest == "weekly":
                timestamp_string = "weekly_digest_timestamp"
                future_digest_timestamp = now + datetime.timedelta(weeks=1)
                time_period = now - datetime.timedelta(weeks=1)
                time_period_description = "7 days"
                previous_time_period = now - datetime.timedelta(weeks=2)

            next_digest_timestamp = ng.db.get_state(timestamp_string, "", True)
            if not next_digest_timestamp:
                # first time here, schedule a digest for appropriate time in future
                ng.db.set_state(timestamp_string, future_digest_timestamp)
                next_digest_timestamp = future_digest_timestamp

            if now < next_digest_timestamp:
                # it's not yet time to send this digest
                continue

            # time to send a digest
            ng.debugger.info("Sending %s digest", (digest,))
            ng.db.set_state(timestamp_string, future_digest_timestamp)

            # how many devices were requested during this time period
            ng.db.cursor.execute("SELECT COUNT(DISTINCT dst_ip) FROM arp WHERE rid IS NOT NULL AND timestamp >= ? AND timestamp <= ?", (time_period, now))
            requested = ng.db.cursor.fetchone()

            # all devices that were actively seen during this time period
            ng.db.cursor.execute("SELECT DISTINCT did FROM arp WHERE did IS NOT NULL AND timestamp >= ? AND timestamp <= ?", (time_period, now))
            seen = ng.db.cursor.fetchall()

            # all devices that were actively seen during the previous time period
            ng.db.cursor.execute("SELECT DISTINCT did FROM arp WHERE did IS NOT NULL AND timestamp >= ? AND timestamp <= ?", (previous_time_period, time_period))
            seen_previous = ng.db.cursor.fetchall()

            new = set(seen) - set(seen_previous)
            gone_away = set(seen_previous) - set(seen)

            noisy = []
            some_new = False
            active_devices = []
            for unique_seen in seen:
                did = unique_seen[0]
                details = get_details(did)
                if not details:
                    ng.debugger.warning("invalid device %d, not included in digest")
                    continue
                active, counter, ip, mac, host_name, custom_name, vendor = details

                ng.db.cursor.execute("SELECT COUNT(DISTINCT(dst_ip)) FROM arp WHERE rid IS NOT NULL AND src_ip = ? AND timestamp >= ? AND timestamp <= ?", (ip, time_period, now))
                requests = ng.db.cursor.fetchone()
                if requests[0] > 10:
                    noisy.append((mac, ip, requests[0], pretty.name_did(did)))
                if unique_seen in new:
                    active_devices.append("""%s (%s)*""" % (pretty.name_did(did), ip))
                    some_new = True
                else:
                    active_devices.append("""%s (%s)""" % (pretty.name_did(did), ip))
            if some_new:
                new_devices_text = "* = not active in the previous " + time_period_description
            else:
                new_devices_text = ""

            noisy_devices_intro = ""
            noisy_devices = []
            if noisy:
                noisy_devices_intro = "The following devices requested 10 or more IPs:"
                for noise in noisy:
                    noisy_text = """%s (%s) requested %d IP addresses""" % (noise[3], noise[1], noise[2])
                    if noise[2] > 100:
                        noisy_text += " (network scan)"
                    elif noise[2] > 50:
                        noisy_text += " (network scan?)"
                    noisy_devices.append(noisy_text)

            gone_devices_intro = ""
            gone_devices = []
            if gone_away:
                gone_devices_intro = """The following IPs were not active, but were active the previous %s:""" % time_period_description
                for gone in gone_away:
                    gone_details = get_details(gone[0])
                    gone_active, gone_counter, gone_ip, gone_mac, gone_host_name, gone_custom_name, gone_vendor = gone_details
                    gone_devices.append("""%s (%s)""" % (pretty.name_did(gone[0]), gone_ip))

            device_breakdown = []
            if digest == "daily":
                rnge = 24
                while rnge > 0:
                    lower = now - datetime.timedelta(hours=rnge)
                    rnge = rnge - 1
                    upper = now - datetime.timedelta(hours=rnge)
                    ng.db.cursor.execute("SELECT DISTINCT did FROM arp WHERE timestamp >= ? AND timestamp < ?", (lower, upper))
                    distinct = ng.db.cursor.fetchall()
                    device_breakdown.append("""%s: %d""" % (lower.strftime("%I %p, %x"), len(distinct)))
            elif digest == "weekly":
                rnge = 7
                while rnge > 0:
                    lower = now - datetime.timedelta(days=rnge)
                    rnge = rnge - 1
                    upper = now - datetime.timedelta(days=rnge)
                    ng.db.cursor.execute("SELECT DISTINCT did FROM arp WHERE timestamp >= ? AND timestamp < ?", (lower, upper))
                    distinct = ng.db.cursor.fetchall()
                    device_breakdown.append("""%s: %d""" % (lower.strftime("%A, %x"), len(distinct)))

            ng.debugger.info("Sending %s digest", (digest,))

            # @TODO fixme
            email.MailSend('digest', 'digest', dict(
                type=digest,
                time_period=time_period_description,
                active_devices_count=len(seen),
                active_devices=active_devices,
                new_devices_text=new_devices_text,
                ips_requested=requested[0],
                noisy_devices_intro=noisy_devices_intro,
                noisy_devices=noisy_devices,
                gone_devices_intro=gone_devices_intro,
                gone_devices=gone_devices,
                device_breakdown=device_breakdown
                ))

    except Exception:
        ng.debugger.dump_exception("send_email_digests() caught exception")


# Don't let the arp or event tables grow too big.
def garbage_collection():
    ng = netgrasp_instance

    try:
        ng.debugger.debug("entering garbage_collection()")

        if not ng.database["gcenabled"]:
            ng.db.debugger.debug("garbage collection disabled")
            return

        garbage_collection_string = "garbage collection"

        now = datetime.datetime.now()
        next_garbage_collection = ng.db.get_state(garbage_collection_string, "", True)

        if not next_garbage_collection:
            # perform first garbage collection now
            next_garbage_collection = now

        if now < next_garbage_collection:
            # it's not yet time to send this digest
            return False

        ng.debugger.info("performing garbage collection")
        # schedule next garbage collection
        ng.db.set_state(garbage_collection_string, now + datetime.timedelta(days=1))

        with exclusive_lock.ExclusiveFileLock(ng, 5, "garbage_collection"):
            # Purge old arp entries.
            ng.db.cursor.execute("SELECT COUNT(*) FROM arp WHERE timestamp < ?", (now - ng.database["oldest_arp"],))
            arp_count = ng.db.cursor.fetchone()
            ng.db.cursor.execute("DELETE FROM arp WHERE timestamp < ?", (now - ng.database["oldest_arp"],))
            # Purge old event entries.
            ng.db.cursor.execute("SELECT COUNT(*) FROM event WHERE timestamp < ?", (now - ng.database["oldest_event"],))
            event_count = ng.db.cursor.fetchone()
            ng.db.cursor.execute("DELETE FROM event WHERE timestamp < ?", (now - ng.database["oldest_event"],))
            ng.db.connection.commit()

        ng.debugger.debug("deleted %d arp entries older than %s", (arp_count[0], now - ng.database["oldest_arp"]))
        ng.debugger.debug("deleted %d event entries older than %s", (event_count[0], now - ng.database["oldest_event"]))

    except Exception:
        ng.debugger.dump_exception("garbage_collection() caught exception")
