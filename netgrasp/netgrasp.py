from netgrasp.debug import debug


#!/usr/bin/env python2
import os
import sys
import fcntl
import signal
import multiprocessing
import ConfigParser
import io
import logging
import logging.handlers
import pwd
import grp
import struct
import socket
import datetime
from email.utils import parseaddr

import time

class Netgrasp:
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

    DEFAULT_USER      = "daemon"
    DEFAULT_GROUP     = "daemon"
    DEFAULT_LOGLEVEL  = logging.INFO
    DEFAULT_LOGFILE   = "netgraspd.log"
    DEFAULT_LOGFORMAT = "%(asctime)s [%(levelname)s/%(processName)s] %(message)s"
    DEFAULT_PIDFILE   = "netgraspd.pid"
    DEFAULT_DBLOCK    = "/tmp/.database_lock"

    config_instance = ''
    database_instane = ''
    email_instance = ''
    notification_instance = ''

    class Config:
        def __init__(self, parser):
            self.parser = parser
            self.found = self.parser.read(['/etc/netgraspd.cfg', '/usr/local/etc/netgraspd.cfg', '~/.netgraspd.cfg', './netgraspd.cnf'])

        def _GetValue(self, section, option, value, default, required, secret):
            if value != None:
                if secret:
                    logger.info("configuration [%s] '%s' set", section, option)
                else:
                    logger.info("configuration [%s] '%s' set to '%s'", section, option, value)
            else:
                if default:
                    value = default
                    if not secret:
                        if self.parser.has_section(section):
                            logger.info("configuration [%s] '%s' set to default of '%s'", section, option, value)
                        else:
                            logger.info("configuration [%s] does not exist: '%s' set to default '%s'", section, option, value)
                    else:
                        logger.info("configuration [%s] '%s' set to default", section, option)
                elif required:
                    logger.critical("Required [%s] '%s' not defined in configuration file, exiting.", section, option)
                    sys.exit("""Required [%s] '%s' not defined in configuration file, exiting.""" % (section, option))
            return value

        def GetText(self, section, option, default = None, required = True, secret = False):
            if (self.parser.has_section(section) and self.parser.has_option(section, option)):
                value = self.parser.get(section, option)
            else:
                value = None
            return self._GetValue(section, option, value, default, required, secret)

        def GetInt(self, section, option, default = None, required = True, secret = False):
            if (self.parser.has_section(section) and self.parser.has_option(section, option)):
                value = self.parser.getint(section, option)
            else:
                value = None
            return self._GetValue(section, option, value, default, required, secret)

        def GetBoolean(self, section, option, default = None, required = True, secret = False):
            if (self.parser.has_section(section) and self.parser.has_option(section, option)):
                value = self.parser.getboolean(section, option)
            else:
                value = None
            return self._GetValue(section, option, value, default, required, secret)

        def GetTextList(self, section, option, default = None, required = True, secret = False, quiet = False):
            if (self.parser.has_section(section) and self.parser.has_option(section, option)):
                text = self.parser.get(section, option)
                values = text.split(',')
                textlist = []
                for value in values:
                    textlist.append(value.strip())
            else:
                textlist = None
            if quiet:
                return textlist
            else:
                return self._GetValue(section, option, textlist, default, required, secret)

        def GetEmailList(self, section, option, default = None, required = True, secret = False):
            emails = self.GetTextList(section, option, default, required, secret, True)
            addresses = []
            for email in emails:
                pieces = email.split('|')
                if len(pieces) == 2:
                    name, address = pieces
                    if valid_email_address(address):
                        addresses.append((name.strip(), address.strip()))
                    else:
                        logger.warning('ignoring invalid email address (%s)', address)
                elif len(pieces) == 1:
                    if valid_email_address(email):
                        addresses.append(email)
                    else:
                        logger.warning('ignoring invalid email address (%s)', email)
                else:
                    logger.warning('ignoring invalid address (%s)', email)
            return self._GetValue(section, option, addresses, default, required, secret)

    class Database:
        def __init__(self):
            self.connection = sqlite3.connect(ng.database_filename, detect_types=sqlite3.PARSE_DECLTYPES)

    class Email:
        def __init__(self):
            self.enabled = ng.config_instance.GetBoolean('Email', 'enabled', False, False)
            if not self.enabled:
                logger.warning('email is disabled')
                return

            try:
                import pyzmail
            except Exception as e:
                logger.critical("fatal exception: %s", e)
                logger.critical("failed to import pyzmail (as user %s), try: 'pip install pyzmail' or disable [Email], exiting.", ng.whoami())
                sys.exit("""Fatal error: failed to import pyzmail (as user %s), try: 'pip install pyzmail' or disable [Email].""" % (ng.whoami()))

            self.email_to = ng.config_instance.GetEmailList('Email', 'to')
            if not len(self.email_to):
                logger.warning('no valid to address configured, email is disabled')
                self.enabled = False
                return

            email_from = ng.config_instance.GetEmailList('Email', 'from')
            if len(email_from) > 1:
                logger.warning('only able to send from one address, using %s', email_from[0])
            elif not len(email_from):
                logger.warning('no valid from address configured, email is disabled')
                self.enabled = False
                return
            self.email_from = email_from[0]

            self.email_hostname = ng.config_instance.GetText('Email', 'smtp_hostname')
            self.email_port = ng.config_instance.GetText('Email', 'smtp_port', None, False)
            self.email_mode = ng.config_instance.GetText('Email', 'smtp_mode', 'normal', False)
            if not self.email_mode in ['normal', 'ssl', 'tls']:
                logger.warning('ignoring invalid email mode (%s), must be one of: normal, ssl, tls', self.email_mode)
                self.email_mode = 'normal'

            self.email_username = ng.config_instance.GetText('Email', 'smtp_username', None, False)
            self.email_password = ng.config_instance.GetText('Email', 'smtp_password', None, False, True)

            self.alerts = []
            self.digest = []
            alerts = ng.config_instance.GetTextList('Email', 'alerts', None, False)
            digests = ng.config_instance.GetTextList('Email', 'digests', None, False)
            for alert in alerts:
                if alert in ng.ALERT_TYPES:
                    self.alerts.append(alert)
                else:
                    logger.warn("ignoring unrecognized alert type (%s), supported types: %s", alert, ng.ALERT_TYPES)
            for digest in digests:
                if digest in ng.DIGEST_TYPES:
                    self.digest.append(digest)
                else:
                    logger.warn("ignoring unrecognized digest type (%s), supported types: %s", digest, ng.DIGEST_TYPES)

        def MailSend(self, subject, encoding, body):
            import pyzmail
            payload, mail_from, rcpt_to, msg_id = pyzmail.generate.compose_mail(ng.email_instance.email_from, ng.email_instance.email_to, subject, encoding, body)
            ret = pyzmail.generate.send_mail(payload, mail_from, rcpt_to, ng.email_instance.email_hostname, ng.email_instance.email_port, ng.email_instance.email_mode, ng.email_instance.email_username, ng.email_instance.email_password)
            if isinstance(ret, dict):
                if ret:
                    logger.warning("failed to send email, failed receipients: %s", ', '.join(ret.keys()))
                else:
                    logger.debug("email sent: %s", ret)
            else:
                logger.warning("email error: %s", ret)

    class Notification:
        def __init__(self):
            self.enabled = ng.config_instance.GetBoolean('Notifications', 'enabled', False, False)
            if not self.enabled:
                logger.warning('notifications are disabled')
                return

            self.alerts = []
            alerts = ng.config_instance.GetTextList('Notifications', 'alerts', None, False)
            for alert in alerts:
                if alert in ng.ALERT_TYPES:
                    self.alerts.append(alert)
                else:
                    logger.warn("ignoring unrecognized alert type (%s), supported types: %s", alert, ng.ALERT_TYPES)

            try:
                import ntfy
            except Exception as e:
                logger.critical("fatal exception: %s", e)
                logger.critical("failed to import ntfy (as user %s), try: 'pip install ntfy' or disable [Notification] alerts, exiting.", ng.whoami())
                sys.exit("""Fatal error: failed to import ntfy (as user %s), try: 'pip install ntfy' or disable [Notification] alerts.""" % (ng.whoami()))

    # Determine who we are, for pretty logging.
    def whoami(self):
        whoami = pwd.getpwuid(os.getuid())
        return whoami[0]

    # Drop root permissions when no longer needed.
    def drop_root(self):
        os.setgroups([])
        os.setgid(grp.getgrnam(self.config_instance.GetText('Security', 'group', ng.DEFAULT_GROUP, False)).gr_gid)
        os.setuid(pwd.getpwnam(self.config_instance.GetText('Security', 'user', ng.DEFAULT_USER, False)).pw_uid)
        logger.info('running as user %s',  self.whoami())

    def set_state(self, key, value, secret = False):
        self.database_lock.acquire()
        self.database_instance.cursor.execute('INSERT OR REPLACE INTO state (key, value) VALUES (?, ?)', (key, value))
        self.database_instance.connection.commit()
        self.database_lock.release()
        if secret:
            logger.info('set key[%s] to hidden value', key)
        else:
            logger.info('set key[%s] to value[%s]', key, value)

    def get_state(self, key, default_value, date = False):
        self.database_instance.cursor.execute('SELECT value FROM state WHERE key=?', (key,));
        value = self.database_instance.cursor.fetchone();
        if value:
            if date:
                logger.debug('returning date: %s', value[0])
                return datetime.datetime.strptime(value[0], "%Y-%m-%d %H:%M:%S.%f")
            else:
                logger.debug('returning value: %s', value[0])
                return value[0]
        else:
            logger.debug('returning default value: %s', default_value)
            return default_value

class ExclusiveFileLock:
    def __init__(self, lockfile):
        self.lockfile = lockfile
        # Create the lockfile if it doesn't already exist.
        self.handle = open(lockfile, 'w')

    # Acquire exclusive, blocking lock.
    def acquire(self):
        fcntl.flock(self.handle, fcntl.LOCK_EX)

    # Release exclusive, blocking lock.
    def release(self):
        fcntl.flock(self.handle, fcntl.LOCK_UN)

    def __del__(self):
        self.handle.close()

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
def main(*pcap):
    logger.info('main process running as user %s',  ng.whoami())

    if pcap:
        # We have daemonized and are not running as root.
        pc = pcap[0]
        ng.database_lock = ExclusiveFileLock(ng.config_instance.GetText('Database', 'lockfile', ng.DEFAULT_DBLOCK, False))
    else:
        # We are running in the foreground as root.
        pcap = get_pcap()
        pc = pcap[0]
        ng.drop_root()
        ng.database_lock = multiprocessing.Lock()

    # At this point we should no longer have/need root privileges.
    assert (os.getuid() != 0) and (os.getgid() != 0), 'Failed to drop root privileges, aborting.'

    parent_conn, child_conn = multiprocessing.Pipe()
    child = multiprocessing.Process(name='wiretap', target=wiretap, args=[pc, child_conn])
    child.daemon = True
    child.start()

    try:
        ng.database_instance = ng.Database()
    except Exception as e:
        logger.critical("%s", e)
        logger.critical("failed to open or create %s (as user %s), exiting", ng.database_filename, ng.whoami())
        sys.exit("""Fatal error: failed to open or create database file %s (as user %s).""" % (ng.database_filename, ng.whoami()))
    logger.info('opened %s as user %s', ng.database_filename, ng.whoami());
    ng.database_instance.cursor = ng.database_instance.connection.cursor()
    # http://www.sqlite.org/wal.html
    ng.database_instance.cursor.execute('PRAGMA journal_mode=WAL')

    create_database()
    update_database()

    ng.active_timeout = ng.config_instance.GetInt('Listen', 'active_timeout', 60 * 60 * 2, False)
    ng.delay = ng.config_instance.GetInt('Listen', 'delay', 15, False)
    if (ng.delay > 30):
        ng.delay = 30
    elif (ng.delay < 1):
        ng.delay = 1

    ng.email_instance = ng.Email()

    run = True
    last_heartbeat = datetime.datetime.now()
    while run:
        now = datetime.datetime.now()
        logger.debug('top of master while loop: %s', now)

        parent_conn.send(HEARTBEAT)
        heartbeat = False
        while parent_conn.poll():
            message = parent_conn.recv()
            if (message == HEARTBEAT):
                heartbeat = True
        # It's possible to receive multiple heartbeats, but many or one is the same to us.
        if heartbeat:
            logger.debug('received heartbeat from wiretap process')
            last_heartbeat = now

        logger.debug('sleeping for %d seconds', ng.delay)
        time.sleep(ng.delay)
        identify_macs()
        detect_stale_ips()
        detect_netscans()
        detect_anomalies()
        send_notifications()
        send_email_alerts()
        send_email_digests()
        garbage_collection()

        # If we haven't heard from the wiretap process in >1 minute, exit.
        time_to_exit = last_heartbeat + datetime.timedelta(minutes=1)
        if (now >= time_to_exit):
            run = False
    logger.critical('No heartbeats from wiretap process for >1 minute, exiting.')

# Perform simplistic email address validation.
def valid_email_address(address):
    if not '@' in parseaddr(address)[1]:
        return False
    else:
        return True

def get_pcap():
    import sys
    logger.info('entering get_pcap() as user %s',  ng.whoami())
    assert os.getuid() == 0, 'Unable to initiate pcap, must be run as root.'

    try:
        import pcap
    except Exception as e:
        logger.critical("fatal exception: %s", e)
        logger.critical("failed to import pcap, try: 'pip install pypcap', exiting")
        sys.exit("Fatal error: failed to import pcap, try: 'pip install pypcap', exiting")

    devices = pcap.findalldevs()
    logger.info('identified devices: %s', devices)
    if len(devices) <= 0:
      logger.critical('no available devices (are you in a jail?), exiting')
      sys.exit("Fatal error: pcap identified no devices, try running tcpdump manually to debug.")

    interface = ng.config_instance.GetText('Listen', 'interface', devices[0], False)
    local_net, local_mask = pcap.lookupnet(interface)

    try:
        pc = pcap.pcap(name=interface, snaplen=256, promisc=True, timeout_ms = 100, immediate=True)
        pc.setfilter('arp')
        logger.debug("pcap: %s", pc)
    except Exception as e:
        logger.critical("fatal exception: %s", e)
        logger.critical("failed to invoke pcap, exiting")
        sys.exit("""Failed to invoke pcap. Fatal exception: %s, exiting.""" % e)

    logger.warning('listening for arp traffic on %s: %s/%s', interface, socket.inet_ntoa(local_net), socket.inet_ntoa(local_mask))
    return [pc]

# Child process: wiretap, uses pcap to sniff arp packets.
def wiretap(pc, child_conn):
    import sys

    if ng.daemonize:
        # We use a lock file when daemonized, as this allows netgraspctl to coordinate
        # with the daemon. Over-write the master-process handler with our own.
        ng.database_lock = ExclusiveFileLock(ng.config_instance.GetText('Database', 'lockfile', ng.DEFAULT_DBLOCK, False))

    try:
        import dpkt
    except Exception as e:
        logger.critical("fatal exception: %s", e)
        logger.critical("failed to import dpkt, try: 'pip install dpkt', exiting")
        sys.exit("Fatal error: failed to import dpkt, try: 'pip install dpkt', exiting")
    try:
        import pcap
    except Exception as e:
        logger.critical("fatal exception: %s", e)
        logger.critical("failed to import pcap, try: 'pip install pypcap', exiting")
        sys.exit("Fatal error: failed to import pcap, try: 'pip install pypcap', exiting")

    assert (os.getuid() != 0) and (os.getgid() != 0), 'Failed to drop root privileges, aborting.'

    try:
        ng.database_instance = ng.Database()
    except Exception as e:
        logger.critical("%s", e)
        logger.critical("failed to open or create %s (as user %s), exiting", ng.database_filename, ng.whoami())
        sys.exit("""Fatal error: failed to open or create database file %s (as user %s).""" % (ng.database_filename, ng.whoami()))
    logger.info('opened %s as user %s', ng.database_filename, ng.whoami());
    ng.database_instance.cursor = ng.database_instance.connection.cursor()

    run = True
    last_heartbeat = datetime.datetime.now()
    while run:
        now = datetime.datetime.now()
        logger.debug('[%d] top of while loop: %s', run, now)

        child_conn.send(HEARTBEAT)

        heartbeat = False
        while child_conn.poll():
            message = child_conn.recv()
            if (message == HEARTBEAT):
                heartbeat = True
        # It's possible to receive multiple heartbeats, but many or one is the same to us.
        if heartbeat:
            logger.debug('received heartbeat from main process')
            last_heartbeat = now

        # Wait an arp packet, then loop again.
        pc.loop(1, received_arp, child_conn)

        # If we haven't heard from the main process in >1 minute, exit.
        time_to_exit = last_heartbeat + datetime.timedelta(minutes=1)
        if (now >= time_to_exit):
            run = False
    logger.critical('No heartbeats from main process for >1 minute, exiting.')

def ip_seen(src_ip, src_mac, dst_ip, dst_mac, request):
    logger.debug('entering ip_seen(%s, %s, %s, %s, %d)', src_ip, src_mac, dst_ip, dst_mac, request)
    now = datetime.datetime.now()

    ng.database_lock.acquire()
    ng.database_instance.cursor.execute('INSERT INTO arplog (src_mac, src_ip, dst_mac, dst_ip, request, timestamp) VALUES(?, ?, ?, ?, ?, ?)', (src_mac, src_ip, dst_mac, dst_ip, request, now))
    ng.database_instance.connection.commit()
    ng.database_lock.release()
    logger.debug('inserted into arplog')

    # @TODO Research and see if we should be treating these another way.
    if (src_ip == '0.0.0.0' or src_mac == ng.BROADCAST):
        logger.info('Ignoring IP source of %s [%s], dst %s [%s]', src_ip, src_mac, dst_ip, dst_mac);
        return False

    # Check if we've seen this IP, MAC pair before.
    active, lastSeen, lastRequested, counter, sid, did, changed_ip = [False, False, False, 0, 0, 0, False]
    logger.debug('ip_seen query 1')
    ng.database_instance.cursor.execute('SELECT active, lastSeen, lastRequested, counter, sid, did FROM seen WHERE ip=? AND mac=? ORDER BY lastSeen DESC LIMIT 1', (src_ip, src_mac))
    result = ng.database_instance.cursor.fetchone()
    if result:
        active, lastSeen, lastRequested, counter, sid, did = result

    if not result:
        # Check if we've seen this MAC, hostname pair before, it may have gotten assigned a new IP.
        # In the event of the same IP and a different hostname, we treat this like a different device
        # (though it's likely a vm, jail, or alias). @TODO Revisit this.
        hostname = dns_lookup(src_ip)
        logger.debug('ip_seen query 2')
        ng.database_instance.cursor.execute("SELECT seen.active, seen.lastSeen, seen.lastRequested, seen.counter, seen.sid, seen.did FROM seen LEFT JOIN host ON seen.mac = host.mac WHERE seen.mac = ? AND host.hostname = ? ORDER BY seen.lastSeen DESC LIMIT 1", (src_mac, hostname))
        result = ng.database_instance.cursor.fetchone()
        if result:
            active, lastSeen, lastRequested, counter, sid, did = result
            changed_ip = True

    if not result:
        # Check if we've seen this IP be requested before.
        logger.debug('ip_seen query 3')
        ng.database_instance.cursor.execute('SELECT active, lastSeen, lastRequested, counter, sid, did FROM seen WHERE ip=? AND mac=? ORDER BY lastSeen DESC LIMIT 1', (src_ip, ng.BROADCAST))
        result = ng.database_instance.cursor.fetchone()
        if result:
            active, lastSeen, lastRequested, counter, sid, did = result

    ng.database_lock.acquire()
    log_event(src_ip, src_mac, ng.EVENT_SEEN)
    if changed_ip:
        log_event(src_ip, src_mac, ng.EVENT_CHANGED_IP)
        logger.info('[%d] (%s) has a new ip [%s]', did, src_mac, src_ip)
    if active:
        if lastSeen:
            # has been active recently
            logger.debug('%s (%s) is active', src_ip, src_mac)
            ng.database_instance.cursor.execute('UPDATE seen set ip=?, mac=?, lastSeen=?, counter=?, active=1 WHERE sid=?', (src_ip, src_mac, now, counter + 1, sid))
        else:
            # has not been active recently, but was requested recently
            if first_seen(src_ip, src_mac):
                # First time we've seen IP since it was stale.
                log_event(src_ip, src_mac, ng.EVENT_SEEN_FIRST_RECENT)
                lastSeen = last_seen(src_ip, src_mac)
                if lastSeen:
                    timeSince = datetime.datetime.now() - lastSeen
                    logger.info('[%d] %s (%s) is active again (after %s)', did, src_ip, src_mac, timeSince)
                else:
                    logger.warning("We've seen a packet %s [%s] with a firstSeen (%s) but no lastSeen -- this shouldn't happen.", src_ip, src_mac, first_seen(src_ip, src_mac))
            else:
                # First time we've actively seen this IP.
                log_event(src_ip, src_mac, ng.EVENT_SEEN_FIRST)
                log_event(src_ip, src_mac, ng.EVENT_SEEN_FIRST_RECENT)
                logger.info('[%d] %s (%s) is active, first time seeing', did, src_ip, src_mac)

            # @TODO properly handle multiple active occurences of the same IP
            ng.database_instance.cursor.execute('UPDATE seen set ip=?, mac=?, firstSeen=?, lastSeen=?, counter=?, active=1 WHERE sid=?', (src_ip, src_mac, now, now, counter + 1, sid))
    else:
        if did:
            # First time we've seen this IP recently.
            log_event(src_ip, src_mac, ng.EVENT_SEEN_FIRST_RECENT)
            logger.info('[%d] %s (%s) is active, first time seeing recently', did, src_ip, src_mac)
        else:
            # First time we've seen this IP.
            ng.database_instance.cursor.execute("SELECT MAX(did) + 1 FROM seen")
            row = fetchone()
            if row:
                did = row
            else:
                did = 1
            log_event(src_ip, src_mac, ng.EVENT_SEEN_FIRST)
            log_event(src_ip, src_mac, ng.EVENT_SEEN_FIRST_RECENT)
            logger.info('[%d] %s (%s) is active, first time seeing', did, src_ip, src_mac)
        ng.database_instance.cursor.execute('INSERT INTO seen (did, mac, ip, firstSeen, lastSeen, counter, active, self) VALUES(?, ?, ?, ?, ?, 1, 1, ?)', (did, src_mac, src_ip, now, now, ip_is_mine(src_ip)))
    ng.database_instance.connection.commit()
    ng.database_lock.release()

def ip_request(ip, mac, src_ip, src_mac):
    logger.debug('entering ip_request(%s, %s, %s, %s)', ip, mac, src_ip, src_mac)
    now = datetime.datetime.now()

    if ((ip == src_ip) or (mac == src_mac)):
        logger.debug('requesting self, ignoring')
        return

    active = False
    lastRequested = False
    ng.database_instance.cursor.execute('SELECT active, lastRequested, sid FROM seen WHERE ip=? AND mac=? AND active=1', (ip, mac))
    requested = ng.database_instance.cursor.fetchone()
    if requested:
        active = requested[0]
        lastRequested = requested[1]
        sid = requested[2]
    else:
        if (mac == ng.BROADCAST):
            # Maybe we already have seen a request for this address
            ng.database_instance.cursor.execute('SELECT active, lastRequested, sid FROM seen WHERE ip=? AND mac=? AND active=1', (ip, ng.BROADCAST))
            requested = ng.database_instance.cursor.fetchone()
            if requested:
                active = requested[0]
                lastRequested = requested[1]
                sid = requested[2]
            else:
                # Maybe the IP has been seen already
                ng.database_instance.cursor.execute('SELECT active, lastRequested, sid FROM seen WHERE ip=? AND active=1', (ip,))
                requested = ng.database_instance.cursor.fetchone()
                if requested:
                    active = requested[0]
                    lastRequested = requested[1]
                    sid = requested[2]

    ng.database_lock.acquire()
    log_event(ip, mac, ng.EVENT_REQUESTED)
    if active:
        # Update:
        ng.database_instance.cursor.execute('UPDATE seen set lastRequested=? WHERE sid=?', (now, sid))
        logger.debug('%s (%s) requested', ip, mac)
    else:
        # First time we've seen a request for this IP.
        log_event(ip, mac, ng.EVENT_REQUESTED_FIRST)
        ng.database_instance.cursor.execute("INSERT INTO seen (mac, ip, firstRequested, lastRequested, counter, active, self) VALUES(?, ?, ?, ?, 1, 1, ?)", (mac, ip, now, now, ip_is_mine(ip)))
        logger.info('%s (%s) requested, first time seeing', ip, mac)
    ng.database_instance.connection.commit()
    ng.database_lock.release()

# Assumes we already have the database lock.
def log_event(ip, mac, event):
    now = datetime.datetime.now()
    ng.database_instance.connection.execute('INSERT INTO event (mac, ip, timestamp, processed, event) VALUES(?, ?, ?, ?, ?)', (mac, ip, now, 0, event))

def ip_is_mine(ip):
    return (ip == socket.gethostbyname(socket.gethostname()))

# Database definitions.
def create_database():
    ng.database_lock.acquire()
    logger.debug('Creating database tables, if not already existing.')

    # Create state table.
    ng.database_instance.cursor.execute("""
      CREATE TABLE IF NOT EXISTS state(
        id INTEGER PRIMARY KEY,
        key VARCHAR UNIQUE,
        value TEXT
      )
    """)

    # Create seen table.
    ng.database_instance.cursor.execute("""
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
    ng.database_instance.cursor.execute("CREATE INDEX IF NOT EXISTS idx_ip_mac_firstSeen ON seen (ip, mac, firstSeen)")
    ng.database_instance.cursor.execute("CREATE INDEX IF NOT EXISTS idx_ip_mac_lastSeen ON seen (ip, mac, lastSeen)")
    ng.database_instance.cursor.execute("CREATE INDEX IF NOT EXISTS idx_ip_mac_firstRequested ON seen (ip, mac, firstRequested)")
    ng.database_instance.cursor.execute("CREATE INDEX IF NOT EXISTS idx_ip_mac_lastRequested ON seen (ip, mac, lastRequested)")
    ng.database_instance.cursor.execute("CREATE INDEX IF NOT EXISTS idx_active_lastSeen ON seen (active, lastSeen)")
    ng.database_instance.cursor.execute("CREATE INDEX IF NOT EXISTS idx_ip_mac_active ON seen (ip, mac, active)")
    # PRAGMA index_list(seen)

    # Create arplog table.
    ng.database_instance.cursor.execute("""
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
    ng.database_instance.cursor.execute("CREATE INDEX IF NOT EXISTS idx_srcip_timestamp_request ON arplog (src_ip, timestamp, request)")

    # Create event table.
    ng.database_instance.cursor.execute("""
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
    ng.database_instance.cursor.execute("CREATE INDEX IF NOT EXISTS idx_event_timestamp_processed ON event (event, timestamp, processed)")
    ng.database_instance.cursor.execute("CREATE INDEX IF NOT EXISTS idx_timestamp_processed ON event (timestamp, processed)")
    # PRAGMA index_list(event)

    # Create vendor table.
    ng.database_instance.cursor.execute("""
      CREATE TABLE IF NOT EXISTS vendor(
        vid INTEGER PRIMARY KEY,
        mac TEXT,
        vendor TEXT,
        customname TEXT
      )
    """)
    ng.database_instance.cursor.execute("CREATE INDEX IF NOT EXISTS idx_mac ON vendor (mac)")

    # Create host table.
    ng.database_instance.cursor.execute("""
      CREATE TABLE IF NOT EXISTS host(
        hid INTEGER PRIMARY KEY,
        mac TEXT,
        ip TEXT,
        hostname TEXT,
        customname TEXT
      )
    """)
    ng.database_instance.cursor.execute("CREATE INDEX IF NOT EXISTS idx_ip_mac ON host (ip, mac)")
    ng.database_instance.connection.commit()
    ng.database_lock.release()

def update_database():
    # Update #1: add did column to seen table, populate
    try:
        ng.database_instance.cursor.execute("SELECT did FROM seen LIMIT 1")
    except Exception as e:
        logger.debug(e)
        logger.debug('applying update #1 to database: adding did column to seen, populating')
        ng.database_lock.acquire()
        ng.database_instance.cursor.execute("ALTER TABLE seen ADD COLUMN did INTEGER")
        # Prior to this we assumed a new IP was a new device.
        ng.database_instance.cursor.execute("SELECT DISTINCT ip, mac FROM seen")
        rows = ng.database_instance.cursor.fetchall()
        did = 1
        for row in rows:
            ip, mac = row
            ng.database_instance.cursor.execute("UPDATE seen SET did = ? WHERE ip = ? AND mac = ?", (did, ip, mac))
            did += 1
        ng.database_instance.connection.commit()
        ng.database_lock.release()

# We've sniffed an arp packet off the wire.
def received_arp(hdr, data, child_conn):
    packet = dpkt.ethernet.Ethernet(data)
    src_ip = socket.inet_ntoa(packet.data.spa)
    src_mac = "%x:%x:%x:%x:%x:%x" % struct.unpack("BBBBBB", packet.src)
    dst_ip = socket.inet_ntoa(packet.data.tpa)
    dst_mac = "%x:%x:%x:%x:%x:%x" % struct.unpack("BBBBBB", packet.dst)
    if (packet.data.op == dpkt.arp.ARP_OP_REQUEST):
        logger.debug('ARP request from %s (%s) to %s (%s)', src_ip, src_mac, dst_ip, dst_mac)
        ip_seen(src_ip, src_mac, dst_ip, dst_mac, True)
        ip_request(dst_ip, dst_mac, src_ip, src_mac)
    elif (packet.data.op == dpkt.arp.ARP_OP_REPLY):
        ip_seen(src_ip, src_mac, dst_ip, dst_mac, False)
        logger.debug('ARP reply from %s (%s) to %s (%s)', src_ip, src_mac, dst_ip, dst_mac)

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
    ng.database_instance.cursor.execute('SELECT did FROM seen WHERE ip=? AND mac=? ORDER BY did DESC LIMIT 1', (ip, mac))
    did = ng.database_instance.cursor.fetchone()
    if not did:
        hostname = dns_lookup(ip)
        ng.database_instance.cursor.execute("SELECT seen.did FROM seen LEFT JOIN host ON seen.mac = host.mac WHERE seen.mac = ? AND host.hostname = ? ORDER BY seen.did DESC LIMIT 1", (src_mac, hostname))
        did = ng.database_instance.cursor.fetchone()
    if not did:
        ng.database_instance.cursor.execute('SELECT did FROM seen WHERE ip=? AND mac=? ORDER BY did DESC LIMIT 1', (ip, ng.BROADCAST,))
        did = ng.database_instance.cursor.fetchone()

    if did:
        return did[0]
    else:
        return False

def first_seen(ip, mac):
    did = get_did(ip, mac)
    ng.database_instance.cursor.execute('SELECT firstSeen FROM seen WHERE did = ? AND firstSeen NOT NULL ORDER BY firstSeen ASC LIMIT 1', (did,))
    active = ng.database_instance.cursor.fetchone()
    if active:
        return active[0]
    else:
        return False

def first_seen_recently(ip, mac):
    did = get_did(ip, mac)
    ng.database_instance.cursor.execute('SELECT firstSeen FROM seen WHERE did = ? AND firstSeen NOT NULL ORDER BY firstSeen DESC LIMIT 1', (did,))
    recent = ng.database_instance.cursor.fetchone()
    if recent:
        return recent[0]
    else:
        return False

def last_seen(ip, mac):
    did = get_did(ip, mac)
    ng.database_instance.cursor.execute('SELECT lastSeen FROM seen WHERE did=? AND lastSeen NOT NULL ORDER BY lastSeen DESC LIMIT 1', (did,))
    active = ng.database_instance.cursor.fetchone()
    if active:
        return active[0]
    else:
        return False

def previously_seen(ip, mac):
    did = get_did(ip, mac)
    ng.database_instance.cursor.execute('SELECT lastSeen FROM seen WHERE did=? AND lastSeen NOT NULL AND active != 1 ORDER BY lastSeen DESC LIMIT 1', (did,))
    previous = ng.database_instance.cursor.fetchone()
    if previous:
        return previous[0]
    else:
        return False

def first_requested(ip, mac):
    did = get_did(ip, mac)
    ng.database_instance.cursor.execute('SELECT firstRequested FROM seen WHERE did=? AND firstRequested NOT NULL ORDER BY firstRequested ASC LIMIT 1', (did,))
    active = ng.database_instance.cursor.fetchone()
    if active:
        return active[0]
    else:
        return False

def last_requested(ip, mac):
    did = get_did(ip, mac)
    ng.database_instance.cursor.execute('SELECT lastRequested FROM seen WHERE did=? AND lastRequested NOT NULL ORDER BY lastRequested DESC LIMIT 1', (did,))
    last = ng.database_instance.cursor.fetchone()
    if last:
        return last[0]
    else:
        return False

# Mark IP/MAC pairs as no longer active if we've not seen ARP activity for >active_timeout seconds
def detect_stale_ips():
    logger.debug('entering detect_stale_ips()')
    stale = datetime.datetime.now() - datetime.timedelta(seconds=ng.active_timeout)

    ng.database_instance.cursor.execute('SELECT mac, ip, firstSeen, lastSeen FROM seen WHERE active = 1 AND lastSeen < ?', (stale,))
    rows = ng.database_instance.cursor.fetchall()
    if rows:
        ng.database_lock.acquire()

    for row in rows:
        mac, ip, firstSeen, lastSeen = row
        if (firstSeen and lastSeen):
            timeActive = lastSeen - firstSeen
        else:
            timeActive = 'unknown'
        log_event(ip, mac, ng.EVENT_STALE)
        logger.info("%s [%s] is no longer active (was active for %s)", ip, mac, timeActive)
        ng.database_instance.cursor.execute('UPDATE seen SET active = 0 WHERE ip=? AND mac=?', (ip, mac))

    if rows:
        ng.database_instance.connection.commit()
        ng.database_lock.release()

def detect_netscans():
    logger.debug('entering detect_netscans()')
    now = datetime.datetime.now()

    three_minutes_ago = now - datetime.timedelta(minutes=3)
    ng.database_instance.cursor.execute('SELECT COUNT(DISTINCT(dst_ip)) AS count, src_mac, src_ip FROM arplog WHERE request=1 AND timestamp>=? GROUP BY src_ip HAVING count > 50', (three_minutes_ago,))
    scans = ng.database_instance.cursor.fetchall()
    if scans:
        ng.database_lock.acquire()
    for scan in scans:
        count, src_mac, src_ip = scan
        ng.database_instance.cursor.execute("SELECT eid FROM event WHERE mac=? AND ip=? AND event=? AND timestamp>?", (src_mac, src_ip, ng.EVENT_SCAN, three_minutes_ago))
        already_detected = ng.database_instance.cursor.fetchone()
        if not already_detected:
            ng.database_instance.cursor.execute('INSERT INTO event (mac, ip, timestamp, processed, event) VALUES(?, ?, ?, 0, ?)', (src_mac, src_ip, now, ng.EVENT_SCAN))
            logger.info('Detected network scan by %s [%s]', src_ip, src_mac)
    if scans:
        ng.database_instance.connection.commit()
        ng.database_lock.release()

def detect_anomalies():
    logger.debug('entering detect_anomalies()')
    now = datetime.datetime.now()
    stale = datetime.datetime.now() - datetime.timedelta(seconds=ng.active_timeout)

    # Multiple MAC's with the same IP.
    ng.database_instance.cursor.execute("SELECT COUNT(*) as count, ip FROM seen WHERE active = 1 AND mac != ? GROUP BY ip HAVING count > 1", (ng.BROADCAST,))
    duplicates = ng.database_instance.cursor.fetchall()
    if duplicates:
        ng.database_lock.acquire()
    for duplicate in duplicates:
        count, ip = duplicate
        ng.database_instance.cursor.execute("SELECT ip, mac, sid, did FROM seen WHERE ip = ? AND active = 1;", (ip,))
        details = ng.database_instance.cursor.fetchall()
        for detail in details:
            ip, mac, sid, did = detail
            ng.database_instance.cursor.execute("SELECT eid FROM event WHERE mac=? AND ip=? AND event=? AND timestamp>?", (mac, ip, ng.EVENT_DUPLICATE_IP, stale))
            already_detected = ng.database_instance.cursor.fetchone()
            if not already_detected:
                ng.database_instance.cursor.execute('INSERT INTO event (mac, ip, timestamp, processed, event) VALUES(?, ?, ?, 0, ?)', (mac, ip, now, ng.EVENT_DUPLICATE_IP))
                logger.info('Detected multiple MACs with same IP %s [%s]', ip, mac)
    if duplicates:
        ng.database_instance.connection.commit()
        ng.database_lock.release()

    # Multiple IP's with the same MAC.
    ng.database_instance.cursor.execute("SELECT COUNT(*) as count, mac FROM seen WHERE active = 1 AND mac != ? GROUP BY mac HAVING count > 1", (ng.BROADCAST,))
    duplicates = ng.database_instance.cursor.fetchall()
    if duplicates:
        ng.database_lock.acquire()
    for duplicate in duplicates:
        count, mac = duplicate
        ng.database_instance.cursor.execute("SELECT ip, mac, sid, did FROM seen WHERE mac = ? AND active = 1;", (mac,))
        details = ng.database_instance.cursor.fetchall()
        for detail in details:
            ip, mac, sid, did = detail
            ng.database_instance.cursor.execute("SELECT eid FROM event WHERE mac=? AND ip=? AND event=? AND timestamp>?", (mac, ip, ng.EVENT_DUPLICATE_MAC, stale))
            already_detected = ng.database_instance.cursor.fetchone()
            if not already_detected:
                ng.database_instance.cursor.execute('INSERT INTO event (mac, ip, timestamp, processed, event) VALUES(?, ?, ?, 0, ?)', (mac, ip, now, ng.EVENT_DUPLICATE_MAC))
                logger.info('Detected multiple IPs with same MAC %s [%s]', ip, mac)
    if duplicates:
        ng.database_instance.connection.commit()
        ng.database_lock.release()

def send_notifications():
    logger.debug('entering send_notifications()')

    if not ng.notification_instance.enabled:
        logger.debug('notifications disabled')
        return False

    if not ng.notification_instance.alerts:
        logger.debug('no notification alerts configured')
        return False

    import ntfy
    timer = Timer()

    day = datetime.datetime.now() - datetime.timedelta(days=1)
    ng.database_instance.cursor.execute('SELECT eid, mac, ip, timestamp, event, processed FROM event WHERE NOT (processed & 8) AND event IN ('+ ','.join('?'*len(ng.notification_instance.alerts)) + ')', ng.notification_instance.alerts)

    rows = ng.database_instance.cursor.fetchall()
    if rows:
        ng.database_lock.acquire()

    counter = 0
    for row in rows:
        eid, mac, ip, timestamp, event, processed = row
        # Give up the lock occasionally while processing a large number of rows, allowing the
        # wiretap process to work if needed, avoiding potential timeout.
        counter = counter + 1
        if (counter > MAXPROCESS):
            logger.debug("updated 100 events, releasing/regrabbing lock")
            ng.database_instance.connection.commit()
            ng.database_lock.release()
            if (timer.elapsed() > MAXSECONDS):
                # We've been processing notifications too long, quit for now and come back later.
                logger.debug("processing notifications >%d seconds, quitting for now", MAXSECONDS)
                return
            counter = 0
            ng.database_lock.acquire()

        logger.debug('processing event %d for %s [%s] at %s', eid, ip, mac, timestamp)

        # only send notifications for configured events
        if event in ng.notification_instance.alerts:
            logger.info('event %s [%d] in %s, generating notification alert', event, eid, ng.notification_instance.alerts)
            firstSeen = first_seen(ip, mac)
            lastSeen = first_seen_recently(ip, mac)
            previouslySeen = previously_seen(ip, mac)
            title = """Netgrasp alert: %s""" % (event)
            body = """%s with IP %s [%s], seen %s, previously seen %s, first seen %s""" % (name_ip(mac, ip), ip, mac, pretty_date(lastSeen), pretty_date(previouslySeen), pretty_date(firstSeen))
            ntfy.notify(body, title)
            ng.database_instance.cursor.execute('UPDATE event SET processed = ? WHERE eid = ?', (processed + 8, eid))
        else:
            logger.debug('event %s [%d] NOT in %s', event, eid, ng.notification_instance.alerts)
    if rows:
        ng.database_instance.connection.commit()
        ng.database_lock.release()

def send_email_alerts():
    logger.debug('entering send_email_alerts()')

    if not ng.email_instance.enabled:
        logger.debug('email disabled')
        return False

    if not ng.email_instance.alerts:
        logger.debug('no email alerts configured')
        return False

    day = datetime.datetime.now() - datetime.timedelta(days=1)

    timer = Timer()

    ng.database_instance.cursor.execute('SELECT eid, mac, ip, timestamp, event, processed FROM event WHERE NOT (processed & 1)');
    rows = ng.database_instance.cursor.fetchall()
    if rows:
        ng.database_lock.acquire()

    counter = 0
    for row in rows:
        eid, mac, ip, timestamp, event, processed = row
        # Give up the lock occasionally while processing a large number of rows, allowing the
        # wiretap process to work if needed, avoiding potential timeout.
        counter = counter + 1
        if (counter > MAXPROCESS):
            logger.debug("updated 100 events, releasing/regrabbing lock")
            ng.database_instance.connection.commit()
            ng.database_lock.release()
            if (timer.elapsed() > MAXSECONDS):
                # We've been processing alerts too long, quit for now and come back later.
                logger.debug("processing email alerts >%d seconds, quitting for now", MAXSECONDS)
                return
            counter = 0
            ng.database_lock.acquire()

        logger.debug('processing event %d for %s [%s] at %s', eid, ip, mac, timestamp)
        alerted = True
        # only send emails for configured events
        if event in ng.email_instance.alerts:
            logger.info('event %s [%d] in %s, generating notification email', event, eid, ng.email_instance.alerts)
            # get more information about this entry ...
            ng.database_instance.cursor.execute('SELECT s.active, s.self, v.vendor, v.customname, h.hostname, h.customname FROM seen s LEFT JOIN vendor v ON s.mac = v.mac LEFT JOIN host h ON s.mac = h.mac AND s.ip = h.ip WHERE s.mac=? AND s.ip=? ORDER BY lastSeen DESC', (mac, ip))
            info = ng.database_instance.cursor.fetchone()
            if not info:
                ng.database_instance.connection.commit()
                ng.database_lock.release()
                logger.warning("Event for ip %s [%s] that we haven't seen", ip, mac)
                return
            active, self, vendor, vendor_customname, hostname, host_customname = info
            firstSeen = first_seen(ip, mac)
            firstRequested = first_requested(ip, mac)
            lastSeen = last_seen(ip, mac)
            previouslySeen = previously_seen(ip, mac)
            lastRequested = last_requested(ip, mac)
            subject = """Netgrasp alert: %s""" % (event)
            body = """IP %s [%s]\n  Vendor: %s\nCustom name: %s\n  Hostname: %s\n  Custom host name: %s\n  First seen: %s\n  Most recently seen: %s\n  Previously seen: %s\n  First requested: %s\n  Most recently requested: %s\n  Currently active: %d\n  Self: %d\n""" % (ip, mac, vendor, vendor_customname, hostname, host_customname, pretty_date(firstSeen), pretty_date(lastSeen), pretty_date(previouslySeen), pretty_date(firstRequested), pretty_date(lastRequested), active, self)
            ng.database_instance.cursor.execute('SELECT DISTINCT dst_ip, dst_mac FROM arplog WHERE src_mac=? AND timestamp>=?', (mac, day))
            results = ng.database_instance.cursor.fetchall()
            if results:
                body += """\nIn the last day, this device talked to:"""
            for peer in results:
                body += """\n - %s (%s)""" % (peer[0], name_ip(peer[1], peer[0]))
            ng.email_instance.MailSend(subject, 'iso-8859-1', (body, 'us-ascii'))
        else:
            logger.debug('event %s [%d] NOT in %s', event, eid, ng.email_instance.alerts)
        if alerted:
            ng.database_instance.cursor.execute('UPDATE event SET processed = ? WHERE eid = ?', (processed + 1, eid))

    if rows:
        ng.database_instance.connection.commit()
        ng.database_lock.release()

# Finds new MAC addresses and assigns them a name.
def identify_macs():
    logger.debug('entering identify_macs()')
    import re
    import httplib

    ng.database_instance.cursor.execute('SELECT s.mac, s.ip FROM seen s LEFT JOIN vendor v ON s.mac = v.mac WHERE s.active = 1 AND v.mac IS NULL')
    rows = ng.database_instance.cursor.fetchall()
    for row in rows:
        raw_mac, ip = row
        if re.match("[0-9a-f]{2}([-:])[0-9a-f]{2}(\\1[0-9a-f]{2}){4}$", raw_mac.lower()):
            mac = raw_mac
        else:
            mac = []
            pieces = raw_mac.split(':')
            if not pieces:
                pieces = row_mac.split('-')
            for piece in pieces:
                if len(piece) == 1:
                    piece = '0'+piece
                mac.append(piece)
            mac = ":".join(mac)
        logger.debug('Looking up vendor for %s [%s]', ip, raw_mac)
        http = httplib.HTTPConnection('api.macvendors.com', 80)
        url = """/%s""" % mac
        http.request("GET", url)
        response = http.getresponse()
        ng.database_lock.acquire()
        if response.status == 200 and response.reason == 'OK':
            vendor = response.read()
            logger.info('Identified %s [%s] as %s', ip, raw_mac, vendor)
            ng.database_instance.cursor.execute('INSERT INTO vendor (mac, vendor) VALUES (?, ?)', (raw_mac, vendor))
        else:
            logger.info('Failed identify vendor for [%s]', raw_mac)
            ng.database_instance.cursor.execute("INSERT INTO vendor (mac, vendor) VALUES (?, 'unknown')", (raw_mac,))
        ng.database_instance.connection.commit()
        ng.database_lock.release()

    ng.database_instance.cursor.execute('SELECT s.mac, s.ip FROM seen s LEFT JOIN host h ON s.mac = h.mac AND s.ip = h.ip WHERE s.active = 1 AND h.mac IS NULL')
    rows = ng.database_instance.cursor.fetchall()
    for row in rows:
        mac, ip = row
        hostname = dns_lookup(ip)
        ng.database_lock.acquire()
        ng.database_instance.cursor.execute('INSERT INTO host (mac, ip, hostname) VALUES (?, ?, ?)', (mac, ip, hostname))
        ng.database_instance.connection.commit()
        ng.database_lock.release()

def dns_lookup(ip):
    logger.debug('entering gethostbyaddr(%s)', ip)
    try:
        hostname, aliaslist, ipaddrlist = socket.gethostbyaddr(ip)
        logger.debug("hostname(%s), aliaslist(%s), ipaddrlist(%s)", hostname, aliaslist, ipaddrlist)
    except Exception as e:
        logger.debug('gethostbyaddr failed: %s', e)
        hostname = 'unknown'
        logger.debug("hostname(%s)", hostname)
    return hostname

# Provides a human-friendly name for a mac-ip pair.
def name_ip(mac, ip):
    logger.debug('entering name_ip(%s, %s)', mac, ip)
    if (mac == ng.BROADCAST):
        ng.database_instance.cursor.execute("SELECT h.mac, h.ip, h.customname, h.hostname, v.customname, v.vendor FROM host h LEFT JOIN vendor v ON h.mac = v.mac WHERE h.ip=?", (ip,))
    else:
        ng.database_instance.cursor.execute("SELECT h.mac, h.ip, h.customname, h.hostname, v.customname, v.vendor FROM host h LEFT JOIN vendor v ON h.mac = v.mac WHERE h.ip=? AND h.mac=?", (ip, mac))
    detail = ng.database_instance.cursor.fetchone()
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
def send_email_digests():
    logger.debug('entering send_email_digests()')

    if not ng.email_instance.enabled:
        return False

    if not ng.email_instance.digest:
        logger.debug('no digests configured')
        return False

    timer = Timer()
    now = datetime.datetime.now()

    digests = ['daily', 'weekly']
    for digest in digests:
        if (digest == 'daily'):
            timestamp_string = 'daily_digest_timestamp'
            future_digest_timestamp = now + datetime.timedelta(days=1)
            time_period = now - datetime.timedelta(days=1)
            time_period_description = '24 hours'
            previous_time_period = now - datetime.timedelta(days=2)
        elif (digest == 'weekly'):
            timestamp_string = 'weekly_digest_timestamp'
            future_digest_timestamp = now + datetime.timedelta(weeks=1)
            time_period = now - datetime.timedelta(weeks=1)
            time_period_description = '7 days'
            previous_time_period = now - datetime.timedelta(weeks=2)

        next_digest_timestamp = ng.get_state(timestamp_string, '', True)
        if not next_digest_timestamp:
            # first time here, schedule a digest for appropriate time in future
            ng.set_state(timestamp_string, future_digest_timestamp)
            next_digest_timestamp = future_digest_timestamp

        if now < next_digest_timestamp:
            # it's not yet time to send this digest
            continue

        # time to send a digest
        logger.info('Sending %s digest', digest)
        ng.set_state(timestamp_string, future_digest_timestamp)

        if (digest == 'daily'):
            # ng.PROCESSED_DAILY_DIGEST  = 2
            ng.database_instance.cursor.execute("SELECT DISTINCT mac, ip FROM event WHERE NOT (processed & 2) AND timestamp>=? AND timestamp<=? AND event = 'requested'", (time_period, now))
            requested = ng.database_instance.cursor.fetchall()
            ng.database_instance.cursor.execute("SELECT DISTINCT mac, ip FROM event WHERE NOT (processed & 2) AND timestamp>=? AND timestamp<=? AND event = 'seen'", (time_period, now))
            seen = ng.database_instance.cursor.fetchall()
        elif (digest == 'weekly'):
            # ng.PROCESSED_WEEKLY_DIGEST = 4
            ng.database_instance.cursor.execute("SELECT DISTINCT mac, ip FROM event WHERE NOT (processed & 4) AND timestamp>=? AND timestamp<=? AND event = 'requested'", (time_period, now))
            requested = ng.database_instance.cursor.fetchall()
            ng.database_instance.cursor.execute("SELECT DISTINCT mac, ip FROM event WHERE NOT (processed & 4) AND timestamp>=? AND timestamp<=? AND event = 'seen'", (time_period, now))
            seen = ng.database_instance.cursor.fetchall()

        ng.database_instance.cursor.execute("SELECT DISTINCT mac, ip FROM event WHERE timestamp>=? AND timestamp<=? AND event = 'seen'", (previous_time_period, time_period))
        seen_previous = ng.database_instance.cursor.fetchall()

        new = set(seen) - set(seen_previous)
        gone = set(seen_previous) - set(seen)

        subject = """Netgrasp %s digest""" % (digest)
        body = """In the past %s, %d IPs were active:""" % (time_period_description, len(seen))
        noisy = []
        some_new = False
        for ip in seen:
            ng.database_instance.cursor.execute('SELECT COUNT(DISTINCT(dst_ip)) FROM arplog WHERE request=1 AND src_ip=? AND timestamp>=? AND timestamp <=?', (ip[1], time_period, now))
            requests = ng.database_instance.cursor.fetchone()
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

        if (digest == 'daily'):
            body += "\n\nActive devices per hour during the past day:"
            range = 24
            while (range > 0):
                lower = now - datetime.timedelta(hours=range)
                range = range - 1
                upper = now - datetime.timedelta(hours=range)
                ng.database_instance.cursor.execute("SELECT DISTINCT mac, ip FROM event WHERE event = 'seen' AND timestamp>=? AND timestamp<?", (lower, upper))
                distinct = ng.database_instance.cursor.fetchall()
                body += """\n - %s: %d""" % (lower.strftime("%I %p, %x"), len(distinct))
        elif (digest == 'weekly'):
            body += "\n\nActive devices per day during the past week:"
            range = 7
            while (range > 0):
                lower = now - datetime.timedelta(days=range)
                range = range - 1
                upper = now - datetime.timedelta(days=range)
                logger.debug("SELECT DISTINCT mac, ip FROM event WHERE event = 'seen' AND timestamp>='%s' AND timestamp<'%s'", lower, upper)
                ng.database_instance.cursor.execute("SELECT DISTINCT mac, ip FROM event WHERE event = 'seen' AND timestamp>=? AND timestamp<?", (lower, upper))
                distinct = ng.database_instance.cursor.fetchall()
                body += """\n - %s: %d""" % (lower.strftime("%A, %x"), len(distinct))

        if (digest == 'daily'):
            ng.database_instance.cursor.execute('SELECT eid, processed FROM event WHERE timestamp>=? AND timestamp<=? AND NOT (processed & 2)', (time_period, now))
            alerted = ng.PROCESSED_DAILY_DIGEST
        elif (digest == 'weekly'):
            ng.database_instance.cursor.execute('SELECT eid, processed FROM event WHERE timestamp>=? AND timestamp<=? AND NOT (processed & 4)', (time_period, now))
            alerted = ng.PROCESSED_WEEKLY_DIGEST
        rows = ng.database_instance.cursor.fetchall()
        ng.database_lock.acquire()
        counter = 0
        for row in rows:
            eid, processed = row
            # Give up the lock occasionally while processing a large number of rows, allowing the
            # wiretap process to work if needed, avoiding potential timeout.
            counter = counter + 1
            if (counter > MAXPROCESS):
                logger.debug("updated 100 events, releasing/regrabbing lock")
                ng.database_instance.connection.commit()
                ng.database_lock.release()
                if (timer.elapsed() > MAXSECONDS):
                    # We've been processing events for too long, quit for now and come back later.
                    logger.debug("processing events >%d seconds, quitting for now", MAXSECONDS)
                    return
                counter = 0
                ng.database_lock.acquire()
            ng.database_instance.cursor.execute('UPDATE event SET processed=? WHERE eid=?', (processed + alerted, eid))
        ng.database_instance.connection.commit()
        ng.database_lock.release()

        logger.info('Sending %s digest', digest)
        ng.email_instance.MailSend(subject, 'iso-8859-1', (body, 'us-ascii'))

def garbage_collection():
    logger.debug('entering garbage_collection()')

    if not ng.config_instance.GetBoolean('Database', 'gcenabled', True, False):
        logger.debug('garbage collection disabled')

    garbage_collection_string = "garbage collection"

    now = datetime.datetime.now()
    next_garbage_collection = ng.get_state(garbage_collection_string, '', True)

    if not next_garbage_collection:
        # perform first garbage collection now
        next_garbage_collection = now

    if now < next_garbage_collection:
        # it's not yet time to send this digest
        return False

    logger.info("performing garbage collection")
    # schedule next garbage collection
    ng.set_state(garbage_collection_string, now + datetime.timedelta(days=1))

    oldest_arplog = now - datetime.timedelta(seconds=ng.config_instance.GetInt('Database', 'oldest_arplog', 60 * 60 * 24 * 7 * 2, False))
    oldest_event = now - datetime.timedelta(seconds=ng.config_instance.GetInt('Database', 'oldest_event', 60 * 60 * 24 * 7 * 2, False))

    ng.database_lock.acquire()
    # Purge old arplog entries.
    ng.database_instance.cursor.execute("SELECT COUNT(*) FROM arplog WHERE timestamp < ?", (oldest_arplog,))
    arplog_count = ng.database_instance.cursor.fetchone()
    ng.database_instance.cursor.execute("DELETE FROM arplog WHERE timestamp < ?", (oldest_arplog,))
    # Purge old event entries.
    ng.database_instance.cursor.execute("SELECT COUNT(*) FROM event WHERE timestamp < ?", (oldest_event,))
    event_count = ng.database_instance.cursor.fetchone()
    ng.database_instance.cursor.execute("DELETE FROM event WHERE timestamp < ?", (oldest_event,))
    ng.database_instance.connection.commit()
    ng.database_lock.release()
    logger.debug("deleted %d arplog entries older than %s", arplog_count[0], oldest_arplog)
    logger.debug("deleted %d event entries older than %s", event_count[0], oldest_event)

if __name__ == '__main__':
    import getopt

    try:
        opts, args = getopt.getopt(sys.argv[1:], "vd")
    except getopt.GetoptError as err:
        print str(err)
        sys.exit(2)

    verbose = False
    daemonize = False
    for o, a in opts:
        if o == '-v':
            verbose = True
        if o == '-d':
            daemonize = True

    ng = Netgrasp()
    ng.config_instance = ng.Config(ConfigParser.ConfigParser())

    ng.verbose = verbose
    ng.daemonize = daemonize

    # Start logger, reading relevant configuration.
    logger = logging.getLogger(__name__)
    formatter = logging.Formatter(ng.DEFAULT_LOGFORMAT)
    if ng.daemonize:
        try:
            handler = logging.FileHandler(ng.config_instance.GetText('Logging', 'filename', ng.DEFAULT_LOGFILE))
        except Exception as e:
            sys.exit("""Fatal exception setting up log handler: %s""" % e)
    else:
        logger.warning("Output forced to stderr, started without -d flag.")
        handler = logging.StreamHandler()

    handler.setFormatter(formatter)
    logger.addHandler(handler)
    if ng.verbose:
        logger.setLevel(logging.DEBUG)
    else:
        logger.setLevel(logging.INFO)
    logger.info('starting')
    logger.info('loaded configuration file: %s', ng.config_instance.found)
    if ng.verbose:
        logger.warning("[Logging] level forced to DEBUG, started with -v flag.")
    else:
        logger.setLevel(ng.config_instance.GetText('Logging', 'level', ng.DEFAULT_LOGLEVEL, False))

    keep_fds=[handler.stream.fileno()]

    if os.getuid() != 0:
        logger.critical("netgrasp must be run as root (currently running as %s), exiting", ng.whoami())
        sys.exit("""Netgrasp must be run as root (currently running as %s), exiting.""" % (ng.whoami()))

    try:
        import sqlite3
    except Exception as e:
        logger.critical("fatal exception: %s", e)
        logger.critical("failed to import sqlite3, try: 'pip install sqlite3', exiting.")
        sys.exit("Fatal error: failed to import sqlite3, try: 'pip install sqlite3', exiting.")

    try:
        import dpkt
    except Exception as e:
        logger.critical("fatal exception: %s", e)
        logger.critical("failed to import dpkt, try: 'pip install dpkt', exiting")
        sys.exit("Fatal error: failed to import dpkt, try: 'pip install dpkt', exiting")

    if ng.daemonize:
        try:
            from daemonize import Daemonize
        except Exception as e:
            logger.critical("fatal exception: %s", e)
            logger.critical("failed to import daemonize, try: 'pip install daemonize', exiting.")
            sys.exit("Fatal error: failed to import daemonize, try: 'pip install daemonize', exiting.")

    ng.notification_instance = ng.Notification()

    ng.database_filename = ng.config_instance.GetText('Database', 'filename')

    if ng.daemonize:
        pidfile = ng.config_instance.GetText('Logging', 'pidfile', ng.DEFAULT_PIDFILE, False)
        username = ng.config_instance.GetText('Security', 'user', ng.DEFAULT_USER, False)
        groupname = ng.config_instance.GetText('Security', 'group', ng.DEFAULT_GROUP, False)
        try:
            daemon = Daemonize(app="netgrasp", pid=pidfile, privileged_action=get_pcap, user=username, group=groupname, action=main, keep_fds=keep_fds, logger=logger, verbose=True)
            daemon.start()
        except Exception as e:
            sys.exit("""Failed to daemonize: %s, exiting""" % e)
    else:
        main()
