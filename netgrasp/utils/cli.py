from netgrasp import netgrasp

def start(ng):
    import os

    pid = ng.is_running()
    if pid:
        ng.debugger.critical("Netgrasp is already running with pid %d.", (pid,))
    ng.debugger.info("Starting netgrasp...")

    if os.getuid() != 0:
        ng.debugger.critical("netgrasp must be run as root (currently running as %s), exiting", (ng.debugger.whoami()))

    # Re-instantiate Netgrasp with proper parameters
    daemon_ng = netgrasp.Netgrasp(ng.config)
    daemon_ng.args = ng.args

    if ng.args.verbose:
        daemon_ng.verbose = ng.args.verbose
    else:
        daemon_ng.verbose = False

    if ng.args.foreground:
        daemon_ng.daemonize = False
    else:
        daemon_ng.daemonize = True

    netgrasp.netgrasp_instance = daemon_ng
    netgrasp.start()

def stop(ng, must_be_running = True):
    import os
    import signal
    import errno

    pid = ng.is_running()

    if not pid:
        if must_be_running:
            ng.debugger.critical("Netgrasp is not running.")
        else:
            ng.debugger.info("Netgrasp is not running.")
    else:
        ng.debugger.info("Stopping netgrasp...")

        try:
            os.kill(pid, signal.SIGTERM)
        except OSError as e:
            if e.errno == errno.EPERM:
                ng.debugger.critical("Failed (perhaps try with sudo): %s", (e))
            else:
                ng.debugger.critical("Failed: %s", (e,))

def restart(ng):
    import time

    stop(ng, False)
    running = ng.is_running()
    loops = 0
    while running:
        loops += 1
        if (loops > 15):
            ng.debugger.critical("Failed to stop netgrasp.")
        time.sleep(0.2)
        running = ng.is_running()
    start(ng)

def status(ng):
    pid = ng.is_running()
    if pid:
        ng.debugger.warning("Netgrasp is running with pid %d", (pid,))
    else:
        ng.debugger.warning("Netgrasp is not running.")

def list(ng):
    import datetime

    from netgrasp.database import database
    from netgrasp.utils import pretty

    pid = ng.is_running()
    if not pid:
        ng.debugger.critical("Netgrasp is not running.")

    ng.database_filename = ng.config.GetText('Database', 'filename')

    try:
        ng.db = database.Database(ng.database_filename, ng.debugger)
        database.database_instance = ng.db
    except Exception as e:
        ng.debugger.error("error: %s", (e,))
        ng.debugger.critical("Failed to open or create database file %s (as user %s), exiting.", (ng.database_filename, ng.debugger.whoami()))

    ng.debugger.info("Opened %s as user %s", (ng.database_filename, ng.debugger.whoami()))

    ng.db.cursor = ng.db.connection.cursor()

    if ng.args.type == "device":
        # List devices.
        query = database.SelectQueryBuilder("seen", ng.debugger, ng.args.verbose)
        query.db_select("{%BASE}.did")
        query.db_select("{%BASE}.mac")
        query.db_select("{%BASE}.ip")
        query.db_select("{%BASE}.lastSeen")

        if ng.args.all:
            description = "All devices"
        else:
            description = "Active devices"
            query.db_where("{%BASE}.active = ?", 1)
        query.db_where("{%BASE}.lastSeen IS NOT NULL")

        if (not ng.args.all or ng.args.all == 1):
            query.db_group("{%BASE}.did")

        query.db_order("{%BASE}.lastSeen DESC")

        rowFormat = "{:>16}{:>34}{:>22}"
        header = ["IP", "Name", "Last seen"]

    elif ng.args.type == 'event':
        # List events.
        query = database.SelectQueryBuilder("event", ng.debugger, ng.args.verbose)
        query.db_select("{%BASE}.did")
        query.db_select("{%BASE}.mac")
        query.db_select("{%BASE}.ip")
        query.db_select("{%BASE}.timestamp")
        query.db_select("{%BASE}.event")

        if ng.args.all:
            description = "All alerts"
        else:
            description = "Recent alerts"
            ng.active_timeout = ng.config.GetInt('Listen', 'active_timeout', 60 * 60 * 2, False)
            recent = datetime.datetime.now() - datetime.timedelta(seconds=ng.active_timeout)
            query.db_where("{%BASE}.timestamp >= ?", recent)

        if (not ng.args.all or ng.args.all == 1):
            query.db_group("{%BASE}.did")
            query.db_group("{%BASE}.event")

        query.db_order("{%BASE}.timestamp DESC")

        rowFormat = "{:>16}{:>24}{:>21}{:>18}"
        header = ["IP", "Name", "Event", "Last seen"]

    if ng.args.mac:
        query.db_where("{%BASE}.mac LIKE ?", "%"+ng.args.mac+"%")
        if not ng.args.mac == netgrasp.BROADCAST:
            query.db_where("{%BASE}.mac != ?", netgrasp.BROADCAST)
    else:
        query.db_where("{%BASE}.mac != ?", netgrasp.BROADCAST)

    if ng.args.ip:
        query.db_where("{%BASE}.ip LIKE ?", "%"+ng.args.ip+"%")

    if ng.args.vendor:
        query.db_leftjoin("vendor", "{%BASE}.mac = vendor.mac")
        query.db_where("vendor.vendor LIKE ?", "%"+ng.args.vendor+"%")

    if ng.args.hostname:
        query.db_leftjoin("host", "{%BASE}.did = host.did")
        query.db_where("host.hostname LIKE ?", "%"+ng.args.hostname+"%")

    if ng.args.custom:
        query.db_leftjoin("vendor", "{%BASE}.mac = vendor.mac")
        query.db_leftjoin("host", "{%BASE}.did = host.did")
        query.db_where("(vendor.customname LIKE ? OR host.customname LIKE ?)", ["%"+ng.args.custom+"%", "%"+ng.args.custom+"%"], True)

    ng.db.cursor.execute(query.db_query(), query.db_args())
    rows = ng.db.cursor.fetchall()
    if rows:
        print """ %s:""" % description
        print rowFormat.format(*header)
    for row in rows:
        if ng.args.type == 'device':
            print rowFormat.format(pretty.truncate_string(row[2], 15), pretty.truncate_string(pretty.name_did(row[0]), 32), pretty.truncate_string(pretty.time_ago(row[3]), 20))
        else:
            print rowFormat.format(pretty.truncate_string(row[2], 15), pretty.truncate_string(pretty.name_did(row[0]), 22), pretty.truncate_string(row[4], 19), pretty.truncate_string(pretty.time_ago(row[3]), 16))

def identify(ng):
    from netgrasp.database import database
    from netgrasp.utils import pretty
    from netgrasp.utils import exclusive_lock

    pid = ng.is_running()
    if not pid:
        ng.debugger.critical("Netgrasp is not running.")

    ng.database_filename = ng.config.GetText("Database", "filename")

    try:
        ng.db = database.Database(ng.database_filename, ng.debugger)
        database.database_instance = ng.db
    except Exception as e:
        ng.debugger.error("%s", (e,))
        ng.debugger.critical("Failed to open or create database file %s (as user %s), exiting.", (ng.database_filename, ng.debugger.whoami()))

        ng.debugger.info("Opened %s as user %s", (ng.database_filename, ng.debugger.whoami()))

    ng.db.cursor = ng.db.connection.cursor()
    ng._database_lock = exclusive_lock.ExclusiveFileLock(ng.config.GetText('Database', 'lockfile', netgrasp.DEFAULT_DBLOCK, False), 5, "identify")
    ng.db.lock = ng._database_lock

    if not ng.args.set:
        description = "Use --set ID 'CUSTOM NAME' to set a custom name on a device"
        header = ["ID", "IP", "Name", "Last seen"]
        rowFormat = "{:>7}{:>16}{:>34}{:>22}"

        query = database.SelectQueryBuilder("host", ng.debugger, ng.args.verbose)
        query.db_select("{%BASE}.hid")
        query.db_select("{%BASE}.did")
        query.db_select("{%BASE}.mac")
        query.db_select("{%BASE}.ip")

        query.db_leftjoin("seen", "{%BASE}.did = seen.did")
        query.db_select("seen.lastSeen")
        query.db_group("seen.did")
        query.db_order("seen.lastSeen DESC")

        if not ng.args.all and not ng.args.custom:
            query.db_where("{%BASE}.customname IS NULL")

        if ng.args.mac:
            query.db_where("{%BASE}.mac LIKE ?", "%"+ng.args.mac+"%")

        if not ng.args.all > 2 and not ng.args.mac == netgrasp.BROADCAST:
            query.db_where("{%BASE}.mac != ?", netgrasp.BROADCAST)

        if ng.args.ip:
            query.db_where("{%BASE}.ip LIKE ?", "%"+ng.args.ip+"%")

        if ng.args.vendor:
            query.db_leftjoin("vendor", "{%BASE}.mac = vendor.mac")
            query.db_where("vendor.vendor LIKE ?", "%"+ng.args.vendor+"%")

        if ng.args.hostname:
            query.db_where("host.hostname LIKE ?", "%"+ng.args.hostname+"%")

        if ng.args.custom:
            query.db_leftjoin("vendor", "{%BASE}.mac = vendor.mac")
            query.db_where("(vendor.customname LIKE ? OR host.customname LIKE ?)", ["%"+ng.args.custom+"%", "%"+ng.args.custom+"%"], True)

        ng.db.cursor.execute(query.db_query(), query.db_args())
        rows = ng.db.cursor.fetchall()
        if rows:
            print """ %s:""" % description
            print rowFormat.format(*header)
        for row in rows:
            ng.db.cursor.execute("SELECT customname FROM host WHERE did = ? ORDER BY customname DESC", (row[1],))
            customname = ng.db.cursor.fetchone()
            if customname and customname[0]:
                # Device changed IP and has custom name associated with previous IP.
                ng.db.cursor.execute("UPDATE host SET customname = ? WHERE did = ?", (customname[0], row[1]))
                continue
            print rowFormat.format(row[0], pretty.truncate_string(row[3], 15), pretty.truncate_string(pretty.name_did(row[1]), 32), pretty.truncate_string(pretty.time_ago(row[4]), 20))
    else:
        if ng.args.verbose > 1:
            print "id:", ng.args.set[0], "| custom name:", ng.args.set[1]
        ng.db.cursor.execute("SELECT vendor.vid FROM vendor LEFT JOIN host ON vendor.mac = host.mac WHERE host.hid = ?", (ng.args.set[0],))
        row = ng.db.cursor.fetchone()
        if row:
            with exclusive_lock.ExclusiveFileLock(ng.db.lock, 5, "failed to set custom name, please try again"):
                db_args = [ng.args.set[1]]
                db_args.append(ng.args.set[0])
                ng.db.cursor.execute("UPDATE host SET customname = ? WHERE hid = ?", db_args)
                db_args = [ng.args.set[1]]
                db_args.append(row[0])
                ng.db.cursor.execute("UPDATE vendor SET customname = ? WHERE vid = ?", db_args)
                ng.db.connection.commit()
