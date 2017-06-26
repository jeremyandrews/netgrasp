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

def update(ng):
    from netgrasp.database import database
    from netgrasp.update import update
    from netgrasp.utils import exclusive_lock
    from netgrasp.utils import email
    from netgrasp.notify import notify

    try:
        ng.database_filename = ng.config.GetText('Database', 'filename')
        ng.db = database.Database(ng.database_filename, ng.debugger)
        database.database_instance = ng.db
    except Exception as e:
        ng.debugger.error("error: %s", (e,))
        ng.debugger.critical("Failed to open or create database file %s (as user %s), exiting.", (ng.database_filename, ng.debugger.whoami()))

    ng.db.cursor = ng.db.connection.cursor()
    ng._database_lock = exclusive_lock.ExclusiveFileLock(ng.config.GetText('Database', 'lockfile', netgrasp.DEFAULT_DBLOCK, False), 5, "identify")
    ng.db.lock = ng._database_lock

    query = database.SelectQueryBuilder("state", ng.debugger, ng.args.verbose)
    query.db_select("{%BASE}.value")
    query.db_where("{%BASE}.key = 'schema_version'")
    ng.db.cursor.execute(query.db_query(), query.db_args())
    schema_version = ng.db.cursor.fetchone()
    if schema_version:
        version = schema_version[0]
    else:
        version = 0

    updates = update.needed(version)
    if updates:
        ng.debugger.warning("schema updates required: %s", (updates,))
    else:
        ng.debugger.critical("no schema updates are required.")

    pid = ng.is_running()
    if pid:
        ng.debugger.critical("Netgrasp must be stopped before running updates.")

    netgrasp.netgrasp_instance = ng

    email.email_instance = None
    notify.notify_instance = None

    update.run_updates(version)

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
        query = database.SelectQueryBuilder("activity", ng.debugger, ng.args.verbose)
        query.db_select("{%BASE}.did")
        query.db_select("mac.address")
        query.db_select("ip.address")
        query.db_select("{%BASE}.updated")

        if ng.args.all:
            description = "All devices"
        else:
            description = "Active devices"
            query.db_where("{%BASE}.active = ?", 1)
        query.db_where("{%BASE}.updated IS NOT NULL")

        if (not ng.args.all or ng.args.all == 1):
            query.db_group("{%BASE}.did")

        query.db_order("{%BASE}.updated DESC")

        rowFormat = "{:>16}{:>34}{:>22}"
        header = ["IP", "Name", "Last seen"]

    elif ng.args.type == 'event':
        # List events.
        query = database.SelectQueryBuilder("event", ng.debugger, ng.args.verbose)
        query.db_select("{%BASE}.did")
        query.db_select("mac.address")
        query.db_select("ip.address")
        query.db_select("{%BASE}.timestamp")
        query.db_select("{%BASE}.type")

        if ng.args.all:
            description = "All alerts"
            # @TODO: this is a bogus WHERE, get rid of altogether
            query.db_where("{%BASE}.timestamp >= ?", 1)
        else:
            description = "Recent alerts"
            ng.active_timeout = ng.config.GetInt('Listen', 'active_timeout', 60 * 60 * 2, False)
            recent = datetime.datetime.now() - datetime.timedelta(seconds=ng.active_timeout)
            query.db_where("{%BASE}.timestamp >= ?", recent)

        if (not ng.args.all or ng.args.all == 1):
            query.db_group("{%BASE}.did")
            query.db_group("{%BASE}.type")

        query.db_order("{%BASE}.timestamp DESC")

        rowFormat = "{:>16}{:>24}{:>21}{:>18}"
        header = ["IP", "Name", "Event", "Last seen"]

    query.db_leftjoin("device", "{%BASE}.did = device.did")
    query.db_leftjoin("ip", "{%BASE}.iid = ip.iid")
    query.db_leftjoin("mac", "device.mid = mac.mid")

    if ng.args.mac:
        query.db_where("mac.address LIKE ?", "%"+ng.args.mac+"%")

    if ng.args.ip:
        query.db_where("ip.address LIKE ?", "%"+ng.args.ip+"%")

    if ng.args.vendor:
        query.db_leftjoin("vendor", "device.vid = vendor.vid")
        query.db_where("vendor.name LIKE ?", "%"+ng.args.vendor+"%")

    if ng.args.hostname or ng.args.custom:
        query.db_leftjoin("host", "device.hid = host.hid")
        if ng.args.hostname:
            query.db_where("host.name LIKE ?", "%"+ng.args.hostname+"%")
        else:
            query.db_where("host.custom_name LIKE ?", "%"+ng.args.custom+"%")

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
        query.db_leftjoin("ip", "{%BASE}.iid = ip.iid")
        query.db_leftjoin("mac", "ip.mid = mac.mid")
        query.db_leftjoin("activity", "{%BASE}.iid = activity.iid")
        query.db_select("activity.did")
        query.db_select("mac.address")
        query.db_select("ip.address")
        query.db_select("activity.updated")
        query.db_group("activity.did")
        query.db_order("activity.updated DESC")

        if not ng.args.all and not ng.args.custom:
            query.db_where("{%BASE}.custom_name IS NULL")

        if ng.args.mac:
            query.db_where("mac.address LIKE ?", "%"+ng.args.mac+"%")

        if ng.args.ip:
            query.db_where("ip.address LIKE ?", "%"+ng.args.ip+"%")

        if ng.args.vendor:
            query.db_leftjoin("vendor", "mac.vid = vendor.vid")
            query.db_where("vendor.name LIKE ?", "%"+ng.args.vendor+"%")

        if ng.args.hostname:
            query.db_where("host.name LIKE ?", "%"+ng.args.hostname+"%")

        if ng.args.custom:
            query.db_where("host.custom_name LIKE ?", "%"+ng.args.custom+"%")

        ng.db.cursor.execute(query.db_query(), query.db_args())
        rows = ng.db.cursor.fetchall()
        if rows:
            print """ %s:""" % description
            print rowFormat.format(*header)
        for row in rows:
            ng.db.cursor.execute("SELECT custom_name FROM host WHERE hid = ? ORDER BY custom_name DESC", (row[0],))
            custom_name = ng.db.cursor.fetchone()
            if custom_name and custom_name[0]:
                # Device changed IP and has custom name associated with previous IP.
                ng.db.cursor.execute("UPDATE host SET custom_name = ? WHERE hid = ?", (custom_name[0], row[0]))
                continue
            print rowFormat.format(row[0], pretty.truncate_string(row[3], 15), pretty.truncate_string(pretty.name_did(row[1]), 32), pretty.truncate_string(pretty.time_ago(row[4]), 20))
    else:
        if ng.args.verbose > 1:
            print "id:", ng.args.set[0], "| custom name:", ng.args.set[1]
        ng.db.cursor.execute("SELECT vendor.vid FROM vendor LEFT JOIN mac ON vendor.vid = mac.vid LEFT JOIN host ON mac.mid = host.hid WHERE host.hid = ?", (ng.args.set[0],))
        with exclusive_lock.ExclusiveFileLock(ng.db.lock, 5, "failed to set custom name, please try again"):
            db_args = [ng.args.set[1]]
            db_args.append(ng.args.set[0])
            ng.db.cursor.execute("UPDATE host SET custom_name = ? WHERE hid = ?", db_args)
            ng.db.connection.commit()
