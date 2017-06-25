CURRENT_VERSION = 1

def needed(active_version):
    if active_version < CURRENT_VERSION:
        return CURRENT_VERSION - active_version
    else:
        return False

def run_updates(active_version):
    from netgrasp.database import database
    from netgrasp.utils import exclusive_lock
    from netgrasp.utils import debug

    debugger = debug.debugger_instance
    db = database.database_instance

    debugger.warning("running updates:")

    if active_version < 1:
        update_1()

    debugger.warning("optimizing...")
    with exclusive_lock.ExclusiveFileLock(db.lock, 5, "run_updates: analyze"):
        # Claim back space for any deleted data.
        db.cursor.execute("VACUUM")
        # Update internal sqlite3 table and index statistics.
        db.cursor.execute("ANALYZE")
        db.connection.commit()
    debugger.warning("all updates complete.")

def update_1():
    from netgrasp import netgrasp
    from netgrasp.database import database
    from netgrasp.utils import exclusive_lock
    from netgrasp.utils import debug

    debugger = debug.debugger_instance
    ng = netgrasp.netgrasp_instance
    db = database.database_instance

    debugger.warning(" running update_1 (please be patient, we're doing stuff) ...")

    # redo all tables except for state
    tables = ["event", "vendor", "host", "arplog", "seen"]
    with exclusive_lock.ExclusiveFileLock(db.lock, 5, "update_1: backup tables"):
        for table in tables:
            table_orig = "orig_"+table
            db.cursor.execute("ALTER TABLE %s RENAME TO %s" % (table, table_orig))
            db.connection.commit()

    # create new schema
    netgrasp.create_database()

    db.cursor.execute("SELECT DISTINCT orig_seen.mac, orig_seen.ip FROM orig_seen WHERE orig_seen.mac != 'ff:ff:ff:ff:ff:ff'")
    seen = db.cursor.fetchall()
    counter = 0
    for device in seen:
        counter += 1
        mac, ip = device
        netgrasp.device_seen(ip, mac)
    debugger.warning("  update_1: migrated %d devices", (counter,))

    db.cursor.execute("SELECT ip.address, mac.address, activity.aid, activity.did, activity.iid, device.mid, device.hid, device.vid, host.name, vendor.name FROM device LEFT JOIN activity ON activity.did = device.did LEFT JOIN host ON device.hid = host.hid LEFT JOIN vendor ON device.vid = vendor.vid LEFT JOIN ip ON device.iid = ip.iid LEFT JOIN mac ON device.mid = mac.mid")
    devices = db.cursor.fetchall()
    with exclusive_lock.ExclusiveFileLock(db.lock, 5, "  update_1: fix dates"):
        for device in devices:
            ip, mac, aid, did, iid, mid, hid, vid, host_name, vendor = device
            # determine when we first saw this device.
            db.cursor.execute("SELECT firstSeen, lastSeen FROM orig_seen WHERE mac = ? AND ip = ? AND firstSeen NOT NULL ORDER BY firstSeen ASC LIMIT 1", (mac, ip))
            created = db.cursor.fetchone()
            if created:
                firstSeen, lastSeen = created
                mid, iid, lookup_did = netgrasp.get_ids(ip, mac)
                if did != lookup_did:
                    debugger.critical("update_1: did %d does not match looked up did %d, something is very wrong, update failed.", (did, lookup_did))
                db.cursor.execute("UPDATE device SET created = ?, updated = ? WHERE did = ?", (firstSeen, lastSeen, did))
                db.cursor.execute("UPDATE mac SET created = ? WHERE mid = ?", (firstSeen, mid))
                db.cursor.execute("UPDATE ip SET created = ? WHERE iid = ?", (firstSeen, iid))
                db.cursor.execute("UPDATE host SET created = ?, updated = ? WHERE iid = ?", (firstSeen, lastSeen, iid))
                db.cursor.execute("SELECT vid FROM mac WHERE mid = ?", (mid,))
                vid = db.cursor.fetchone()
                if vid:
                    update = True
                    db.cursor.execute("SELECT created FROM vendor WHERE vid = ?", (vid[0],))
                    created = db.cursor.fetchone()
                    if created and created[0] <= firstSeen:
                        update = False
                    if update:
                        db.cursor.execute("UPDATE vendor SET created = ? WHERE vid = ?", (firstSeen, vid[0]))
                else:
                    debugger.critical("update_1: failed to find vendor for mid(%d), iid(%d), did(%d), update failed", (mid, iid, did))
                db.connection.commit()
    debugger.warning("  update_1: fixed timestamps")

    db.cursor.execute("SELECT host.hid, ip.address FROM host LEFT JOIN ip ON host.iid = ip.iid")
    hosts = db.cursor.fetchall()
    migrated = 0
    with exclusive_lock.ExclusiveFileLock(db.lock, 5, "update_1: transfer custom_name"):
        for host in hosts:
            hid, ip = host
            db.cursor.execute("SELECT customname FROM orig_host WHERE ip = ? LIMIT 1", (ip,))
            custom = db.cursor.fetchone()
            if custom:
                db.cursor.execute("UPDATE host SET custom_name = ? WHERE hid = ?", (custom[0], hid))
                migrated += 1
        db.connection.commit()
    debugger.warning("  update_1: migrated %d custom names", (migrated,))

    db.cursor.execute("SELECT activity.aid, activity.did, activity.iid, ip.address, mac.address FROM activity LEFT JOIN ip ON activity.iid = ip.iid LEFT JOIN mac ON ip.mid = mac.mid")
    activity = db.cursor.fetchall()
    migrated = 0
    with exclusive_lock.ExclusiveFileLock(db.lock, 5, "update_1: transfer activity"):
        for device in activity:
            aid, did, iid, ip, mac = device
            # cleanup invalid entry created during migration
            db.cursor.execute("DELETE FROM activity WHERE aid = ?", (aid,))
            # add all seen records
            db.cursor.execute("SELECT firstSeen, lastSeen, counter, active FROM orig_seen WHERE ip = ? AND mac = ? ORDER BY firstSeen ASC", (ip, mac))
            seen = db.cursor.fetchall()
            for row in seen:
                firstSeen, lastSeen, counter, active = row
                db.cursor.execute("INSERT INTO activity (did, iid, created, updated, counter, active) VALUES(?, ?, ?, ?, ?, ?)", (did, iid, firstSeen, lastSeen, counter, active))
                migrated += 1
        debugger.warning("  update_1: migrated %d activity records", (migrated,))
        migrated = 0
        for device in activity:
            aid, did, iid, ip, mac = device
            # add all requested records (for actually seen devices only)
            db.cursor.execute("SELECT firstRequested, lastRequested FROM orig_seen WHERE ip = ? AND mac = ? AND firstRequested IS NOT NULL GROUP BY ip ORDER BY firstSeen ASC", (ip, mac))
            seen = db.cursor.fetchall()
            for row in seen:
                firstRequested, lastRequested = row
                # we didn't track number of requests or activity, so default to 1 and 0
                db.cursor.execute("INSERT INTO request (did, ip, created, updated, counter, active) VALUES(?, ?, ?, ?, ?, ?)", (did, ip, firstRequested, lastRequested, 1, 0))
                migrated += 1
        debugger.warning("  update_1: migrated %d request records", (migrated,))
        db.connection.commit()

    # not copying arplog : daily/weekly digests will be inaccurate for 2 days/ 2 weeks
    # not copying events : not necessary

    with exclusive_lock.ExclusiveFileLock(db.lock, 5, "update_1: cleanup"):
        db.cursor.execute("DROP TABLE orig_event")
        db.cursor.execute("DROP TABLE orig_vendor")
        db.cursor.execute("DROP TABLE orig_host")
        db.cursor.execute("DROP TABLE orig_arplog")
        db.cursor.execute("DROP TABLE orig_seen")
        db.connection.commit()
    debugger.warning("  update_1: finished")
