def time_ago(elapsed):
    try:
        import datetime

        from netgrasp.utils import debug
        debugger = debug.debugger_instance

        debugger.debug("time_ago(%s)", (elapsed,))

        if not elapsed:
            return "never"
        now = datetime.datetime.now()
        diff = now - elapsed
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
    except exception as e:
        debugger.dump_exception("time_ago() fixme")

def time_elapsed(elapsed):
    try:
        import datetime

        from netgrasp.utils import debug
        debugger = debug.debugger_instance

        debugger.debug("time_elapsed(%s)", (elapsed,))

        if not elapsed:
            return "a second"
        second_diff = elapsed.seconds
        day_diff = elapsed.days

        if day_diff < 0:
            return ''

        if day_diff == 0:
            if second_diff < 10:
                return "a few seconds"
            if second_diff < 60:
                return str(second_diff) + " seconds"
            if second_diff < 120:
                return "a minute"
            if second_diff < 3600:
                return str(second_diff / 60) + " minutes"
            if second_diff < 7200:
                return "an hour"
            if second_diff < 86400:
                return str(second_diff / 3600) + " hours"
        if day_diff == 1:
            return "a day"
        if day_diff < 7:
            return str(day_diff) + " days"
        if day_diff < 31:
            return str(day_diff / 7) + " weeks"
        if day_diff < 365:
            return str(day_diff / 30) + " months"
        return str(day_diff / 365) + " years"
    except Exception as e:
        debugger.dump_exception("time_elapsed() FIXME")

# Provides a human-friendly name for a mac-ip pair.
def name_did(did):
    try:
        import datetime

        from netgrasp import netgrasp
        from netgrasp.utils import debug
        from netgrasp.database import database

        debugger = debug.debugger_instance
        db = database.database_instance

        debugger.debug("entering name_did(%s)", (did,))

        db.cursor.execute("SELECT ip FROM host WHERE did = ?", (did,))
        ip = db.cursor.fetchone()
        detail = None
        if ip:
            db.cursor.execute("SELECT h.mac, h.ip, h.customname, h.hostname, v.customname, v.vendor FROM host h LEFT JOIN vendor v ON h.mac = v.mac WHERE h.ip=? AND h.mac != ?", (ip[0], netgrasp.BROADCAST))
            detail = db.cursor.fetchone()

        if not detail:
            db.cursor.execute("SELECT h.mac, h.ip, h.customname, h.hostname, v.customname, v.vendor FROM host h LEFT JOIN vendor v ON h.mac = v.mac WHERE h.did=?", (did,))
            detail = db.cursor.fetchone()

        if detail:
            mac, ip, custom_hostname, hostname, custom_vendorname, vendor = detail
            if custom_hostname:
                return custom_hostname
            elif hostname and (hostname != "unknown"):
                return hostname
            elif custom_vendorname:
                return custom_vendorname
            elif vendor:
                return """%s device""" % (vendor)
            else:
                return """%s [%s]""" % (ip, mac)
        else:
            return None
    except Exception as e:
        debugger.dump_exception("name_did() FIXME")

# Truncate strings when they're too long.
def truncate_string(string, maxlength, suffix = "..."):
    if not string or len(string) <= maxlength:
        return string
    return """%s%s""" % (string[:(maxlength - len(suffix))], suffix)
