import datetime

def pretty_date(time):
    try:
        from netgrasp.utils import debug
        debugger = debug.debugger_instance

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
    except Exception as e:
        debugger.dump_exception("pretty_date() FIXME")

# Provides a human-friendly name for a mac-ip pair.
def name_ip(ip, mac):
    try:
        from netgrasp import netgrasp
        from netgrasp.utils import debug
        from netgrasp.database import database

        debugger = debug.debugger_instance
        db = database.database_instance

        debugger.debug("entering name_ip(%s, %s)", (ip, mac))
        if (mac == netgrasp.BROADCAST):
            db.cursor.execute("SELECT h.mac, h.ip, h.customname, h.hostname, v.customname, v.vendor FROM host h LEFT JOIN vendor v ON h.mac = v.mac WHERE h.ip=?", (ip,))
        else:
            db.cursor.execute("SELECT h.mac, h.ip, h.customname, h.hostname, v.customname, v.vendor FROM host h LEFT JOIN vendor v ON h.mac = v.mac WHERE h.ip=? AND h.mac=?", (ip, mac))
        detail = db.cursor.fetchone()
        if not detail:
            return detail
        if detail[2]:
            return detail[2]
        elif detail[3] and (detail[3] != "unknown"):
            return detail[3]
        elif detail[4]:
            return detail[4]
        elif detail[5]:
            return """%s device""" % (detail[5])
        else:
            return detail[0]
    except Exception as e:
        debugger.dump_exception("name_ip() FIXME")

# Truncate strings when they're too long.
def truncate_string(string, maxlength, suffix = "..."):
    if len(string) <= maxlength:
        return string
    return """%s%s""" % (string[:(maxlength - len(suffix))], suffix)
