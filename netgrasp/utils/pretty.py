import datetime

def time_ago(elapsed, precision = True):
    from netgrasp import netgrasp

    ng = netgrasp.netgrasp_instance

    try:
        ng.debugger.debug("time_ago(%s)", (elapsed,))

        if not elapsed:
            return "never"

        now = datetime.datetime.now()
        diff = now - elapsed
        second_diff = diff.seconds
        day_diff = diff.days

        ng.debugger.debug("time_ago second_diff(%d) day_diff(%d)", (second_diff, day_diff))

        if day_diff < 0:
            return "unknown"

        if day_diff == 0:
            if second_diff < 10:
                return "just now"

            if second_diff < 60:
                return str(second_diff) + " seconds ago"

            if second_diff < 120:
                return "a minute ago"

            if second_diff < 3600:
                time_string = str(second_diff / 60) + " minutes "
                if precision:
                    second_remainder = (second_diff % 60)
                    if second_remainder == 1:
                        time_string += "1 second ago"
                    elif second_remainder:
                        time_string += str(second_diff % 60) + " seconds ago"
                    else:
                        time_string += "ago"
                else:
                    time_string += "ago"
                return time_string

            if second_diff < 7200:
                return "an hour ago"

            time_string = str(second_diff / 3600) + " hours "
            if precision:
                minutes_remainder = (second_diff % 3600) / 60
                if minutes_remainder == 1:
                    time_string += "1 minute ago"
                elif minutes_remainder:
                    time_string += str(minutes_remainder) + " minutes ago"
                else:
                    time_string += "ago"
            else:
                time_string += "ago"
            return time_string

        if day_diff == 1:
            if precision and second_diff:
                time_string = "1 day "
                if second_diff < 120:
                    time_string += "ago"
                elif second_diff < 3600:
                    time_string += str(second_diff / 60) + " minutes ago"
                elif second_diff < 7200:
                    time_string += "1 hour ago"
                elif second_diff < 86400:
                    time_string += str(second_diff / 3600) + " hours ago"
                else:
                    time_string += "ago"
                return time_string
            else:
                return "yesterday"

        if day_diff < 7:
            time_string = str(day_diff) + " days "
            if precision:
                if second_diff < 7200:
                    time_string += "ago"
                elif second_diff < 86400:
                    time_string += str(second_diff / 3600) + " hours ago"
                else:
                    time_string += "ago"
                return time_string
            else:
                return time_string + "ago"

        if day_diff < 31:
            time_string = str(day_diff / 7) + " weeks "
            if precision:
                day_remainder = day_diff % 7
                if day_remainder == 1:
                    time_string += "1 day ago"
                elif day_remainder:
                    time_string += str(day_remainder) + " days ago"
                else:
                    time_string += "ago"
                return time_string
            else:
                return time_string + "ago"

        if day_diff < 365:
            time_string = str(day_diff / 30) + " months "
            if precision:
                day_remainder = day_diff % 30
                week_remainder = day_remainder / 7
                if not day_remainder:
                    time_string += "ago"
                elif day_remainder == 1:
                    time_string += "1 day ago"
                elif day_remainder < 7:
                    time_string += str(day_remainder) + " days ago"
                elif week_remainder == 1:
                    time_string += "1 week ago"
                else:
                    time_string += str(week_remainder) + " weeks ago"
                return time_string
            else:
                return time_string + "ago"

        time_string = str(day_diff / 365) + " years "
        if precision:
            day_remainder = day_diff % 365
            month_remainder = day_diff % 12
            week_remainder = day_diff % 7
            if not day_remainder:
                time_string += "ago"
            elif day_remainder == 1:
                time_string += "1 day ago"
            elif day_remainder < 7:
                time_string += str(day_remainder) + " days ago"
            elif week_remainder == 1:
                time_string += "1 week ago"
            elif week_remainder < 5:
                time_string += str(week_remainder) + " weeks ago"
            elif month_remainder == 1:
                week_string += "1 month ago"
            else:
                time_string += str(month_remainder) + " months ago"
            return time_string
        else:
            return time_string + "ago"

    except Exception:
        ng.debugger.dump_exception("time_ago() fixme")


def time_elapsed(elapsed):
    from netgrasp import netgrasp

    ng = netgrasp.netgrasp_instance

    try:
        ng.debugger.debug("time_elapsed(%s)", (elapsed,))

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

    except Exception:
        ng.debugger.dump_exception("time_elapsed() caught exception")


# Provides a human-friendly name for a mac-ip pair.
def name_did(did, ip=None):
    from netgrasp import netgrasp

    ng = netgrasp.netgrasp_instance

    try:
        ng.debugger.debug("entering name_did(%s, %s)", (did, ip))

        if did:
            details = netgrasp.get_details(did)
            if details:
                active, counter, ip, mac, hostname, custom_name, vendor = details
                if custom_name:
                    return custom_name
                elif hostname and (hostname != "unknown"):
                    return hostname
                elif vendor:
                    return """%s device""" % vendor
                else:
                    return """%s [%s]""" % (ip, mac)

        # This may be a request for a device we've not yet seen.
        if ip:
            hostname = netgrasp.dns_lookup(ip)
            if hostname:
                return hostname

        return "Unrecognized device"

    except Exception:
        ng.debugger.dump_exception("name_did() caught exception")


# Truncate strings when they're too long.
def truncate_string(string, maxlength, suffix="..."):
    if not string or len(string) <= maxlength:
        return string
    return """%s%s""" % (string[:(maxlength - len(suffix))], suffix)
