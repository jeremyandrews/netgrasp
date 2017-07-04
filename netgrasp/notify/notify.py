class Notify:
    def __init__(self ):
        from netgrasp import netgrasp
        ng = netgrasp.netgrasp_instance

        if not ng.notification["enabled"]:
            ng.debugger.warning('notifications are disabled')
            return

        alerts = []
        for alert in ng.notification["alerts"]:
            if alert in netgrasp.ALERT_TYPES:
                alerts.append(alert)
            else:
                debugger.warning("ignoring unrecognized alert type (%s), supported types: %s", (alert, netgrasp.ALERT_TYPES))
        ng.notification["alerts"] = alerts
