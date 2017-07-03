class Notify:
    def __init__(self ):
        from netgrasp import netgrasp

        if not ng.notificiation["enabled"]:
            debugger.warning('notifications are disabled')
            return

        for alert in ng.notification["alerts"]:
            if alert in netgrasp.ALERT_TYPES:
                self.alerts.append(alert)
            else:
                debugger.warning("ignoring unrecognized alert type (%s), supported types: %s", (alert, netgrasp.ALERT_TYPES))
