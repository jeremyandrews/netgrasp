class Notify:
    def __init__(self, debugger, config):
        from netgrasp import netgrasp
        self.debugger = debugger
        self.config = config
        self.enabled = self.config.GetBoolean('Notifications', 'enabled', False, False)
        if not self.enabled:
            debugger.warning('notifications are disabled')
            return

        self.alerts = []
        alerts = self.config.GetTextList('Notifications', 'alerts', None, False)
        for alert in alerts:
            if alert in netgrasp.ALERT_TYPES:
                self.alerts.append(alert)
            else:
                debugger.warning("ignoring unrecognized alert type (%s), supported types: %s", (alert, netgrasp.ALERT_TYPES))

        try:
            import ntfy
        except Exception as e:
            debugger.error("fatal exception: %s", e)
            debugger.critical("failed to import ntfy (as user %s), try 'pip install ntfy', exiting", (debugger.whoami()))
        debugger.info('successfuly imported ntfy')

