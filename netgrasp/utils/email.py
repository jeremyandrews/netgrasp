from netgrasp.utils import debug

email_instance = None

class Email:
    def __init__(self, config, debugger):
        from netgrasp import netgrasp
        self.debugger = debugger
        self.config = config

        self.enabled = config.GetBoolean("Email", "enabled", False, False)
        if not self.enabled:
            debugger.warning("email is disabled")
            return

        try:
            import pyzmail
        except Exception as e:
            self.debugger.error("fatal exception: %s", (e,))
            self.debugger.critical("failed to import pyzmail (as user %s), try: 'pip install pyzmail' or disable [Email], exiting.", (self.debugger.whoami(),))

        self.email_to = config.GetEmailList("Email", "to")
        if not len(self.email_to):
            self.debugger.warning("no valid to address configured, email is disabled")
            self.enabled = False
            return

        email_from = config.GetEmailList("Email", "from")
        if len(email_from) > 1:
            self.debugger.warning("only able to send from one address, using %s", (email_from[0],))
        elif not len(email_from):
            self.debugger.warning("no valid from address configured, email is disabled")
            self.enabled = False
            return
        self.email_from = email_from[0]

        self.email_hostname = config.GetText("Email", "smtp_hostname")
        self.email_port = config.GetText("Email", "smtp_port", None, False)
        self.email_mode = config.GetText("Email", "smtp_mode", "normal", False)
        if not self.email_mode in ["normal", "ssl", "tls"]:
            self.debugger.warning("ignoring invalid email mode (%s), must be one of: normal, ssl, tls", (self.email_mode,))
            self.email_mode = "normal"

        self.email_username = config.GetText("Email", "smtp_username", None, False)
        self.email_password = config.GetText("Email", "smtp_password", None, False, True)

        self.alerts = []
        self.digest = []
        alerts = config.GetTextList("Email", "alerts", None, False)
        digests = config.GetTextList("Email", "digests", None, False)
        for alert in alerts:
            if alert in netgrasp.ALERT_TYPES:
                self.alerts.append(alert)
            else:
                self.debugger.warn("ignoring unrecognized alert type (%s), supported types: %s", (alert, netgrasp.ALERT_TYPES))
        for digest in digests:
            if digest in netgrasp.DIGEST_TYPES:
                self.digest.append(digest)
            else:
                self.debugger.warn("ignoring unrecognized digest type (%s), supported types: %s", (digest, netgrasp.DIGEST_TYPES))

    def LoadTemplate(self, template):
        try:
            debugger = debug.debugger_instance
            debugger.debug("entering email.LoadTemplate(%s)", (template,))

            import pkg_resources
            import json

            import netgrasp

            # @TODO allow template overrides

            specific_template = "mail_templates/template." + template + ".json"
            default_template = "mail_templates/template.default.json"
            if pkg_resources.resource_exists("netgrasp", specific_template):
                json_template = pkg_resources.resource_string("netgrasp", specific_template)
            elif pkg_resources.resource_exists("netgrasp", default_template):
                json_template = pkg_resources.resource_string("netgrasp", default_template)

            debugger.debug("template loaded: %s", (json_template,))
            data = json.loads(json_template)

            debugger.debug("template parsed: %s", (data,))
            return (data["subject"], data["body"]["html"], data["body"]["text"])
        except:
            debugger.dump_exception("LoadTemplate() FIXME")

    def MailSend(self, template, replace):
        try:
            debugger = debug.debugger_instance
            debugger.debug("entering email.MailSend(%s, %s)", (template, replace))

            from string import Template

            import pyzmail
            template_subject, template_body_html, template_body_text = self.LoadTemplate(template)

            subject = Template(template_subject).substitute(replace)
            body_html = Template(template_body_html).substitute(replace)
            body_text = Template(template_body_text).substitute(replace)

            payload, mail_from, rcpt_to, msg_id = pyzmail.generate.compose_mail(self.email_from, self.email_to, subject, "iso-8859-1", (body_text, "us-ascii"), (body_html, "us-ascii"))
            ret = pyzmail.generate.send_mail(payload, mail_from, rcpt_to, self.email_hostname, self.email_port, self.email_mode, self.email_username, self.email_password)

            if isinstance(ret, dict):
                if ret:
                    failed_recipients = ", ".join(ret.keys())
                    debugger.warning("failed to send email, failed receipients: %s", (failed_recipients,))
                else:
                    debugger.debug("email sent: %s", (ret,))

        except Exception as e:
            debugger.dump_exception("MailSend() FIXME")
