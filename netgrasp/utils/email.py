from netgrasp.utils import debug

class Email:
    def __init__(self):
        from netgrasp import netgrasp
        ng = netgrasp.netgrasp_instance

        if not ng.email["enabled"]:
            ng.debugger.warning("email is disabled")
            return

        try:
            import pyzmail
        except Exception as e:
            ng.debugger.error("fatal exception: %s", (e,))
            ng.debugger.critical("failed to import pyzmail (as user %s), try: 'pip install pyzmail' or disable [Email], exiting.", (ng.debugger.whoami(),))

        if not len(ng.email["to"]):
            ng.debugger.warning("no valid to address configured, email is disabled")
            ng.email["enabled"] = False
            return

        if len(ng.email["from"]) > 1:
            ng.debugger.warning("only able to send from one address, using %s", (ng.email["from"][0],))
        elif not len(ng.email["from"]):
            ng.debugger.warning("no valid from address configured, email is disabled")
            ng.email["enabled"] = False
            return
        ng.email["from"] = ng.email["from"][0]

        if not ng.email["mode"] in ["normal", "ssl", "tls"]:
            ng.debugger.warning("ignoring invalid email mode (%s), must be one of: normal, ssl, tls", (ng.email["mode"],))
            ng.email["mode"] = "normal"

        alerts = []
        for alert in ng.email["alerts"]:
            if alert in netgrasp.ALERT_TYPES:
                alerts.append(alert)
            else:
                ng.debugger.warning("ignoring unrecognized alert type (%s), supported types: %s", (alert, netgrasp.ALERT_TYPES))
        ng.email["alerts"] = alerts

        digests = []
        for digest in ng.email["digests"]:
            if digest in netgrasp.DIGEST_TYPES:
                digests.append(digest)
            else:
                ng.debugger.warning("ignoring unrecognized digest type (%s), supported types: %s", (digest, netgrasp.DIGEST_TYPES))
        ng.email["digests"] = digests

def LoadTemplate(template, template_type, replace):
    import jinja2

    from netgrasp import netgrasp

    ng = netgrasp.netgrasp_instance

    try:
        ng.debugger.debug("entering email.LoadTemplate(%s, %s)", (template, template_type, replace))

        # @TODO allow template overrides

        env = jinja2.Environment(
            loader = jinja2.PackageLoader("netgrasp", "mail_templates"),
            autoescape = jinja2.select_autoescape(['html']),
            extensions=['jinja2.ext.i18n']
        )
        # For now we're just using i18n for pluralization, not translations.
        env.install_null_translations()

        templates = {}
        for extension in ["subject.txt", "html", "txt"]:
            try:
                specific_template = "template." + template_type +  "." + template + "." + extension
                templates[extension] = env.get_template(specific_template)
                ng.debugger.debug("loaded specific %s template: %s", (extension, specific_template))
            except jinja2.TemplateNotFound:
                default_template = "template." + template_type + ".default." + extension
                templates[extension] = env.get_template(default_template)
                ng.debugger.debug("loaded default %s template: %s", (extension, default_template))

        subject = templates["subject.txt"].render(replace)
        body_html = templates["html"].render(replace)
        body_text = templates["txt"].render(replace)

        return subject, body_html, body_text

    except:
        ng.debugger.dump_exception("LoadTemplate() exception")

def MailSend(template, template_type, replace):
    from netgrasp import netgrasp
    ng = netgrasp.netgrasp_instance

    try:
        ng.debugger.debug("entering email.MailSend(%s, %s, %s)", (template, template_type, replace))

        import pyzmail

        subject, body_html, body_text = LoadTemplate(template, template_type, replace)

        payload, mail_from, rcpt_to, msg_id = pyzmail.generate.compose_mail(ng.email["from"], ng.email["to"], subject, "iso-8859-1", (body_text, "us-ascii"), (body_html, "us-ascii"))
        ret = pyzmail.generate.send_mail(payload, mail_from, rcpt_to, ng.email["hostname"], ng.email["port"], ng.email["mode"], ng.email["username"], ng.email["password"])

        if isinstance(ret, dict):
            if ret:
                failed_recipients = ", ".join(ret.keys())
                ng.debugger.warning("failed to send email, failed receipients: %s", (failed_recipients,))
            else:
                ng.debugger.debug("email sent: %s", (ret,))

    except Exception as e:
        ng.debugger.dump_exception("MailSend() exception")
