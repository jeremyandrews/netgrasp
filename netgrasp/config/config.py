from netgrasp.debug import debug

import ConfigParser
import sys

class Config:
    def __init__(self, parser, debugger):
        self.parser = parser
        self.debugger = debugger
        self.found = self.parser.read(['/etc/netgraspd.cfg', '/usr/local/etc/netgraspd.cfg', '~/.netgraspd.cfg', './netgraspd.cnf'])

    def _GetValue(self, section, option, value, default, required, secret):
        if value != None:
            if secret:
                debugger.info("configuration [%s] '%s' set", (section, option))
            else:
                debugger.info("configuration [%s] '%s' set to '%s'", (section, option, value))
        else:
            if default:
                value = default
                if not secret:
                    if self.parser.has_section(section):
                        debugger.info("configuration [%s] '%s' set to default of '%s'", (section, option, value))
                    else:
                        debugger.info("configuration [%s] does not exist: '%s' set to default '%s'", (section, option, value))
                else:
                    debugger.info("configuration [%s] '%s' set to default", (section, option))
            elif required:
                debugger.critical("Required [%s] '%s' not defined in configuration file, exiting.", (section, option))
        return value

    def GetText(self, section, option, default = None, required = True, secret = False):
        if (self.parser.has_section(section) and self.parser.has_option(section, option)):
            value = self.parser.get(section, option)
        else:
            value = None
        return self._GetValue(section, option, value, default, required, secret)

    def GetInt(self, section, option, default = None, required = True, secret = False):
        if (self.parser.has_section(section) and self.parser.has_option(section, option)):
            value = self.parser.getint(section, option)
        else:
            value = None
        return self._GetValue(section, option, value, default, required, secret)

    def GetBoolean(self, section, option, default = None, required = True, secret = False):
        if (self.parser.has_section(section) and self.parser.has_option(section, option)):
            value = self.parser.getboolean(section, option)
        else:
            value = None
        return self._GetValue(section, option, value, default, required, secret)

    def GetTextList(self, section, option, default = None, required = True, secret = False, quiet = False):
        if (self.parser.has_section(section) and self.parser.has_option(section, option)):
            text = self.parser.get(section, option)
            values = text.split(',')
            textlist = []
            for value in values:
                textlist.append(value.strip())
        else:
            textlist = None
        if quiet:
            return textlist
        else:
            return self._GetValue(section, option, textlist, default, required, secret)

    def GetEmailList(self, section, option, default = None, required = True, secret = False):
        emails = self.GetTextList(section, option, default, required, secret, True)
        addresses = []
        for email in emails:
            pieces = email.split('|')
            if len(pieces) == 2:
                name, address = pieces
                if valid_email_address(address):
                    addresses.append((name.strip(), address.strip()))
                else:
                    debugger.error('ignoring invalid email address (%s)', (address,))
            elif len(pieces) == 1:
                if valid_email_address(email):
                    addresses.append(email)
                else:
                    debugger.error('ignoring invalid email address (%s)', (email,))
            else:
                debugger.error('ignoring invalid email address (%s)', (email,))
        return self._GetValue(section, option, addresses, default, required, secret)

