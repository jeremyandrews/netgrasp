from netgrasp.utils import debug

import ConfigParser
import sys

config_instance = None

class Config:
    def __init__(self, debugger):
        from netgrasp import netgrasp
        self.parser = ConfigParser.ConfigParser()
        self.debugger = debugger
        self.found = self.parser.read(netgrasp.DEFAULT_CONFIG)

    def _GetValue(self, section, option, value, default, required, secret):
        if not value and default:
            value = default

        if required and not value and value != False:
            self.debugger.critical("Required [%s] '%s' not defined in configuration file, exiting.", (section, option))

        if value != None:
            if secret:
                self.debugger.info2("configuration [%s] '%s' set", (section, option))
            else:
                self.debugger.info2("configuration [%s] '%s' set to '%s'", (section, option, value))
        else:
            if value:
                if secret:
                    self.debugger.info2("configuration [%s] '%s' set to default", (section, option))
                else:
                    if default:
                        if secret:
                            self.debugger.info2("configuration [%s] '%s' set to default", (section, option))
                        else:
                            self.debugger.info2("configuration [%s] '%s' set to default of '%s'", (section, option, value))
        return value

    def GetText(self, section, option, default = None, required = True, secret = False):
        try:
            if (self.parser.has_section(section) and self.parser.has_option(section, option)):
                value = self.parser.get(section, option)
            else:
                value = None
            return self._GetValue(section, option, value, default, required, secret)

        except Exception as e:
            self.debugger.dump_exception("GetText() exception while reading configuration")

    def GetInt(self, section, option, default = None, required = True, secret = False):
        try:
            if (self.parser.has_section(section) and self.parser.has_option(section, option)):
                value = self.parser.getint(section, option)
            else:
                value = None
            return self._GetValue(section, option, value, default, required, secret)

        except Exception as e:
            self.debugger.dump_exception("GetInt() exception while reading configuration")

    def GetBoolean(self, section, option, default = None, required = True, secret = False):
        try:
            if (self.parser.has_section(section) and self.parser.has_option(section, option)):
                value = self.parser.getboolean(section, option)
            else:
                value = None
            return self._GetValue(section, option, value, default, required, secret)

        except Exception as e:
            self.debugger.dump_exception("GetBoolean() exception while reading configuration")

    def GetTextList(self, section, option, default = None, required = True, secret = False, quiet = False):
        try:
            if (self.parser.has_section(section) and self.parser.has_option(section, option)):
                text = self.parser.get(section, option)
                values = text.split(",")
                textlist = []
                for value in values:
                    textlist.append(value.strip())
            else:
                textlist = None
            if quiet:
                return textlist
            else:
                return self._GetValue(section, option, textlist, default, required, secret)

        except Exception as e:
            self.debugger.dump_exception("GetTextList() exception while reading configuration")

    def GetEmailList(self, section, option, default = None, required = True, secret = False):
        try:
            emails = self.GetTextList(section, option, default, required, secret, True)
            addresses = []
            if emails:
                for email in emails:
                    pieces = email.split("|")
                    if len(pieces) == 2:
                        name, address = pieces
                        if valid_email_address(address):
                            addresses.append((name.strip(), address.strip()))
                        else:
                            self.debugger.error("ignoring invalid email address (%s)", (address,))
                    elif len(pieces) == 1:
                        if valid_email_address(email):
                            addresses.append(email)
                        else:
                            self.debugger.error("ignoring invalid email address (%s)", (email,))
                    else:
                        self.debugger.error("ignoring invalid email address (%s)", (email,))
            return self._GetValue(section, option, addresses, default, required, secret)

        except Exception as e:
            self.debugger.dump_exception("GetEmailList() exception while reading configuration")

    def GetItemPairs(self, section, keys):
        import re
        try:
            pairs = {}
            valid = True
            if (self.parser.has_section(section)):
                temp = []
                items = self.parser.items(section)
                for key, value in items:
                    match = re.match(r"([a-z]+)([0-9]+)", key, re.I)
                    if match:
                        groups = match.groups()
                        if groups:
                            keytype = groups[0]
                            keyvalue = groups[1]
                            if keytype in keys:
                                temp.append((keytype, keyvalue, value))
                temp.sort()
                for keytype, keyvalue, value in temp:
                    if keytype in pairs:
                        pairs[keytype].append((keyvalue, value))
                    else:
                        pairs[keytype] = [(keyvalue, value)]
                previous_size = -1
                for key in keys:
                    ordered = []
                    try:
                        pairs[key].sort
                        previous_id = -1
                        for id, value in pairs[key]:
                            if previous_id >= 0 and previous_id + 1 != int(id):
                                valid = False
                                self.debugger.error("[%s] '%s' missing key %d", (section, key, previous_id + 1))
                                print "[%s] '%s' missing key %d" % (section, key, previous_id + 1)
                            ordered.append(value)
                            previous_id = int(id)
                        pairs[key] = ordered
                        size = len(pairs[key])
                        if previous_size >= 0 and previous_size != size:
                            valid = False
                            self.debugger.error("[%s] '%s' has mismatched number of keys", (section, key,))
                            print "[%s] '%s' has mismatched number of keys" % (section, key,)
                        previous_size = size
                    except:
                        valid = False
                        self.debugger.error("one or more '%s' keys missing from configuration", (key,))
                for key in keys:
                    try:
                        size = len(pairs[key])
                    except:
                        valid = False
                if valid:
                    return pairs
                else:
                    return {}
            else:
                pairs = None
            return pairs

        except Exception as e:
            self.debugger.dump_exception("GetItems() exception while reading configuration")

# Perform simplistic email address validation.
def valid_email_address(address):
    try:
        from email.utils import parseaddr
        if not "@" in parseaddr(address)[1]:
            return False
        else:
            return True

    except Exception as e:
        self.debugger.dump_exception("valid_email_address() exception while reading configuration")
