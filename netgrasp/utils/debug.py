import logging
import sys
import pwd
import os

ALWAYS   = 0
VERBOSE  = 1
VERBOSE2 = 2
VERBOSE3 = 3
FATAL    = True
NOTFATAL = False

DEBUG    = (logging.DEBUG, VERBOSE, NOTFATAL)
DEBUG2   = (logging.DEBUG, VERBOSE2, NOTFATAL)
DEBUG3   = (logging.DEBUG, VERBOSE3, NOTFATAL)
INFO     = (logging.INFO, VERBOSE, NOTFATAL)
INFO2    = (logging.INFO, VERBOSE2, NOTFATAL)
WARNING  = (logging.WARNING, ALWAYS, NOTFATAL)
ERROR    = (logging.ERROR, ALWAYS, NOTFATAL)
CRITICAL = (logging.CRITICAL, ALWAYS, FATAL)

PRINT    = 0
FILE     = 1

debugger_instance = None

# mode: PRINT or FILE
class Debugger:
    def __init__(self, verbose = False, logger = None, mode = PRINT, level = logging.CRITICAL):
        if verbose:
            self.verbose = True
        else:
            self.verbose = False

        self.logger = logger
        self.mode = mode
        self.level = level
        if logger:
            self.logger.setLevel(self.level)

    def log(self, message, args, severity):
        try:
            level, verbose, fatal = severity
            if self.mode == FILE:
                if not self.logger:
                    self.mode = PRINT
                    self.log(message, args, logging.CRITICAL)
                    self.fatal("fatal error, no logger provided, exiting")
                if args:
                    self.logger.log(level, message, *args)
                else:
                    self.logger.log(level, message)

            if fatal:
                # if writing to file we log and then print message, otherwise just print
                self.fatal(message, args)

            if self.mode == PRINT:
                if self.verbose and verbose >= self.verbose:
                    if args:
                        print message % args
                    else:
                        print message
        except Exception as e:
            self.logger.dump_exception("debugger FIXME")

    def dump_exception(self, message = None):
        import os
        import sys

        exc_type, exc_value, exc_traceback = sys.exc_info()

        if exc_type:
            if message:
                self.error("%s: type(%s) value(%s) traceback(%s)", (exc_type, exc_value, exc_traceback))
            else:
                self.error("type(%s) value(%s) traceback(%s)", (message, exc_type, exc_value, exc_traceback))

    # Determine who we are, for pretty logging.
    def whoami(self):
        whoami = pwd.getpwuid(os.getuid())
        if whoami:
            return whoami[0]

    def setLevel(self, level):
        self.level = level
        if self.mode == FILE:
            self.logger.setLevel(level)

    def debug(self, message, args = None):
        self.log(message, args, DEBUG)

    def debug2(self, message, args = None):
        self.log(message, args, DEBUG2)

    def debug3(self, message, args = None):
        self.log(message, args, DEBUG3)

    def info(self, message, args = None):
        self.log(message, args, INFO)

    def info2(self, message, args = None):
        self.log(message, args, INFO2)

    def warning(self, message, args = None):
        self.log(message, args, WARNING)

    def error(self, message, args = None):
        self.log(message, args, ERROR)

    def critical(self, message, args = None):
        self.log(message, args, CRITICAL)

    def fatal(self, message, args = None):
        if args:
            sys.exit(message % args)
        else:
            sys.exit(message)
