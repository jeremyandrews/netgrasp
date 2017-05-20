import logging
import sys

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
WARNING  = (logging.WARNING, ALWAYS, NOTFATAL)
ERROR    = (logging.ERROR, ALWAYS, NOTFATAL)
CRITICAL = (logging.CRITICAL, ALWAYS, FATAL)

PRINT    = 0
FILE     = 1

# mode: PRINT or FILE
class Debugger:
    def __init__(self, mode = PRINT, logger = None, level = logging.WARNING, verbosity = False):
        self.mode = mode
        self.logger = logger
        self.level = level
        self.verbosity = False

    def debug(self, message, args, severity):
        level, verbose, fatal = severity
        if self.mode == FILE:
            if not self.logger:
                self.mode = PRINT
                self.debug(message, args, level, 9)
                self.fatal("fatal error, no logger provided, exiting")
            if not verbose or verbose >= self.verbosity:
                self.logger.log(level, message, *args)

        if fatal:
            # if writing to file we log and then print message, otherwise just print
            self.fatal(message, args)

        if self.mode == PRINT:
            if verbose >= self.verbosity:
                if args:
                    print message % args
                else:
                    print message

    def fatal(self, message, args = None):
        if args:
            sys.exit(message % args)
        else:
            sys.exit(message)
