import debug
import logging
import logging.handlers

logger = logging.getLogger(__name__)
formatter = logging.Formatter("%(asctime)s [%(levelname)s/%(processName)s] %(message)s")
handler = logging.StreamHandler()
handler.setFormatter(formatter)
logger.addHandler(handler)


debugger = debug.Debugger(debug.PRINT, logger, logging.WARNING, 1)
debugger.debug('test: %s-%d', ('this', 1), debug.WARNING)
