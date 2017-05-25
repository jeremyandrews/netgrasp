import fcntl
import os
import errno
import time

from netgrasp.utils import debug

class ExclusiveFileLock:
    def __init__(self, lockfile, timeout = 5, timeout_message = None):
        self._lockfile = lockfile
        self._timeout = timeout
        self._timeout_message = timeout_message
        self._fd = None
        self.debugger = debug.debugger_instance

    def __enter__(self):
        self._fd = os.open(self._lockfile, os.O_CREAT)
        started = time.time()
        while True:
            try:
                fcntl.flock(self._fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                # We got the lock.
                return
            except (OSError, IOError) as ex:
                if ex.errno != errno.EAGAIN:
                    # Resource temporarily unavailable.
                    if self._timeout_message:
                        self.debugger.warning("LOCK UNAVAILABLE: %s", self._timeout_message)
                    raise
                elif self._timeout is not Non and time.time() > (start + self._timeout):
                    # Exceeded timeout.
                    if self._timeout_message:
                        self.debugger.warning("LOCK TIMEOUT: %s", self._timeout_message)
                    raise
            # Briefly wait before trying the lock again.
            time.sleep(0.1)

    def __exit__(self, *args):
        fcntl.flock(self._fd, fcntl.LOCK_UN)
        os.close(self._fd)
        self._fd = None

        try:
            # Remove the lockfile if we can.
            os.unlink(self._path)
        except:
            pass
