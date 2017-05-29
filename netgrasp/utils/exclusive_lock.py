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
        try:
            self._fd = os.open(self._lockfile, os.O_CREAT)
            started = time.time()
            while True:
                self.debugger.debug("grabbing lock")
                try:
                    fcntl.flock(self._fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    self.debugger.debug("grabbed lock")
                    # We got the lock.
                    return
                except (OSError, IOError) as ex:
                    if ex.errno != errno.EAGAIN:
                        # Resource temporarily unavailable.
                        if self._timeout_message:
                            self.debugger.warning("LOCK UNAVAILABLE: %s", (self._timeout_message,))
                        raise
                    elif self._timeout is not None and time.time() > (started + self._timeout):
                        # Exceeded timeout.
                        if self._timeout_message:
                            self.debugger.warning("LOCK TIMEOUT: %s", (self._timeout_message,))
                        raise
                # Briefly wait before trying the lock again.
                time.sleep(0.05)
        except Exception as e:
            self.debugger.dump_exception("ExclusiveFileLock.__enter__()", False)

    def __exit__(self, *args):
        try:
            self.debugger.debug("releasing lock")
            fcntl.flock(self._fd, fcntl.LOCK_UN)
            self.debugger.debug("released lock")
            os.close(self._fd)
            self._fd = None

            try:
                # Remove the lockfile if we can.
                os.unlink(self._path)
            except:
                pass
        except Exception as e:
            self.debugger.dump_exception("ExclusiveFileLock.__exit__()", False)
