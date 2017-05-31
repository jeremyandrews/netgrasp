import fcntl
import os
import errno
import time
from netgrasp.utils import debug
from netgrasp.utils import simple_timer

class ExclusiveFileLock:
    def __init__(self, lockfile, timeout, name):
        self._lockfile = lockfile
        self._timeout = timeout
        self._name = name
        self._timer = None
        self._fd = None
        self.debugger = debug.debugger_instance

    def __enter__(self):
        try:
            self._fd = os.open(self._lockfile, os.O_CREAT)
            started = time.time()
            while True:
                self.debugger.debug("grabbing lock: %s", (self._name))
                self._timer = simple_timer.Timer()
                try:
                    fcntl.flock(self._fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    # We got the lock.
                    self.debugger.debug("grabbed lock (took %.5f seconds): %s", (round(self._timer.elapsed(), 5), self._name))
                    self._timer = simple_timer.Timer()
                    return
                except (OSError, IOError) as ex:
                    if ex.errno != errno.EAGAIN:
                        # Resource temporarily unavailable.
                        self.debugger.warning("LOCK UNAVAILABLE: %s", (self._name,))
                        raise
                    elif self._timeout is not None and time.time() > (started + self._timeout):
                        # Exceeded timeout.
                        self.debugger.warning("LOCK TIMEOUT: %s", (self._name,))
                        raise
                # Briefly wait before trying the lock again.
                time.sleep(0.05)
        except Exception as e:
            self.debugger.dump_exception("ExclusiveFileLock.__enter__()", False)

    def __exit__(self, *args):
        try:
            fcntl.flock(self._fd, fcntl.LOCK_UN)
            held_lock = round(self._timer.elapsed(), 5)
            if held_lock > 1:
                # Holding the lock this long suggests a possible problem.
                self.debugger.warning("released lock (held %.5f seconds): %s", (held_lock, self._name))
            else:
                self.debugger.debug("released lock (held %.5f seconds): %s", (held_lock, self._name))
            os.close(self._fd)
            self._timer = None
            self._fd = None

            try:
                # Remove the lockfile if we can.
                os.unlink(self._path)
            except:
                pass
        except Exception as e:
            self.debugger.dump_exception("ExclusiveFileLock.__exit__()", False)
