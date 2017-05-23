import fcntl
from netgrasp.utils import debug

class ExclusiveFileLock:
    def __init__(self, lockfile):
        self.lockfile = lockfile
        # Create the lockfile if it doesn't already exist.
        self.handle = open(lockfile, 'w')

    # Acquire exclusive, blocking lock.
    def acquire(self):
        debugger = debug.debugger_instance
        debugger.debug("lock acquired")
        fcntl.flock(self.handle, fcntl.LOCK_EX)

    # Release exclusive, blocking lock.
    def release(self):
        debugger = debug.debugger_instance
        debugger.debug("lock released")
        fcntl.flock(self.handle, fcntl.LOCK_UN)

    def __del__(self):
        self.handle.close()
