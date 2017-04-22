import os
import sys
import multiprocessing
import time
import ConfigParser
import io
import logging

def wiretap():
    name = multiprocessing.current_process().name
    assert os.getuid() == 0, 'Unable to initiate pcap, must be run as root.'
    try:
        import dpkt
    except:
        sys.exit("ERROR: Failed to import dpkt, try: 'pip install dpkt'")
    try:
        import pcap
    except:
        sys.exit("ERROR: Failed to import pcap, try: 'pip install pypcap'")

if __name__ == '__main__':
    multiprocessing.log_to_stderr()
    logger = multiprocessing.get_logger()
    # @TODO make configurable
    logger.setLevel(logging.INFO)

    if os.getuid() != 0:
        raise Exception('Must be run as root.');

    config = ConfigParser.ConfigParser()
    found = config.read(['/etc/netgrasp.cfg', '/usr/local/etc/netgrasp.cfg', '~/.netgrasp.cfg', './netgrasp.cnf'])
    print found

    if config.has_section('Security'):
        gid = config.get('Security', 'gid', 1);
        uid = config.get('Security', 'uid', 1);
        print 'here'
    else:
        # Default to uid/gid 1, typically the daemon user
        gid = 1;
        uid = 1;

    wiretap = multiprocessing.Process(name='wiretap', target=wiretap)
    wiretap.daemon = True
    wiretap.start()

    # remove group privileges
    os.setgroups([])

    os.setgid(gid)
    os.setuid(uid)

    assert (os.getuid() != 0) and (os.getgid() != 0), 'Failed to drop root privileges, aborting.'

    wiretap.join()
