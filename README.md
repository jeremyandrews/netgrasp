Python network observation tool.

Dependencies:
 - dpkt https://github.com/kbandla/dpkt (pip install dpkt)
 - pcap https://github.com/dugsong/pypcap (pip install pypcap)

Architecture:

 - Multi-process, allows for priv-sep
   o master process:
     - spawns other threads
     - writes MAC info to db
     - logs
     - send emails
   o MAC process:
     - detects MAC pacets
   o email process:

Database:
 - macs:
    interface TEXT,
    network TEXT,
    firstSeen NUMERIC,
    lastSeen NUMERIC,
    ip TEXT,
    mac TEXT,
    lastChecked NUMERIC,
    stale NUMERIC, (bool?)

	db['connection'].execute("""CREATE TABLE IF NOT EXISTS history(
	  timestamp NUMERIC,
	  currency_from TEXT,
	  currency_to TEXT,
	  value REAL,
	  PRIMARY KEY(timestamp, currency_from, currency_to))""")
