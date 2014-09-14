Python network observation tool.

Dependencies:
 - dpkt https://code.google.com/p/dpkt
 - pcap http://code.google.com/p/pypcap

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
