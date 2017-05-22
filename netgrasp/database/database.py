from netgrasp.utils import debug

database_instance = None

class Database:
    def __init__(self, filename, debugger):
        self.file = filename
        self.debugger = debugger

        try:
            import sqlite3
        except Exception as e:
            self.debugger.error("Error: %e")
            self.debugger.critical("Failed to import sqlite3, try: 'pip install sqlite3', exiting.")
        
        self.connection = sqlite3.connect(filename, detect_types=sqlite3.PARSE_DECLTYPES)

    def set_state(self, key, value, secret = False):
        self.lock.acquire()
        self.cursor.execute("INSERT OR REPLACE INTO state (key, value) VALUES (?, ?)", (key, value))
        self.connection.commit()
        self.lock.release()
        if secret:
            self.debugger.info("set key[%s] to hidden value", (key,))
        else:
            self.debugger.info("set key[%s] to value[%s]", (key, value))

    def get_state(self, key, default_value, date = False):
        self.cursor.execute("SELECT value FROM state WHERE key=?", (key,));
        value = self.cursor.fetchone();
        if value:
            if date:
                import datetime
                self.debugger.debug("returning date: %s", (value[0],))
                return datetime.datetime.strptime(value[0], "%Y-%m-%d %H:%M:%S.%f")
            else:
                self.debugger.debug("returning value: %s", (value[0],))
                return value[0]
        else:
            self.debugger.debug("returning default value: %s", (default_value,))
            return default_value

class SelectQueryBuilder():
    def __init__(self, table):
        self.table = table
        self.select = []
        self.where = []
        self.where_args = []
        self.group = []
        self.order = []
        self.leftjoin = []

    def _base_table(self, value):
        if isinstance(value, basestring):
            return value.replace('{%BASE}', self.table)
        else:
            return value

    def db_select(self, key):
        key = self._base_table(key)
        self.select.append(key)

    def db_where(self, key, value = False, multiple = False):
        key = self._base_table(key)
        self.where.append(key)
        value = self._base_table(value)
        if multiple:
            for v in value:
                self.where_args.append(v)
        elif value:
            self.where_args.append(value)


    def db_group(self, key):
        key = self._base_table(key)
        self.group.append(key)

    def db_order(self, value):
        value = self._base_table(value)
        self.order.append(value)

    def db_leftjoin(self, table, value):
        value = self._base_table(value)
        self.leftjoin.append(" LEFT JOIN " + table + " ON " + value)

    def db_query(self):
        query_string = "SELECT " + ", ".join(self.select) + " FROM " + self.table
        if len(self.leftjoin):
            query_string += " ".join(self.leftjoin)
        query_string += " WHERE " + " AND ".join(self.where)
        if len(self.group):
            query_string += " GROUP BY " + ", ".join(self.group)
        if len(self.order):
            query_string += " ORDER BY " + ", ".join(self.order)
        if ngs.config_instance.verbose > 1:
            print "Select query:"
            print query_string
        if ngs.config_instance.verbose > 2:
            print "Query plan:"
            self.cursor.execute("EXPLAIN QUERY PLAN " + query_string, self.where_args)
            plans = self.cursor.fetchall()
            for plan in plans:
                print " - " + plan[3]
        return query_string

    def db_args(self):
        if ngs.config_instance.verbose > 1:
            print 'Select args: ', self.where_args
        return self.where_args
        
        
