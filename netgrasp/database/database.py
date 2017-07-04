from netgrasp.utils import debug
from netgrasp.utils import exclusive_lock

class Database:
    def __init__(self):
        from netgrasp import netgrasp
        ng = netgrasp.netgrasp_instance

        try:
            import sqlite3
        except Exception as e:
            ng.debugger.error("Error: %e")
            ng.debugger.critical("Failed to import sqlite3, try: 'pip install sqlite3', exiting.")
        
        self.connection = sqlite3.connect(ng.database["filename"], detect_types=sqlite3.PARSE_DECLTYPES)

    def set_state(self, key, value, secret = False):
        from netgrasp import netgrasp
        ng = netgrasp.netgrasp_instance

        try:
            ng.debugger.debug("entering database.set_state(%s) secret(%s)", (key, secret))
            with exclusive_lock.ExclusiveFileLock(ng, 5, "set_state, " + key):
                ng.db.cursor.execute("INSERT OR REPLACE INTO state (key, value) VALUES (?, ?)", (key, value))
                ng.db.connection.commit()
            if secret:
                ng.debugger.info("set key[%s] to hidden value", (key,))
            else:
                ng.debugger.info("set key[%s] to value[%s]", (key, value))

        except Exception as e:
            ng.debugger.dump_exception("set_state() exception")

    def get_state(self, key, default_value, date = False):
        from netgrasp import netgrasp
        ng = netgrasp.netgrasp_instance

        try:
            ng.debugger.debug("entering database.get_state(%s) date(%s)", (key, date))
            ng.db.cursor.execute("SELECT value FROM state WHERE key=?", (key,));
            value = ng.db.cursor.fetchone();
            if value:
                if date:
                    import datetime
                    ng.debugger.debug("returning date: %s", (value[0],))
                    return datetime.datetime.strptime(value[0], "%Y-%m-%d %H:%M:%S.%f")
                else:
                    ng.debugger.debug("returning value: %s", (value[0],))
                    return value[0]
            else:
                ng.debugger.debug("returning default value: %s", (default_value,))
                return default_value

        except Exception as e:
            ng.debugger.dump_exception("get_state() exception")

class SelectQueryBuilder():
    def __init__(self, table):
        from netgrasp import netgrasp
        ng = netgrasp.netgrasp_instance

        self.table = table
        self.select = []
        self.where = []
        self.where_args = []
        self.group = []
        self.order = []
        self.leftjoin = []
        self.verbose = ng.verbose

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
        from netgrasp import netgrasp
        ng = netgrasp.netgrasp_instance

        query_string = "SELECT " + ", ".join(self.select) + " FROM " + self.table
        if len(self.leftjoin):
            query_string += " ".join(self.leftjoin)
        if len(self.where):
            query_string += " WHERE " + " AND ".join(self.where)
        if len(self.group):
            query_string += " GROUP BY " + ", ".join(self.group)
        if len(self.order):
            query_string += " ORDER BY " + ", ".join(self.order)
        ng.debugger.debug("Select query: %s", (query_string,))
        ng.debugger.debug2("Query plan:")
        ng.db.cursor.execute("EXPLAIN QUERY PLAN " + query_string, self.where_args)
        plans = ng.db.cursor.fetchall()
        for plan in plans:
            ng.debugger.debug2(" - %s", plan[3])
        return query_string

    def db_args(self):
        from netgrasp import netgrasp
        ng = netgrasp.netgrasp_instance

        ng.debugger.debug("Select args: %s", (self.where_args,))
        return self.where_args
