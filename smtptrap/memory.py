import sqlite3
from myzabbix import DISCOVERY_LATENCY
from time import sleep

class Memory(object):
    """A wrapper around sqlite3 database. This could be better, se TODO remark in 
    SubjectMatcher class."""
    
    def __init__(self, dbpath=config.server_memory):
        # Check database
        #
        self.db = sqlite3.connect(dbpath)
        self.internal=[]
        try:
            self.db.execute('SELECT * FROM subject')
        except sqlite3.OperationalError:
            self.db.execute('CREATE TABLE subject (host varchar(100), key varchar(50), value varchar(255))')
        try:
            self.db.execute('DELETE FROM subject_lock')
            self.db.commit()
        except sqlite3.OperationalError:
            self.db.execute('CREATE TABLE subject_lock (host varchar(100))')
        

    def get_subject_values(self, host, key):
        cursor = self.db.execute('SELECT value FROM subject WHERE host=? AND key=?', (host,key) )
        return [item[0] for item in cursor.fetchall()];

    def get_subject_key_values(self, host):
        cursor = self.db.execute('SELECT key,value FROM subject WHERE host=?', (host,) )
        return cursor.fetchall()

    def add_subject(self, host, key, value):
        self.db.execute("""INSERT INTO subject ('host','key','value') VALUES (?,?,?)""",
                    (host, key, value))
        self.db.commit()
        
    def lock_host(self, host):
        self.internal.append(host)
        self.db.execute("""INSERT INTO subject_lock ('host') VALUES (?)""",
                    (host,))
        self.db.commit()

    def host_has_key_value(self, host, key, value):
        cursor = self.db.execute("""SELECT count(*) FROM subject WHERE host=? AND key=? AND value=?""",
                    (host, key, value))
        return cursor.fetchall()[0][0]

    def host_is_locked(self, host, bypass=False):
        if host in self.internal and bypass:
            return False
        else:
            cursor = self.db.execute("""SELECT count(*) FROM new_subject WHERE host=?""",
                        (host,))
        return cursor.fetchall()[0][0]

    def get_hosts(self):
        cursor = self.db.execute("""SELECT DISTINCT host FROM subject""")
        return [item[0] for item in cursor.fetchall()];
    
    def list(self):
        cursor = self.db.execute("""SELECT host,key,value FROM subject ORDER BY host,key,value""")
        return cursor.fetchall()

    def remove(self, host, key, value):
        self.db.execute("""DELETE FROM subject WHERE host like ? AND key like ? AND value like ?""",
                    (host, key, value))
        self.db.commit()

    def unlock_host(self, host):
        self.db.execute("""DELETE FROM subject_lock WHERE host like ?""",
                    (host, ))                    
        self.db.commit()

    def wait_for_host(self, host, bypass=False):
        while self.host_is_locked(self.host, bypass):
                    sleep(DISCOVERY_LATENCY)