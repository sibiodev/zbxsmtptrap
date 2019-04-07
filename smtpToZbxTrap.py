#!/usr/bin/python

# install notes:
# pip install py-zabbix inbox.py bs4 unidecode


from inbox import Inbox
from email import message_from_string
from zabbix.sender import ZabbixMetric, ZabbixSender
from unidecode import unidecode
import json
from time import sleep
import ConfigParser
import argparse

from base64 import b64decode
import quopri
import bs4

from os import environ

import sqlite3
import re

import logging
from logging.handlers import RotatingFileHandler




BIND_TO_ADDR = '127.0.0.1'
BIND_TO_PORT = '10025'

ZABBIX_SERVER_ADDR = '127.0.0.1'
ZABBIX_SERVER_PORT = '10051'

LOG_FILE='/var/log/smtptozbx/smtptozbx.log'
SERVER_MEMORY = "/var/lib/smtptotrap/memory.db"

DECODE_HTML = True

DEFAULT_INI = '/etc/zabbix/smtpToZbxTrap.ini'






class ServerConfiguration(object):
    """Configuration holding class, unpack config file (ini file) in config.section_variable 
    It also does some specific mechanics about ltfs.ini [drive]/[json] section and checks some 
    files."""
    __section_names__ = ['server','zabbix']
    __variable_sections__ = ['subjects']
    
    def __init__(self,file_name):
        """Initialize instance by reading the config file"""
        self.set_defaults()
        config = ConfigParser.ConfigParser()
        config.read(file_name)
        for section_name in self.__section_names__:
            for config_name, config_value in config.items(section_name):
                self.__dict__['%s_%s'%(section_name,config_name)] = config_value
        for section_name in self.__variable_sections__:
            self.__dict__[section_name] = dict(config.items(section_name))

    def set_defaults(self):
        self.server_bind_address=BIND_TO_ADDR
        self.server_bind_port=BIND_TO_PORT
        self.server_log_file=LOG_FILE
        self.server_memory=SERVER_MEMORY
        self.server_decode_html=DECODE_HTML
        self.zabbix_port=ZABBIX_SERVER_PORT
        self.zabbix_address=ZABBIX_SERVER_ADDR

logger = logging.getLogger('smtptozbx')
logger.setLevel(logging.DEBUG)


argument_parser = argparse.ArgumentParser(description='smtpToZbxTrap listener daemon')

argument_parser.add_argument('--ini', 
        dest='ini',
        default=DEFAULT_INI,
        help='Configuration file to use (default: %(default)s)')


group = argument_parser.add_mutually_exclusive_group(required=True)

group.add_argument('--service',
                   action='store_true',
                   help='Run as a service, listen for emails')

group.add_argument('--refresh',
                   action='store_true',
                   help='Resend discoveries in memory to update')

group.add_argument('--list',
                   action='store_true',
                   help='List content of memory')

group.add_argument('--remove',
                   nargs=3,
                   metavar=('HOST','KEY','VALUE'),
                   dest='remove',
                   help='Remove one or more value from memory (wild card character is %)')



args = argument_parser.parse_args()

config=ServerConfiguration(args.ini)

handler = RotatingFileHandler(config.server_log_file, maxBytes=1000000, backupCount=10)
handler.setFormatter( logging.Formatter(fmt='%(asctime)s %(message)s',
                                datefmt='%Y-%m-%d %I:%M:%S %p') )
logger.addHandler(handler)



def filter_unicode(text):
    return text.decode('ascii', errors='ignore')

class MyZabbix(object):
    """A small convenience object to pack ZabbixMetric and ZabbixSender together."""
    
    def __init__(self, zabbix_server, zabbix_port, host):
        self.host = host
        self.server = zabbix_server
        self.port = zabbix_port
        self.metrics = []
    
    def add(self, key, value):
        key = filter_unicode(key)
        value = filter_unicode(value)
        host = filter_unicode(self.host)
        self.metrics.append( ZabbixMetric(host,key,value) )
        
    def send(self):
        if self.metrics:
            logger.debug('Sending metrics to %s:%d'%(self.server,self.port))
            if DEBUG:
                logger.debug('metrics:{}'.format(self.metrics))
                response = None
            else:
                logger.debug('metrics:{}'.format(self.metrics))
                response = ZabbixSender(self.server, self.port).send(self.metrics)
                logger.debug(response)
            self.metrics = []
        else:
            logger.debug('Metric are empty, nothing to send to %s:%s'%(self.server,self.port) )
            response = None
        return response

class Memory(object):
    """A small wrapper around sqlite3 database. This could be better, se TODO remark in 
    SubjectMatcher class."""
    
    def __init__(self, dbpath=config.server_memory):
        # Check database
        #
        self.db = sqlite3.connect(dbpath)

        try:
            self.db.execute('SELECT * FROM subject')
        except sqlite3.OperationalError:
            self.db.execute('CREATE TABLE subject (host varchar(100), key varchar(50), value varchar(255))')

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
        
    def host_has_key_value(self, host, key, value):
        cursor = self.db.execute("""SELECT count(*) FROM subject WHERE host=? AND key=? AND value=?""",
                    (host, key, value))
        return cursor.fetchall()[0][0]
    
    def get_hosts(self):
        cursor = self.db.execute("""SELECT DISTINCT host FROM subject""")
        return [item[0] for item in cursor.fetchall()];
    
    def list(self):
        cursor = self.db.execute("""SELECT host,key,value FROM subject ORDER BY host,key,value""")
        return cursor.fetchall()

    def remove(self, host, key, value):
        self.db.execute("""DELETE FROM subject WHERE 'host' like ? AND 'key' like ? AND 'value' like ?""",
                    (host, key, value))
        self.db.commit()

class SubjectDiscovery(object):
    """This object is here to produce the subjectdiscovery SMTP trap (smtp.trap.subject.dicovery[ key ]).
    You must fill in manually constant SUBJECT_DISCOVERY for the key (which is a prototype class name) 
    associated with a regexp that will trigger the discovery if it matches (regexp must have one named group
    named after the key and this group will catch the value), thus yielding a new "value" which will then
    trigger associated prototypes in your discovery rule.
    
    Keep in mind that in this context value is the name of the new prototype, and not a zabbix metric value.
    
    """
    
    def __init__(self, memory, myzabbix, host):
        self.memory = memory
        self.host = host
        self.prototype_classes = []
        self.prototype_regexp = {}
        self.zabbix = myzabbix
        self.host_match = {}
        for prototype_class, regexp in config.subjects.items():
            self.prototype_classes.append(prototype_class)
            self.prototype_regexp[prototype_class] = re.compile(regexp)
        
    def parse(self, subject):
        for prototype_class in self.prototype_classes:
            m = self.prototype_regexp[prototype_class].match(subject)
            if m:
                metricgroups = m.groupdict()
                prototype_name = metricgroups[prototype_class]
                self.host_match[(prototype_class,prototype_name)]=metricgroups
                if self.memory.host_has_key_value(self.host, prototype_class,
                                                  prototype_name):
                    logger.debug('This prototype ({}:{}) is already known for host {}.'.format(
                        prototype_class,prototype_name,self.host))
                    continue
                else:
                    prototype_names = list(self.memory.get_subject_values(
                        self.host,prototype_class))
                    prototype_names.append(prototype_name)
                    
                    data = [ { "{{#{}}}".format(prototype_class.upper())  : prototype_name  }
                                         for prototype_name in prototype_names ]
                                         
                    discovery = json.dumps({"data": data}, indent=4)
                    
                        
                    self.zabbix.add("smtp.trap.subject.discovery[{}]".format(prototype_class),
                                discovery)
                    logger.debug('New prototype name {}: discovery sent : {}.'.format(prototype_name,discovery))
                    self.memory.add_subject(self.host, prototype_class, prototype_name)
                    logger.debug('New value {}: added in memory.'.format(prototype_name))

def resend_discovery(zabbix_server=config.zabbix_address, zabbix_port=int(config.zabbix_port)):
    memory = Memory()
    
    for host in memory.get_hosts():
        myzabbix = MyZabbix(zabbix_server, zabbix_port, host)
        host_prototypes = {}
        for proto_class,proto_name in memory.get_subject_key_values(host):
            if proto_class not in host_prototypes:
                host_prototypes[proto_class]=[]
            if proto_name not in host_prototypes[proto_class]:
                host_prototypes[proto_class].append(proto_name)
            
        for proto_class in host_prototypes.keys():
            data = [ { "{{#{}}}".format(proto_class.upper())  : proto_name  }
                        for proto_name in host_prototypes[proto_class] ]
            discovery = json.dumps({"data": data}, indent=4)
            myzabbix.add("smtp.trap.subject.discovery[{}]".format(proto_class),
                                discovery)
            
        myzabbix.send()
    

class SubjectMatcher(object):
    r"""This object is here to use prototypes created by SubjectDiscovery class. 
    It will trigger a metrics smtp.trap.match.subject[ prototypeclass, prototypename, metricname ] 
    provided you have filled in constant SUBJECT_MATCH with other named groups than the key. 
    
    It relies on Memory object so it will only works if some discovery rule is setup and has been triggered.
    (otherwise the Memory will by empty and there will be no trigger). 
    
    For instance, let's say you want to set traps for backup jobs. Thus the prototypeclass/elementtype would be
    something like "backupjob", now you want to catch the "status" of the job (value would be "success" or 
    "failure"), and the subject would be like 'Job Backup of Domain Controler: Success' :
    
    SUBJECT_MATCH = [ ('backupjob',r'Job (?P<backupjob>.*) : (?P<status>\w+)') ]
    
    then you would use a discovery with this rule:
    
    smtp.trap.subject.discovery[backupjob]
    
    and a prototype element like this :
    
    smtp.trap.subject.match[backupjob, {#BACKUPJOB} , status]
    
    (where {#BACKUPJOB} would be "Backup of Domain Controler" in this context)
        
    """
    #TODO : the use of sqlite3 as a local memory is not very smart. As is not smart the fact that all hosts
    # are tested for all regexp. It would be much better to use Zabbix API and to have keys like:
    #     smtp.trap.subject.discovery[backupjob, "Job (.*):"]
    # and
    #     smtp.trap.subject.match[backupjob, {#BACKUPJOB}, status, "Job {} : (\w+)"]
    # thus there would be no Memory and no need for including manually the regexp in the code which is crappy.
    # BUT it requires at least a read only access to Zabbix API...
    
    def __init__(self, memory, myzabbix, host, host_match):
        self.memory = memory
        self.zabbix = myzabbix
        self.host = host
        self.host_match=host_match
        
    def parse(self, subject, body):
        for (prototype_class, prototype_name), metricgroups in self.host_match.items():
            logger.debug('metricgroups : {}'.format(repr(metricgroups)))
            for metric_name, metric_value in metricgroups.items():
                if metric_name==prototype_class:
                    continue
                else:
                    self.zabbix.add('smtp.trap.subject.match[{},{},{}]'.format(
                                        prototype_class,
                                        prototype_name,
                                        metric_name),
                                    metric_value)
            self.zabbix.add('smtp.trap.subject.match.subject[{},{}]'.format(
                                prototype_class, prototype_name),
                            subject)    
            self.zabbix.add('smtp.trap.subject.match.body[{},{}]'.format(
                                prototype_class, prototype_name),
                            body)

inbox = Inbox()

@inbox.collate

def handle(to, sender, subject, body, zabbix_server=config.zabbix_address, 
                zabbix_port=int(config.zabbix_port)):
    for recipient in to:
        host = recipient.partition('@')[0]
        logger.info('host is %s'%host)
        myzabbix = MyZabbix(zabbix_server, zabbix_port, host)
        
        decoded_body = ""
        email = message_from_string(body)
        for part in email.walk():
            if part.get_content_maintype()!="text":
                continue
            charset = part.get_content_charset()

            encoding = part.get('Content-Transfer-Encoding')
            if encoding=='base64':
                decoded = b64decode(part.get_payload())
            elif encoding=='quoted-printable':
                decoded = quopri.decodestring(part.get_payload())
            else:
                decoded = part.get_payload()
            
            if DECODE_HTML and part.get_content_subtype()=='html':
                try:
                    logger.debug('trying decode html (charset {})...'.format(charset))
                    decoded_body += unidecode("|".join(bs4.BeautifulSoup(decoded.decode(charset),"lxml").strings))
                except Exception as e:
                    logger.debug('...failed for reason {}'.format(e))
                    decoded_body += decoded
            else:
                decoded_body += decoded

        logger.debug('final body: %s'%decoded_body)
        
        smtptrap_memory = Memory()
        subject_discovery = SubjectDiscovery(smtptrap_memory, myzabbix, host)
        subject_discovery.parse(subject)
        # must send discovery if there is one before sending any other metrics
        if myzabbix.metrics:
            myzabbix.send()
            logger.debug('Now waiting one minute before submitting fresh results after discovery.')
            sleep(60)
        else:
            logger.debug('No discovery in this email.')

        subject_matcher = SubjectMatcher(smtptrap_memory, myzabbix, host,
                                         subject_discovery.host_match)
        subject_matcher.parse(subject, decoded_body)
        
        myzabbix.add('smtp.trap[message]', decoded_body)
        myzabbix.add('smtp.trap[sender]', sender)
        myzabbix.add('smtp.trap[subject]', subject)
        myzabbix.send()




if __name__=='__main__':
    if args.service:
        logger.info('Starting')
        inbox.serve(address = config.server_bind_address,
                    port = int(config.server_bind_port))
    elif args.refresh:
        logger.info('Refreshing discoveries')
        resend_discovery()
    elif args.list:
        last_host, last_key = None, None
        for host,key,value in Memory().list():
            if host!=last_host:
                last_host=host
                last_key=key
                print(host,end=':')
                print(key,end=':')
            else:
                print(" "*len(last_host),end=':')
                if key!=last_key:
                    last_key=key
                    print(key,end=':')
                else:
                    print(" "*len(last_key),end=':')
            print (value)
    elif args.remove:
        host, key, value = args.remove
        Memory().remove(host, key, value)
        print('Those where removed: ',host,key,value)
        

            
