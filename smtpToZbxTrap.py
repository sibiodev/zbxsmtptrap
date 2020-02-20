#!/usr/bin/python

# install notes:
# pip install py-zabbix inbox.py bs4 unidecode


from inbox import Inbox
from email import message_from_string

from unidecode import unidecode
import json
from time import sleep
import argparse

#import StringIO
import subprocess

from base64 import b64decode
import quopri
import bs4

from os import environ

import re

import logging
from logging.handlers import RotatingFileHandler



from utilities.server_configuration import ServerConfiguration
from utilities.myzabbix import MyZabbix, DISCOVERY_LATENCY
from utilities.memory import Memory

from parser import dmarc

DEFAULT_INI = '/etc/zabbix/smtpToZbxTrap.ini'






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
                   help='Remove one or more value from memory (wild card character is %%)')



args = argument_parser.parse_args()

config=ServerConfiguration(args.ini)       

handler = RotatingFileHandler(config.server_log_file, maxBytes=1000000, backupCount=10)
handler.setFormatter( logging.Formatter(fmt='%(asctime)s %(message)s',
                                datefmt='%Y-%m-%d %I:%M:%S %p') )
logger.addHandler(handler)

 





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
        self.seen_prototype_classes=[]
        
    def parse(self, subject):
        self.seen_prototype_classes=[]
        for prototype_class in self.prototype_classes:
            m = self.prototype_regexp[prototype_class].match(subject)
            if m:
                metricgroups = m.groupdict()
                prototype_name = metricgroups[prototype_class]
                self.seen_prototype_classes.append(prototype_class)
                self.host_match[(prototype_class,prototype_name)]=metricgroups
                self.zabbix.add_discovery(prototype_class, prototype_name)
    
    def get_prototypes(self):
        """Return prototypes class seen at last parse
        """
        return self.seen_prototype_classes

def resend_discovery(zabbix_server=config.zabbix_address, zabbix_port=config.zabbix_port):
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


def _decode(part):
    encoding = part.get('Content-Transfer-Encoding')
    if encoding=='base64':
        decoded = b64decode(part.get_payload())
    elif encoding=='quoted-printable':
        decoded = quopri.decodestring(part.get_payload())
    else:
        decoded = part.get_payload()
    return decoded

@inbox.collate
def handle(to, sender, subject, body, zabbix_server=config.zabbix_address, 
                zabbix_port=config.zabbix_port, decode_html=config.server_decode_html,
                attachments=config.attachments,
                base_traps=config.server_send_base_traps):
    for recipient in to:
        host = recipient.partition('@')[0]
        logger.info('host is %s'%host)
        myzabbix = MyZabbix(zabbix_server, zabbix_port, host)
        
        # parse subject
        #   if myzabbix has some metrics, because it comes from SubjectDiscovery,
        #   these metrics are necessarily discoveries
        smtptrap_memory = Memory()
        subject_discovery = SubjectDiscovery(smtptrap_memory, myzabbix, host)
        subject_discovery.parse(subject)
        #   must send discovery if there is one before sending any other metrics
        if myzabbix.metrics:
            myzabbix.send()
            logger.debug('Now waiting {} seconds before submitting fresh results after discovery.'.format(
                DISCOVERY_LATENCY
            ))
            sleep(DISCOVERY_LATENCY)
            smtptrap_memory.unlock_lock(host)
        else:
            logger.debug('No discovery in this email.')


        # parse body & attachments
        decoded_body = ""
        email = message_from_string(body)
        for part in email.walk():
            if part.get_content_maintype()=="text":
                charset = part.get_content_charset()

                decoded = _decode(part)
                
                if decode_html and part.get_content_subtype()=='html':
                    try:
                        logger.debug('trying decode html (charset {})...'.format(charset))
                        decoded_body += unidecode("|".join(bs4.BeautifulSoup(decoded.decode(charset),"lxml").strings))
                    except Exception as e:
                        logger.debug('...failed for reason {}'.format(e))
                        decoded_body += decoded
                else:
                    decoded_body += decoded
            else:
                part_type = part.get_content_type()
                logger.debug('Found a {} attachment.'.format(part_type))
                for prototype in subject_discovery.get_prototypes():
                    if prototype in attachments:
                        if part_type in attachments[prototype]:
                            logger.info('{} attachment is required for prototype {}'.format(
                                part_type, prototype
                            ))
                            parser_definition = attachments[prototype][part_type]
                            logger.info('Sending attachment to feeder {}'.format(
                                parser_definition
                            ))
                            parser_module, parser_name = parser_definition.split('.')
                            if parser_module == 'dmarc':
                                module = dmarc
                            else:
                                logger.error('Unknown parser module {}'.format(parser_module))
                                continue
                            if parser_name in dir(module):
                                parser = module.__dict__(parser_name)
                            else:
                                logger.error('Unknown parser function {}'.format(parser_name))
                                continue
                            try:
                                parser(_decode(part), myzabbix)
                            except Exception as e:
                                logger.error('feeder output is undecipherable : {}'.format(e))
                            
        logger.debug('final body: %s'%decoded_body)
        

        subject_matcher = SubjectMatcher(smtptrap_memory, myzabbix, host,
                                         subject_discovery.host_match)
        subject_matcher.parse(subject, decoded_body)
        
        if base_traps:
            myzabbix.add('smtp.trap[message]', decoded_body)
            myzabbix.add('smtp.trap[sender]', sender)
            myzabbix.add('smtp.trap[subject]', subject)
            for attachment in attachments:
                myzabbix.add('smtp.trap[attachment]', attachment)
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
            else:
                host=" "*len(last_host)
                if key!=last_key:
                    last_key=key
                else:
                    key=" "*len(last_key)
            print('{}:{}:{}'.format(host, key, value))
    elif args.remove:
        host, key, value = args.remove
        Memory().remove(host, key, value)
        print('Those where removed: {}:{}:{}'.format(host,key,value))        

            
