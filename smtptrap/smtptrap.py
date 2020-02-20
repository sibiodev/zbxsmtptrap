#!/usr/bin/python

# install notes:
# pip install py-zabbix inbox.py bs4 unidecode



from email import message_from_string

import json
from time import sleep


#import StringIO
import subprocess


import bs4

from os import environ

import re
import logging
from smtptrap.memory import Memory
from smtptrap.myzabbix import MyZabbix
from smtptrap.subject import SubjectDiscovery, SubjectMatcher
from smtptrap.parsers import archive,xmlitems,textpart

logger = logging.getLogger('smtptozbx')









class SmtpTrap(object):

    def __init__(self, zabbix_server, zabbix_port, decode_html, subject_regexps, attachments, base_traps):
        self.zabbix_server=zabbix_server
        self.zabbix_port=zabbix_port
        self.memory = Memory()
        self.subject_discovery = SubjectDiscovery(self.memory, subject_regexps)
        self.attachments = attachments
        self.decode_html = decode_html

    def handle(self, to, sender, subject, body):
        for recipient in to:
            host = recipient.partition('@')[0]
            logger.info('host is %s'%host)
            myzabbix = MyZabbix(zabbix_server=self.zabbix_server, 
                zabbix_port=self.zabbix_port, 
                memory=self.memory, 
                host=host)

            # parse subject
            #   if myzabbix has some metrics, because it comes from SubjectDiscovery,
            #   these metrics are necessarily discoveries
            subject_match = self.subject_discovery.parse(subject)
            #   must send discovery if there is one before sending any other metrics
            if subject_match:
                for prototype_class, prototype_name in subject_match.keys():
                    myzabbix.check_discovery(host, prototype_class, prototype_name)
                if myzabbix.has_discovery():
                    myzabbix.send_discovery()
                else:
                    logger.debug('No discovery in this email.')
            
                    # parse body & attachments
                    decoded_body = ""
                    email = message_from_string(body)
                    for part in email.walk():
                        if part.get_content_maintype()=="text":
                            charset = part.get_content_charset()

                            decoded = textpart._decode(part)
                            
                            if self.decode_html and part.get_content_subtype()=='html':
                                try:
                                    logger.debug('trying decode html (charset {})...'.format(charset))
                                    decoded_body += textpart.dump_html(decoded, charset)
                                except Exception as e:
                                    logger.debug('...failed for reason {}'.format(e))
                                    decoded_body += decoded
                            else:
                                decoded_body += decoded
                        else:
                            part_type = part.get_content_type()
                            logger.debug('Found a {} attachment.'.format(part_type))
                            for prototype_class, prototype_name in subject_match.get_prototypes():
                                if prototype_class in self.attachments:
                                    if part_type in self.attachments[prototype_class]:
                                        logger.info('{} attachment is required for prototype {}'.format(
                                            part_type, prototype_class
                                        ))

                                        part_payload = part.get_payload()

                                        parser_definition = self.attachments[prototype][part_type]
                                        logger.info('Sending attachment to feeder {}'.format(
                                            parser_definition
                                        ))

                                        feeders = parser_definition.split(':')
                                        for feeder in feeders:
                                            if feeder=='gunzip':
                                                part_payload = archive.gunzip(part_payload)
                                            elif feeder=='unzip':
                                                part_payload = archive.unzip(part_payload)
                                            elif feeder=='xmlitems':
                                                items = xmlitems.xmlitems(part_payload)
                                                part_payload=''
                                                for item_name, attr, value in items:
                                                    myzabbix.add('smtp.trap.subject.match.item[{},{},{},{}]'.format(
                                                                prototype_class,
                                                                prototype_name,
                                                                item_name,
                                                                attr,
                                                            ),
                                                            value
                                                        )
                                            else:
                                                logger.error('Unknown attachment feeder {}'.format(feeder))
                                                break
                                        else:
                                            # if some payload remains, attach it
                                            if part_payload:
                                                myzabbix.add('smtp.trap.subject.match.attachment[{},{},{}]'.format(
                                                                prototype_class,
                                                                prototype_name,
                                                                part_type,
                                                            ),
                                                            part_payload
                                                            )
                                        
                    logger.debug('final body: %s'%decoded_body)
                    subject_matcher = SubjectMatcher(myzabbix = myzabbix, 
                                                subject_match = subject_match)
                    subject_matcher.parse(subject, decoded_body)

                    
                    if base_traps:
                        myzabbix.add('smtp.trap[message]', decoded_body)
                        myzabbix.add('smtp.trap[sender]', sender)
                        myzabbix.add('smtp.trap[subject]', subject)
                    myzabbix.send()
            
            
            else:
                logger.warning('Not a matching subject email, doing nothing')



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
    


            