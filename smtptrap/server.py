from logging.handlers import RotatingFileHandler
import logging
from inbox import Inbox
import argparse

from smtptrap.config import ServerConfiguration
from smtptrap.smtptrap import SmtpTrap

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

smtptrap=SmtpTrap(zabbix_server = config.zabbix_address, 
            zabbix_port=config.zabbix_port, 
            decode_html=config.server_decode_html,
            subject_regexps=config.subjects,
            attachments=config.attachments,
            base_traps=config.server_send_base_traps)    

handler = RotatingFileHandler(config.server_log_file, maxBytes=1000000, backupCount=10)
handler.setFormatter( logging.Formatter(fmt='%(asctime)s %(message)s',
                                datefmt='%Y-%m-%d %I:%M:%S %p') )
logger.addHandler(handler)

 
if __name__=='__main__':
    if args.service:
        logger.info('Starting')

        inbox = Inbox()

        @inbox.collate
        def handle(to, sender, subject, body):
            return smtptrap.handle(to, sender, subject, body)

        inbox.serve(address = config.server_bind_address,
                    port = int(config.server_bind_port))
    elif args.refresh:
        logger.info('Refreshing discoveries')
        smtptrap.resend_discovery()
    elif args.list:
        last_host, last_key = None, None
        for host,key,value in smtptrap.memory.list():
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
        smtptrap.memory.remove(host, key, value)
        print('Those where removed: {}:{}:{}'.format(host,key,value))  








