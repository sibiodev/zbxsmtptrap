import types
import ConfigParser

BIND_TO_ADDR = '127.0.0.1'
BIND_TO_PORT = '10025'

ZABBIX_SERVER_ADDR = '127.0.0.1'
ZABBIX_SERVER_PORT = '10051'

LOG_FILE='/var/log/smtptozbx/smtptozbx.log'
SERVER_MEMORY = "/var/lib/smtptotrap/memory.db"

DECODE_HTML = True

# should we send base traps (non discovery)
SEND_BASE_TRAPS = True


class ServerConfiguration(object):
    """Configuration holding class, unpack config file (ini file) in config.section_variable 
    It also does some specific mechanics about ltfs.ini [drive]/[json] section and checks some 
    files."""
    __section_names__ = ['server','zabbix']
    __variable_sections__ = ['subjects','attachments']
    __splittable_key_sections__ = ['attachments']
    
    def bool(self, str):
        if type(str) == types.BooleanType:
            return str
        else:
            return str.lower() in ['y','yes','true','1']
    
    def __init__(self,file_name):
        """Initialize instance by reading the config file"""
        self.set_defaults()
        config = ConfigParser.ConfigParser()
        config.read(file_name)
        for section_name in self.__section_names__:
            for config_name, config_value in config.items(section_name):
                config_long_name = '%s_%s'%(section_name,config_name)
                self.__dict__[config_long_name] = config_value
        for section_name in self.__variable_sections__:
            if section_name in self.__splittable_key_sections__:
                # here we just want to split coma separated keys 
                # i.e entry like: 
                # [section_name]
                #     subkey1,subkey2: value
                # i.e. self.section_name['subkey1']['subkey2']='value'
                self.__dict__[section_name]={}
                for key, value in config.items(section_name):
                    node = self.__dict__[section_name]
                    sub_keys = key.split(',')
                    sub_key_number = len(sub_keys)
                    for position,sub_key in enumerate(sub_keys):
                        sub_key = sub_key.strip()
                        if position+1 == sub_key_number:
                            # we are at the leaf
                            node[sub_key]=value
                            break
                        elif sub_key not in node:
                            node[sub_key]={}
                        node=node[sub_key]
            else:
                self.__dict__[section_name] = dict(config.items(section_name))
        self.format_type()

    def set_defaults(self):
        self.server_bind_address=BIND_TO_ADDR
        self.server_bind_port=BIND_TO_PORT
        self.server_log_file=LOG_FILE
        self.server_memory=SERVER_MEMORY
        self.server_decode_html=DECODE_HTML
        self.server_send_base_traps=SEND_BASE_TRAPS
        self.zabbix_port=ZABBIX_SERVER_PORT
        self.zabbix_address=ZABBIX_SERVER_ADDR

    def format_type(self):
        self.server_decode_html = self.bool(self.server_decode_html)
        self.zabbix_port=int(self.zabbix_port)
        self.server_bind_port=int(self.server_bind_port) 
