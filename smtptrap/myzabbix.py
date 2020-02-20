from zabbix.sender import ZabbixMetric, ZabbixSender
import logging
import json
from time import sleep

# how long must we wait between a discoveyr and a new value in seconds
DISCOVERY_LATENCY=60

logger = logging.getLogger('smtptozbx')

def filter_unicode(text):
    return text.decode('ascii', errors='ignore')

class MyZabbixError(Exception):
    pass

class MyZabbix(object):
    """A convenience object to pack ZabbixMetric and ZabbixSender together, and deal with 
    discovery and proper per host locking."""
    
    def __init__(self, zabbix_server, zabbix_port, memory, host):
        self.server = zabbix_server
        self.port = zabbix_port
        self.metrics = []
        self.discovery_metrics = {}
        self.memory = memory
        self.host = host
    
    def add(self, key, value):
        key = filter_unicode(key)
        value = filter_unicode(value)
        host = filter_unicode(self.host)
        self.metrics.append( ZabbixMetric(host,key,value) )

    def check_discovery(self, prototype_class, prototype_name):
        """Check if discovery is already known to Zabbix and then add it to the memory
        """
        self.memory.wait_for_host(self.host, bypass=True)
        if self.memory.host_has_key_value(host, prototype_class,prototype_name):
            logger.debug('This prototype ({}:{}) is already known for host {}.'.format(
                prototype_class,prototype_name,host))
        else:
            self.memory.lock(host)
            if prototype_class not in self.discovery_metrics:
                self.discovery_metrics[prototype_class]=[]
            self.discovery_metrics[prototype_class].append(prototype_name)

    def has_discovery(self):
        return bool(self.discovery_metrics)

    def _send(self, metrics):
        logger.debug('Sending metrics to %s:%d'%(self.server,self.port))
        logger.debug('metrics:{}'.format(self.metrics))
        response = ZabbixSender(self.server, self.port).send(self.metrics)
        logger.debug(response)
        return response

    def send_discoveries(self):
        if self.discovery_metrics:
            lowlevel_discovery_metrics=[]
            for prototype_class in self.discovery_metrics.keys():
                prototype_names = list(memory.get_subject_values(
                    host,prototype_class))
                prototype_names.extend(self.discovery_metrics[prototype_class])
                    
                data = [ { "{{#{}}}".format(prototype_class.upper())  : prototype_name  }
                            for prototype_name in prototype_names ]
                                        
                discovery = json.dumps({"data": data}, indent=4)

                lowlevel_discovery_metrics.append( ZabbixMetric(
                    filter_unicode(self.host),
                    filter_unicode("smtp.trap.subject.discovery[{}]".format(prototype_class)),
                    filter_unicode(discovery) 
                ) )
                
            response = self._send(lowlevel_discovery_metrics)
            logger.debug('Discoveries sent for host {} : {}'.format(self.host,response))

            for prototype_class in self.discovery_metrics.keys():
                for prototype_name in self.discovery_metrics[prototype_class]:
                    self.memory.add_subject(host, prototype_class, prototype_name)
                    logger.debug('New prototype name {}: discovery sent : {}.'.format(prototype_name,discovery))
                    
            sleep(DISCOVERY_LATENCY)
            self.memory.unlock(self.host)
            self.discovery_metrics={}
        else:
            logger.debug('Discoveries are empty, nothing to send to %s:%s'%(self.server,self.port) )
            response = None 

        return response

    def send(self):
        if self.metrics:
            self.memory.wait_for_host(self.host)
            response = self._send(self.metrics)
            self.metrics = []
        else:
            logger.debug('Metric are empty, nothing to send to %s:%s'%(self.server,self.port) )
        return response
