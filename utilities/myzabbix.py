from zabbix.sender import ZabbixMetric, ZabbixSender
import logging
import json
from time import sleep

# how long must we wait between a discoveyr and a new value in seconds
DISCOVERY_LATENCY=60

logger = logging.getLogger('smtptozbx')

def filter_unicode(text):
    return text.decode('ascii', errors='ignore')

class MyZabbix(object):
    """A convenience object to pack ZabbixMetric and ZabbixSender together, and deal with 
    discovery and proper per host locking."""
    
    def __init__(self, zabbix_server, zabbix_port, host, memory):
        self.host = host
        self.server = zabbix_server
        self.port = zabbix_port
        self.metrics = []
        self.discovery_metrics = {}
        self.memory = memory
    
    def add(self, key, value):
        key = filter_unicode(key)
        value = filter_unicode(value)
        host = filter_unicode(self.host)
        self.metrics.append( ZabbixMetric(host,key,value) )

    def add_discovery(self, prototype_class, prototype_name):
        self.memory.wait_for_host(self.host, bypass=True)
        if self.memory.host_has_key_value(self.host, prototype_class,prototype_name):
            logger.debug('This prototype ({}:{}) is already known for host {}.'.format(
                prototype_class,prototype_name,self.host))
        elif (prototype_class, prototype_name) in self.discovery_metrics.items():
            logger.debug('This prototype ({}:{}) is already learned in this email for host {}.'.format(
                prototype_class,prototype_name,self.host))
        else:
            self.memory.lock(self.host)
            if prototype_class not in self.discovery_metrics:
                self.discovery_metrics[prototype_class]=[prototype_name]
            else:
                self.discovery_metrics[prototype_class].append(prototype_name)

    def _send(self, metrics):
        logger.debug('Sending metrics to %s:%d'%(self.server,self.port))
        logger.debug('metrics:{}'.format(self.metrics))
        response = ZabbixSender(self.server, self.port).send(self.metrics)
        logger.debug(response)
        return response

    def send(self):
        if self.discovery_metrics:
            lowlevel_discovery_metrics=[]
            for prototype_class in self.discovery_metrics.keys():
                prototype_names = list(self.memory.get_subject_values(
                    self.host,prototype_class))
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

            for prototype_class in self.discovery_metrics.keys():
                for prototype_name in self.discovery_metrics[prototype_class]:
                    logger.debug('New prototype name {}: discovery sent : {}.'.format(prototype_name,discovery))
                    self.memory.add_subject(self.host, prototype_class, prototype_name)

            self.discovery_metrics={}
            sleep(DISCOVERY_LATENCY)
            self.memory.unlock(self.host)
        else:
            logger.debug('Metric are empty, nothing to send to %s:%s'%(self.server,self.port) )
            response = None 
        
        if self.metrics:
            response = self._send(self.metrics)
            self.metrics = []
        else:
            logger.debug('Metric are empty, nothing to send to %s:%s'%(self.server,self.port) )
        return response
