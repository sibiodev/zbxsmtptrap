import re
import logging
logger = logging.getLogger('smtptozbx')


class SubjectMatch(object):
    """This object represent a match in a particular subject scan.
    """
    def __init__(self):
        self._values = {}
        self._seen_prototypes=[]
    def __nonzero__(self):
        return bool(self._values)
    def add(self, prototype_class, prototype_name, metricgroups):
        self._seen_prototypes.append((prototype_class, prototype_name))
        self._values[(prototype_class,prototype_name)]=metricgroups
    def items(self):
        return self._values.items()
    def keys(self):
        return self._values.keys()
    def get_prototypes(self):
        """Return prototypes class seen at last parse
        """
        return self._seen_prototypes


class SubjectDiscovery(object):
    """This object is here to produce the subjectdiscovery SMTP trap (smtp.trap.subject.dicovery[ key ]).
    You must fill in manually constant SUBJECT_DISCOVERY for the key (which is a prototype class name) 
    associated with a regexp that will trigger the discovery if it matches (regexp must have one named group
    named after the key and this group will catch the value), thus yielding a new "value" which will then
    trigger associated prototypes in your discovery rule.
    
    Keep in mind that in this context value is the name of the new prototype, and not a zabbix metric value.
    
    """
    
    def __init__(self, subject_regexps):
        self.prototype_classes = []
        self.prototype_regexp = {}
        self.host_match = {}
        for prototype_class, regexp in subject_regexps.items():
            self.prototype_classes.append(prototype_class)
            self.prototype_regexp[prototype_class] = re.compile(regexp)
        
    def parse(self, subject):
        subject_match = SubjectMatch()
        for prototype_class in self.prototype_classes:
            m = self.prototype_regexp[prototype_class].match(subject)
            if m:
                metricgroups = m.groupdict()
                prototype_name = metricgroups[prototype_class]
                subject_match.add(prototype_class,prototype_name,metricgroups)

        return subject_match
    
    


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
    
    def __init__(self, myzabbix, subject_match):
        self.zabbix = myzabbix
        self.subject_match=subject_match
        
    def parse(self, subject, body):
        for (prototype_class, prototype_name), metricgroups in self.subject_match.items():
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
