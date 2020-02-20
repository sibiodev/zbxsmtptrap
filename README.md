# zbxsmtptrap

inspired by BDiE8VNy

The idea of zbxsmtptrap is to trap email as SNMPtrap does. While email is not a really light mechanism is has several quality over SNMP:
 - it is available as an alternative to SNMP for a variety of programs and tend to be more available than SNMP, or be a default free option in a number of case,
 - it is easier to include in scripts,
 - it routes easily and benefit from traditional email infrastructures.

 Example applications are :
  - backup monitoring (notably Veeam which offers a much better integration with Zabbix using smtptrap than with its highly inefficient and CPU costly powershell snippet),
  - high level system monitoring (like graylog, etc.)

## Install

### Prerequisite

  You need python 2.6+ and you need to install requirements.txt with pip:
  ```bash
  pip install -r requirements.txt
  ```

### Configuration

  You will need to adapt smtpToZbxTrap.ini file to suit your needs. Notably, unless you use the already made regular expression, you will have to create one.

  If you need to catch attachments (other than html part which is included as the body),
  you must add an entry matching your regular expression title in [send_attachments] section and indicate a "feed" program that will have to read the attachment from its standard entry (stdin). This feed program must be specified as an entry matching the regular expresion title in [feed_attachments].

  See the example below.

### Zabbix setup

  Last you will need to create a discovery rule suited to your regular expression. See the example in smtpToZbxTrap.ini


## Example

### Regular expression

This is to be present (and by default one is already present) in `[subjects]` section of smtptozbxtrap.ini :

```
veeamjob: \[(?P<status>.*)\] (?P<veeamjob>.+) \((?P<detail>.*)\)
```
NB: this is a slightly simplified version. Note that you need one of the named group to match the name you give to this new type of subject, here this name is `veeamjob`, this is the entity to be discovered. Other named group, `status` and `detail` will be treated as items of this new entity.

The email must be sent to the server where smtptozbxtrap service is running (not necessarily the host where zabbix server itself is running), and as in the initial thread mentionned at the top of this page, the recipient (before the @) must match Zabbix hostname of the monitored host.

#### Attachment

If you need to parse an attachment with the above example add this in configuration file:
```
[send_attachments]
  veeamjob: application/gzip, application/zip

[feed_attachments]
  veemjob: /usr/local/bin/my_veeam_attachment_feeder.pl
```
Note that the feeder only get the attachment on its standard input, as for now, it does not
receive any other values catched by the regular expression (maybe in the future).

A feeder must read its standard input and do something with it.

### Zabbix setup

You need a low level discovery (LLD) rule of type `Zabbix trapper` with key: `smtp.trap.subject.discovery[veeamjob]`. Use a template if you need to apply to several hosts of course.

Next, you can set up different item prototype (of type `Zabbix trapper`) with these keys:

`smtp.trap.subject.match[veeamjob,{#VEEAMJOB},status]`

(this item will cath the status of Veeam job as the name suggests)

The body can also be catched with this key:
`smtp.trap.subject.match.body[veeamjob,{#VEEAMJOB}]`

(this will catch the body only if the host match the recipient of the email and the subject match the subject regular expression).

HTML bodies are transcripted to full text (this behaviour is controlled by `decode_html` boolean in `[server]` section in smtpToZbxTrap.ini), to allow further retreatment by dependent items for instance (and they are simply more readable decoded in Zabbix interface)


## Memory

smtpToZbxTrap maintain a memory of discovered hosts and subjects (entities). This memory is an sqlite database whith a single table:

```SQL
CREATE TABLE subject (
    host varchar(100), 
    key varchar(50), 
    value varchar(255)
)
```
This simple setup has the default to require a little maintenance of this memory on several (rare) occasions.

By usefullness:

### Refresh discovery

In case you change your discovery rules, you will need your discovery to be resent. This is automatic for entities discovered after the modification, but will not happend for already discovered entities. For them, you will need to 'refresh' the rule, do this with :

```bash
python smtpToZbxTrap.py --refresh
```

### Explore memory

Sometimes you need to know what is inside your memory. Of course, you can use sqlite directly, but for convenience a small function has been added:

```bash
python smtpToZbxTrap.py --list
```

### Clean memory

Last, sometimes, an host or entity need to be removed (so that it is not sent anymore to Zabbix). This should be done for deleted zabbix hosts to limit Zabbix trapper solicitation.

```bash
python smtpToZbxTrap.py --remove <host> <key> <value>
```

This will delete all entries in memory matching `<host>`, `<key>` and `<value>`(that should be replaced with real values of course). The `%`caracter is the wildcard here.

# Enhancements

## Better discoveries
Now we lock memory specifically for one host when a discovery is made. This prevent new values
to be sent to zabbix *even* if they come from another email.

# Limitations

## Discoveries are slow
This is not too bad, as we are talking about email. You are not supposed to be in a hurry when treating emails, so a one minute delay is not too bad. The first time an entity is discovered, most often, a trap should be sent immediately after its discovery. This does not work properly if we do so, so we wait one minute after sending the discovery leaving time for Zabbix to create the entity, before we sent the first item trap. 

## Email server is very simple
At the time of this writing, the inbox.py code on which we depends implement a minimal set of SMTP dialect (notably HELO but not EHLO).

## Encoding treatment is basic
Although this code works in production, it has only been thoroughly tested in Veeam context and in France (mix of English and French spelling and writing).  

ASFAIK there should not be anymore a violent crash of the server, but entities, values and keys should be in plain ascii any non ascii character will be ignored.

