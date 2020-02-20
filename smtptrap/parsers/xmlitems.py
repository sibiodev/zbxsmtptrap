
# Zip parser
############################################################################################
#
# Zabbix Zip parser
#
# This program is designed to XML attachment... 
#
# ...such as sent by Google or Zerospam for DMARC (I have never personally received any from
# Microsoft). I will refer as them as "the receiver" because they have sent this report
# because they havereceived mail for which you have requested a report through DMARC.
#
# The XML structure contains several "records" for one domain policy. Each record
# gives a source IP address (the sender detected by the receiver), a figure (count) that
# is the number of emails and two criteria, SPF and DKIM, each can be "pass" (ok) or "fail"
# (not ok). 
#
# In this version we do not take into account from/mfrom domain misalignment, just the 
# final figure.
#
# The goal of this feeder is to discover the different source IP addresses and send 4 
# metrics per address : SPF pass, DKIM pass, SPF fail, DKIM fail.
#
############################################################################################



# in fact using XMLPath data can be preprocessed easily
# so we could just split the record in order to create one event per record
# or we could just split all values and get zabbix event with all details
import xml.etree.ElementTree as ET
import StringIO


def xmlitems(payload):
    """This xml should represent a list of thing like:
<root>
   <item>
       <attribute>value1</attribute>
   </item>
   <item>
       <attribute>value2</attribute>
   </item>
   <item>
      <subitem>
         <attribute>value3</attribute>
      </subitem>
   </item>
</root>

and this will return:

[ ('item','attribute','value1'), ('item','attribute','value2'), ('item','subitem.attribute','value3') ]
    """
    with StringIO.StringIO(payload) as xmlcontent:
        xmlflow = ET.parse(xmlcontent)
        root = xmlflow.getroot()
        items=[]
        for item in root.getchildren():
            item_name = item.tag
            for child in item.getchildren():
                attribute_name = child.tag
                while child.getchildren():
                    child = list(child.getchildren())[-1]
                    attribute_name = "{}.{}".format(attribute_name,child.tag)
                attribute_value = child.text
                items.append( (item_name, attribute_name, attribute_value) )
        return items
