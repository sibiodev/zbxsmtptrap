############################################################################################
#
# Zabbix DMARC feeder
#
# This program is designed to read a ziped or gziped standard DMARC XML attachment 
# such as sent by Google or Zerospam (I have never personally received any from
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

