# Zip parser
############################################################################################
#
# Zabbix Zip parser
#
# This program is designed to read a ziped or gziped standard attachments 
#
############################################################################################
import StringIO
import gzip
import zipfile




def gunzip(payload):
    """Gunzip a payload
    """
    with StringIO.StringIO(payload) as gzcontent:
        with gzip.GzipFile(fileobj=gzcontent,mode='r') as gzhandler:
            ungzipped = gzhandler.read()
    return ungzipped

def unzip(payload):
    """Unzip a payload
    """
    with StringIO.StringIO(payload) as zipcontent:
        with zipfile.ZipFile(fileobj=zipcontent,mode='r') as zhandler:
            unzipped = zhandler.read()
    return unzipped

