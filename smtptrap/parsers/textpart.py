from base64 import b64decode
import quopri
from unidecode import unidecode
import bs4

def _decode(part):
    encoding = part.get('Content-Transfer-Encoding')
    if encoding=='base64':
        decoded = b64decode(part.get_payload())
    elif encoding=='quoted-printable':
        decoded = quopri.decodestring(part.get_payload())
    else:
        decoded = part.get_payload()
    return decoded

def dump_html(decoded, charset):
    return unidecode("|".join(bs4.BeautifulSoup(decoded.decode(charset),"lxml").strings))