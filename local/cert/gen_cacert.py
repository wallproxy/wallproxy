#!/usr/bin/env python
# Lib\site-packages\pip\_vendor\requests\cacert.pem

import base64, hashlib, re, sys
try: from OpenSSL import crypto
except ImportError: crypto = None

PY3 = sys.version_info[0] >= 3

print('read CA.crt')
with open('CA.crt', 'U') as fp:
    data = fp.read().strip()

if crypto:
    cert = crypto.load_certificate(crypto.FILETYPE_PEM, data)
    issuer = cert.get_issuer(); subj = cert.get_subject()
    info = '''\
# Issuer: CN=%s O=%s OU=%s
# Subject: CN=%s O=%s OU=%s
# Label: "%s"
# Serial: %d''' % (issuer.CN, issuer.O, issuer.OU,
        subj.CN, subj.O, subj.OU, subj.CN, cert.get_serial_number())
else:
    info = '''\
# Issuer: CN=WallProxy CA O=WallProxy OU=WallProxy Root
# Subject: CN=WallProxy CA O=WallProxy OU=WallProxy Root
# Label: "WallProxy CA"
# Serial: 0'''

hexf = lambda s:':'.join('%02x'%i for i in bytearray(s))
d = re.compile(r'(?ms)BEGIN CERTIFICATE[^\n]+\n(.+?)\n[^\n]+END CERTIFICATE')
d = base64.b64decode(d.search(data).group(1))
data = '''%s
# MD5 Fingerprint: %s
# SHA1 Fingerprint: %s
# SHA256 Fingerprint: %s
%s
''' % (info,
       hexf(hashlib.md5(d).digest()),
       hexf(hashlib.sha1(d).digest()),
       hexf(hashlib.sha256(d).digest()),
       data)

print('write cacert.pem')
with open('cacert.pem', 'wb') as fp:
    fp.write(data.encode('latin-1') if PY3 else data)
