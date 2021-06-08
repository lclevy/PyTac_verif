'''
PyTac_verif.py

a free tool to verify Covid-19 vaccination certificate signature (ECDSA) 

Laurent Clevy (@Lorenzo2472)
8juin2021

2d-doc specification from ANTS
https://ants.gouv.fr/content/download/516/5665/version/11/file/Specifications-techniques-des-codes-a-barres_2D-Doc_v3.1.3.pdf

how to check signature (requires checking Certificate Revocation Lists, not done here)
https://ants.gouv.fr/content/download/515/5660/version/5/file/ANTS_2D-Doc_Processus_v1.2.pdf

tested with FR00 0001 and FR03 AV01 certificates
'''

openssl_check = False

from binascii import hexlify

from Crypto.PublicKey import ECC
from Crypto.Signature import DSS
from Crypto.Util.asn1 import DerSequence
from Crypto.Util.asn1 import DerInteger
from Crypto.Hash import SHA256

from base64 import b32decode
from struct import Struct, unpack_from
from collections import namedtuple
from datetime import date, timedelta
from os import system
import sys

def parse_certificate(data):
  bin_data = data.replace(b'<GS>',b'\x1d').replace(b'<RS>',b'\x1e').replace(b'<US>',b'\x1f')
  sign_offset = bin_data.find( b'\x1f' ) #31 == <US>
  if sign_offset<0:
    print('error no 0x1f marker')
    return
  else:
    msg = bin_data[:sign_offset]  
    signature = bin_data[sign_offset+1:]
    signature = signature + (8-len(signature)%8)*b'=' #base32 padding
    bsign = b32decode(signature)
    return msg, bsign

def convert_date(d): #number of days since 1jan2000
  return date(2000,1,1) + timedelta( int(d,16) ) 


#ANTS_2D-Doc_CABSpec_v3.1.1.pdf, page 17
S_HEADER4 = Struct('2s2s4s4s4s4s2s2s2s')
NT_HEADER4 = namedtuple('header', 'marker version CA_id cert_id publish_date sign_date doc_id perimeter_id country')

with open(sys.argv[1], 'rb') as avf:
  content = avf.read()

if content[:4]==b'DC04': #only Datacode v4
  header = NT_HEADER4(*S_HEADER4.unpack_from(content, 0))
  print(header)

  #print( convert_date( '111E' ) ) #31dec2011
  print( 'publish_date', convert_date( header.publish_date ) )
  print( 'sign_date   ', convert_date( header.sign_date ) )
  print( 'cert', content[4:12] )
  pubkey = '%s_PUB.PEM' % content[4:12].decode('ascii')
else:
  sys.exit()
  
#extract content and signature
msg, bsign = parse_certificate(content)

r = bsign[:32]
s = bsign[32:]

#requires openssl installed
if openssl_check:
  print('\ntesting with openssl')
  der_sign = DerSequence( [DerInteger(int.from_bytes(r, 'big')), DerInteger(int.from_bytes(s, 'big'))] ).encode()
  with open('sign.der', 'wb') as signf:
    signf.write( der_sign )
   
  with open('msg.hex', 'wb') as msgf:
    msgf.write(msg )

  system('openssl dgst -sha256 -verify %s -signature sign.der msg.hex' % pubkey)

#only with Python
print('\ntesting with PyCryptodome')
key = ECC.import_key( open(pubkey).read() )
verifier = DSS.new(key, 'deterministic-rfc6979')
try:
    verifier.verify(SHA256.new(msg), bsign)
    print ("The message is authentic.")
except ValueError:
    print ("The message is not authentic.")

'''
        Serial Number:
            a9:30:4b:dc:47:d3:38:45
        Signature Algorithm: sha1WithRSAEncryption
        Issuer: C = FR, O = AC DE TEST, OU = 0002 00000000000000, CN = FR00
        Validity
            Not Before: Nov  1 13:47:46 2012 GMT
            Not After : Nov  1 13:47:46 2015 GMT
        Subject: C = FR, O = CERTIFICAT DE TEST, OU = 0002 00000000000000, CN = 0001
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey

you can get FR03 AV01 and AV02 certificates here:
https://ants.gouv.fr/content/download/517/5670/version/23/file/TLS_valide-signed-xades-baseline-b.xml
lines 214, 215 for FR03 certs
http://certificates.certigna.fr/search.php?iHash=xvNLC1KMs03t%2FgxzdBYParPnf%2BM

Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            34:ff:bf:04:17:98:3d:cd:85:85:76:9b:9f:91:09:31
        Signature Algorithm: sha256WithRSAEncryption
        Issuer: C = FR, O = DHIMYOTIS, OU = 0002 48146308100036, CN = FR03
        Validity
            Not Before: Apr 22 22:00:00 2021 GMT
            Not After : Apr 21 21:59:59 2024 GMT
        Subject: C = FR, O = CAISSE NATIONALE D'ASSURANCE MALADIE, OU = 0002 18003502402369, CN = AV01
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                pub:
                    04:d5:3f:6e:1b:66:c4:3f:bb:96:34:3e:91:4f:f9:
                    49:b3:6c:bb:f3:b0:64:10:9a:11:30:c2:d7:be:a3:
                    ca:14:50:b7:72:4a:85:00:f9:c5:8d:b8:af:fe:87:
                    65:58:7d:38:6b:53:fd:0a:f6:82:47:11:b7:d4:53:
                    04:38:56:72:5c
                ASN1 OID: prime256v1
                NIST CURVE: P-256
        X509v3 extensions:
            Authority Information Access: 
                CA Issuers - URI:http://autorite.dhimyotis.com/2ddoc.der
                CA Issuers - URI:http://autorite.certigna.fr/2ddoc.der
                OCSP - URI:http://2ddoc.ocsp.certigna.fr
                OCSP - URI:http://2ddoc.ocsp.dhimyotis.com

            X509v3 Authority Key Identifier: 
                keyid:4D:83:84:50:D0:7D:A3:DE:E0:02:96:46:28:A5:F7:46:A1:AD:28:7A

            X509v3 Basic Constraints: 
                CA:FALSE
            X509v3 Certificate Policies: 
                Policy: 1.2.250.1.177.2.2.1.1
                  CPS: https://www.certigna.com/autorite-certification

            X509v3 CRL Distribution Points: 

                Full Name:
                  URI:http://crl.dhimyotis.com/2ddoc.crl

                Full Name:
                  URI:http://crl.certigna.fr/2ddoc.crl

            X509v3 Extended Key Usage: 
                Any Extended Key Usage
            X509v3 Key Usage: critical
                Digital Signature, Non Repudiation
            X509v3 Subject Alternative Name: 
                othername:<unsupported>
            X509v3 Subject Key Identifier: 
                07:E8:EE:73:C1:53:C6:DD:0F:ED:D4:EA:CC:5B:F5:D6:49:85:D3:2C
    Signature Algorithm: sha256WithRSAEncryption
         44:1a:fe:d7:f1:6c:96:48:1b:95:35:5e:32:ab:bf:e1:60:c5:
         f4:5d:2e:3c:a5:98:b8:7f:aa:e5:93:06:72:21:e8:9c:77:c5:
         be:55:aa:98:31:d8:36:57:01:37:f3:4b:9e:05:0d:2e:3b:25:
         f4:14:41:c2:58:97:12:0a:9f:35:a9:40:c5:13:db:b6:2b:49:
         2d:d6:2e:a8:d6:d6:ca:cf:ad:b6:6f:3e:4b:0d:21:a2:27:f7:
         a2:1b:56:49:75:5c:c5:16:a4:49:8e:f2:fe:bc:df:e2:07:7e:
         fe:0d:87:25:be:a6:79:a9:1f:c1:fc:de:eb:47:17:5d:8f:3f:
         3c:a8:ad:76:cb:85:f0:75:22:a7:e5:c9:b3:d2:96:ef:72:dc:
         4a:56:06:39:5d:8a:53:97:8b:cd:06:79:45:9b:91:85:b3:a8:
         b5:92:76:19:d5:d0:b2:a4:75:0b:4b:aa:78:bb:3a:c7:dc:94:
         c2:51:c2:73:76:2a:10:93:d6:7d:06:34:10:03:73:2e:c5:88:
         c0:e7:10:f6:d7:03:c8:53:48:8e:82:7c:fb:54:d4:5f:b2:c7:
         68:2d:61:49:88:e8:19:fc:c0:00:4c:75:3f:10:04:f1:13:03:
         21:7b:5c:71:ad:80:6d:e3:a1:bf:81:ed:cc:fb:69:90:ac:71:
         05:cf:22:2b:a2:c1:f3:30:e7:bc:06:69:d5:92:36:8a:91:4c:
         5a:7b:28:2c:be:a4:7d:7d:70:9d:b1:af:9d:dc:43:3b:35:fe:
         5f:a7:d1:dc:0a:e0:c0:77:97:b6:31:1c:ef:1e:d8:5e:11:63:
         bb:73:46:3a:f7:d5:11:6c:f6:92:b7:98:cd:46:8f:30:ea:1f:
         f6:5a:1d:30:db:69:09:dd:41:ef:5d:e1:22:47:8b:f5:85:91:
         e4:5a:8f:d5:54:41:3b:99:a8:5b:d7:ad:e9:90:d0:4f:8d:b7:
         e8:52:28:6e:9a:fd:99:1f:5b:1d:b7:d8:09:64:85:0b:a6:67:
         ad:6d:57:f3:6e:1f:a7:d7:2b:10:13:c1:e0:23:a4:9a:5f:fc:
         f2:f4:aa:fd:bf:67:20:94:4a:58:60:23:97:7a:16:af:f5:76:
         01:c9:d5:40:64:3b:78:d2:37:d8:1e:3a:b0:97:69:5e:c7:cd:
         67:cc:27:ef:94:27:ef:fc:b5:76:43:21:83:a1:32:8b:b1:77:
         69:9e:64:1d:ad:2f:b1:d9:86:72:62:33:89:f6:bd:78:37:19:
         42:25:f4:2f:78:50:9b:c4:65:ae:9b:f3:2b:92:7c:86:ea:ba:
         54:32:80:78:40:70:4a:60:91:b5:12:88:f4:62:66:4b:28:73:
         da:5d:5c:e9:b5:e0:85:33
-----BEGIN CERTIFICATE-----
MIIFoTCCA4mgAwIBAgIQNP+/BBeYPc2FhXabn5EJMTANBgkqhkiG9w0BAQsFADBO
MQswCQYDVQQGEwJGUjESMBAGA1UECgwJREhJTVlPVElTMRwwGgYDVQQLDBMwMDAy
IDQ4MTQ2MzA4MTAwMDM2MQ0wCwYDVQQDDARGUjAzMB4XDTIxMDQyMjIyMDAwMFoX
DTI0MDQyMTIxNTk1OVowaTELMAkGA1UEBhMCRlIxLTArBgNVBAoMJENBSVNTRSBO
QVRJT05BTEUgRCdBU1NVUkFOQ0UgTUFMQURJRTEcMBoGA1UECwwTMDAwMiAxODAw
MzUwMjQwMjM2OTENMAsGA1UEAwwEQVYwMTBZMBMGByqGSM49AgEGCCqGSM49AwEH
A0IABNU/bhtmxD+7ljQ+kU/5SbNsu/OwZBCaETDC176jyhRQt3JKhQD5xY24r/6H
ZVh9OGtT/Qr2gkcRt9RTBDhWclyjggIpMIICJTCB0AYIKwYBBQUHAQEEgcMwgcAw
MwYIKwYBBQUHMAKGJ2h0dHA6Ly9hdXRvcml0ZS5kaGlteW90aXMuY29tLzJkZG9j
LmRlcjAxBggrBgEFBQcwAoYlaHR0cDovL2F1dG9yaXRlLmNlcnRpZ25hLmZyLzJk
ZG9jLmRlcjApBggrBgEFBQcwAYYdaHR0cDovLzJkZG9jLm9jc3AuY2VydGlnbmEu
ZnIwKwYIKwYBBQUHMAGGH2h0dHA6Ly8yZGRvYy5vY3NwLmRoaW15b3Rpcy5jb20w
HwYDVR0jBBgwFoAUTYOEUNB9o97gApZGKKX3RqGtKHowCQYDVR0TBAIwADBWBgNV
HSAETzBNMEsGCiqBegGBMQICAQEwPTA7BggrBgEFBQcCARYvaHR0cHM6Ly93d3cu
Y2VydGlnbmEuY29tL2F1dG9yaXRlLWNlcnRpZmljYXRpb24wWwYDVR0fBFQwUjAo
oCagJIYiaHR0cDovL2NybC5kaGlteW90aXMuY29tLzJkZG9jLmNybDAmoCSgIoYg
aHR0cDovL2NybC5jZXJ0aWduYS5mci8yZGRvYy5jcmwwDwYDVR0lBAgwBgYEVR0l
ADAOBgNVHQ8BAf8EBAMCBsAwLwYDVR0RBCgwJqAkBgkqgXoBgTFlhXWgFwwVQXR0
ZXN0YXRpb25fdmFjY2luYWxlMB0GA1UdDgQWBBQH6O5zwVPG3Q/t1OrMW/XWSYXT
LDANBgkqhkiG9w0BAQsFAAOCAgEARBr+1/FslkgblTVeMqu/4WDF9F0uPKWYuH+q
5ZMGciHonHfFvlWqmDHYNlcBN/NLngUNLjsl9BRBwliXEgqfNalAxRPbtitJLdYu
qNbWys+ttm8+Sw0hoif3ohtWSXVcxRakSY7y/rzf4gd+/g2HJb6meakfwfze60cX
XY8/PKitdsuF8HUip+XJs9KW73LcSlYGOV2KU5eLzQZ5RZuRhbOotZJ2GdXQsqR1
C0uqeLs6x9yUwlHCc3YqEJPWfQY0EANzLsWIwOcQ9tcDyFNIjoJ8+1TUX7LHaC1h
SYjoGfzAAEx1PxAE8RMDIXtcca2AbeOhv4HtzPtpkKxxBc8iK6LB8zDnvAZp1ZI2
ipFMWnsoLL6kfX1wnbGvndxDOzX+X6fR3ArgwHeXtjEc7x7YXhFju3NGOvfVEWz2
kreYzUaPMOof9lodMNtpCd1B713hIkeL9YWR5FqP1VRBO5moW9et6ZDQT4236FIo
bpr9mR9bHbfYCWSFC6ZnrW1X824fp9crEBPB4COkml/88vSq/b9nIJRKWGAjl3oW
r/V2AcnVQGQ7eNI32B46sJdpXsfNZ8wn75Qn7/y1dkMhg6Eyi7F3aZ5kHa0vsdmG
cmIzifa9eDcZQiX0L3hQm8RlrpvzK5J8huq6VDKAeEBwSmCRtRKI9GJmSyhz2l1c
6bXghTM=
-----END CERTIFICATE-----
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE1T9uG2bEP7uWND6RT/lJs2y787Bk
EJoRMMLXvqPKFFC3ckqFAPnFjbiv/odlWH04a1P9CvaCRxG31FMEOFZyXA==
-----END PUBLIC KEY-----

Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            34:26:68:a2:ff:09:28:0d:ff:7e:ca:2e:c7:31:07:cb
        Signature Algorithm: sha256WithRSAEncryption
        Issuer: C = FR, O = DHIMYOTIS, OU = 0002 48146308100036, CN = FR03
        Validity
            Not Before: Apr 22 22:00:00 2021 GMT
            Not After : Apr 21 21:59:59 2024 GMT
        Subject: C = FR, O = CAISSE NATIONALE D'ASSURANCE MALADIE, OU = 0002 18003502402369, CN = AV02
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                pub:
                    04:de:32:fa:cd:0d:1a:42:3f:5e:24:75:30:e1:50:
                    c7:07:db:0c:a2:f8:8b:54:89:40:0e:7a:01:c0:2e:
                    37:31:df:29:f7:0e:b9:e7:3d:9b:0e:16:04:11:a8:
                    d0:d9:a9:90:ce:df:9e:53:b1:dd:5a:bb:ea:63:6d:
                    c3:a3:dd:48:ce
                ASN1 OID: prime256v1
                NIST CURVE: P-256

'''
