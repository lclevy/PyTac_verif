'''
PyTac_verif.py

a free tool to verify Covid-19 vaccination certificate signature (ECDSA) 

Laurent Clevy (@Lorenzo2472)

8jun2021 : initial version with signature verification
12jun2021 : download and process TSL and relevant issuer CERTs database with update "-u" option. NO CRYPTO VERIFICATION YET !

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
from Crypto.Util.asn1 import DerSequence, DerInteger, DerBitString, DerObjectId
from Crypto.Hash import SHA256

from base64 import b32decode, b64decode, b64encode
from struct import Struct, unpack_from
from collections import namedtuple
from datetime import date, timedelta
from os import system
import sys
import argparse
import requests
import re
import xml.etree.ElementTree as ET

def parse_certificate(data):
  bin_data = data.replace(b'<GS>',b'\x1d').replace(b'<RS>',b'\x1e').replace(b'<US>',b'\x1f')
  sign_offset = bin_data.find( b'\x1f' ) #31 == <US>
  if sign_offset<0:
    print('error no 0x1f marker')
    return
  else:
    msg = bin_data[:sign_offset]  
    signature = bin_data.strip()[sign_offset+1:]
    signature = signature + (8-len(signature)%8)*b'=' #base32 padding
    bsign = b32decode(signature)
    return msg, bsign

NT_TRUSTSERVICEPROVIDER = namedtuple('tsp', 'trade_name info_uri service_name x509')
def parse_TSL(tls):

  #see https://www.etsi.org/deliver/etsi_ts/119600_119699/119612/02.02.01_60/ts_119612v020201p.pdf
  '''
  TrustServiceStatusList
    0_SchemeInformation
    1_TrustServiceProviderList
      TrustServiceProvider'
        0_TSPInformation'
          0_TSPName'
          1_TSPTradeName'
            Name FR03
            Name FR03
          TSPAddress'
          TSPInformationURI'
        1_TSPServices'
          0_ServiceInformation
            0_ServiceTypeIdentifier
            1_ServiceName
            2_ServiceDigitalIdentity
              0_DigitalId
                0_X509Certificate
    2_Signature' 
  '''
  root = ET.fromstring( tls )
  print('%d trusted services providers found' % len(root[1]) )
  
  #print(root[2]) #signature
  
  tsp = dict()
  for p in root[1]: #TrustServiceProviderList
    TSPTradeName = p[0][1][0].text #TrustServiceProvider.TSPInformation.TSPTradeName = FR03
    TSPInformationURI = p[0][3][0].text #TrustServiceProvider.TSPInformation.TSPInformationURI
    ServiceName = p[1][0][0][1][0].text #TrustServiceProvider.TSPServices.ServiceInformation.ServiceName
    x509 = p[1][0][0][2][0][0].text #TrustServiceProvider.TSPServices.ServiceInformation.ServiceDigitalIdentity.DigitalId.X509Certificate
    tsp[TSPTradeName] = NT_TRUSTSERVICEPROVIDER( TSPTradeName, TSPInformationURI, ServiceName, x509 )
  return tsp


#parse x509 database and extract data containing 'name'
def parse_certdb(db):
  tag_start = b'Content-Type: application/pkix-cert\x0d\x0a\x0d\x0a'
  tag_end = b'\x0d\x0a--End'
  
  name = b'CAISSE NATIONALE D\'ASSURANCE MALADIE'

  start = 0
  while start >= 0:
    start = allcerts.find( tag_start, start )
    if start >= 0:
      start_cert = start+len(tag_start)
      endp = allcerts.find( tag_end, start_cert ) 
      if endp > 0:
        cert  = allcerts[start_cert:endp]
        if cert.find( name )>=0: 
          issuer_cn, subject_cn, pubkey_der = parse_der_cert( cert ) 
          cert_filename = '%s%s_CERT.DER' % ( issuer_cn, subject_cn )
          with open(cert_filename, 'wb') as certf:
            print('saving %s...' % cert_filename)
            certf.write( cert )
        start = endp + len(tag_end)
      else:
        print('?')      
        start = start+1
  
def convert_date(d): #number of days since 1jan2000
  return date(2000,1,1) + timedelta( int(d,16) ) 


'''
https://datatracker.ietf.org/doc/html/rfc5280#section-4.1
seq
  0 seq
    0 version
    1 serial
    2 signature algo (seq)
    3 issuer (seq)
      0 C
      1 O
      2 OU
      3 CN = FR03   
    4 validity
    5 subject (seq)
      0 C
      1 O
      2 OU
      3 
        0 obj_id
        1 UTF8 AV01   
    6 subject pubkey info (seq)
      0 seq
        0 obj_id 1.2.840.10045.2.1 ecPublicKey
        1 obj_id 1.2.840.10045.3.1.7 prime256v1
      1 bit_string   pubkey
    7 x509 ext
  1 seq
  2
'''
def parse_der_cert( der ):
  cert_der = DerSequence().decode( der )
  #assert DerObjectId().decode( DerSequence().decode(DerSequence().decode( DerSequence().decode(cert_der[0])[6] )[0] )[0] ).value == 
  
  issuer_cn = DerSequence().decode(cert_der[0])[3][-4:].decode('ascii')
  subject_cn = DerSequence().decode(cert_der[0])[5][-4:].decode('ascii')
  assert DerObjectId().decode( DerSequence().decode(DerSequence().decode( DerSequence().decode(cert_der[0])[6] )[0] )[0] ).value == '1.2.840.10045.2.1' #ecPublicKey
  assert DerObjectId().decode( DerSequence().decode(DerSequence().decode( DerSequence().decode(cert_der[0])[6] )[0] )[1] ).value == '1.2.840.10045.3.1.7' #prime256v1
  pubkey_der =  DerSequence().decode(cert_der[0])[6]
  return issuer_cn, subject_cn, pubkey_der  


def dl(url):
  try:
    r = requests.get(url)
    if r.status_code==200:
      print('downloaded %s' % url)
      d = r.headers['content-disposition']
      return r.content
    else:
      print('error' , r.status_code)
  except requests.exceptions.ConnectionError:
    print('requests.exceptions.ConnectionError')
  return None


#ANTS_2D-Doc_CABSpec_v3.1.1.pdf, page 17
S_HEADER4 = Struct('2s2s4s4s4s4s2s2s2s')
NT_HEADER4 = namedtuple('header', 'marker version CA_id cert_id publish_date sign_date doc_id perimeter_id country')

parser = argparse.ArgumentParser()
parser.add_argument("vdata", help="vaccination_data", action="store")
parser.add_argument('-v', '--verify', help="verify signature", action="store_true")
parser.add_argument('-s', '--sign', help="generate signature", action="store_true")
parser.add_argument('-u', '--update', help="update certificate database", action="store_true")
args = parser.parse_args()

with open(args.vdata, 'rb') as avf:
  content = avf.read()

TSL_url = 'https://ants.gouv.fr/content/download/517/5670/version/23/file/TLS_valide-signed-xades-baseline-b.xml'
TSL_filename = 'TLS_valide-signed-xades-baseline-b.xml'

if content[:4]==b'DC04': #only Datacode v4
  print('[+]parsing Attestation vaccinale data')
  header = NT_HEADER4(*S_HEADER4.unpack_from(content, 0))
  print(header)

  #print( convert_date( '111E' ) ) #31dec2011
  print( 'publish_date', convert_date( header.publish_date ) )
  print( 'sign_date   ', convert_date( header.sign_date ) )
  print( 'cert', content[4:12] )
  pubkey = '%s_PUB.PEM' % content[4:12].decode('ascii')
  cert_name = '%s_CERT.DER' % content[4:12].decode('ascii')
  
  if args.update: #TO DO: verify signature of all files and CERTs ! 
  
    #get Trusted Service providers list and process it
    print('\n[+]updating Trusted Service providers list')    
    tsl = dl( TSL_url ) 
    if tsl is None:
      print('falling back to local copy, network is broken')
      with open(TSL_filename) as tslf:
        tsl = tslf.read()
    else:
      print('overwriting local %s' % TSL_filename)    
      with open(TSL_filename, 'wb') as tslf:
        tslf.write( tsl )
    tsp = parse_TSL( tsl ) #parse Trusted Services List

    #process cert database for relevant issuer 
    print('\n[+]extracting AV certs from issuer %s' % content[4:8].decode('ascii') )
    allcerts = dl( tsp[content[4:8].decode('ascii')].info_uri ) 
    if allcerts is None:
      print('falling back to local copy, network is broken')
      with open('allcerts - FR03.der', 'rb') as allcertsf:
        allcerts = allcertsf.read()

    parse_certdb( allcerts )

else:
  print('only version 4 is supported')
  sys.exit()

#extract content and signature
msg, bsign = parse_certificate(content)

if args.verify:
  #only with Python
  print('\n[+]verifying signature with PyCryptodome')
  try:
    cert = open(cert_name, 'rb').read()
    key = ECC.import_key( cert )
    verifier = DSS.new(key, 'deterministic-rfc6979')
    try:
        verifier.verify(SHA256.new(msg), bsign)
        print ("The message is authentic.")
    except ValueError:
        print ("The message is not authentic.")
  except FileNotFoundError:
    print('certificate %s not found, maybe you need to update (-u) ?' % cert_name)
    
'''
#broken yet
if args.sign:
  privkey = '%s_PRIV.PEM' % content[4:12].decode('ascii')
  with open( privkey ) as privf:
    key = ECC.import_key( privf.read() )
    signer = DSS.new(key, 'deterministic-rfc6979')
    signature = signer.sign( SHA256.new(msg) )  
    print(SHA256.new(msg).hexdigest())
    print(hexlify(signature))
    print(hexlify(bsign))
'''
#requires openssl installed
if args.verify and openssl_check:
  print('\ntesting with openssl')
  
  r = bsign[:32]
  s = bsign[32:]
  der_sign = DerSequence( [DerInteger(int.from_bytes(r, 'big')), DerInteger(int.from_bytes(s, 'big'))] ).encode()
  with open('sign.der', 'wb') as signf:
    signf.write( der_sign )
   
  with open('msg.hex', 'wb') as msgf:
    msgf.write(msg )

  system('openssl x509 -in %s -inform DER -pubkey -outform PEM -out %s' % (cert_name, pubkey))
  system('openssl dgst -sha256 -verify %s -signature sign.der msg.hex' % pubkey)

