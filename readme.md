# PyTac_verif.py



a free Python tool to validate the authenticity of french Covid-19 vaccination certificate, signed with ECDSA

Laurent Clévy (@lorenzo2472)

12june2021



### Context

The french document "attestation vaccinale" (vaccination certificate) is available as 2d-doc on paper. Once scanned using a barcode scanner application, the result is usually text like this:

```
DC04FR0000011E6D1E6DL101FRL0THEOULE SUR MER<GS>L1JEAN PAUL<GS>L231051962L3COVID-19<GS>L4J07BX03<GS>L5COMIRNATY PFIZER/BIONTECH<GS>L6COMIRNATY PFIZER/BIONTECH<GS>L71L82L901032021LACO<US>32T2SI2RUMPDLBHAFSBDF2CUE7GI4NR5WC3NSBEU6AZ7QZJZCPMCTXTVIDZAKEYO7237SQ2ZPOCMZKG7U3Q2LIMPPVJMA7TQAAKC5DY
```

Except control characters are generally not well converted : bytes with values 0x1d, 0x1e or 0x1f, respectively called `<GS>`, `<RS>` and `<US>` are often missing. Thus, you'll need to add or replace these missing control markers : add the 4 characters sequence "`<GS>`" before fields L1, L2, L4, L5, L6 and L7 fields, and sequence "`<US>`" before the signature, after sequence "LACO" or "LATE", as in the example above.

In order to be correctly processed by PyTac_verif.py, your 2d-doc data must be format as the example above.

Specifications for french 2d-doc documents are here: https://ants.gouv.fr/Les-solutions/2D-Doc



### "Attestation vaccinale" format

Only the header is described here, for more info, see section 3.3.3 and page 144 in [2].

DC04**FR03**AV01**1E7F**1E7F**L1**01**FR**

| value | meaning                                                |
| ----- | ------------------------------------------------------ |
| DC04  | datacode version 4                                     |
| FR03  | x509 certificate issuer                                |
| AV01  | x509 certificate number                                |
| 1E7F  | emitting date                                          |
| 1E7F  | signature date                                         |
| L1    | type of document : "attestation vaccinale"             |
| 01    | ANTS perimeter (Agence Nationale des Titres Sécurisés) |
| FR    | emitting country : France                              |

Based on trusted list here:

https://ants.gouv.fr/content/download/517/5670/version/23/file/TLS_valide-signed-xades-baseline-b.xml,

FR03 is "Dhimyotis" and x509 certificates database be reached at http://certificates.certigna.fr/search.php?iHash=xvNLC1KMs03t%2FgxzdBYParPnf%2BM. Inside the later file, we can find 2 relevant x509 certificates : AV01 and AV02. These x509 certificates are files FR03AV01_CERT.PEM and FR03AV02_CERT.PEM.



### Usage

    >more FR000001_av.txt
    DC04FR0000011E6D1E6DL101FRL0THEOULE SUR MER<GS>L1JEAN PAUL<GS>L231051962L3COVID-19<GS>L4J07BX03<GS>L5COMIRNATY PFIZER/BIONTECH<GS>L6COMIRNATY PFIZER/BIONTECH<GS>L71L82L901032021LACO<US>32T2SI2RUMPDLBHAFSBDF2CUE7GI4NR5WC3NSBEU6AZ7QZJZCPMCTXTVIDZAKEYO7237SQ2ZPOCMZKG7U3Q2LIMPPVJMA7TQAAKC5DY

This is the example given in specifications

    >python PyTac_verif.py -v FR000001_av.txt
    [+]parsing Attestation vaccinale data
    header(marker=b'DC', version=b'04', CA_id=b'FR00', cert_id=b'0001', publish_date=b'1E6D', sign_date=b'1E6D', doc_id=b'L1', perimeter_id=b'01', country=b'FR')
    publish_date 2021-04-29
    sign_date    2021-04-29
    cert b'FR000001'
    
    [+]verifying signature with PyCryptodome
    The message is authentic.

Public key used:

    >more FR000001_PUB.PEM`
    -----BEGIN PUBLIC KEY-----
    MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEqY8NfM1igIiTvsTUNuedGDSh1uAB`
    1w8cTNzNnZ4v4in3JAUU6N3AypjQx0QMnMSShJoPvac/w5L02grgf4TCPA==
    -----END PUBLIC KEY-----



on a real one (censored, just replace with yours), with FR03AV01 x509 certificate:

    >more FR03AV01_av.txt
    DC04FR03AV011E7F1E7FL101FR[...]LATE<US>C5BUAX4MZOINK7LCKIK4UOXW5WET6AQ3N4LVEJYOLUEMSRUD3YE5W44QTZ2PIRRWSQPVIUB5UQNSBUL27R6TFT4PJLJ63CXIPPG5SNY


Verification:

    >python PyTac_verif.py -v FR03AV01_av.txt`
    
    [+]parsing Attestation vaccinale data
    header(marker=b'DC', version=b'04', CA_id=b'FR03', cert_id=b'AV01', publish_date=b'1E7F', sign_date=b'1E7F', doc_id=b'L1', perimeter_id=b'01', country=b'FR')
    publish_date 2021-05-17
    sign_date    2021-05-17
    cert b'FR03AV01'`
    
    [+]testing with PyCryptodome
    The message is authentic.

Here x509 certificate FR03AV01_CERT.DER is used.



You can now discover, download and extract relevant x509 files using the update '-u' option:

    >python PyTac_verif.py -vu FR03AV01_av.txt
    [+]parsing Attestation vaccinale data
    header(marker=b'DC', version=b'04', CA_id=b'FR03', cert_id=b'AV01', publish_date=b'1E7F', sign_date=b'1E7F', doc_id=b'L1', perimeter_id=b'01', country=b'FR')
    publish_date 2021-05-17
    sign_date    2021-05-17
    cert b'FR03AV01'
    
    [+]updating Trusted Service providers list
    downloaded https://ants.gouv.fr/content/download/517/5670/version/23/file/TLS_valide-signed-xades-baseline-b.xml
    overwriting local TLS_valide-signed-xades-baseline-b.xml
    5 trusted services providers found
    
    [+]extracting AV certs from issuer FR03
    downloaded http://certificates.certigna.fr/search.php?iHash=xvNLC1KMs03t%2FgxzdBYParPnf%2BM
    saving FR03AV01_CERT.DER...
    saving FR03AV02_CERT.DER...
    
    [+]verifying signature with PyCryptodome
    The message is authentic.




**In real life, we must check the whole certificates chain validity and revocation lists (maybe in a future version) !**





### Useful certificates

```
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
```

and

```
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
```



### Verification algorithm

In 2d-doc, signature is encoded in base32, and algorithm is ECDSA P-256, see section 5.1 in [1]

Reference x509 certificate (file FR000001_CERT.PEM) and private key (FR000001_PRIV.PEM) are given in section 15.1 of [1]



### References

[1] Spécifications techniques des Codes à Barres 2D-Doc, version 3.1.1, ANTS, 19/10/2020 : https://ants.gouv.fr/content/download/516/5665/version/9/file/ANTS_2D-Doc_CABSpec_v3.1.1.pdf

[2] Spécifications techniques des Codes à Barres 2D-Doc, version 3.1.3, ATNS, 30/04/2021 : https://ants.gouv.fr/content/download/516/5665/version/11/file/Specifications-techniques-des-codes-a-barres_2D-Doc_v3.1.3.pdf

Electronic Signatures Infrastructures, Trusted lists, ETSI TS 119 612 V2.2.1 (2016-04) : https://www.etsi.org/deliver/etsi_ts/119600_119699/119612/02.02.01_60/ts_119612v020201p.pdf