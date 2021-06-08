# PyTac_verif.py



a free Python tool to validate the authenticity of french Covid-19 vaccination certificate, signed with ECDSA

Laurent Clévy (@lorenzo2472)

8june2021





Check specifications here:

https://ants.gouv.fr/Les-solutions/2D-Doc





### Usage

`I:\dev\PyTac_verif>more FR000001_av.txt`
`DC04FR0000011E6D1E6DL101FRL0THEOULE SUR MER<GS>L1JEAN PAUL<GS>L231051962L3COVID-19<GS>L4J07BX03<GS>L5COMIRNATY PFIZER/BIONTECH<GS>L6COMIRNATY PFIZER/BIONTECH<GS>L71L82L901032021LACO<US>32T2SI2RUMPDLBHAFSBDF2CUE7GI4NR5WC3NSBEU6AZ7QZJZCPMCTXTVIDZAKEYO7237SQ2ZPOCMZKG7U3Q2LIMPPVJMA7TQAAKC5DY`

This is the example given in specifications

`I:\dev\PyTac_verif>python PyTac_verif.py FR000001_av.txt`
`header(marker=b'DC', version=b'04', CA_id=b'FR00', cert_id=b'0001', publish_date=b'1E6D', sign_date=b'1E6D', doc_id=b'L1', perimeter_id=b'01', country=b'FR')`
`publish_date 2021-04-29`
`sign_date    2021-04-29`
`cert b'FR000001'`

`testing with openssl`
`Verified OK`

`testing with PyCryptodome`
`The message is authentic.`



`I:\dev\PyTac_verif>more FR000001_PUB.PEM`
`-----BEGIN PUBLIC KEY-----`
`MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEqY8NfM1igIiTvsTUNuedGDSh1uAB`
`1w8cTNzNnZ4v4in3JAUU6N3AypjQx0QMnMSShJoPvac/w5L02grgf4TCPA==`
`-----END PUBLIC KEY-----`



on a real one (censored, just replace with yours):

`I:\dev\PyTac_verif>more FR03AV01_av.txt`
`DC04FR03AV011E7F1E7FL101FR[...]LATE<US>C5BUAX4MZOINK7LCKIK4UOXW5WET6AQ3N4LVEJYOLUEMSRUD3YE5W44QTZ2PIRRWSQPVIUB5UQNSBUL27R6TFT4PJLJ63CXIPPG5SNY`



`I:\dev\PyTac_verif>python PyTac_verif.py FR03AV01_av.txt`
`header(marker=b'DC', version=b'04', CA_id=b'FR03', cert_id=b'AV01', publish_date=b'1E7F', sign_date=b'1E7F', doc_id=b'L1', perimeter_id=b'01', country=b'FR')`
`publish_date 2021-05-17`
`sign_date    2021-05-17`
`cert b'FR03AV01'`

`testing with openssl`
`Verified OK`

`testing with PyCryptodome`
`The message is authentic.`



Public certificate FR03AV01_PUB.PEM is used, here is the public key:

`I:\dev\PyTac_verif>more FR03AV01_PUB.PEM`
`-----BEGIN PUBLIC KEY-----`
`MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE1T9uG2bEP7uWND6RT/lJs2y787Bk`
`EJoRMMLXvqPKFFC3ckqFAPnFjbiv/odlWH04a1P9CvaCRxG31FMEOFZyXA==`
`-----END PUBLIC KEY-----`



**In real life, we must check the whole certificates chain validity and revocation lists !**

here: https://ants.gouv.fr/content/download/517/5670/version/23/file/TLS_valide-signed-xades-baseline-b.xml



### Useful certificates

Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            34:ff:bf:04:17:98:3d:cd:85:85:76:9b:9f:91:09:31
        Signature Algorithm: sha256WithRSAEncryption
        Issuer: C = FR, O = DHIMYOTIS, OU = 0002 48146308100036, CN = **FR03**
        Validity
            Not Before: Apr 22 22:00:00 2021 GMT
            Not After : Apr 21 21:59:59 2024 GMT
        Subject: C = FR, O = CAISSE NATIONALE D'ASSURANCE MALADIE, OU = 0002 18003502402369, CN = **AV01**

and

Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            34:26:68:a2:ff:09:28:0d:ff:7e:ca:2e:c7:31:07:cb
        Signature Algorithm: sha256WithRSAEncryption
        Issuer: C = FR, O = DHIMYOTIS, OU = 0002 48146308100036, CN = **FR03**
        Validity
            Not Before: Apr 22 22:00:00 2021 GMT
            Not After : Apr 21 21:59:59 2024 GMT
        Subject: C = FR, O = CAISSE NATIONALE D'ASSURANCE MALADIE, OU = 0002 18003502402369, CN = **AV02**

### References

https://ants.gouv.fr/content/download/516/5665/version/11/file/Specifications-techniques-des-codes-a-barres_2D-Doc_v3.1.3.pdf

https://ants.gouv.fr/content/download/515/5660/version/5/file/ANTS_2D-Doc_Processus_v1.2.pdf

