"""pykeytool module
__version__ = '0.1'
__author__ = 'Stuart Wilson'
pykeytool provides functions for scripts:
Generating Batch keypairs in Hardware or Software
Generating Batch CSR's and writing to file system
Submitting Batch CSR's to IoT SC using Rest API and writing certs to file system
Generating PKCS12 and writing to file system
"""
import configparser
import datetime
import logging.config
import OpenSSL
import asn1crypto.keys
import json
import requests
import time
from Cryptodome.PublicKey import RSA
from OpenSSL import crypto
from PyKCS11 import *
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
# TODO: Fix the base dir as this will be installed into site-packages
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Set Logging to file - logs/pykeytool.log:
logging.config.fileConfig(os.path.join(BASE_DIR, 'config', 'logging.ini'), disable_existing_loggers=False)
logger = logging.getLogger(__name__)

# Set Global Variables for pykeytool module
# RAAPI SETTINGS
config = configparser.ConfigParser()
config.read(os.path.join(BASE_DIR, 'config', 'config.ini'))
raapiurl = config.get('RAAPISERVER', 'URL')
pollinterval = config.get('RAAPISERVER', 'POLLINTERVAL')
pollcount = config.get('RAAPISERVER', 'POLLCOUNT')
rapkcs12 = config.get('RAAPISERVER', 'RAPKCS12')
raapicert = config.get('RAAPISERVER', 'RAAPICERT')
raapikey = config.get('RAAPISERVER', 'RAAPIKEY')
raapicacerts = config.get('RAAPISERVER', 'RAAPICACERTS')
raapidir = config.get('RAAPISERVER', 'RAAPICRED_DIR')

# General processing
batchsize = config.get('GENERAL', 'BATCHSIZE')
threads = config.get('GENERAL', 'THREADS')
#batchdir = config.get('GENERAL', 'BATCHDIR')
cacert = config.get('GENERAL', 'CACERT')

# CRYPTO
keygen = config.get('CRYPTO', "KEYGEN")
keytype = config.get('CRYPTO', 'KEYTYPE')
keysize = config.getint('CRYPTO', 'KEYSIZE')
keycipher = config.get('CRYPTO', 'KEYCIPHER')

# PKCS11
pkcs11_lib = config.get('PKCS11', 'PKCS11_LIB')
pkcs11_pin = config.get('PKCS11', 'PKCS11_PIN')

if keygen == 'HARDWARE':
    os.environ["CKNFAST_OVERRIDE_SECURITY_ASSURANCES"] = "tokenkeys"
    pin = pkcs11_pin
    os.environ["PYKCS11LIB"] = pkcs11_lib
    pkcs11 = PyKCS11Lib()
    pkcs11.load()  # define environment variable PYKCS11LIB=YourPKCS11Lib
    slot = pkcs11.getSlotList(tokenPresent=True)[1]
    session = pkcs11.openSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION)
    session.login(pkcs11_pin)
'''
# Read command line args
'''

def encode_rsa_private_key(key, session):
    """
    Encode a PKCS11 RSA private key object into PKCS#1 DER-encoded format.
    :param key: PKCS11 CKO_PRIVATEKEY Object key - RSA private key
    :param session: PKCS11 session
    :rtype: string RSA private key (cryptodome)
    """
    """
    fields = [
        ('version', RSAPrivateKeyVersion),
        ('modulus', Integer),
        ('public_exponent', Integer),
        ('private_exponent', Integer),
        ('prime1', Integer),
        ('prime2', Integer),
        ('exponent1', Integer),
        ('exponent2', Integer),
        ('coefficient', Integer),
        ('other_prime_infos', OtherPrimeInfos, {'optional': True})
    ]
    """

    all_attributes = list(PyKCS11.CKA.keys())
    # only use the integer values and not the strings like 'CKM_RSA_PKCS'
    all_attributes = [e for e in all_attributes if isinstance(e, int)]
    attributes = session.getAttributeValue(key, all_attributes)
    attrDict = dict(list(zip(all_attributes, attributes)))
    if attrDict[PyKCS11.CKA_CLASS] == PyKCS11.CKO_PRIVATE_KEY \
            and attrDict[PyKCS11.CKA_KEY_TYPE] == PyKCS11.CKK_RSA:
        return asn1crypto.keys.RSAPrivateKey({
            'version': asn1crypto.keys.RSAPrivateKeyVersion(0),
            'modulus': int.from_bytes(attrDict[PyKCS11.CKA_MODULUS], byteorder='big'),
            'public_exponent': int.from_bytes(attrDict[PyKCS11.CKA_PUBLIC_EXPONENT], byteorder='big'),
            'private_exponent': int.from_bytes(attrDict[PyKCS11.CKA_PRIVATE_EXPONENT], byteorder='big'),
            'prime1': int.from_bytes(attrDict[PyKCS11.CKA_PRIME_1], byteorder='big'),
            'prime2': int.from_bytes(attrDict[PyKCS11.CKA_PRIME_2], byteorder='big'),
            'exponent1': int.from_bytes(attrDict[PyKCS11.CKA_EXPONENT_1], byteorder='big'),
            'exponent2': int.from_bytes(attrDict[PyKCS11.CKA_EXPONENT_2], byteorder='big'),
            'coefficient': int.from_bytes(attrDict[PyKCS11.CKA_COEFFICIENT], byteorder='big'),
        }).dump()


def create_key_pair(keytype, keysize, keygen, keyid="pkcs_testing"):
    """
    Create a public/private key pair.
    :param keytype: Key type, must be one of TYPE_RSA and TYPE_DSA
    :param keysize: bits - Number of bits to use in the key
    :param keygen: string HARDWARE or SOFTWARE
    :param keyid: string used for CKA_LABEL.
    :rtype:  string -    The public/private key pair in a PKey object
    """
    if keygen == 'SOFTWARE':
        logger.debug('Creating key in software keytype: %s keysize: %s', keytype, keysize)
        pkey = OpenSSL.crypto.PKey()
        # TODO: Update Config to take different key Types
        pkey.generate_key(crypto.TYPE_RSA, keysize)
        return pkey
    elif keygen == 'HARDWARE':
        logger.debug('Creating key in hardware keytype: %s keysize: %s', keytype, keysize)

        # ############   key-pair generation    ##########################
        # The first step in the process is to create the key-templates. See PKCS#11
        # `10.8 Public key objects` to learn which attributes are available. Section
        # 10.9 covers private keys.
        label = keyid  # just a label for identifying objects
        key_length = keysize  # key-length in bits

        # the key_id has to be the same for both objects, it will also be necessary
        # when importing the certificate, to ensure it is linked with these keys.
        key_id = keyid.encode('utf-8')

        public_template = [
            (PyKCS11.CKA_CLASS, PyKCS11.CKO_PUBLIC_KEY),
            (PyKCS11.CKA_TOKEN, PyKCS11.CK_TRUE),
            (PyKCS11.CKA_PRIVATE, PyKCS11.CK_FALSE),
            (PyKCS11.CKA_MODULUS_BITS, key_length),
            (PyKCS11.CKA_PUBLIC_EXPONENT, (0x01, 0x00, 0x01)),
            (PyKCS11.CKA_ENCRYPT, PyKCS11.CK_TRUE),
            (PyKCS11.CKA_VERIFY, PyKCS11.CK_TRUE),
            (PyKCS11.CKA_VERIFY_RECOVER, PyKCS11.CK_TRUE),
            (PyKCS11.CKA_WRAP, PyKCS11.CK_TRUE),
            (PyKCS11.CKA_KEY_TYPE, PyKCS11.CKK_RSA),
            (PyKCS11.CKA_LABEL, label),
            (PyKCS11.CKA_ID, key_id),
        ]

        private_template = [
            (PyKCS11.CKA_CLASS, PyKCS11.CKO_PRIVATE_KEY),
            (PyKCS11.CKA_PRIVATE, PyKCS11.CK_TRUE),
            (PyKCS11.CKA_TOKEN, PyKCS11.CK_TRUE),
            (PyKCS11.CKA_SIGN_RECOVER, PyKCS11.CK_TRUE),
            (PyKCS11.CKA_SENSITIVE, PyKCS11.CK_FALSE),
            (PyKCS11.CKA_DECRYPT, PyKCS11.CK_TRUE),
            (PyKCS11.CKA_SIGN, PyKCS11.CK_TRUE),
            (PyKCS11.CKA_UNWRAP, PyKCS11.CK_TRUE),
            (PyKCS11.CKA_LABEL, label),
            (PyKCS11.CKA_ID, key_id),
        ]

        (pubKey, privKey) = session.generateKeyPair(public_template, private_template)

        privKeyHandle = session.findObjects([(CKA_CLASS, CKO_PRIVATE_KEY), (CKA_ID, key_id)])[0]
        # Encode the PKCS11 object into string formated and create asn1crypto.keys.RSAPrivateKey object
        privkey = RSA.importKey(encode_rsa_private_key(privKeyHandle, session))
        encrypted_key = privkey.export_key()
        # Convert Cryptodome RSA Private Key to OpenSSL.crypto.PKey
        private_key = serialization.load_pem_private_key(encrypted_key, password=None, backend=default_backend())
        pkey = OpenSSL.crypto.PKey().from_cryptography_key(private_key)
        keystatus = pkey.check()
        logger.info('Checking consistency of RSA private key : status %s', keystatus)
        return pkey


def create_cert_request(pkey, digest="sha256", **name):
    """
    Create a certificate request.
    Arguments: pkey   - The key to associate with the request
               digest - Digestion method to use for signing, default is sha256
               **name - The name of the subject of the request, possible
                        arguments are:
                          C     - Country name
                          ST    - State or province name
                          L     - Locality name
                          O     - Organization name
                          OU    - Organizational unit name
                          CN    - Common name
                          emailAddress - E-mail address
                          eg = CN='FA10234587B',OU='OEM 5G ICL',O='Verizon', C='US',
    Returns:   The certificate request in an X509Req object
    """
    req = crypto.X509Req()
    subj = req.get_subject()

    for key, value in name.items():
        setattr(subj, key, value)

    req.set_pubkey(pkey)
    req.sign(pkey, digest)

    return req


def create_pkcs12(id, pkey, cacert, outputdir, password):
    """
        Create a intial PKCS12 file with private key and ca certificates.
        Arguments: id - unique identifier to identify key and csr. These will be out to files based on the id
        Returns:   The p12 object
        """
    # st_cert=open(cert, 'rt').read()

    # cert = crypto.load_certificate(c.FILETYPE_PEM, cert)
    p12file = os.path.join(outputdir, id + '.p12')
    p12 = OpenSSL.crypto.PKCS12()
    p12.set_privatekey(pkey)

    try:
        f = open(cacert, 'rt')
        cacertlist = []
    except:
        logger.warn("Certificate file '%s' could not be opened", cacert)
        return None
    try:
        try:
            cacertlist.append(OpenSSL.crypto.load_certificate(crypto.FILETYPE_PEM, f.read()))
            p12.set_ca_certificates(cacertlist)
        except crypto.Error as e:
            logger.warn("Certificate file '%s' could not be loaded: %s", cacert, e)
            return None
    finally:
        f.close()

    if os.path.exists(p12file):
        logger.warn("PKCS12 file exists for id %s at %s, aborting.", id, p12file)
        sys.exit(1)
    else:
        open(p12file, 'wb').write(p12.export(passphrase=password, iter=2048, maciter=2048))
        logger.info('Created pkcs12 file for %s at %s', id, p12file)
        return p12


def update_pkcs12(id, outputdir, password):
    """
        Update and existing PKCS12 file with a corresponding certificate.
        Arguments: id - unique identifier to identify certificate file
        Returns:   The p12 object
    """

    # st_cert=open(cert, 'rt').read()
    pkcs12file = os.path.join(outputdir, id + '.p12')
    certfile = os.path.join(outputdir, id + '.crt')
    p12 = OpenSSL.crypto.load_pkcs12(open(pkcs12file, "rb").read(), password)

    cert = crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, open(certfile, "r").read())
    p12.set_certificate(cert)
    pkcs12handle = open(pkcs12file, "wb")
    pkcs12handle.write(p12.export(passphrase=password, iter=2048, maciter=2048))
    logger.info('PKCS12 Created for id:%s and written to %s', id, pkcs12file)
    return p12


def generate_offline_keyandcsr(id, password, outputdir, digest="sha256", **name):
    """
    Generates a private key and csr and outputs to file.
    Arguments: id - unique identifier to identify key and csr. These will be out to files based on the id
               digest - The hashing algo to use to create the csr
               **name - The name of the subject of the request, possible
                        arguments are:
                          C     - Country name
                          ST    - State or province name
                          L     - Locality name
                          O     - Organization name
                          OU    - Organizational unit name
                          CN    - Common name
                          emailAddress - E-mail address
                          eg = CN='FA10234587B',OU='OEM 5G ICL',O='Verizon', C='US',
    Returns:   True or False
    :type password: object
    """
    logger.info('Start key/csr generation for id %s', id)
    pkey = create_key_pair(keytype, keysize, keygen, id)
    # 1. Generate key pair using create_key_pair and output to temp file - id.pkey
    '''keyfile = os.path.join(batchdir, id + '.pkey')
    if os.path.exists(keyfile):
        # Identified duplicate key identifier - needs further investigation.
        logger.error('Private Key file for %s exists at %s aborting', id, keyfile)
        sys.exit(1)
    else:
        pkey = create_key_pair(keytype, keysize, keygen, id)
        open(keyfile, "wb").write(crypto.dump_privatekey(crypto.FILETYPE_PEM, pkey, str(keycipher), b'password'))
        logger.info('Private Key generated for %s and written to %s', id, keyfile)'''

    # 2. Generate CSR output to temp file - id.csr
    csrfile = os.path.join(outputdir, id + '.csr')

    if os.path.exists(csrfile):
        logger.error('CSR file for %s exists at %s aborting', id, csrfile)
        sys.exit(1)
    else:
        csr = create_cert_request(pkey, digest="sha256", **name)
        f = open(csrfile, "wb")
        f.write(OpenSSL.crypto.dump_certificate_request(OpenSSL.crypto.FILETYPE_PEM, csr))
        f.close()

    # 3. Generate P12 and output to file id.p12

    create_pkcs12(id, pkey, cacert, outputdir, password)


def generate_online_cert(id, context, batchdir):
    """Submits a csr to the MCS Rest API via HTTPS and updates the corresponding p12 with certificate
    Arguments: id - unique identifier to identify csr
               context - The context to submit the CSR to in order to get a certificate
    Returns:   True or False
    """

    '''
    # Make connection to RA API using p12
    logger.info('Submit Request for to get available contexts to %s', raapiurl)
    req = requests.get(raapiurl + '/contexts', cert=(
    raapidir + '/thingspace_client.crt', raapidir + '/thingspace_client.key'),
                       verify=(raapidir + '/thingspacecacerts.crt'))
    parsed_json = json.loads(req.text)

    if parsed_json['contexts'] == []:
        logger.info('No Contexts available for RA Administrator')
    else:
        for rows in parsed_json['contexts']:
            logger.debug('ContextID: %s', rows['id'])
            logger.debug('Context Type: %s', rows['context_type'])
            logger.debug('Certificate Type: %s', rows['certificate_profile'])
    '''
    # Set the request format and strip off the new line characters

    csrfile = os.path.join(batchdir, id + ".csr")
    csr = OpenSSL.crypto.load_certificate_request(OpenSSL.crypto.FILETYPE_PEM, open(csrfile, "rb").read())
    raapireq = OpenSSL.crypto.dump_certificate_request(OpenSSL.crypto.FILETYPE_PEM, csr).decode().replace('\n', '')
    payload = {"csr": raapireq, "context_id": context}
    logger.info('Submit Request for cert order for id:%s to contextid:%s', id, context)
    certorderreq = requests.post(raapiurl + '/certificate_order', cert=(
        raapicert, raapikey),
                                 verify=raapicacerts, json=payload)

    certorderresp = json.loads(certorderreq.text)

    if certorderresp['id'] == []:
        logger.info('No cert order returned from IoT SC')
    else:
        certorderid = certorderresp['id']
        logger.info('Cert Order ID:%s for id:%s returned from IoT SC', str(certorderid), str(id))

    # Check if Cert has been issued
    certstatuspayload = {"csr": raapireq, "context_id": '4142'}

    certorderstatus = requests.get(raapiurl + '/certificate_order/' + str(certorderid) + '/status',
                                   cert=(raapicert,
                                         raapikey),
                                   verify=raapicacerts)
    # Loop configurable time to retrieve cert (hardcode 5 times)
    for i in range(0, 6):
        certorderstatusresp = json.loads(certorderstatus.text)
        if certorderstatusresp['certificate_order_status'] != 'ISSUED':
            logger.debug('Response for Cert Order ID:%s is %s on attempt %d', str(certorderid),
                         certorderstatusresp['status'], i)
            time.sleep(5)
            # Call again
            certorderstatus = requests.get(
                raapiurl + '/certificate_order/' + str(certorderid) + '/status', cert=(
                    raapicert,
                    raapikey),
                verify=raapicacerts)
        else:
            # ISSUED
            certid = certorderstatusresp['certId']
            logger.info('Obtained Cert ID:%s for Cert Order ID:%s is %s on attempt %s', str(certid), str(certorderid),
                        certorderstatusresp['certificate_order_status'], i)
            break

    # Pull back certificate

    headers = {'accept': 'application/x-x509-user-cert'}
    logger.info('Retrieving Cert ID:%s', str(certid))
    getcert = requests.get(raapiurl + '/certificate/' + str(certid), cert=(
        raapicert, raapikey),
                           verify=raapicacerts, headers=headers)
    cert = getcert.text

    # Parse Certificate content to populate UserCredential Model.
    x509cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)
    # Serial Number = int
    serial_number = x509cert.get_serial_number()
    logger.info('Cert Serial Number:%s for id:%s', str(serial_number), id)
    # Subject = X509Name
    certsubjectcn = x509cert.get_subject().CN
    logger.info('Cert Subject CN:%s for id:%s', str(certsubjectcn), id)
    # Issuer = X509Name
    certissuercn = x509cert.get_issuer().CN
    logger.info('Cert Issuer Subject CN:%s for id:%s', str(certissuercn), id)
    # Expiry Date = Timestamp String ASN.1 GENERALIZEDTIME
    # expiry_date = x509cert.get_notAfter()
    certexpiry_date = datetime.datetime.strptime(x509cert.get_notAfter().decode('ascii'), '%Y%m%d%H%M%SZ')
    logger.info('Cert Expiry Date:%s for id:%s', certexpiry_date, id)
    # Write certificate to file

    certfile = os.path.join(batchdir, id + '.crt')

    if os.path.exists(certfile):
        logger.error('Certificate file exists %s, aborting', certfile)
        sys.exit(1)
    else:
        f = open(certfile, "wb")
        f.write(OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM, x509cert))
        f.close()


def update_offline_pkcs12(id, outputdir, passphrase):
    """Updates the p12 with the correct certificates"""
    # Take Certs and update p12
    # Check public key matches private key in p12
    # Remove private keys and log

    # Update p12 and encrypt using password
    pkcs12file = update_pkcs12(id, outputdir, passphrase)
