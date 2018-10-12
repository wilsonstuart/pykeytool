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
import pem
import pykeytool.utils
import hashlib
import pykeytool

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


if __name__ == '__main__':
    if keygen == 'HARDWARE':
        os.environ["CKNFAST_OVERRIDE_SECURITY_ASSURANCES"] = "tokenkeys"
        pin = pkcs11_pin
        os.environ["PYKCS11LIB"] = pkcs11_lib
        pkcs11 = PyKCS11Lib()
        pkcs11.load()  # define environment variable PYKCS11LIB=YourPKCS11Lib
        slot = pkcs11.getSlotList(tokenPresent=True)[1]
        session = pkcs11.openSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION)
        #session.login(pkcs11_pin)
    '''
    # Read command line args
    '''
    keyid='351539100002692'
    #keyid ='351539100002684'
    key_length = keysize  # key-length in bits
    label = keyid  # just a label for identifying objects
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


    privKeyHandle = session.findObjects([(CKA_CLASS, CKO_PRIVATE_KEY), (CKA_ID, key_id)])[0]
    # Encode the PKCS11 object into string formated and create asn1crypto.keys.RSAPrivateKey object
    RSAPrivateKeyTest = pykeytool.encode_rsa_private_key(privKeyHandle, session)
    object = asn1crypto.keys.RSAPrivateKey.load(RSAPrivateKeyTest)
    print('Version:', object['version'].native)
    print('Modulus:', object['modulus'].native)
    print('Public Exponent - e:', object['public_exponent'].native)
    print('Private Exponent - d', object['private_exponent'].native)
    print('Prime 1 - p:', object['prime1'].native)
    print('Prime 2 - q:', object['prime2'].native)
    print('Exponent 1 - dmod(p-1):', object['exponent1'].native)
    print('Exponent 2 - dmod(q-1):', object['exponent2'].native)

    try:
        privkey1 = RSA.construct((object['modulus'].native, object['public_exponent'].native, object['private_exponent'].native, object['prime1'].native, object['prime2'].native), True)
        privkey = RSA.importKey(RSAPrivateKeyTest)
        encrypted_key = privkey.export_key()
        # Convert Cryptodome RSA Private Key to OpenSSL.crypto.PKey
        private_key = serialization.load_pem_private_key(encrypted_key, password=None, backend=default_backend())
        pkey = OpenSSL.crypto.PKey().from_cryptography_key(private_key)
        keystatus = pkey.check()
        publickey = crypto.dump_publickey(OpenSSL.crypto.FILETYPE_PEM, pkey)
        logger.info('Checking consistency of RSA private key : status %s', keystatus)
    except ValueError:
        print('ValueError, Generate a new key')
