import OpenSSL

import pykeytool
import fileinput
import os
import requests
import configparser
import json
import logging

from pykeytool.pykeytool import generate_offline_keyandcsr
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import asymmetric

if __name__ == '__main__':
    BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    logging.config.fileConfig(os.path.join(BASE_DIR, 'config', 'logging.ini'), disable_existing_loggers=False)
    logger = logging.getLogger(__name__)
    config = pykeytool.configparser.ConfigParser()
    config.read(os.path.join(BASE_DIR, 'config', 'config.ini'))
    raapiurl = config.get('RAAPISERVER', 'URL')
    pollinterval = config.get('RAAPISERVER', 'POLLINTERVAL')
    pollcount = config.get('RAAPISERVER', 'POLLCOUNT')
    rapkcs12 = config.get('RAAPISERVER', 'RAPKCS12')
    raapicert = config.get('RAAPISERVER', 'RAAPICERT')
    raapikey = config.get('RAAPISERVER', 'RAAPIKEY')
    raapicacerts = config.get('RAAPISERVER', 'RAAPICACERTS')
    raapidir = config.get('RAAPISERVER', 'RAAPICRED_DIR')

    req = requests.get(raapiurl + '/contexts', cert=(
        raapicert, raapikey),
                       verify=raapicacerts)
    parsed_json = json.loads(req.text)

    if parsed_json['contexts'] == []:
        logger.info('No Contexts available for RA Administrator')
    else:
        for rows in parsed_json['contexts']:
            logger.debug('ContextID: %s', rows['id'])
            logger.debug('Context Type: %s', rows['context_type'])
            logger.debug('Certificate Type: %s', rows['certificate_profile'])

    '''with open("testrsa.bin", "rb") as key_file:
        #Convert Cryptodome RSA Private Key to PKey
        #Load
        private_key = serialization.load_pem_private_key(key_file.read(), password=None, backend=default_backend())
        pkey = OpenSSL.crypto.PKey().from_cryptography_key(private_key)
        keystatus = pkey.check()
        print('Checking consistency of RSA private key : status', keystatus)'''