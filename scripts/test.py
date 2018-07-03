import OpenSSL

import pykeytool
import fileinput
import os

from pykeytool.pykeytool import generate_offline_keyandcsr
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import asymmetric

if __name__ == '__main__':
    with open("testrsa.bin", "rb") as key_file:
        #Convert Cryptodome RSA Private Key to PKey
        #Load
        private_key = serialization.load_pem_private_key(key_file.read(), password=None, backend=default_backend())
        pkey = OpenSSL.crypto.PKey().from_cryptography_key(private_key)
        keystatus = pkey.check()
        print('Checking consistency of RSA private key : status', keystatus)