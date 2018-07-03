==============================================================================
pykeytool - IoT SC PKI Tool for Generating Keys and submitting csr's to IoT SC
==============================================================================

A tool used to:
* Generate RSA Keys in bulk based on Software or Hardware (using pkcs11)
* Generate CSR's (Certificate Signing Requests)
* Submit the CSR's to the IoT SC Rest API
* Retrieve Certificates from IoT SC
* Package the certificates and keys into pkcs12 files
* Encrypt the pkcs12 files in batches of encrypted archive.

Getting Started
---------------
Update your environment to use Python 3.6
For Centos: https://danieleriksson.net/2017/02/08/how-to-install-latest-python-on-centos/
For windows: https://www.python.org/downloads/
Ensure SWIG 3.0.2 is installed

Install from Pip:

::

    pip install pykeytools


Or build from source:

::

    python setup.py build


Usage
-----
You must configure the program using config/config.ini and config/logging.ini
If you are using a HSM please install the HSM providers client libraries and update the config.
The raapi folder is used if you are submitting certificates requests to a CA via the IoT SC Rest API
You must invoke virtual environment prior to running any of the scripts.
