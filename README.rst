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
    * For Centos: https://danieleriksson.net/2017/02/08/how-to-install-latest-python-on-centos/

Preparations – install prerequisites::

    # Start by making sure your system is up-to-date:
    yum update
    # Compilers and related tools:
    yum groupinstall -y "development tools"
    # Libraries needed during compilation to enable all features of Python:
    yum install -y zlib-devel bzip2-devel openssl-devel ncurses-devel sqlite-devel readline-devel tk-devel gdbm-devel db4-devel libpcap-devel xz-devel expat-devel
    # If you are on a clean "minimal" install of CentOS you also need the wget tool:
    yum install -y wget
    * For windows: https://www.python.org/downloads/

Download, compile and install Python::

    # Python 3.6.3:
    wget http://python.org/ftp/python/3.6.3/Python-3.6.3.tar.xz
    tar xf Python-3.6.3.tar.xz
    cd Python-3.6.3
    ./configure --prefix=/usr/local --enable-shared LDFLAGS="-Wl,-rpath /usr/local/lib"
    make && make altinstall

After running the commands above your newly installed Python interpreter will be available as::

    /usr/local/bin/python3.6

Install/upgrade pip, setuptools and wheel::

    # First get the script:
    wget https://bootstrap.pypa.io/get-pip.py

    # Then execute it using Python 2.7 and/or Python 3.6:
    python2.7 get-pip.py
    python3.6 get-pip.py

Create your pykeytoolenv Python environment::

    # Use the built-in functionality in Python 3.6 to create a sandbox called my36project
    python3.6 -m venv pykeytoolenv

    # Activate the pykeytoolenv sandbox:
    source pykeytoolenv/bin/activate
    # Check the Python version in the sandbox (it should be Python 3.6.3):
    python --version
    # Deactivate the sandbox:
    deactivate

Ensure SWIG 3.0.2 is installed


Install Requirements from Pip (ensure you have activate the pykeytoolenv:

::

    source pykeytoolenv/bin/activate

::

    pip install -r requirements.txt


Usage
-----
You must configure the program using config/config.ini and config/logging.ini
If you are using a HSM please install the HSM providers client libraries and update the config.
The raapi folder is used if you are submitting certificates requests to a CA via the IoT SC Rest API
You must invoke virtual environment prior to running any of the scripts.

To Generate Keys and CSR's you can run:
scripts/generatekeyandcsr -pkcs12pw <password> -r /home/userx/batch1_oem1/requests.txt -ou <OrgUnit in DN to be used>

To Generate Certificates using the CSR's
scripts/generatecert -r /home/userx/batch1_oem1/requests.txt -c <context id to be used>

To Generate PKCS12's using the Certificates
scripts/generatepkcs12 -pkcs12pw <password> -r /home/userx/batch1_oem1/requests.txt

Notes
-----
