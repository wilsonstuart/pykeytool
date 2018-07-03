#!/usr/bin/env python
from setuptools import setup

# Lets makes ure we have the correct modules installed before continuing.
# OpenSSL is required.


def readme():
    with open('README.rst') as f:
        return f.read()


setup(
    name="pykeytool",
    version="0.1",
    description="pykeytool - IoT SC PKI Tool for Generating Keys and submitting csr's to IoT SC",
    long_description=readme(),
    url='http://github.com/wilsonstuart/pykeytool',
    packages=['pykeytool', ],
    zip_safe=False,
    install_requires=['pyopenssl', 'argparse', 'pyyaml', 'Crypto', 'PyKCS11', 'cryptography', 'asn1crypto', 'requests', 'pycryptodomex', 'cython'],
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Programming Language :: Python :: 3.6',
        'Environment :: Console'
        'Topic :: PKI',
        ],
    scripts=['scripts/generatekeyandcsr', 'scripts/generatepkcs12', 'scripts/generatecert'],
    data_files=[('config', ['config/config.ini', 'config/logging.ini']),
                ('raapi', []),
                ]
)
