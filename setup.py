#!/usr/bin/env python3

# python setup.py sdist --format=zip,gztar

import argparse
import imp
import os
import platform
import sys
from setuptools import setup

with open('./requirements.txt') as f:
    requirements = f.read().splitlines()

requirements += ['eth-hash', 'eth-utils', 'eth-abi']

version = imp.load_source('version', 'lib/version.py')

if sys.version_info[:3] < (3, 4, 0):
    sys.exit("Error: Electrum requires Python version >= 3.4.0...")

data_files = []

if platform.system() in ['Linux', 'FreeBSD', 'DragonFly']:
    parser = argparse.ArgumentParser()
    parser.add_argument('--root=', dest='root_path', metavar='dir', default='/')
    opts, _ = parser.parse_known_args(sys.argv[1:])
    usr_share = os.path.join(sys.prefix, "share")
    icons_dirname = 'pixmaps'
    if not os.access(opts.root_path + usr_share, os.W_OK) and \
       not os.access(opts.root_path, os.W_OK):
        icons_dirname = 'icons'
        if 'XDG_DATA_HOME' in os.environ.keys():
            usr_share = os.environ['XDG_DATA_HOME']
        else:
            usr_share = os.path.expanduser('~/.local/share')
    data_files += [
        (os.path.join(usr_share, 'applications/'), ['qtum-electrum.desktop']),
        (os.path.join(usr_share, icons_dirname), ['icons/electrum.png'])
    ]

setup(
    name="Qtum Electrum",
    version=version.ELECTRUM_VERSION,
    install_requires=requirements,
    extras_require={
        'full': ['Cython>=0.27', 'rlp==0.6.0', 'trezor[hidapi]>=0.9.0',
                 'keepkey', 'btchip-python', 'websocket-client', 'hidapi'],
        ':python_version < "3.5"': ['typing>=3.0.0'],
    },
    dependency_links=[
        'https://github.com/icodeface/eth-hash',
        'https://github.com/icodeface/eth-utils',
        'https://github.com/icodeface/eth-abi',
    ],
    packages=[
        'qtum_electrum',
        'qtum_electrum_gui',
        'qtum_electrum_gui.qt',
        'qtum_electrum_plugins',
        'qtum_electrum_plugins.audio_modem',
        'qtum_electrum_plugins.email_requests',
        'qtum_electrum_plugins.greenaddress_instant',
        'qtum_electrum_plugins.hw_wallet',
        'qtum_electrum_plugins.labels',
        'qtum_electrum_plugins.ledger',
        'qtum_electrum_plugins.trezor',
        'qtum_electrum_plugins.trustedcoin',
        'qtum_electrum_plugins.virtualkeyboard',
    ],
    package_dir={
        'qtum_electrum': 'lib',
        'qtum_electrum_gui': 'gui',
        'qtum_electrum_plugins': 'plugins',
    },
    package_data={
        'qtum_electrum': [
            'www/index.html',
            'wordlist/*.txt',
            'locale/*/LC_MESSAGES/electrum.mo',
            '*.json',
        ]
    },
    scripts=['qtum-electrum'],
    data_files=data_files,
    description="Lightweight Qtum Wallet",
    author="CodeFace",
    author_email="codeface@qtum.org",
    license="MIT Licence",
    url="https://qtum.org",
    long_description="""Lightweight Qtum Wallet"""
)
