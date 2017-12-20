#!/bin/bash
PYTHON_VERSION=3.5.4

ETH_UTILS_GIT_URL=https://github.com/icodeface/eth-utils
ETH_ABI_GIT_URL=https://github.com/icodeface/eth-abi
BRANCH=master

export WINEPREFIX=/opt/wine64
PYHOME=c:/python$PYTHON_VERSION
PYTHON="wine $PYHOME/python.exe -OO -B"

# Let's begin!
cd `dirname $0`
set -e

cd tmp

# Install
$PYTHON -m pip install git+ETH_UTILS_GIT_URL
$PYTHON -m pip install git+ETH_ABI_GIT_URL

