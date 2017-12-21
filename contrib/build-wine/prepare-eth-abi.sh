#!/bin/bash
PYTHON_VERSION=3.5.4

ETH_UTILS_GIT_URL=https://github.com/icodeface/eth-utils
ETH_ABI_GIT_URL=https://github.com/icodeface/eth-abi
BRANCH=master

export WINEPREFIX=/opt/wine64
PYHOME=c:/python$PYTHON_VERSION
PYTHON="wine $PYHOME/python.exe -OO -B"

cd `dirname $0`
set -e
cd tmp
if [ ! -d "eth-utils" ]; then
    git clone -b $BRANCH $ETH_UTILS_GIT_URL eth-utils
fi
if [ ! -d "eth-abi" ]; then
    git clone -b $BRANCH $ETH_ABI_GIT_URL eth-abi
fi

pushd eth-utils
git pull
git checkout $BRANCH
$PYTHON setup.py install
popd

pushd eth-abi
git pull
git checkout $BRANCH
$PYTHON setup.py install
popd





