#!/bin/bash
PYTHON_VERSION=3.5.4

ETH_HASH_GIT_URL=https://github.com/icodeface/eth-hash
ETH_UTILS_GIT_URL=https://github.com/icodeface/eth-utils
ETH_ABI_GIT_URL=https://github.com/icodeface/eth-abi
BRANCH=master

export WINEPREFIX=/opt/wine64
PYHOME=c:/python$PYTHON_VERSION
PYTHON="wine $PYHOME/python.exe -OO -B"

cd `dirname $0`
set -e

mkdir -p tmp
cd tmp

if [ ! -d "eth-hash" ]; then
    git clone -b $BRANCH $ETH_HASH_GIT_URL eth-hash
fi
if [ ! -d "eth-utils" ]; then
    git clone -b $BRANCH $ETH_UTILS_GIT_URL eth-utils
fi
if [ ! -d "eth-abi" ]; then
    git clone -b $BRANCH $ETH_ABI_GIT_URL eth-abi
fi

pushd eth-hash
git pull
git checkout $BRANCH
$PYTHON setup.py install
popd

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





