Qtum Electrum
=====================================

  Licence: MIT Licence

  Qtum Electrum is a lightweight Qtum wallet forked from [Electrum](https://github.com/spesmilo/electrum)


Getting started
===============

Download latest release [here](https://github.com/qtumproject/qtum-electrum/releases).


Compatible with Qtum mobile wallet
==================================

Qtum Electrum standard wallet uses [bip44](https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki) derivation path with coin_type set to 88 which not compatible with the current qtum mobile wallet.

If you want to be compatible with the qtum mobile wallet, you need to choose "Qtum mobile wallet compatible" to create or restore your wallet.

![](https://github.com/qtumproject/qtum-electrum/blob/master/snap/mobile_compatible.png)


Compatible with Qtum Qt Core wallet
==================================

If you want to import private master key from [Qtum Qt Core wallet](https://github.com/qtumproject/qtum/releases/), you need to choose "Qtum Qt Core wallet compatible" to restore your wallet.

![](https://github.com/qtumproject/qtum-electrum/blob/master/snap/qt_core_compatible.png)


Development version
===================

Check out the code from Github:

    git clone https://github.com/qtumproject/qtum-electrum.git
    cd qtum-electrum

Install dependencies::

    sudo apt-get install libusb-1.0-0-dev libudev-dev
    on osx:
        brew install libusb
        
    pip3 install -r requirements.txt
    pip3 install -r requirements-binaries.txt
    pip3 install -r requirements-fixed.txt

Compile the protobuf description file:

    sudo apt-get install protobuf-compiler
    protoc --proto_path=qtum_electrum --python_out=qtum_electrum qtum_electrum/paymentrequest.proto

Create translations (optional):

    sudo apt-get install python-requests gettext

    on osx:
    brew install gettext
    brew link gettext --force

    ./contrib/make_locale

Run it:

    ./run_qtum_electrum



Creating Binaries
=================


To create binaries, create the 'packages' directory:

    ./contrib/make_packages

This directory contains the python dependencies used by Electrum.

Mac OS X
--------

See [contrib/build-osx/README.md](https://github.com/qtumproject/qtum-electrum/blob/master/contrib/build-osx/README.md) file.

Windows
-------

See [contrib/build-wine/README.md](https://github.com/qtumproject/qtum-electrum/blob/master/contrib/build-wine/README.md) file.


Linux
-----

See [contrib/build-linux/README.md](https://github.com/qtumproject/qtum-electrum/blob/master/contrib/build-linux/README.md) file.



