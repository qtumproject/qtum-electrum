[TOC]

Qtum Electrum
=====================================

  Licence: MIT Licence
  Qtum Electrum is a lightweight Qtum wallet forked from [Electrum](https://github.com/spesmilo/electrum)


Getting started
===============

Electrum is a pure python application. If you want to use the Qt interface, install the Qt dependencies::

    sudo apt-get install python3-pyqt5

If you downloaded the official package (tar.gz), you can run Electrum from its root directory, without installing it on your system; all the python dependencies are included in the 'packages' directory. To run Electrum from its root directory, just do::

    ./electrum

If you cloned the git repository, you need to compile extra files before you can run Electrum. Read the next section, "Development Version".


Development version
===================

Check out the code from Github::

    git clone git@github.com:qtumproject/qtum-electrum.git
    cd qtum-electrum

Install dependencies::

    pip3 install -r requirements.txt

Compile the icons file for Qt::

    sudo apt-get install pyqt5-dev-tools
    pyrcc5 icons.qrc -o gui/qt/icons_rc.py -py3

Compile the protobuf description file::

    sudo apt-get install protobuf-compiler
    protoc --proto_path=lib/ --python_out=lib/ lib/paymentrequest.proto

Create translations (optional)::

    sudo apt-get install python-pycurl gettext

    on osx:
    brew install gettext
    brew link gettext --force

    ./contrib/make_locale



Creating Binaries
=================


To create binaries, create the 'packages' directory::

    ./contrib/make_packages

This directory contains the python dependencies used by Electrum.

Mac OS X
--------


    # PyQt5/uic/port_v2/ascii_upper.py
    change string.maketrans to str.maketrans

    # py2app
    use py2app==0.12

    # On MacPorts installs:
    sudo python3 setup-release.py py2app

    # On Homebrew installs:
    ARCHFLAGS="-arch i386 -arch x86_64" sudo python3 setup-release.py py2app --includes sip

    sudo hdiutil create -fs HFS+ -volname "Qtum Electrum" -srcfolder dist/Qtum\ Electrum.app dist/qtum-electrum-VERSION-macosx.dmg

Windows
-------

See [contrib/build-wine/README.md](https://github.com/qtumproject/qtum-electrum/blob/master/contrib/build-wine/README.md) file.


Android
-------

See [gui/kivy/Readme.md](https://github.com/qtumproject/qtum-electrum/blob/master/gui/kivy/Readme.md) file.


