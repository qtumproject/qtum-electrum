Qtum Electrum - Lightweight Qtum client
=======================================

Qtum Electrum is a lightweight Qtum wallet forked from `Electrum <https://github.com/spesmilo/electrum>`_.

::

  Licence: MIT Licence
  Language: Python (>= 3.6)


.. image:: /screenshot/history.png
.. image:: /screenshot/tokens.png


Getting started
===============

Electrum is a pure python application. If you want to use the Qt interface, install the Qt dependencies::

    // linux
    sudo apt-get install python3-pyqt5

    // macOS (thanks @puruoni)
    brew install pyqt5
    export PATH="/opt/homebrew/opt/qt@5/bin:$PATH"
    export PATH="/opt/homebrew/opt/pyqt@5/bin:$PATH"
    cp -pr /opt/homebrew/Cellar/pyqt@5/5.15.9/lib/python3.10/site-packages/*  /opt/homebrew/lib/python3.10/site-packages/.

    // *** In the case of pyenv ***
    cp -pr /opt/homebrew/Cellar/pyqt@5/5.15.9/lib/python3.10/site-packages/* /Users/[username]/.pyenv/versions/3.10.8/lib/python3.10/site-packages/.


For elliptic curve operations, `libsecp256k1`_ is a required dependency::

    // linux
    sudo apt-get install libsecp256k1-0

    // macOS
    brew tap cuber/homebrew-libsecp256k1
    brew install libsecp256k1

Alternatively, when running from a cloned repository, a script is provided to build
libsecp256k1 yourself::

    sudo apt-get install automake libtool
    ./contrib/make_libsecp256k1.sh

Due to the need for fast symmetric ciphers, either one of `pycryptodomex`_
or `cryptography`_ is required. Install from your package manager
(or from pip)::

    sudo apt-get install python3-cryptography


If you would like hardware wallet support, see `this`_.

.. _libsecp256k1: https://github.com/bitcoin-core/secp256k1
.. _pycryptodomex: https://github.com/Legrandin/pycryptodome
.. _cryptography: https://github.com/pyca/cryptography
.. _this: https://github.com/spesmilo/electrum-docs/blob/master/hardware-linux.rst

Development version (git clone)
-------------------------------

Check out the code from GitHub::

    git clone https://github.com/qtumproject/qtum-electrum.git
    cd qtum-electrum
    git submodule update --init

Run install (this should install dependencies)::

    python3 -m pip install -r ./contrib/requirements/requirements-eth.txt
    python3 -m pip install --user -e .

    // fix protobuf on M1 macOS
    export PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION=python

Create translations (optional)::

    sudo apt-get install python-requests gettext
    ./contrib/make_locale


Finally, to start Electrum::

    ./run_electrum


Creating Binaries
=================

Linux (tarball)
---------------

See :code:`contrib/build-linux/sdist/README.md`.


Linux (AppImage)
----------------

See :code:`contrib/build-linux/appimage/README.md`.


Mac OS X / macOS
----------------

See :code:`contrib/osx/README.md`.


Windows
-------

See :code:`contrib/build-wine/README.md`.


Android
-------

See :code:`electrum/gui/kivy/Readme.md`.
