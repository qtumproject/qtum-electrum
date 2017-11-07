"""
py2app/py2exe build script for Electrum

Usage (Mac OS X):
     python3 setup-release.py py2app

Usage (Windows):
     python3 setup-release.py py2exe
"""

from setuptools import setup
import os
import re
import shutil
import sys

from lib.version import ELECTRUM_VERSION as version

name = "Qtum Electrum"
mainscript = 'electrum'

if sys.version_info[:3] < (3, 4, 0):
    print("Error: " + name + " requires Python version >= 3.4.0...")
    sys.exit(1)

if sys.platform == 'darwin':
    from plistlib import Plist
    plist = Plist.fromFile('Info.plist')
    plist.update(dict(CFBundleIconFile='electrum.icns'))
    shutil.copy(mainscript, 'run_electrum.py')
    mainscript = 'run_electrum.py'
    extra_options = dict(
        setup_requires=['py2app'],
        app=[mainscript],
        options=dict(py2app=dict(argv_emulation=False,
                                 includes=['PyQt5.QtCore', 'PyQt5.QtGui', 'PyQt5.QtWebKit', 'PyQt5.QtNetwork', 'sip'],
                                 packages=['lib', 'gui', 'plugins'],
                                 qt_plugins=['platforms'],
                                 iconfile='electrum.icns',
                                 plist=plist,
                                 resources=['icons', 'cacert.pem'])),
    )
elif sys.platform == 'win32':
    extra_options = dict(
        setup_requires=['py2exe'],
        app=[mainscript],
    )
else:
    extra_options = dict(
        # Normally unix-like platforms will use "setup.py install"
        # and install the main script as such
        scripts=[mainscript],
    )

setup(
    name=name,
    version=version,
    **extra_options
)
from distutils import dir_util

if sys.platform == 'darwin':
    # Remove the copied py file
    os.remove(mainscript)
