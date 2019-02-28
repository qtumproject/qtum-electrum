# -*- mode: python -*-

from PyInstaller.utils.hooks import collect_data_files, collect_submodules, collect_dynamic_libs
import sys
import os

PACKAGE='Qtum Electrum'
PYPKG='qtum_electrum'
MAIN_SCRIPT='run_qtum_electrum'
ICONS_FILE=PYPKG + '/gui/icons/electrum.icns'

for i, x in enumerate(sys.argv):
    if x == '--name':
        VERSION = sys.argv[i+1]
        break
else:
    raise Exception('no version')

electrum = os.path.abspath(".") + "/"
block_cipher=None

# see https://github.com/pyinstaller/pyinstaller/issues/2005
hiddenimports = []
hiddenimports += collect_submodules('trezorlib')
hiddenimports += collect_submodules('btchip')
hiddenimports += collect_submodules('keepkeylib')
hiddenimports += collect_submodules('websocket')

datas = [
    (electrum+'qtum_electrum/*.json', PYPKG),
    (electrum+'qtum_electrum/wordlist/english.txt', PYPKG + '/wordlist'),
    (electrum+'qtum_electrum/locale', PYPKG + '/locale'),
    (electrum+'qtum_electrum/plugins', PYPKG + '/plugins'),
    (electrum+'qtum_electrum/gui/icons', PYPKG + '/gui/icons'),
]

datas += collect_data_files('trezorlib')
datas += collect_data_files('btchip')
datas += collect_data_files('keepkeylib')

# Add libusb so Trezor will work
binaries = [(electrum + "contrib/build-osx/libusb-1.0.dylib", ".")]
binaries += [(electrum + "contrib/build-osx/libsecp256k1.0.dylib", ".")]

# Workaround for "Retro Look":
binaries += [b for b in collect_dynamic_libs('PyQt5') if 'macstyle' in b[0]]

# We don't put these files in to actually include them in the script but to make the Analysis method scan them for imports
a = Analysis([electrum+MAIN_SCRIPT,
              electrum+'qtum_electrum/gui/qt/main_window.py',
              electrum+'qtum_electrum/gui/text.py',
              electrum+'qtum_electrum/util.py',
              electrum+'qtum_electrum/wallet.py',
              electrum+'qtum_electrum/simple_config.py',
              electrum+'qtum_electrum/qtum.py',
              electrum+'qtum_electrum/dnssec.py',
              electrum+'qtum_electrum/commands.py',
              electrum+'qtum_electrum/plugins/email_requests/qt.py',
              electrum+'qtum_electrum/plugins/trezor/qt.py',
              electrum+'qtum_electrum/plugins/ledger/qt.py',
              ],
             binaries=binaries,
             datas=datas,
             hiddenimports=hiddenimports,
             hookspath=[])


# http://stackoverflow.com/questions/19055089/pyinstaller-onefile-warning-pyconfig-h-when-importing-scipy-or-scipy-signal
for d in a.datas:
    if 'pyconfig' in d[0]:
        a.datas.remove(d)
        break

# Strip out parts of Qt that we never use. Reduces binary size by tens of MBs. see #4815
qt_bins2remove=('qtweb', 'qt3d', 'qtgame', 'qtdesigner', 'qtquick', 'qtlocation', 'qttest', 'qtxml')
print("Removing Qt binaries:", *qt_bins2remove)
for x in a.binaries.copy():
    for r in qt_bins2remove:
        if x[0].lower().startswith(r):
            a.binaries.remove(x)
            print('----> Removed x =', x)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(pyz,
          a.scripts,
          a.binaries,
          a.datas,
          name=PACKAGE,
          debug=False,
          strip=False,
          upx=True,
          icon=electrum+ICONS_FILE,
          console=False)

app = BUNDLE(exe,
             version = VERSION,
             name=PACKAGE + '.app',
             icon=electrum+ICONS_FILE,
             bundle_identifier=None,
             info_plist={
                'NSHighResolutionCapable': 'True',
                'NSSupportsAutomaticGraphicsSwitching': 'True'
             }
)
