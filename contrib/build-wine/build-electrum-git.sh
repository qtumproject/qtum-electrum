#!/bin/bash

# You probably need to update only this link
ELECTRUM_GIT_URL=https://github.com/qtumproject/qtum-electrum.git
BRANCH=master
NAME_ROOT=Qtum-electrum
PYTHON_VERSION=3.5.4

if [ "$#" -gt 0 ]; then
    BRANCH="$1"
fi

# These settings probably don't need any change
export WINEPREFIX=/opt/wine64
export PYTHONHASHSEED=22


PYHOME=c:/python$PYTHON_VERSION
PYTHON="wine $PYHOME/python.exe -OO -B"


# Let's begin!
cd `dirname $0`
set -e

cd tmp

if [ -d "qtum-electrum-git" ]; then
    # GIT repository found, update it
    echo "Pull"
    cd qtum-electrum-git
    git pull
    git checkout $BRANCH
    cd ..
else
    # GIT repository not found, clone it
    echo "Clone"
    git clone -b $BRANCH $ELECTRUM_GIT_URL qtum-electrum-git
fi

cd qtum-electrum-git
VERSION=`git describe --tags`
echo "Last commit: $VERSION"

cd ..

rm -rf $WINEPREFIX/drive_c/electrum
cp -r qtum-electrum-git $WINEPREFIX/drive_c/electrum
cp qtum-electrum-git/LICENCE .

# add locale dir
cp -r ../../../lib/locale $WINEPREFIX/drive_c/electrum/lib/

# Build Qt resources
wine $WINEPREFIX/drive_c/python$PYTHON_VERSION/Scripts/pyrcc5.exe C:/electrum/icons.qrc -o C:/electrum/gui/qt/icons_rc.py


pushd $WINEPREFIX/drive_c/electrum
$PYTHON setup.py install
popd

cd ..

rm -rf dist/

# build standalone version
wine "C:/python$PYTHON_VERSION/scripts/pyinstaller.exe" --noconfirm --ascii --name $NAME_ROOT-win-$VERSION.exe -w deterministic.spec

# build NSIS installer
# $VERSION could be passed to the electrum.nsi script, but this would require some rewriting in the script iself.
wine "$WINEPREFIX/drive_c/Program Files (x86)/NSIS/makensis.exe" /DPRODUCT_VERSION=$VERSION electrum.nsi

cd dist
mv electrum-setup.exe $NAME_ROOT-win-$VERSION-setup.exe
cd ..

# build portable version
cp portable.patch $WINEPREFIX/drive_c/electrum
pushd $WINEPREFIX/drive_c/electrum
patch < portable.patch 
popd
wine "C:/python$PYTHON_VERSION/scripts/pyinstaller.exe" --noconfirm --ascii --name $NAME_ROOT-win-$VERSION-portable.exe -w deterministic.spec

echo "Done."
