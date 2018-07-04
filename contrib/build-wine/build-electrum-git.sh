#!/bin/bash

# You probably need to update only this link
ELECTRUM_GIT_URL=https://github.com/qtumproject/qtum-electrum.git
BRANCH=master
NAME_ROOT=Qtum-electrum
PYTHON_VERSION=3.5.4

# These settings probably don't need any change
export WINEPREFIX=/opt/wine64
export PYTHONHASHSEED=22
export PYTHONDONTWRITEBYTECODE=1

PYHOME=c:/python$PYTHON_VERSION
PYTHON="wine $PYHOME/python.exe -OO -B"

# Let's begin!
cd `dirname $0`
set -e

mkdir -p tmp
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

pushd qtum-electrum-git
if [ ! -z "$1" ]; then
    git checkout $1
fi

VERSION=`git describe --tags`
echo "Last commit: $VERSION"
find -exec touch -d '2000-11-11T11:11:11+00:00' {} +
popd

rm -rf $WINEPREFIX/drive_c/qtum-electrum
cp -r qtum-electrum-git $WINEPREFIX/drive_c/qtum-electrum
cp qtum-electrum-git/LICENCE .

# add locale dir
cp -r ../../../lib/locale $WINEPREFIX/drive_c/qtum-electrum/lib/

# Install frozen dependencies
$PYTHON -m pip install -r ../../../requirements.txt

# Build Qt resources
wine $WINEPREFIX/drive_c/python$PYTHON_VERSION/Scripts/pyrcc5.exe C:/qtum-electrum/icons.qrc -o C:/qtum-electrum/gui/qt/icons_rc.py

pushd $WINEPREFIX/drive_c/qtum-electrum
$PYTHON setup.py install
popd

cd ..

rm -rf dist/

# build standalone version and portable versions
wine "C:/python$PYTHON_VERSION/scripts/pyinstaller.exe" --noconfirm --ascii --clean --name $NAME_ROOT-win-$VERSION -w deterministic.spec

# set timestamps in dist, in order to make the installer reproducible
pushd dist
find -exec touch -d '2000-11-11T11:11:11+00:00' {} +
popd

# build NSIS installer
# $VERSION could be passed to the electrum.nsi script, but this would require some rewriting in the script iself.
wine "$WINEPREFIX/drive_c/Program Files (x86)/NSIS/makensis.exe" /DPRODUCT_VERSION=$VERSION electrum.nsi

cd dist
mv electrum-setup.exe $NAME_ROOT-win-$VERSION-setup.exe
cd ..

echo "Done."
sha256sum dist/Qtum-electrum*exe