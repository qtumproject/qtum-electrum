#!/bin/bash

set -e

PROJECT_ROOT="$(dirname "$(readlink -e "$0")")/../../.."
CONTRIB="$PROJECT_ROOT/contrib"
CONTRIB_APPIMAGE="$CONTRIB/build-linux/appimage"
DISTDIR="$PROJECT_ROOT/dist"
BUILDDIR="$CONTRIB_APPIMAGE/build/appimage"
APPDIR="$BUILDDIR/electrum.AppDir"
CACHEDIR="$CONTRIB_APPIMAGE/.cache/appimage"

export GCC_STRIP_BINARIES="1"

# pinned versions
PYTHON_VERSION=3.7.9
PKG2APPIMAGE_COMMIT="eb8f3acdd9f11ab19b78f5cb15daa772367daf15"
SQUASHFSKIT_COMMIT="ae0d656efa2d0df2fcac795b6823b44462f19386"


VERSION=`git describe --tags --dirty --always`
APPIMAGE="$DISTDIR/Qtum-electrum-$VERSION-x86_64.AppImage"

. "$CONTRIB"/build_tools_util.sh

rm -rf "$BUILDDIR"
mkdir -p "$APPDIR" "$CACHEDIR" "$DISTDIR"

# potential leftover from setuptools that might make pip put garbage in binary
rm -rf "$PROJECT_ROOT/build"


info "downloading some dependencies."
download_if_not_exist "$CACHEDIR/functions.sh" "https://raw.githubusercontent.com/AppImage/pkg2appimage/$PKG2APPIMAGE_COMMIT/functions.sh"
verify_hash "$CACHEDIR/functions.sh" "78b7ee5a04ffb84ee1c93f0cb2900123773bc6709e5d1e43c37519f590f86918"

download_if_not_exist "$CACHEDIR/appimagetool" "https://github.com/AppImage/AppImageKit/releases/download/12/appimagetool-x86_64.AppImage"
verify_hash "$CACHEDIR/appimagetool" "d918b4df547b388ef253f3c9e7f6529ca81a885395c31f619d9aaf7030499a13"

download_if_not_exist "$CACHEDIR/Python-$PYTHON_VERSION.tar.xz" "https://www.python.org/ftp/python/$PYTHON_VERSION/Python-$PYTHON_VERSION.tar.xz"
verify_hash "$CACHEDIR/Python-$PYTHON_VERSION.tar.xz" "91923007b05005b5f9bd46f3b9172248aea5abc1543e8a636d59e629c3331b01"



info "building python."
tar xf "$CACHEDIR/Python-$PYTHON_VERSION.tar.xz" -C "$BUILDDIR"
(
    cd "$BUILDDIR/Python-$PYTHON_VERSION"
    LC_ALL=C export BUILD_DATE=$(date -u -d "@$SOURCE_DATE_EPOCH" "+%b %d %Y")
    LC_ALL=C export BUILD_TIME=$(date -u -d "@$SOURCE_DATE_EPOCH" "+%H:%M:%S")
    # Patch taken from Ubuntu http://archive.ubuntu.com/ubuntu/pool/main/p/python3.7/python3.7_3.7.6-1.debian.tar.xz
    patch -p1 < "$CONTRIB_APPIMAGE/patches/python-3.7-reproducible-buildinfo.diff"
    ./configure \
      --cache-file="$CACHEDIR/python.config.cache" \
      --prefix="$APPDIR/usr" \
      --enable-ipv6 \
      --enable-shared \
      -q
    make -j4 -s || fail "Could not build Python"
    make -s install > /dev/null || fail "Could not install Python"
    # When building in docker on macOS, python builds with .exe extension because the
    # case insensitive file system of macOS leaks into docker. This causes the build
    # to result in a different output on macOS compared to Linux. We simply patch
    # sysconfigdata to remove the extension.
    # Some more info: https://bugs.python.org/issue27631
    sed -i -e 's/\.exe//g' "$APPDIR"/usr/lib/python3.7/_sysconfigdata*
)


info "Building squashfskit"
git clone "https://github.com/squashfskit/squashfskit.git" "$BUILDDIR/squashfskit"
(
    cd "$BUILDDIR/squashfskit"
    git checkout "${SQUASHFSKIT_COMMIT}^{commit}"
    make -C squashfs-tools mksquashfs || fail "Could not build squashfskit"
)
MKSQUASHFS="$BUILDDIR/squashfskit/squashfs-tools/mksquashfs"


"$CONTRIB"/make_libsecp256k1.sh || fail "Could not build libsecp"
cp -f "$PROJECT_ROOT/electrum/libsecp256k1.so.0" "$APPDIR/usr/lib/libsecp256k1.so.0" || fail "Could not copy libsecp to its destination"


appdir_python() {
  env \
    PYTHONNOUSERSITE=1 \
    LD_LIBRARY_PATH="$APPDIR/usr/lib:$APPDIR/usr/lib/x86_64-linux-gnu${LD_LIBRARY_PATH+:$LD_LIBRARY_PATH}" \
    "$APPDIR/usr/bin/python3.7" "$@"
}

python='appdir_python'


info "installing pip."
"$python" -m ensurepip

info "update submodule."
(
    cd "$PROJECT_ROOT"
    git submodule update --init
)


info "preparing locale."
(
    pushd "$PROJECT_ROOT"/electrum/locale
    if ! which msgfmt > /dev/null 2>&1; then
        fail "Please install gettext"
    fi
    for i in ./*; do
        dir="$PROJECT_ROOT/electrum/locale/$i/LC_MESSAGES"
        mkdir -p $dir
        msgfmt --output-file="$dir/electrum.mo" "$i/electrum.po" || true
    done
    popd
)


info "Installing build dependencies."
mkdir -p "$CACHEDIR/pip_cache"
"$python" -m pip install --no-dependencies --no-warn-script-location --cache-dir "$CACHEDIR/pip_cache" -r "$CONTRIB/deterministic-build/requirements-build-appimage.txt"

info "installing electrum and its dependencies."
"$python" -m pip install --no-dependencies --no-warn-script-location --cache-dir "$CACHEDIR/pip_cache" -r "$CONTRIB/deterministic-build/requirements.txt"
"$python" -m pip install --no-dependencies --no-warn-script-location --cache-dir "$CACHEDIR/pip_cache" -r "$CONTRIB/deterministic-build/requirements-binaries.txt"
"$python" -m pip install --no-dependencies --no-warn-script-location --cache-dir "$CACHEDIR/pip_cache" -r "$CONTRIB/deterministic-build/requirements-qt.txt"
"$python" -m pip install --no-dependencies --no-warn-script-location --cache-dir "$CACHEDIR/pip_cache" -r "$CONTRIB/deterministic-build/requirements-hw.txt"
"$python" -m pip install --no-dependencies --no-warn-script-location --cache-dir "$CACHEDIR/pip_cache" -r "$CONTRIB/deterministic-build/requirements-eth.txt"
"$python" -m pip install --no-dependencies --no-warn-script-location --cache-dir "$CACHEDIR/pip_cache" "$PROJECT_ROOT"

# was only needed during build time, not runtime
"$python" -m pip uninstall -y Cython


info "copying zbar"
cp "/usr/lib/x86_64-linux-gnu/libzbar.so.0" "$APPDIR/usr/lib/libzbar.so.0"


info "desktop integration."
cp "$PROJECT_ROOT/electrum.desktop" "$APPDIR/electrum.desktop"
cp "$PROJECT_ROOT/electrum/gui/icons/electrum.png" "$APPDIR/electrum.png"


# add launcher
cp "$CONTRIB_APPIMAGE/apprun.sh" "$APPDIR/AppRun"

info "finalizing AppDir."
(
    export PKG2AICOMMIT="$PKG2APPIMAGE_COMMIT"
    . "$CACHEDIR/functions.sh"

    cd "$APPDIR"
    # copy system dependencies
    copy_deps; copy_deps; copy_deps
    move_lib

    # apply global appimage blacklist to exclude stuff
    # move usr/include out of the way to preserve usr/include/python3.7m.
    mv usr/include usr/include.tmp
    delete_blacklisted
    mv usr/include.tmp usr/include
) || fail "Could not finalize AppDir"

info "Copying additional libraries"
(
    # On some systems it can cause problems to use the system libusb (on AppImage excludelist)
    cp -f /usr/lib/x86_64-linux-gnu/libusb-1.0.so "$APPDIR/usr/lib/libusb-1.0.so" || fail "Could not copy libusb"
    # some distros lack libxkbcommon-x11
    cp -f /usr/lib/x86_64-linux-gnu/libxkbcommon-x11.so.0 "$APPDIR"/usr/lib/x86_64-linux-gnu || fail "Could not copy libxkbcommon-x11"
)

info "stripping binaries from debug symbols."
# "-R .note.gnu.build-id" also strips the build id
# "-R .comment" also strips the GCC version information
strip_binaries()
{
  chmod u+w -R "$APPDIR"
  {
    printf '%s\0' "$APPDIR/usr/bin/python3.7"
    find "$APPDIR" -type f -regex '.*\.so\(\.[0-9.]+\)?$' -print0
  } | xargs -0 --no-run-if-empty --verbose strip -R .note.gnu.build-id -R .comment
}
strip_binaries

remove_emptydirs()
{
  find "$APPDIR" -type d -empty -print0 | xargs -0 --no-run-if-empty rmdir -vp --ignore-fail-on-non-empty
}
remove_emptydirs


info "removing some unneeded stuff to decrease binary size."
rm -rf "$APPDIR"/usr/{share,include}
PYDIR="$APPDIR"/usr/lib/python3.7
rm -rf "$PYDIR"/{test,ensurepip,lib2to3,idlelib,turtledemo}
rm -rf "$PYDIR"/{ctypes,sqlite3,tkinter,unittest}/test
rm -rf "$PYDIR"/distutils/{command,tests}
rm -rf "$PYDIR"/config-3.7m-x86_64-linux-gnu
rm -rf "$PYDIR"/site-packages/{opt,pip,setuptools,wheel}
rm -rf "$PYDIR"/site-packages/Cryptodome/SelfTest
rm -rf "$PYDIR"/site-packages/{psutil,qrcode,websocket}/tests
for component in connectivity declarative help location multimedia quickcontrols2 serialport webengine websockets xmlpatterns ; do
  rm -rf "$PYDIR"/site-packages/PyQt5/Qt/translations/qt${component}_*
  rm -rf "$PYDIR"/site-packages/PyQt5/Qt/resources/qt${component}_*
done
rm -rf "$PYDIR"/site-packages/PyQt5/Qt/{qml,libexec}
rm -rf "$PYDIR"/site-packages/PyQt5/{pyrcc.so,pylupdate.so,uic}
rm -rf "$PYDIR"/site-packages/PyQt5/Qt/plugins/{bearer,gamepads,geometryloaders,geoservices,playlistformats,position,renderplugins,sceneparsers,sensors,sqldrivers,texttospeech,webview}
for component in Bluetooth Concurrent Designer Help Location NetworkAuth Nfc Positioning PositioningQuick Qml Quick Sensors SerialPort Sql Test Web Xml ; do
    rm -rf "$PYDIR"/site-packages/PyQt5/Qt/lib/libQt5${component}*
    rm -rf "$PYDIR"/site-packages/PyQt5/Qt${component}*
done
rm -rf "$PYDIR"/site-packages/PyQt5/Qt.so

# these are deleted as they were not deterministic; and are not needed anyway
find "$APPDIR" -path '*/__pycache__*' -delete
# note that *.dist-info is needed by certain packages.
# e.g. see https://gitlab.com/python-devs/importlib_metadata/issues/71
for f in "$PYDIR"/site-packages/importlib_metadata-*.dist-info; do mv "$f" "$(echo "$f" | sed s/\.dist-info/\.dist-info2/)"; done
rm -rf "$PYDIR"/site-packages/*.dist-info/
rm -rf "$PYDIR"/site-packages/*.egg-info/
for f in "$PYDIR"/site-packages/importlib_metadata-*.dist-info2; do mv "$f" "$(echo "$f" | sed s/\.dist-info2/\.dist-info/)"; done


find -exec touch -h -d '2000-11-11T11:11:11+00:00' {} +


info "creating the AppImage."
(
    cd "$BUILDDIR"
    cp "$CACHEDIR/appimagetool" "$CACHEDIR/appimagetool_copy"
    # zero out "appimage" magic bytes, as on some systems they confuse the linker
    sed -i 's|AI\x02|\x00\x00\x00|' "$CACHEDIR/appimagetool_copy"
    chmod +x "$CACHEDIR/appimagetool_copy"
    "$CACHEDIR/appimagetool_copy" --appimage-extract
    # We build a small wrapper for mksquashfs that removes the -mkfs-fixed-time option
    # that mksquashfs from squashfskit does not support. It is not needed for squashfskit.
    cat > ./squashfs-root/usr/lib/appimagekit/mksquashfs << EOF
#!/bin/sh
args=\$(echo "\$@" | sed -e 's/-mkfs-fixed-time 0//')
"$MKSQUASHFS" \$args
EOF
    env VERSION="$VERSION" ARCH=x86_64 SOURCE_DATE_EPOCH=1530212462 ./squashfs-root/AppRun --no-appstream --verbose "$APPDIR" "$APPIMAGE"
)


info "done."
ls -la "$DISTDIR"
sha256sum "$DISTDIR"/*
