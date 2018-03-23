# Building Mac OS binaries

## edit PyQt5/uic/port_v2/ascii_upper.py
    change string.maketrans to str.maketrans

## libffi
    brew install libffi

## libusb
    brew install libusb
    cp /usr/local/Cellar/libusb/1.0.21/lib/libusb-1.0.dylib contrib/build-osx

## build
    sudo ./contrib/build-osx/make_osx