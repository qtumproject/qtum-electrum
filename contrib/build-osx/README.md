# Building Mac OS binaries


#### 1. Get Xcode

Building the QR scanner (CalinsQRReader) requires full Xcode (not just command line tools).

The last Xcode version compatible with El Capitan is Xcode 8.2.1

Get it from [here](https://developer.apple.com/download/more/).

Unfortunately, you need an "Apple ID" account.

After downloading, uncompress it.

Make sure it is the "selected" xcode (e.g.):

    sudo xcode-select -s $HOME/Downloads/Xcode.app/Contents/Developer/

## 2. Build QR scanner separately on newer Mac

Alternatively, you can try building just the QR scanner on newer macOS.

On newer Mac, run:

    pushd contrib/build-osx/CalinsQRReader; xcodebuild; popd
    cp -r contrib/build-osx/CalinsQRReader/build prebuilt_qr

Move `prebuilt_qr` to El Capitan: `contrib/osx/CalinsQRReader/prebuilt_qr`.

## 3. Build Qtum Electrum
    ./contrib/build-osx/prepare.sh
    sudo ./contrib/build-osx/make_osx