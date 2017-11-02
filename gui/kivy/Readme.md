## Install kivy
    sudo apt-get install python3-kivy

## Install JDK
    sudo apt-get install default-jdk

## Install p4a
    sudo pip3 install python-for-android

## Create packages
    ./contrib/make_packages

## Install buildozer
    sudo pip3 install buildozer

## Configure buildozer
    check and edit kivy/tools/buildozer.spec
    make sure p4a.source_dir is set correctly

## Build

    make theming
    make apk


If something in included modules like kivy or any other module changes
then you need to rebuild the distribution. To do so:

    rm -rf .buildozer/android/platform/python-for-android/dist


## Build with ssl

    rm -rf .buildozer/android/platform/build/
    ./contrib/make_apk
    pushd /opt/electrum/.buildozer/android/platform/build/build/libs_collections/Electrum/armeabi-v7a
    cp libssl1.0.2g.so /opt/crystax-ndk-10.3.2/sources/openssl/1.0.2g/libs/armeabi-v7a/libssl.so
    cp libcrypto1.0.2g.so /opt/crystax-ndk-10.3.2/sources/openssl/1.0.2g/libs/armeabi-v7a/libcrypto.so
    popd
    ./contrib/make_apk


