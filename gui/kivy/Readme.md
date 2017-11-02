## Install kivy
    sudo pip3 install Pillow
    sudo apt-get install python3-kivy

## Install JDK
    sudo apt-get install default-jdk

## Install p4a
    sudo pip3 install python-for-android

## Create packages
    ./contrib/make_packages

## Install buildozer
    sudo dpkg --add-architecture i386
    sudo apt-get update
    sudo apt-get install build-essential ccache libncurses5:i386 libstdc++6:i386 libgtk2.0-0:i386 libpangox-1.0-0:i386 libpangoxft-1.0-0:i386 libidn11:i386 unzip zlib1g-dev zlib1g:i386
    sudo pip3 install --upgrade buildozer

## Download CrystaX NDK
    cd ~/.buildozer/android/platform/
    wget https://www.crystax.net/download/crystax-ndk-10.3.2-linux-x86_64.tar.xz
    tar -xvf crystax-ndk-10.3.2-linux-x86_64.tar.xz

## Configure buildozer
    check and edit kivy/tools/buildozer.spec make sure p4a.source_dir and android.ndk_path are set correctly

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


