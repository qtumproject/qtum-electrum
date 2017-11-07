## Install kivy
    https://kivy.org/docs/installation/installation-linux.html
    sudo pip3 install Pillow
    sudo add-apt-repository ppa:kivy-team/kivy
    sudo apt-get update
    sudo apt-get install python3-kivy
    you can get compatiable cython version from https://kivy.org/docs/installation/installation-linux.html

## Install JDK
    sudo apt-get install default-jdk

## Install p4a
    cd /opt
    git clone https://github.com/kivy/python-for-android.git

## Create packages
    ./contrib/make_packages

## Install buildozer
    https://github.com/kivy/buildozer#installing-buildozer-with-python3-support
    sudo dpkg --add-architecture i386
    sudo apt-get update
    sudo apt-get install build-essential ccache libncurses5:i386 libstdc++6:i386 libgtk2.0-0:i386 libpangox-1.0-0:i386 libpangoxft-1.0-0:i386 libidn11:i386 unzip zlib1g-dev zlib1g:i386
    sudo pip3 install --upgrade buildozer

## Download CrystaX NDK
    pushd /opt
    wget https://www.crystax.net/download/crystax-ndk-10.3.2-linux-x86_64.tar.xz
    tar -xvf crystax-ndk-10.3.2-linux-x86_64.tar.xz
    popd

## Configure buildozer
    check kivy/tools/buildozer.spec to make sure p4a.source_dir and android.ndk_path are correct


## Enable SSL
    https://stackoverflow.com/questions/41944790/crystax-sqlite-3-android-mk-cannot-find-module-with-tag-openssl-1-0-2h
    https://github.com/named-data-mobile/NFD-android/blob/master/README.md
    pushd /opt
    git clone https://github.com/crystax/android-vendor-openssl.git
    cd crystax-ndk-10.3.2
    cp sources/openssl/1.0.1p/Android.mk -o sources/openssl/1.0.2h/Android.mk
    popd

## make theming
    pushd ./gui/kivy
    make theming
    popd


## Build
    rm -rf .buildozer/android/platform/build/
    ./contrib/make_apk


If something in included modules like kivy or any other module changes
then you need to rebuild the distribution. To do so:

    rm -rf .buildozer/android/platform/python-for-android/dist






