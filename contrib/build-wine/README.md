Windows Binary Builds
=====================

These scripts can be used for cross-compilation of Windows Electrum executables from Linux/Wine.
Produced binaries are deterministic so you should be able to generate binaries that match the official releases.


## Usage:
1. Install wine

For example:

```
$ sudo apt-get install wine-development
$ sudo ln -sf /usr/bin/wine-development /usr/local/bin/wine
$ wine --version
 wine-2.0 (Debian 2.0-3+b2)
```

or

```
$ sudo add-apt-repository ppa:ricotz/unstable
$ sudo apt update
$ sudo apt install wine-stable
$ wine --version
wine-2.0.3 (Ubuntu 2.0.3-0ubuntu1~16.04~ricotz0)
```


2. Install the following dependencies:

 - dirmngr
 - gpg
 - 7z

```
sudo apt-get install dirmngr gnupg2 p7zip-full
```
or

```
$ pacman -S wine gnupg
$ wine --version
 wine-2.21
```

3. Make sure `/opt` is writable by the current user.
4. Run `sudo chmod+x ./*.sh`
5. Run `./prepare-wine.sh`
6. Run `./build.sh`.
7. The generated binaries are in `./dist`.
