Windows Binary Builds
=====================

These scripts can be used for cross-compilation of Windows Electrum executables from Linux/Wine.
Produced binaries are deterministic so you should be able to generate binaries that match the official releases.


## Usage:
1. Install wine

For example:

```
$ sudo apt-get install wine-development
```

or

```
$ sudo add-apt-repository ppa:ricotz/unstable
$ sudo apt update
$ sudo apt install wine-stable
```


2. Install the following dependencies:

 - dirmngr
 - gpg
 - 7z
 - (and, for building libsecp256k1)
   - mingw-w64
   - autotools-dev
   - autoconf
   - libtool

```
sudo apt-get install dirmngr gnupg2 p7zip-full
sudo apt-get install mingw-w64 autotools-dev autoconf libtool
```


3. Make sure `/opt` is writable by the current user.
4. Run `sudo chmod +x ./*.sh`
5. Run `./prepare-wine.sh`
6. Run `./build.sh`.
7. The generated binaries are in `./dist`.
