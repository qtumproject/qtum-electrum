Windows binaries
================

✓ _These binaries should be reproducible, meaning you should be able to generate
   binaries that match the official releases._

This assumes an Ubuntu (x86_64) host, but it should not be too hard to adapt to another
similar system. The docker commands should be executed in the project's root
folder.

0. clone code without `--recursive`
    
    ```
    $ git clone https://github.com/qtumproject/qtum-electrum.git 
    ```

1. Install Docker

    ```
    $ curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo apt-key add -
    $ sudo add-apt-repository "deb [arch=amd64] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable"
    $ sudo apt-get update
    $ sudo apt-get install -y docker-ce
    ```

2. Build image

    ```
    $ cd qtum-electrum/contrib/build-wine
    $ ./build.sh
    ```

    Note: see [this](https://stackoverflow.com/a/40516974/7499128) if having dns problems

3. The generated binaries are in `./contrib/build-wine/dist`.


Code Signing
============

Electrum Windows builds are signed with a Microsoft Authenticode™ code signing
certificate in addition to the GPG-based signatures.

The advantage of using Authenticode is that Electrum users won't receive a 
Windows SmartScreen warning when starting it.

The release signing procedure involves a signer (the holder of the
certificate/key) and one or multiple trusted verifiers:


| Signer                                                    | Verifier                          |
|-----------------------------------------------------------|-----------------------------------|
| Build .exe files using `build.sh`                         |                                   |
| Sign .exe with `./sign.sh`                                |                                   |
| Upload signed files to download server                    |                                   |
|                                                           | Build .exe files using `build.sh` |
|                                                           | Compare files using `unsign.sh`   |
|                                                           | Sign .exe file using `gpg -b`     |

| Signer and verifiers:                                                                         |
|-----------------------------------------------------------------------------------------------|
| Upload signatures to 'electrum-signatures' repo, as `$version/$filename.$builder.asc`         |



Verify Integrity of signed binary
=================================

Every user can verify that the official binary was created from the source code in this 
repository. To do so, the Authenticode signature needs to be stripped since the signature
is not reproducible.

This procedure removes the differences between the signed and unsigned binary:

1. Remove the signature from the signed binary using osslsigncode or signtool.
2. Set the COFF image checksum for the signed binary to 0x0. This is necessary
   because pyinstaller doesn't generate a checksum.
3. Append null bytes to the _unsigned_ binary until the byte count is a multiple
   of 8.

The script `unsign.sh` performs these steps.
