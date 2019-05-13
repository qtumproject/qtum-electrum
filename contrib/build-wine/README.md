# Build Windows binaries with Docker

1. Install Docker

   ```
   see [https://docs.docker.com/install/](https://docs.docker.com/install/)
   ```

2. Build image

    ```
    $ sudo docker build -t qtum-electrum-wine-builder-img contrib/build-wine/docker
    ```

    Note: see [this](https://stackoverflow.com/a/40516974/7499128) if having dns problems

3. Build Windows binaries

    It's recommended to build from a fresh clone
    (but you can skip this if reproducibility is not necessary).

    ```
    $ FRESH_CLONE=contrib/build-wine/fresh_clone && \
        rm -rf $FRESH_CLONE && \
        mkdir -p $FRESH_CLONE && \
        cd $FRESH_CLONE  && \
        git clone https://github.com/qtumproject/qtum-electrum.git && \
        cd qtum-electrum
    ```

    And then build from this directory:
    ```
    $ git checkout $REV
    $ sudo docker run -it \
        --name qtum-electrum-wine-builder-cont \
        -v $PWD:/opt/wine64/drive_c/electrum \
        --rm \
        --workdir /opt/wine64/drive_c/electrum/contrib/build-wine \
        qtum-electrum-wine-builder-img \
        ./build.sh
    ```
