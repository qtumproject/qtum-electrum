#!/bin/bash
#
# env vars:
# - ELECBUILD_NOCACHE: if set, forces rebuild of docker image
# - ELECBUILD_COMMIT: if set, do a fresh clone and git checkout

set -e

PROJECT_ROOT="$(dirname "$(readlink -e "$0")")/../.."
PROJECT_ROOT_OR_FRESHCLONE_ROOT="$PROJECT_ROOT"
CONTRIB="$PROJECT_ROOT/contrib"
CONTRIB_WINE="$CONTRIB/build-wine"

. "$CONTRIB"/build_tools_util.sh


DOCKER_BUILD_FLAGS=""
if [ ! -z "$ELECBUILD_NOCACHE" ] ; then
    info "ELECBUILD_NOCACHE is set. forcing rebuild of docker image."
    DOCKER_BUILD_FLAGS="--pull --no-cache"
fi

info "building docker image."
docker build \
    $DOCKER_BUILD_FLAGS \
    -t qtum-electrum-wine-builder-img \
    "$CONTRIB_WINE"

info "building binary..."
docker run -it \
    --privileged \
    --name qtum-electrum-wine-builder-cont \
    -v "$PROJECT_ROOT_OR_FRESHCLONE_ROOT":/opt/wine64/drive_c/electrum \
    --rm \
    --workdir /opt/wine64/drive_c/electrum/contrib/build-wine \
    qtum-electrum-wine-builder-img \
    ./make_win.sh
