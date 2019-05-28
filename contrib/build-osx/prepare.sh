#!/bin/bash

. $(dirname "$0")/../build_tools_util.sh

which brew > /dev/null 2>&1 || fail "Please install brew from https://brew.sh/ to continue"

info "Installing zlib and sqlite"
brew install zlib sqlite

info "Installing autoconf automake libtool"
brew install autoconf automake libtool