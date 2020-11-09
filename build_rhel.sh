#!/bin/bash

# Pass any cmake options this way:

# ./build_rhel.sh -DFLEDGE_INSTALL=/some_path/Fledge

source scl_source enable devtoolset-7
export CC=$(scl enable devtoolset-7 "command -v gcc")
export CXX=$(scl enable devtoolset-7 "command -v g++")

mkdir build
cd build/
cmake $@ ..
make