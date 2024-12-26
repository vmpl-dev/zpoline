#!/bin/bash

if [ -z "$1" ]; then
    echo "Usage: $0 <app> <args>"
    exit 1
fi

export VMPL_ENABLED=1
export RUN_IN_VMPL=1
export LIBZPHOOK=./apps/basic/libzphook_basic.so

# To use zpoline, please set 0 to ```/proc/sys/vm/mmap_min_addr```.
sudo sh -c "echo 0 > /proc/sys/vm/mmap_min_addr"

LD_PRELOAD=libdunify.so:./libzpoline.so $(which $1) $@