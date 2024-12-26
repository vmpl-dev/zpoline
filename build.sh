#!/bin/bash -v

make clean
make clean -C apps/basic

make all
make all -C apps/basic

sudo make install
sudo make install -C apps/basic
