#!/bin/bash -v

make clean
make clean -C apps/basic

make all
make all -C apps/basic