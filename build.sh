#!/bin/sh

DEFINES="-DOPT -DASM -DMINER_4WAY -DSHA256"

CC="gcc"
CFLAGS="-Wall -O2 -fomit-frame-pointer"

LD="gcc"
LDFLAGS="-Wl,-s"

echo "$CC $CFLAGS $DEFINES -c neoscrypt.c"
`$CC $CFLAGS $DEFINES -c neoscrypt.c`

echo "$CC $CFLAGS $DEFINES -c neoscrypt_test.c"
`$CC $CFLAGS $DEFINES -c neoscrypt_test.c`

echo "$CC $DEFINES -c neoscrypt_asm.S"
`$CC $DEFINES -c neoscrypt_asm.S`

echo "$LD $LDFLAGS -o neoscrypt neoscrypt.o neoscrypt_test.o neoscrypt_asm.o"
`$LD $LDFLAGS -o neoscrypt neoscrypt.o neoscrypt_test.o neoscrypt_asm.o`
