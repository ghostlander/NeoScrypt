#!/bin/sh

DEFINES="-DNEOSCRYPT_ASM -DNEOSCRYPT_OPT -DNEOSCRYPT_MINER_4WAY -DNEOSCRYPT_SHA256"

CC="gcc"
CFLAGS="-Wall -O2 -fomit-frame-pointer -fno-stack-protector"

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
