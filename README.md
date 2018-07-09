NeoScrypt
=========

NeoScrypt is a strong memory intensive key derivation function.

Compile time definitions:
 - -DNEOSCRYPT_SHA256 enables optional SHA-256 support (Scrypt compatibility);
 - -DNEOSCRYPT_BLAKE256 enables optional BLAKE-256 support;
 - -DNEOSCRYPT_OPT enables FastKDF performance optimisations;
 - -DNEOSCRYPT_ASM enables 32-bit and 64-bit assembly optimisations;
 - -DNEOSCRYPT_MINER_4WAY enables 4-way mining per thread (requires -DNEOSCRYPT_ASM).

There are also test vectors and benchmarks available.


Documentation
-------------

Refer to the following white paper for an introduction to NeoScrypt:
http://phoenixcoin.org/archive/neoscrypt_v1.pdf

