NeoScrypt
=========

NeoScrypt is a strong memory intensive key derivation function.

Compile time definitions:
 - -DSHA256 enables optional SHA-256 support (Scrypt compatibility);
 - -DBLAKE256 enables optional BLAKE-256 support;
 - -DOPT enables FastKDF performance optimisations;
 - -DASM enables 32-bit and 64-bit assembly optimisations;
 - -DMINER_4WAY enables 4-way mining per thread (requires -DASM).

There are also test vectors and benchmarks available.


Documentation
-------------

Refer to the following white paper for an introduction to NeoScrypt:
http://phoenixcoin.org/archive/neoscrypt_v1.pdf

