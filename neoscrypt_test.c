/*
 * Copyright (c) 2014-2018 John Doering <ghostlander@phoenixcoin.org>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */


/* Various test vectors and benchmarks for NeoScrypt */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/time.h>

#include "neoscrypt.h"


#ifdef NEOSCRYPT_OPT
extern void neoscrypt_fastkdf_opt(const uchar *password, const uchar *salt,
  uchar *output, uint mode);
#else
extern void neoscrypt_fastkdf(const uchar *password, uint password_len,
  const uchar *salt, uint salt_len, uint N, uchar *output, uint output_len);
#endif


/* Performance evaluation:
 * -b [number] is a benchmark ID:
 *    1  BLAKE2s;
 *    2  FastKDF (32 rounds);
 *    3  NeoScrypt INT;
 *    4  Scrypt INT;
 *    5  NeoScrypt SSE2;
 *    6  Scrypt SSE2;
 *    7  BLAKE2s SSE2-4way;
 *    8  FastKDF SSE2-4way;
 *    9  NeoScrypt SSE2-4way;
 *   10  Scrypt SSE2-4way;
 * -i [number] is an iteration count for a benchmark specified above */
int main(int argc, char *argv[]) {
    uint prf_input_len = 64, prf_key_len = 32, prf_output_len = 32;
    uint kdf_input_len = 80, kdf_output_len = 256;
    uint neoscrypt_output_len = 32;
    uchar input[kdf_input_len], output[kdf_output_len];
#if defined(NEOSCRYPT_ASM) && defined(NEOSCRYPT_MINER_4WAY)
    uchar prf_input_4way[256], prf_key_4way[128];
    uchar kdf_input_4way[320], kdf_key_4way[320], kdf_output_4way[1024];
    const size_t align = 0x40;
    uchar *scratchbuf;
#ifndef NEOSCRYPT_SHA256
    scratchbuf = (uchar *) malloc(134464 + align);
#else
    scratchbuf = (uchar *) malloc(525632 + align);
#endif
#endif
    uint ret_status = 0, status, i;
    const char *fail_str = "failed!\n", *pass_str = "passed.\n";

    /* For benchmarks */
    int opt, arg;
    uint id = 0, it = 0;
    struct timeval time;
    ullong delta, start, ustart, finish, ufinish;
    uint *pinput = (uint *) &input[0];
#if defined(NEOSCRYPT_ASM) && defined(NEOSCRYPT_MINER_4WAY)
    uint *pprf_input = (uint *) &prf_input_4way[0];
    uint *pkdf_input = (uint *) &kdf_input_4way[0];
#endif

    for(i = 0; i < kdf_input_len; i++) {
        input[i] = (uchar)i;
    }

    while((opt = getopt(argc, argv, "b:i:")) != -1)
      switch(opt) {

        case('b'):
            arg = atoi(optarg);
            if(arg > 0) id = (uint)arg;
            break;

        case('i'):
            arg = atoi(optarg);
            if(arg > 0) it = (uint)arg;
            break;

        default:
            break;

    }

    switch(id) {

        case(1):
            if(!it) it = 1000000;
            gettimeofday(&time, NULL);
            start  = time.tv_sec;
            ustart = time.tv_usec;
            for(i = 0; i < it; i++) {
                neoscrypt_blake2s(input, prf_input_len, input, prf_key_len,
                  output, prf_output_len);
                pinput[0] = i;
            }
            gettimeofday(&time, NULL);
            finish  = time.tv_sec;
            ufinish = time.tv_usec;
            delta = (finish - start) * 1000000 + ufinish - ustart;
            printf("BLAKE2s: %.3f MH/s\n",
              (double)it / (double)delta);
            return(0);

        case(2):
            if(!it) it = 50000;
            gettimeofday(&time, NULL);
            start  = time.tv_sec;
            ustart = time.tv_usec;
            for(i = 0; i < it; i++) {
#ifdef NEOSCRYPT_OPT
                neoscrypt_fastkdf_opt(input, input, output, 0);
#else
                neoscrypt_fastkdf(input, kdf_input_len, input, kdf_input_len, 32,
                  output, kdf_output_len);
#endif
                pinput[0] = i;
            }
            gettimeofday(&time, NULL);
            finish  = time.tv_sec;
            ufinish = time.tv_usec;
            delta = (finish - start) * 1000000 + ufinish - ustart;
            printf("FastKDF (32 rounds): %.3f KH/s\n",
              (double)it * 1000 / (double)delta);
            return(0);

        case(3):
            if(!it) it = 5000;
            gettimeofday(&time, NULL);
            start  = time.tv_sec;
            ustart = time.tv_usec;
            for(i = 0; i < it; i++) {
                neoscrypt(input, output, 0x80000620);
                pinput[0] = i;
            }
            gettimeofday(&time, NULL);
            finish  = time.tv_sec;
            ufinish = time.tv_usec;
            delta = (finish - start) * 1000000 + ufinish - ustart;
#ifndef NEOSCRYPT_ASM
            printf("NeoScrypt: %.3f KH/s\n",
#else
            printf("NeoScrypt INT: %.3f KH/s\n",
#endif
              (double)it * 1000 / (double)delta);
            return(0);

#ifdef NEOSCRYPT_SHA256
        case(4):
            if(!it) it = 5000;
            gettimeofday(&time, NULL);
            start  = time.tv_sec;
            ustart = time.tv_usec;
            for(i = 0; i < it; i++) {
                neoscrypt(input, output, 0x80000903);
                pinput[0] = i;
            }
            gettimeofday(&time, NULL);
            finish  = time.tv_sec;
            ufinish = time.tv_usec;
            delta = (finish - start) * 1000000 + ufinish - ustart;
#ifndef NEOSCRYPT_ASM
            printf("Scrypt: %.3f KH/s\n",
#else
            printf("Scrypt INT: %.3f KH/s\n",
#endif
              (double)it * 1000 / (double)delta);
            return(0);
#endif

        case(5):
            if(!it) it = 5000;
            gettimeofday(&time, NULL);
            start  = time.tv_sec;
            ustart = time.tv_usec;
            for(i = 0; i < it; i++) {
                neoscrypt(input, output, 0x80001620);
                pinput[0] = i;
            }
            gettimeofday(&time, NULL);
            finish  = time.tv_sec;
            ufinish = time.tv_usec;
            delta = (finish - start) * 1000000 + ufinish - ustart;
#ifndef NEOSCRYPT_ASM
            printf("NeoScrypt: %.3f KH/s\n",
#else
            printf("NeoScrypt SSE2: %.3f KH/s\n",
#endif
              (double)it * 1000 / (double)delta);
            return(0);

#ifdef NEOSCRYPT_SHA256
        case(6):
            if(!it) it = 5000;
            gettimeofday(&time, NULL);
            start  = time.tv_sec;
            ustart = time.tv_usec;
            for(i = 0; i < it; i++) {
                neoscrypt(input, output, 0x80001903);
                pinput[0] = i;
            }
            gettimeofday(&time, NULL);
            finish  = time.tv_sec;
            ufinish = time.tv_usec;
            delta = (finish - start) * 1000000 + ufinish - ustart;
#ifndef NEOSCRYPT_ASM
            printf("Scrypt: %.3f KH/s\n",
#else
            printf("Scrypt SSE2: %.3f KH/s\n",
#endif
              (double)it * 1000 / (double)delta);
            return(0);
#endif

#if defined(NEOSCRYPT_ASM) && defined(NEOSCRYPT_MINER_4WAY)
        case(7):
            if(!it) it = 1000000;
            gettimeofday(&time, NULL);
            start  = time.tv_sec;
            ustart = time.tv_usec;
            for(i = 0; i < it; i += 4) {
                neoscrypt_blake2s_4way(prf_input_4way, prf_key_4way, output);
                pprf_input[0] = i;
            }
            gettimeofday(&time, NULL);
            finish  = time.tv_sec;
            ufinish = time.tv_usec;
            delta = (finish - start) * 1000000 + ufinish - ustart;
            printf("BLAKE2s SSE2 4-way: %.3f MH/s\n",
              (double)it / (double)delta);
            return(0);

        case(8):
            if(!it) it = 50000;
            gettimeofday(&time, NULL);
            start  = time.tv_sec;
            ustart = time.tv_usec;
            for(i = 0; i < it; i += 4) {
                neoscrypt_fastkdf_4way(kdf_input_4way, kdf_key_4way, kdf_output_4way,
                  (uchar *) &scratchbuf[(size_t)scratchbuf & (align - 1)], 0);
                pkdf_input[0] = i;
            }
            gettimeofday(&time, NULL);
            finish  = time.tv_sec;
            ufinish = time.tv_usec;
            delta = (finish - start) * 1000000 + ufinish - ustart;
            printf("FastKDF (32 rounds) SSE2 4-way: %.3f KH/s\n",
              (double)it  * 1000 / (double)delta);
            return(0);

        case(9):
            if(!it) it = 5000;
            gettimeofday(&time, NULL);
            start  = time.tv_sec;
            ustart = time.tv_usec;
            for(i = 0; i < it; i += 4) {
                neoscrypt_4way(input, output,
                  (uchar *) &scratchbuf[(size_t)scratchbuf & (align - 1)]);
                pinput[0] = i;
            }
            gettimeofday(&time, NULL);
            finish  = time.tv_sec;
            ufinish = time.tv_usec;
            delta = (finish - start) * 1000000 + ufinish - ustart;
            printf("NeoScrypt SSE2 4-way: %.3f KH/s\n",
              (double)it * 1000 / (double)delta);
            return(0);

#ifdef NEOSCRYPT_SHA256
        case(10):
            if(!it) it = 5000;
            gettimeofday(&time, NULL);
            start  = time.tv_sec;
            ustart = time.tv_usec;
            for(i = 0; i < it; i += 4) {
                scrypt_4way(input, output,
                  (uchar *) &scratchbuf[(size_t)scratchbuf & (align - 1)]);
                pinput[0] = i;
            }
            gettimeofday(&time, NULL);
            finish  = time.tv_sec;
            ufinish = time.tv_usec;
            delta = (finish - start) * 1000000 + ufinish - ustart;
            printf("Scrypt SSE2 4-way: %.3f KH/s\n",
              (double)it * 1000 / (double)delta);
            return(0);
#endif
#endif

        default:
            break;

    }

    neoscrypt_blake2s(input, prf_input_len, input, prf_key_len,
      output, prf_output_len);

    uchar blake2s_ref[32] = {
        0x89, 0x75, 0xB0, 0x57, 0x7F, 0xD3, 0x55, 0x66,
        0xD7, 0x50, 0xB3, 0x62, 0xB0, 0x89, 0x7A, 0x26,
        0xC3, 0x99, 0x13, 0x6D, 0xF0, 0x7B, 0xAB, 0xAB,
        0xBD, 0xE6, 0x20, 0x3F, 0xF2, 0x95, 0x4E, 0xD4 };

    for(i = 0, status = 0; i < prf_output_len; i++) {
        if(output[i] != blake2s_ref[i]) {
            status = 1;
            ret_status = 1;
            break;
        }
    }

    printf("BLAKE2s integrity test %s", status ? fail_str : pass_str);


#ifdef NEOSCRYPT_OPT
    neoscrypt_fastkdf_opt(input, input, output, 0);
#else
    neoscrypt_fastkdf(input, kdf_input_len, input, kdf_input_len, 32,
      output, kdf_output_len);
#endif

    uchar fastkdf_ref[256] = {
        0xCC, 0xBC, 0x19, 0x71, 0xEC, 0x44, 0xE3, 0x17,
        0xB3, 0xC9, 0xDE, 0x16, 0x76, 0x02, 0x60, 0xB8,
        0xE2, 0xD4, 0x79, 0xB6, 0x88, 0xCA, 0xB5, 0x4A,
        0xCF, 0x6E, 0x0E, 0x9A, 0xAE, 0x48, 0x78, 0x12,
        0xA1, 0x95, 0x1E, 0xE1, 0xD1, 0x0A, 0xC2, 0x94,
        0x1F, 0x0A, 0x39, 0x73, 0xFE, 0xA4, 0xCD, 0x87,
        0x4B, 0x38, 0x54, 0x72, 0xB5, 0x53, 0xC3, 0xEA,
        0xC1, 0x26, 0x8D, 0xA7, 0xFF, 0x3F, 0xC1, 0x79,
        0xA6, 0xFF, 0x96, 0x54, 0x29, 0x05, 0xC0, 0x22,
        0x90, 0xDB, 0x53, 0x87, 0x2D, 0x29, 0x00, 0xA6,
        0x14, 0x16, 0x38, 0x63, 0xDA, 0xBC, 0x0E, 0x99,
        0x68, 0xB3, 0x98, 0x92, 0x42, 0xE3, 0xF6, 0xB4,
        0x19, 0xE3, 0xE3, 0xF6, 0x8E, 0x67, 0x47, 0x7B,
        0xB6, 0xFB, 0xEA, 0xCE, 0x6D, 0x0F, 0xAF, 0xF6,
        0x19, 0x43, 0x8D, 0xF7, 0x3E, 0xB5, 0xFB, 0xA3,
        0x64, 0x5E, 0xD2, 0x72, 0x80, 0x6B, 0x39, 0x93,
        0xB7, 0x80, 0x04, 0xCB, 0xF5, 0xC2, 0x61, 0xB1,
        0x90, 0x4E, 0x2B, 0x02, 0x57, 0x53, 0x77, 0x16,
        0x6A, 0x52, 0xBD, 0xD1, 0x62, 0xEC, 0xA1, 0xCB,
        0x89, 0x03, 0x29, 0xA2, 0x02, 0x5C, 0x9A, 0x62,
        0x99, 0x44, 0x54, 0xEA, 0x44, 0x91, 0x27, 0x3A,
        0x50, 0x82, 0x62, 0x03, 0x99, 0xB3, 0xFA, 0xF7,
        0xD4, 0x13, 0x47, 0x61, 0xFB, 0x0A, 0xE7, 0x81,
        0x61, 0x57, 0x58, 0x4C, 0x69, 0x4E, 0x67, 0x0A,
        0xC1, 0x21, 0xA7, 0xD2, 0xF6, 0x6D, 0x2F, 0x10,
        0x01, 0xFB, 0xA5, 0x47, 0x2C, 0xE5, 0x15, 0xD7,
        0x6A, 0xEF, 0xC9, 0xE2, 0xC2, 0x88, 0xA2, 0x3B,
        0x6C, 0x8D, 0xBB, 0x26, 0xE7, 0xC4, 0x15, 0xEC,
        0x5E, 0x5D, 0x74, 0x79, 0xBD, 0x81, 0x35, 0xA1,
        0x42, 0x27, 0xEB, 0x57, 0xCF, 0xF6, 0x2E, 0x51,
        0x90, 0xFD, 0xD9, 0xE4, 0x53, 0x6E, 0x12, 0xA1,
        0x99, 0x79, 0x4D, 0x29, 0x6F, 0x5B, 0x4D, 0x9A };

    for(i = 0, status = 0; i < kdf_output_len; i++) {
        if(output[i] != fastkdf_ref[i]) {
            status = 1;
            ret_status = 1;
            break;
        }
    }

    printf("FastKDF integrity test %s", status ? fail_str : pass_str);


    neoscrypt(input, output, 0x80000620);

    uchar neoscrypt_ref[32] = {
        0x72, 0x58, 0x96, 0x1A, 0xFB, 0x33, 0xFD, 0x12,
        0xD0, 0x0C, 0xAC, 0xB8, 0xD6, 0x3F, 0x4F, 0x4F,
        0x52, 0xBB, 0x69, 0x17, 0x04, 0x38, 0x65, 0xDD,
        0x24, 0xA0, 0x8F, 0x57, 0x88, 0x53, 0x12, 0x2D };

    for(i = 0, status = 0; i < neoscrypt_output_len; i++) {
        if(output[i] != neoscrypt_ref[i]) {
            status = 1;
            ret_status = 1;
            break;
        }
    }

#ifndef NEOSCRYPT_ASM
    printf("NeoScrypt integrity test %s", status ? fail_str : pass_str);
#else
    printf("NeoScrypt INT integrity test %s", status ? fail_str : pass_str);

    neoscrypt(input, output, 0x80001620);

    for(i = 0, status = 0; i < neoscrypt_output_len; i++) {
        if(output[i] != neoscrypt_ref[i]) {
            status = 1;
            ret_status = 1;
            break;
        }
    }

    printf("NeoScrypt SSE2 integrity test %s", status ? fail_str : pass_str);
#endif

#ifdef NEOSCRYPT_SHA256

    neoscrypt(input, output, 0x80000903);

    uchar scrypt_ref[32] = {
        0xBC, 0x54, 0x0A, 0x1A, 0x80, 0x1D, 0xF9, 0x6E,
        0x49, 0x30, 0x05, 0xC7, 0x1E, 0x01, 0x0E, 0x2D,
        0x38, 0x76, 0x07, 0xFB, 0xF0, 0xFE, 0xC4, 0x16,
        0xFD, 0x3C, 0x26, 0x45, 0xAA, 0x1B, 0xA9, 0xD2 };

    for(i = 0, status = 0; i < neoscrypt_output_len; i++) {
        if(output[i] != scrypt_ref[i]) {
            status = 1;
            ret_status = 1;
            break;
        }
    }

#ifndef NEOSCRYPT_ASM
    printf("Scrypt integrity test %s", status ? fail_str : pass_str);
#else
    printf("Scrypt INT integrity test %s", status ? fail_str : pass_str);

    neoscrypt(input, output, 0x80001903);

    for(i = 0, status = 0; i < neoscrypt_output_len; i++) {
        if(output[i] != scrypt_ref[i]) {
            status = 1;
            ret_status = 1;
            break;
        }
    }

    printf("Scrypt SSE2 integrity test %s", status ? fail_str : pass_str);
#endif

#endif /* NEOSCRYPT_SHA256 */

#if defined(NEOSCRYPT_ASM) && defined(NEOSCRYPT_MINER_4WAY)

    prf_input_4way[0] = 0x00;
    prf_key_4way[0] = 0x00;
    prf_input_4way[64] = 0x01;
    prf_key_4way[32] = 0x01;
    prf_input_4way[128] = 0x02;
    prf_key_4way[64] = 0x02;
    prf_input_4way[192] = 0x03;
    prf_key_4way[96] = 0x03;

    for(i = 1; i < 32; i++) {
        prf_input_4way[i] = (uchar)i;
        prf_key_4way[i] = (uchar)i;
        prf_input_4way[64 + i] = (uchar)i;
        prf_key_4way[32 + i] = (uchar)i;
        prf_input_4way[128 + i] = (uchar)i;
        prf_key_4way[64 + i] = (uchar)i;
        prf_input_4way[192 + i] = (uchar)i;
        prf_key_4way[96 + i] = (uchar)i;
    }

    for(i = 32; i < 64; i++) {
        prf_input_4way[i] = (uchar)i;
        prf_input_4way[64 + i] = (uchar)i;
        prf_input_4way[128 + i] = (uchar)i;
        prf_input_4way[192 + i] = (uchar)i;
    }

    neoscrypt_blake2s_4way(prf_input_4way, prf_key_4way, output);

    for(i = 0, status = 0; i < 32; i++) {
        if(output[i] != blake2s_ref[i]) {
            status = 1;
            ret_status = 1;
            break;
        }
    }

    printf("BLAKE2s SSE2 4-way part A integrity test %s",
      status ? fail_str : pass_str);

    uchar blake2s_ref_B[32] = {
        0xCB, 0x5D, 0xF2, 0x7A, 0x5A, 0x71, 0xE3, 0x65,
        0xAD, 0x5B, 0x01, 0xCE, 0x09, 0x7C, 0xCB, 0x48,
        0xD9, 0xB0, 0xFC, 0x5D, 0x6F, 0xF9, 0x16, 0xB1,
        0x29, 0xD3, 0x6A, 0xEF, 0x42, 0x11, 0x56, 0x61 };

    for(i = 0, status = 0; i < 32; i++) {
        if(output[32 + i] != blake2s_ref_B[i]) {
            status = 1;
            ret_status = 1;
            break;
        }
    }

    printf("BLAKE2s SSE2 4-way part B integrity test %s",
      status ? fail_str : pass_str);

    uchar blake2s_ref_C[32] = {
        0xD5, 0x18, 0xCE, 0x18, 0x81, 0xA6, 0x98, 0x17,
        0x63, 0xB2, 0xAC, 0xD1, 0x5B, 0x2A, 0x6D, 0x84,
        0xD4, 0x16, 0x02, 0x08, 0xCF, 0x87, 0xB1, 0x5D,
        0x49, 0x58, 0xF0, 0x41, 0x60, 0x5C, 0x8C, 0xC6 };

    for(i = 0, status = 0; i < 32; i++) {
        if(output[64 + i] != blake2s_ref_C[i]) {
            status = 1;
            ret_status = 1;
            break;
        }
    }

    printf("BLAKE2s SSE2 4-way part C integrity test %s",
      status ? fail_str : pass_str);

    uchar blake2s_ref_D[32] = {
        0x00, 0x57, 0xB5, 0x8F, 0x9A, 0xEF, 0xC7, 0x72,
        0xFA, 0x66, 0xA0, 0x6A, 0xA1, 0xC5, 0x8A, 0x67,
        0x33, 0xF2, 0xC9, 0x2E, 0xC1, 0x60, 0x30, 0x9B,
        0x98, 0x1D, 0x0B, 0x9B, 0xB8, 0x92, 0x00, 0xF1 };

    for(i = 0, status = 0; i < 32; i++) {
        if(output[96 + i] != blake2s_ref_D[i]) {
            status = 1;
            ret_status = 1;
            break;
        }
    }

    printf("BLAKE2s SSE2 4-way part D integrity test %s",
      status ? fail_str : pass_str);


    kdf_input_4way[0] = 0x00;
    kdf_key_4way[0] = 0x00;
    kdf_input_4way[80] = 0x01;
    kdf_key_4way[80] = 0x01;
    kdf_input_4way[160] = 0x02;
    kdf_key_4way[160] = 0x02;
    kdf_input_4way[240] = 0x03;
    kdf_key_4way[240] = 0x03;

    for(i = 1; i < 80; i++) {
        kdf_input_4way[i] = (uchar)i;
        kdf_key_4way[i] = (uchar)i;
        kdf_input_4way[80 + i] = (uchar)i;
        kdf_key_4way[80 + i] = (uchar)i;
        kdf_input_4way[160 + i] = (uchar)i;
        kdf_key_4way[160 + i] = (uchar)i;
        kdf_input_4way[240 + i] = (uchar)i;
        kdf_key_4way[240 + i] = (uchar)i;
    }

    neoscrypt_fastkdf_4way(&kdf_input_4way[0], &kdf_key_4way[0], &kdf_output_4way[0],
      (uchar *) &scratchbuf[(size_t)scratchbuf & (align - 1)], 0);

    for(i = 0, status = 0; i < 256; i++) {
        if(kdf_output_4way[i] != fastkdf_ref[i]) {
            status = 1;
            ret_status = 1;
            break;
        }
    }

    printf("FastKDF SSE2 4-way part A integrity test %s",
      status ? fail_str : pass_str);

    uchar fastkdf_ref_B[256] = {
        0x0D, 0xAF, 0x88, 0xEE, 0xF7, 0xC2, 0x3B, 0xF5,
        0x95, 0x16, 0xA8, 0x91, 0x18, 0x39, 0x42, 0xB7,
        0xFF, 0x8C, 0xD8, 0xB3, 0x90, 0xAE, 0xE1, 0xDF,
        0x0C, 0x22, 0xD2, 0x3E, 0x38, 0xE7, 0x1C, 0xA8,
        0xA2, 0x5F, 0x45, 0x57, 0x3E, 0x64, 0x42, 0x35,
        0xB9, 0x96, 0x37, 0xA9, 0x8F, 0x56, 0xDD, 0x54,
        0x01, 0x1B, 0xDE, 0xA0, 0x98, 0x67, 0x73, 0x41,
        0xE2, 0x5C, 0xD9, 0xC0, 0x71, 0xF2, 0xE7, 0xE1,
        0x13, 0xA8, 0x59, 0x2F, 0x21, 0xFA, 0x0A, 0x0B,
        0xF9, 0x2B, 0x32, 0x76, 0x1E, 0x58, 0x31, 0xEA,
        0x10, 0x6C, 0x35, 0xAC, 0xB5, 0x77, 0x12, 0xAD,
        0x1C, 0x7E, 0x73, 0x28, 0x26, 0x59, 0x5C, 0x2F,
        0x8A, 0xFE, 0x69, 0x5E, 0x48, 0xE6, 0xAE, 0x50,
        0xD7, 0x40, 0x08, 0xC7, 0xDF, 0x60, 0x6A, 0x45,
        0x98, 0x2C, 0x99, 0x34, 0xBF, 0x24, 0xD3, 0x17,
        0xFA, 0x32, 0xF9, 0xDF, 0x51, 0x91, 0x63, 0xED,
        0x11, 0x05, 0x1A, 0x0D, 0x1F, 0xC0, 0x38, 0xAC,
        0x80, 0xE0, 0xED, 0xFF, 0xB4, 0x14, 0xC3, 0x31,
        0x31, 0x42, 0x0A, 0x76, 0x56, 0x3B, 0x15, 0x54,
        0xB6, 0x71, 0x59, 0x4F, 0x6B, 0xEB, 0x46, 0x73,
        0x05, 0x68, 0xC9, 0xC4, 0x90, 0x1C, 0x7F, 0x28,
        0x4F, 0x55, 0xCD, 0x3C, 0x0B, 0x5F, 0x89, 0x82,
        0x8B, 0x8C, 0x22, 0x31, 0x3A, 0xA9, 0xF1, 0x1F,
        0x21, 0x55, 0xDE, 0x9D, 0x1E, 0x13, 0xA0, 0x67,
        0x88, 0x14, 0x53, 0x40, 0xEE, 0xDC, 0xEF, 0xFF,
        0xB7, 0x17, 0xD2, 0x87, 0xB3, 0xB3, 0x4C, 0xEE,
        0xA8, 0x2E, 0x9D, 0x49, 0x39, 0x44, 0x1B, 0xF2,
        0xA2, 0x75, 0x57, 0xFF, 0xD2, 0x5F, 0xCB, 0xF1,
        0x1C, 0x0E, 0xAE, 0xA1, 0x6B, 0x1D, 0x89, 0x1B,
        0x8E, 0x79, 0x35, 0xFF, 0xD7, 0xE2, 0x58, 0xE6,
        0xF1, 0xA2, 0xE9, 0xF4, 0xD6, 0xCE, 0xA0, 0x92,
        0x2E, 0x92, 0xFF, 0xF6, 0x9D, 0xB0, 0xF9, 0x9E };

    for(i = 0, status = 0; i < 256; i++) {
        if(kdf_output_4way[256 + i] != fastkdf_ref_B[i]) {
            status = 1;
            ret_status = 1;
            break;
        }
    }

    printf("FastKDF SSE2 4-way part B integrity test %s",
      status ? fail_str : pass_str);

    uchar fastkdf_ref_C[256] = {
        0x84, 0xE5, 0xF3, 0x5A, 0x19, 0xB5, 0x4B, 0x67,
        0x0F, 0x4D, 0xBE, 0x0C, 0x14, 0x2E, 0x76, 0xEC,
        0x7E, 0xC3, 0xDA, 0x98, 0xBC, 0x93, 0xBD, 0x71,
        0x7D, 0x33, 0x17, 0xE2, 0x92, 0x4C, 0xF9, 0x09,
        0x35, 0x56, 0xC0, 0x4D, 0x26, 0xBC, 0xC3, 0x6C,
        0x31, 0x49, 0x53, 0x92, 0x09, 0x22, 0xE8, 0xD2,
        0x0C, 0xD0, 0x11, 0x12, 0xCC, 0x79, 0x72, 0xA2,
        0x55, 0x5E, 0x03, 0x47, 0x5D, 0x4C, 0xAD, 0x1D,
        0x09, 0x38, 0xB8, 0x5F, 0x2C, 0xED, 0x27, 0x3E,
        0x49, 0x8F, 0x78, 0xB9, 0x5C, 0xC6, 0x91, 0x54,
        0x91, 0x23, 0xCE, 0xA2, 0x3E, 0x7D, 0x99, 0x35,
        0xF6, 0xBE, 0xDF, 0xA7, 0x07, 0x83, 0x03, 0xEE,
        0xE1, 0x32, 0x8A, 0x7D, 0x51, 0xD8, 0x6B, 0x3B,
        0xFC, 0xCD, 0xC4, 0x1A, 0x34, 0xCA, 0x06, 0x41,
        0x54, 0x3E, 0x9D, 0xC6, 0x6F, 0x5F, 0x5C, 0xFC,
        0x37, 0xA2, 0x5F, 0x41, 0x7A, 0x8F, 0xA9, 0xC9,
        0xBF, 0x35, 0x42, 0x04, 0xAC, 0x8B, 0xC3, 0x0F,
        0x27, 0x4E, 0x5C, 0x7D, 0x15, 0x21, 0x1F, 0x7D,
        0xC7, 0xF8, 0x7F, 0x34, 0xF3, 0xA4, 0xF0, 0x4D,
        0xF5, 0xF2, 0xC4, 0x71, 0x88, 0xAD, 0xEA, 0x76,
        0x5B, 0x20, 0xB5, 0x7A, 0xE1, 0xEE, 0xD6, 0x85,
        0xA0, 0xFC, 0x9C, 0x0D, 0xE9, 0xA0, 0x88, 0x84,
        0xFC, 0x4A, 0xA3, 0x85, 0xE1, 0x05, 0x69, 0xA6,
        0xE0, 0x2E, 0x04, 0x9B, 0x12, 0x58, 0x14, 0xC8,
        0x2A, 0x10, 0x21, 0xC3, 0xCB, 0xCB, 0xF5, 0x9A,
        0x70, 0x79, 0x66, 0x72, 0x46, 0x31, 0xE4, 0x0C,
        0xC8, 0x58, 0x29, 0x00, 0x5E, 0xED, 0x35, 0x37,
        0x33, 0xB7, 0x6C, 0xD7, 0x5A, 0xA3, 0x4F, 0x31,
        0x88, 0xF1, 0xD1, 0x31, 0xFF, 0x81, 0x74, 0x87,
        0x2F, 0x38, 0x27, 0xCF, 0x64, 0xF6, 0xD0, 0x51,
        0xBC, 0xCA, 0x06, 0x60, 0xD9, 0x2C, 0x18, 0xD5,
        0x47, 0x6D, 0xBF, 0xCA, 0x82, 0x5A, 0x3D, 0xB9 };

    for(i = 0, status = 0; i < 256; i++) {
        if(kdf_output_4way[512 + i] != fastkdf_ref_C[i]) {
            status = 1;
            ret_status = 1;
            break;
        }
    }

    printf("FastKDF SSE2 4-way part C integrity test %s",
      status ? fail_str : pass_str);

    uchar fastkdf_ref_D[256] = {
        0x7A, 0x83, 0x7A, 0xFE, 0x6D, 0x52, 0xE1, 0xD0,
        0xCB, 0xE6, 0x93, 0x27, 0xFD, 0x76, 0x44, 0xF3,
        0xD8, 0x1C, 0x92, 0x12, 0x39, 0x3E, 0x8D, 0x92,
        0x92, 0x6B, 0x93, 0x74, 0xDC, 0x40, 0x5A, 0xDC,
        0xCA, 0xA8, 0xA1, 0xA5, 0xA2, 0x5B, 0x20, 0x8F,
        0x0D, 0x20, 0x52, 0xD8, 0x1B, 0xB6, 0xE4, 0x03,
        0xF0, 0x89, 0xC9, 0x78, 0x9B, 0x66, 0x98, 0x22,
        0xC5, 0xB7, 0x78, 0x65, 0x53, 0x0C, 0x82, 0x06,
        0xE1, 0x75, 0x64, 0xE9, 0xB5, 0x09, 0x34, 0xC7,
        0xDF, 0x48, 0xD8, 0x03, 0x28, 0x1E, 0xA0, 0x77,
        0x98, 0x6C, 0x12, 0xC2, 0xB5, 0xA3, 0x59, 0xA6,
        0x3D, 0x9D, 0x01, 0x05, 0x1D, 0xDA, 0x2F, 0x30,
        0xCF, 0x28, 0xC1, 0x7C, 0xE9, 0x06, 0x49, 0xEF,
        0x36, 0xEA, 0xD5, 0x0D, 0x19, 0x2E, 0x7D, 0x92,
        0x81, 0xCE, 0xB2, 0x30, 0xD8, 0x36, 0x71, 0x04,
        0x71, 0x26, 0x84, 0x56, 0xEC, 0xD4, 0x6B, 0x16,
        0x51, 0x00, 0xCB, 0x5A, 0x56, 0x53, 0x99, 0x51,
        0x57, 0x0E, 0xCC, 0x91, 0x38, 0x9B, 0xA3, 0xF3,
        0xF6, 0xE8, 0xCC, 0xE7, 0xA2, 0xB9, 0x2B, 0xFC,
        0x8E, 0x5A, 0x2C, 0x77, 0x95, 0x75, 0x3C, 0xD2,
        0xB6, 0x20, 0xB5, 0x5C, 0xD5, 0xC9, 0xD0, 0x29,
        0x34, 0x7E, 0x97, 0x6A, 0xF1, 0xA7, 0xC3, 0x26,
        0x29, 0xA2, 0xE3, 0xA1, 0xF5, 0x6D, 0xEB, 0x0F,
        0x44, 0xC0, 0x49, 0x13, 0xDC, 0x1E, 0xE7, 0x8E,
        0x72, 0x05, 0xE0, 0x72, 0x89, 0x85, 0x9F, 0xA2,
        0x96, 0x73, 0xFA, 0xC6, 0x44, 0x13, 0x56, 0xB6,
        0xB6, 0x76, 0xC3, 0xA9, 0x22, 0xF6, 0x78, 0x4F,
        0xDA, 0x53, 0xEB, 0xF6, 0xC4, 0xD2, 0x19, 0xF1,
        0x91, 0x8A, 0xB6, 0x37, 0xDC, 0x56, 0x40, 0x60,
        0x46, 0xE9, 0x89, 0xBA, 0x4E, 0xFA, 0xD8, 0x41,
        0xC3, 0xE3, 0x53, 0xD9, 0xA1, 0x2C, 0x23, 0x53,
        0xAF, 0x7E, 0x74, 0x1B, 0x7B, 0x44, 0x46, 0xA2 };

    for(i = 0, status = 0; i < 256; i++) {
        if(kdf_output_4way[768 + i] != fastkdf_ref_D[i]) {
            status = 1;
            ret_status = 1;
            break;
        }
    }

    printf("FastKDF SSE2 4-way part D integrity test %s",
      status ? fail_str : pass_str);



    neoscrypt_4way(input, output, (uchar *) &scratchbuf[(size_t)scratchbuf & (align - 1)]);

    for(i = 0, status = 0; i < neoscrypt_output_len; i++) {
        if(output[i] != neoscrypt_ref[i]) {
            status = 1;
            ret_status = 1;
            break;
        }
    }

    printf("NeoScrypt SSE2 4-way part A integrity test %s",
      status ? fail_str : pass_str);

    uchar neoscrypt_ref_B[32] = {
        0x2B, 0x41, 0xC5, 0xD9, 0xB9, 0x08, 0x5D, 0x77,
        0x25, 0xEA, 0x64, 0xC9, 0xD2, 0x3E, 0xAE, 0x7D,
        0x8A, 0xC9, 0xA0, 0xAA, 0x6F, 0xED, 0x93, 0xDC,
        0x85, 0xD7, 0x84, 0xB9, 0xA5, 0x05, 0x7E, 0x34 };

    for(i = 0, status = 0; i < neoscrypt_output_len; i++) {
        if(output[32 + i] != neoscrypt_ref_B[i]) {
            status = 1;
            ret_status = 1;
            break;
        }
    }

    printf("NeoScrypt SSE2 4-way part B integrity test %s",
      status ? fail_str : pass_str);

    uchar neoscrypt_ref_C[32] = {
        0x41, 0x69, 0xB7, 0x7B, 0xD5, 0xD6, 0xAD, 0x6D,
        0x4D, 0xA9, 0xE8, 0x51, 0x9A, 0x36, 0x34, 0xB5,
        0x11, 0xC3, 0x64, 0xFA, 0x3D, 0x60, 0xCD, 0x17,
        0xD9, 0x73, 0xBF, 0xFC, 0x20, 0xD5, 0x53, 0x20 };

    for(i = 0, status = 0; i < neoscrypt_output_len; i++) {
        if(output[64 + i] != neoscrypt_ref_C[i]) {
            status = 1;
            ret_status = 1;
            break;
        }
    }

    printf("NeoScrypt SSE2 4-way part C integrity test %s",
      status ? fail_str : pass_str);

    uchar neoscrypt_ref_D[32] = {
        0xF8, 0x7F, 0x7A, 0xB6, 0xF6, 0x63, 0xF9, 0x82,
        0x38, 0x87, 0xCD, 0x00, 0x03, 0xC7, 0x50, 0x80,
        0x62, 0x10, 0x63, 0xC3, 0x1C, 0x59, 0xD0, 0xF4,
        0x60, 0x71, 0x55, 0x20, 0x24, 0x52, 0xDC, 0x2B };

    for(i = 0, status = 0; i < neoscrypt_output_len; i++) {
        if(output[96 + i] != neoscrypt_ref_D[i]) {
            status = 1;
            ret_status = 1;
            break;
        }
    }

    printf("NeoScrypt SSE2 4-way part D integrity test %s",
      status ? fail_str : pass_str);

#ifdef NEOSCRYPT_SHA256

    scrypt_4way(input, output, (uchar *) &scratchbuf[(size_t)scratchbuf & (align - 1)]);

    for(i = 0, status = 0; i < neoscrypt_output_len; i++) {
        if(output[i] != scrypt_ref[i]) {
            status = 1;
            ret_status = 1;
            break;
        }
    }

    printf("Scrypt SSE2 4-way part A integrity test %s",
      status ? fail_str : pass_str);

    uchar scrypt_ref_B[32] = {
        0xA5, 0x98, 0x8C, 0x92, 0x82, 0x21, 0x83, 0x54,
        0xB3, 0x01, 0x56, 0xA7, 0x0C, 0xFA, 0x48, 0xBA,
        0x1F, 0x7E, 0x33, 0x02, 0xE1, 0x5C, 0x95, 0x6A,
        0xF4, 0x34, 0x44, 0xC3, 0xF5, 0xA2, 0xEB, 0xCD };

    for(i = 0, status = 0; i < neoscrypt_output_len; i++) {
        if(output[32 + i] != scrypt_ref_B[i]) {
            status = 1;
            ret_status = 1;
            break;
        }
    }

    printf("Scrypt SSE2 4-way part B integrity test %s",
      status ? fail_str : pass_str);

    uchar scrypt_ref_C[32] = {
        0xFD, 0x07, 0x1B, 0xB5, 0x48, 0x64, 0xEB, 0x5B,
        0x54, 0x33, 0xF8, 0xD9, 0x37, 0x52, 0xDB, 0x09,
        0xA2, 0xE6, 0x8B, 0xCE, 0x3F, 0xF6, 0x08, 0x9B,
        0xC9, 0xF7, 0x08, 0x0C, 0x6D, 0xC6, 0x78, 0x75 };

    for(i = 0, status = 0; i < neoscrypt_output_len; i++) {
        if(output[64 + i] != scrypt_ref_C[i]) {
            status = 1;
            ret_status = 1;
            break;
        }
    }

    printf("Scrypt SSE2 4-way part C integrity test %s",
      status ? fail_str : pass_str);

    uchar scrypt_ref_D[32] = {
        0x19, 0x3C, 0x12, 0xDE, 0x78, 0x96, 0xB2, 0xE2,
        0x7E, 0xDC, 0xD5, 0xF1, 0xDC, 0xEC, 0x6F, 0xAE,
        0x16, 0x63, 0xA0, 0x96, 0x2F, 0xF4, 0x5F, 0x73,
        0xB0, 0x13, 0x1E, 0xD4, 0x2B, 0x5E, 0xAB, 0x79 };

    for(i = 0, status = 0; i < neoscrypt_output_len; i++) {
        if(output[96 + i] != scrypt_ref_D[i]) {
            status = 1;
            ret_status = 1;
            break;
        }
    }

    printf("Scrypt SSE2 4-way part D integrity test %s",
      status ? fail_str : pass_str);

#endif /* NEOSCRYPT_SHA256 */

    free(scratchbuf);

#endif /* (NEOSCRYPT_ASM) && (NEOSCRYPT_MINER_4WAY) */

    return(ret_status);
}
