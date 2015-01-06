/*
 * Copyright (c) 2014-2015 John Doering <ghostlander@phoenixcoin.org>
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


#if (OPT)
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
 *    7  NeoScrypt SSE2-4way;
 *    8  Scrypt SSE2-4way;
 * -i [number] is an iteration count for a benchmark specified above */
int main(int argc, char *argv[]) {
    uint prf_input_len = 64, prf_key_len = 32, prf_output_len = 32;
    uint kdf_input_len = 80, kdf_output_len = 256;
    uint neoscrypt_output_len = 32;
    uchar input[kdf_input_len], output[kdf_output_len];
    uint ret_status = 0, status, i;
    const char *fail_str = "failed!\n", *pass_str = "passed.\n";

    /* For benchmarks */
    int opt, arg;
    uint id = 0, it = 0;
    struct timeval time;
    ulong delta, start, ustart, finish, ufinish;
    uint *pinput = (uint *) &input[0];

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
#if (OPT)
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
#if !(ASM)
            printf("NeoScrypt: %.3f KH/s\n",
#else
            printf("NeoScrypt INT: %.3f KH/s\n",
#endif
              (double)it * 1000 / (double)delta);
            return(0);

#if (SHA256)
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
#if !(ASM)
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
#if !(ASM)
            printf("NeoScrypt: %.3f KH/s\n",
#else
            printf("NeoScrypt SSE2: %.3f KH/s\n",
#endif
              (double)it * 1000 / (double)delta);
            return(0);

#if (SHA256)
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
#if !(ASM)
            printf("Scrypt: %.3f KH/s\n",
#else
            printf("Scrypt SSE2: %.3f KH/s\n",
#endif
              (double)it * 1000 / (double)delta);
            return(0);
#endif

#if (ASM) && (MINER_4WAY)
        case(7):
            if(!it) it = 5000;
            gettimeofday(&time, NULL);
            start  = time.tv_sec;
            ustart = time.tv_usec;
            for(i = 0; i < it; i += 4) {
                neoscrypt_4way(input, output, 0x0);
                pinput[0] = i;
            }
            gettimeofday(&time, NULL);
            finish  = time.tv_sec;
            ufinish = time.tv_usec;
            delta = (finish - start) * 1000000 + ufinish - ustart;
            printf("NeoScrypt SSE2 4-way: %.3f KH/s\n",
              (double)it * 1000 / (double)delta);
            return(0);

#if (SHA256)
        case(8):
            if(!it) it = 5000;
            gettimeofday(&time, NULL);
            start  = time.tv_sec;
            ustart = time.tv_usec;
            for(i = 0; i < it; i += 4) {
                neoscrypt_4way(input, output, 0x1);
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

#if (OPT)
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

#if !(ASM)
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

#if (SHA256)

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

#if !(ASM)
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

#endif /* (SHA256) */

#if (ASM) && (MINER_4WAY)

    neoscrypt_4way(input, output, 0x0);

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

#if (SHA256)

    neoscrypt_4way(input, output, 0x1);

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

#endif /* (SHA256) */

#endif /* (ASM) && (MINER_4WAY) */

    return(ret_status);
}
