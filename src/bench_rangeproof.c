/**********************************************************************
 * Copyright (c) 2014, 2015 Pieter Wuille, Gregory Maxwell            *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "../include/secp256k1_rangeproof.h"
#include "util.h"
#include "bench.h"

typedef struct {
    secp256k1_context* ctx;
    secp256k1_pedersen_commitment commit;
    unsigned char proof[5134];
    unsigned char blind[32];
    unsigned char nonce[32];
    size_t len;
    int min_bits;
    uint64_t v;
} bench_rangeproof_t;

static void bench_rangeproof_setup(void* arg) {
    int i;
    uint64_t minv;
    uint64_t maxv;
    bench_rangeproof_t *data = (bench_rangeproof_t*)arg;

    data->v = 0;
    for (i = 0; i < 32; i++) {
        data->blind[i] = i + 1;
        data->nonce[i] = (i + 42) & 0xff;
    }
    CHECK(secp256k1_pedersen_commit(data->ctx, &data->commit, data->blind, data->v, secp256k1_generator_h));
    data->len = 5134;
    CHECK(secp256k1_rangeproof_sign(data->ctx, data->proof, &data->len, 0, &data->commit, data->blind, data->nonce, 0, data->min_bits, data->v, NULL, 0, NULL, 0, secp256k1_generator_h));
    CHECK(secp256k1_rangeproof_verify(data->ctx, &minv, &maxv, &data->commit, data->proof, data->len, NULL, 0, secp256k1_generator_h));
}

static void bench_rangeproof(void* arg, int iters) {
    int i;
    bench_rangeproof_t *data = (bench_rangeproof_t*)arg;

    for (i = 0; i < iters/data->min_bits; i++) {
        int j;
        uint64_t minv;
        uint64_t maxv;
        j = secp256k1_rangeproof_verify(data->ctx, &minv, &maxv, &data->commit, data->proof, data->len, NULL, 0, secp256k1_generator_h);
        for (j = 0; j < 4; j++) {
            data->proof[j + 2 + 32 *((data->min_bits + 1) >> 1) - 4] = (i >> 8)&255;
        }
    }
}

static void bench_rangeproof_rewind(void* arg, int iters) {
    int i;
    int ret;
    bench_rangeproof_t *data = (bench_rangeproof_t*)arg;
    unsigned char blind_out[32];
    uint64_t value_out;
    unsigned char message_out[4096];
    size_t message_len;
    uint64_t minv;
    uint64_t maxv;

    for (i = 0; i < iters/data->min_bits; i++) {
        message_len = sizeof(message_out);
        ret = secp256k1_rangeproof_rewind(
            data->ctx,
            blind_out,
            &value_out,
            message_out,
            &message_len,
            data->nonce,
            &minv,
            &maxv,
            &data->commit,
            data->proof,
            data->len,
            NULL,
            0,
            secp256k1_generator_h
        );
        CHECK(ret == 1);
    }
}

static void bench_rangeproof_extract(void* arg, int iters) {
    int i;
    int ret;
    bench_rangeproof_t *data = (bench_rangeproof_t*)arg;
    unsigned char blind_out[32];
    uint64_t value_out;
    uint64_t minv;
    uint64_t maxv;

    for (i = 0; i < iters/data->min_bits; i++) {
        ret = secp256k1_rangeproof_extract(
            data->ctx,
            blind_out,
            &value_out,
            &minv,
            &maxv,
            &data->commit,
            data->proof,
            data->len,
            data->nonce,
            NULL,
            0,
            secp256k1_generator_h
        );
        CHECK(ret == 1);
    }
}

int main(void) {
    bench_rangeproof_t data;
    int iters;

    data.ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);

    data.min_bits = 32;
    iters = data.min_bits*get_iters(32);

    run_benchmark("rangeproof_verify_bit", bench_rangeproof, bench_rangeproof_setup, NULL, &data, 10, iters);

    printf("\nComparison: rangeproof_rewind vs rangeproof_extract (extracting value and blinding)\n");
    run_benchmark("rangeproof_rewind_bit", bench_rangeproof_rewind, bench_rangeproof_setup, NULL, &data, 10, iters);
    run_benchmark("rangeproof_extract_bit", bench_rangeproof_extract, bench_rangeproof_setup, NULL, &data, 10, iters);

    secp256k1_context_destroy(data.ctx);
    return EXIT_SUCCESS;
}
