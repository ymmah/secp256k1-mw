/**********************************************************************
 * Copyright (c) 2017 Andrew Poelstra                                 *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#include <stdint.h>

#include "include/secp256k1_generator.h"
#include "include/secp256k1_bulletproof.h"
#include "include/secp256k1_rangeproof.h"
#include "util.h"
#include "bench.h"

#define MAX_PROOF_SIZE	2000
#define CIRCUIT_DIR "src/modules/bulletproof/bin_circuits/"

typedef struct {
    secp256k1_context *ctx;
    secp256k1_scratch_space *scratch;
    unsigned char nonce[32];
    unsigned char **proof;
    secp256k1_bulletproof_generators *generators;
    size_t n_proofs;
    size_t plen;
    size_t iters;
} bench_bulletproof_t;

typedef struct {
    bench_bulletproof_t *common;
    secp256k1_pedersen_commitment **commit;
    const unsigned char **blind;
    size_t *value;
    size_t n_commits;
    size_t nbits;
    secp256k1_generator altgen;
} bench_bulletproof_rangeproof_t;

typedef struct {
    bench_bulletproof_t *common;

    secp256k1_bulletproof_circuit **circ;
    secp256k1_bulletproof_circuit_assignment *assn;
} bench_bulletproof_circuit_t;

static void bench_bulletproof_common_setup(bench_bulletproof_t *data) {
    size_t i;
    const unsigned char nonce[32] = "my kingdom for some randomness!!";

    memcpy(data->nonce, nonce, 32);
    data->proof = (unsigned char **)malloc(data->n_proofs * sizeof(*data->proof));
    for (i = 0; i < data->n_proofs; i++) {
        data->proof[i] = (unsigned char *)malloc(MAX_PROOF_SIZE);
    }
    data->plen = MAX_PROOF_SIZE;
}

static void bench_bulletproof_rangeproof_setup(void* arg) {
    bench_bulletproof_rangeproof_t *data = (bench_bulletproof_rangeproof_t*)arg;
    size_t i;

    const unsigned char genbd[32] = "yet more blinding, for the asset";
    unsigned char blind[32] = "and my kingdom too for a blinder";

    bench_bulletproof_common_setup (data->common);

    data->commit = (secp256k1_pedersen_commitment **)malloc(data->common->n_proofs * sizeof(*data->commit));
    data->blind = (const unsigned char **)malloc(data->n_commits * sizeof(*data->blind));
    data->value = (size_t *)malloc(data->n_commits * sizeof(*data->commit));

    for (i = 0; i < data->common->n_proofs; i++) {
        data->commit[i] = (secp256k1_pedersen_commitment *)malloc(data->n_commits * sizeof(*data->commit[i]));
    }

    CHECK(secp256k1_generator_generate(data->common->ctx, &data->altgen, genbd));
    for (i = 0; i < data->n_commits; i++) {
        data->blind[i] = malloc(32);
        blind[0] = i;
        blind[1] = i >> 8;
        memcpy((unsigned char*) data->blind[i], blind, 32);
        data->value[i] = i * 17;
        CHECK(secp256k1_pedersen_commit(data->common->ctx, &data->commit[0][i], data->blind[i], data->value[i], &data->altgen));
    }
    for (i = 1; i < data->common->n_proofs; i++) {
        memcpy(data->commit[i], data->commit[0], data->n_commits * sizeof(*data->commit[0]));
    }

    CHECK(secp256k1_bulletproof_rangeproof_prove(data->common->ctx, data->common->scratch, data->common->generators, data->common->proof[0], &data->common->plen, data->value, data->blind, data->n_commits, &data->altgen, data->nbits, data->common->nonce, NULL, 0) == 1);
    for (i = 1; i < data->common->n_proofs; i++) {
        memcpy(data->common->proof[i], data->common->proof[0], data->common->plen);
        CHECK(secp256k1_bulletproof_rangeproof_verify(data->common->ctx, data->common->scratch, data->common->generators, data->common->proof[i], data->common->plen, data->commit[i], data->n_commits, data->nbits, &data->altgen, NULL, 0) == 1);
    }
    CHECK(secp256k1_bulletproof_rangeproof_verify(data->common->ctx, data->common->scratch, data->common->generators, data->common->proof[0], data->common->plen, data->commit[0], data->n_commits, data->nbits, &data->altgen, NULL, 0) == 1);
    CHECK(secp256k1_bulletproof_rangeproof_verify_multi(data->common->ctx, data->common->scratch, data->common->generators, (const unsigned char **) data->common->proof, data->common->n_proofs, data->common->plen, (const secp256k1_pedersen_commitment **) data->commit, data->n_commits, data->nbits, &data->altgen, NULL, 0) == 1);
}

static void bench_bulletproof_circuit_setup(void* arg) {
    bench_bulletproof_circuit_t *data = (bench_bulletproof_circuit_t *) arg;
    size_t i;

    bench_bulletproof_common_setup (data->common);

    CHECK(secp256k1_bulletproof_circuit_prove(data->common->ctx, data->common->scratch, data->common->generators, data->circ[0], data->common->proof[0], &data->common->plen, data->assn, data->common->nonce, NULL, 0) == 1);
    for (i = 1; i < data->common->n_proofs; i++) {
        data->circ[i] = data->circ[0];
        memcpy(data->common->proof[i], data->common->proof[0], data->common->plen);
    }
    CHECK(secp256k1_bulletproof_circuit_verify(data->common->ctx, data->common->scratch, data->common->generators, data->circ[0], data->common->proof[0], data->common->plen, NULL, 0) == 1);
    CHECK(secp256k1_bulletproof_circuit_verify_multi(data->common->ctx, data->common->scratch, data->common->generators, (const secp256k1_bulletproof_circuit* const*) data->circ, (const unsigned char **) data->common->proof, data->common->n_proofs, data->common->plen) == 1);
}

static void bench_bulletproof_common_teardown(bench_bulletproof_t *data) {
    size_t i;

    for (i = 0; i < data->n_proofs; i++) {
        free(data->proof[i]);
    }
    free(data->proof);
}

static void bench_bulletproof_rangeproof_teardown(void* arg) {
    bench_bulletproof_rangeproof_t *data = (bench_bulletproof_rangeproof_t*)arg;
    size_t i;

    if (data->blind != NULL) {
        for (i = 0; i < data->n_commits; i++) {
            free((unsigned char*) data->blind[i]);
        }
    }
    if (data->commit != NULL) {
        for (i = 0; i < data->common->n_proofs; i++) {
            free(data->commit[i]);
        }
        free(data->commit);
    }
    free(data->blind);
    free(data->value);

    bench_bulletproof_common_teardown(data->common);
}

static void bench_bulletproof_circuit_teardown(void* arg) {
    bench_bulletproof_circuit_t *data = (bench_bulletproof_circuit_t *) arg;
    bench_bulletproof_common_teardown(data->common);
}

static void bench_bulletproof_rangeproof_prove(void* arg) {
    bench_bulletproof_rangeproof_t *data = (bench_bulletproof_rangeproof_t*)arg;
    size_t i;
    for (i = 0; i < 25; i++) {
        CHECK(secp256k1_bulletproof_rangeproof_prove(data->common->ctx, data->common->scratch, data->common->generators, data->common->proof[0], &data->common->plen, data->value, data->blind, data->n_commits, &data->altgen, data->nbits, data->common->nonce, NULL, 0) == 1);
    }
}

static void bench_bulletproof_rangeproof_verify(void* arg) {
    size_t i;
    bench_bulletproof_rangeproof_t *data = (bench_bulletproof_rangeproof_t*)arg;

    for (i = 0; i < data->common->iters; i++) {
        CHECK(secp256k1_bulletproof_rangeproof_verify_multi(data->common->ctx, data->common->scratch, data->common->generators, (const unsigned char **) data->common->proof, data->common->n_proofs, data->common->plen, (const secp256k1_pedersen_commitment **) data->commit, data->n_commits, data->nbits, &data->altgen, NULL, 0) == 1);
    }
}

static void bench_bulletproof_circuit_prove(void* arg) {
    bench_bulletproof_circuit_t *data = (bench_bulletproof_circuit_t *) arg;
    CHECK(secp256k1_bulletproof_circuit_prove(data->common->ctx, data->common->scratch, data->common->generators, data->circ[0], data->common->proof[0], &data->common->plen, data->assn, data->common->nonce, NULL, 0) == 1);
    CHECK(secp256k1_bulletproof_circuit_prove(data->common->ctx, data->common->scratch, data->common->generators, data->circ[0], data->common->proof[0], &data->common->plen, data->assn, data->common->nonce, NULL, 0) == 1);
    CHECK(secp256k1_bulletproof_circuit_prove(data->common->ctx, data->common->scratch, data->common->generators, data->circ[0], data->common->proof[0], &data->common->plen, data->assn, data->common->nonce, NULL, 0) == 1);
}

static void bench_bulletproof_circuit_verify(void* arg) {
    bench_bulletproof_circuit_t *data = (bench_bulletproof_circuit_t *) arg;
    size_t i;
    for (i = 0; i < 10; i++) {
        CHECK(secp256k1_bulletproof_circuit_verify_multi(data->common->ctx, data->common->scratch, data->common->generators, (const secp256k1_bulletproof_circuit* const*) data->circ, (const unsigned char **) data->common->proof, data->common->n_proofs, data->common->plen) == 1);
    }
}

static void run_rangeproof_test(bench_bulletproof_rangeproof_t *data, size_t nbits, size_t n_commits) {
    char str[64];

    data->nbits = nbits;
    data->n_commits = n_commits;
    data->common->iters = 100;

    data->common->n_proofs = 1;
    sprintf(str, "bulletproof_prove, %i, %i, 0, ", (int)nbits, (int) n_commits);
    run_benchmark(str, bench_bulletproof_rangeproof_prove, bench_bulletproof_rangeproof_setup, bench_bulletproof_rangeproof_teardown, (void *)data, 5, 25);

    data->common->n_proofs = 1;
    sprintf(str, "bulletproof_verify, %i, %i, 1, ", (int)nbits, (int) n_commits);
    run_benchmark(str, bench_bulletproof_rangeproof_verify, bench_bulletproof_rangeproof_setup, bench_bulletproof_rangeproof_teardown, (void *)data, 5, data->common->iters);

    data->common->n_proofs = 2;
    sprintf(str, "bulletproof_verify, %i, %i, 2, ", (int)nbits, (int) n_commits);
    run_benchmark(str, bench_bulletproof_rangeproof_verify, bench_bulletproof_rangeproof_setup, bench_bulletproof_rangeproof_teardown, (void *)data, 5, data->common->iters);

    data->common->iters = 10;
    data->common->n_proofs = 50;
    sprintf(str, "bulletproof_verify, %i, %i, 50, ", (int)nbits, (int) n_commits);
    run_benchmark(str, bench_bulletproof_rangeproof_verify, bench_bulletproof_rangeproof_setup, bench_bulletproof_rangeproof_teardown, (void *)data, 5, data->common->iters);

    data->common->iters = 1;
    data->common->n_proofs = 100;
    sprintf(str, "bulletproof_verify, %i, %i, 100, ", (int)nbits, (int) n_commits);
    run_benchmark(str, bench_bulletproof_rangeproof_verify, bench_bulletproof_rangeproof_setup, bench_bulletproof_rangeproof_teardown, (void *)data, 5, data->common->iters);

    data->common->n_proofs = 500;
    sprintf(str, "bulletproof_verify, %i, %i, 500, ", (int)nbits, (int) n_commits);
    run_benchmark(str, bench_bulletproof_rangeproof_verify, bench_bulletproof_rangeproof_setup, bench_bulletproof_rangeproof_teardown, (void *)data, 5, data->common->iters);

    data->common->n_proofs = 1000;
    sprintf(str, "bulletproof_verify, %i, %i, 1000, ", (int)nbits, (int) n_commits);
    run_benchmark(str, bench_bulletproof_rangeproof_verify, bench_bulletproof_rangeproof_setup, bench_bulletproof_rangeproof_teardown, (void *)data, 5, data->common->iters);
}

void run_circuit_test(bench_bulletproof_circuit_t *data, const char *name) {
    char fname[128];
    size_t i;

    data->circ = (secp256k1_bulletproof_circuit **)malloc(500 * sizeof(*data->circ));

    sprintf(fname, CIRCUIT_DIR "%s.circ", name);
    data->circ[0] = secp256k1_bulletproof_circuit_decode(data->common->ctx, fname);
    CHECK(data->circ[0] != NULL);

    for (i = 1; i < 500; i++) {
        data->circ[i] = data->circ[0];
    }

    sprintf(fname, CIRCUIT_DIR "%s.assn", name);
    data->assn = secp256k1_bulletproof_circuit_assignment_decode(data->common->ctx, fname);
    CHECK(data->assn != NULL);

    data->common->n_proofs = 1;
    sprintf(fname, "bulletproof_prove_%s, ", name);
    run_benchmark(fname, bench_bulletproof_circuit_prove, bench_bulletproof_circuit_setup, bench_bulletproof_circuit_teardown, (void *)data, 1, 3);

    data->common->n_proofs = 1;
    sprintf(fname, "bulletproof_verify_%s, %i, ", name, 1);
    run_benchmark(fname, bench_bulletproof_circuit_verify, bench_bulletproof_circuit_setup, bench_bulletproof_circuit_teardown, (void *)data, 5, 10);

    data->common->n_proofs = 2;
    sprintf(fname, "bulletproof_verify_%s, %i, ", name, 2);
    run_benchmark(fname, bench_bulletproof_circuit_verify, bench_bulletproof_circuit_setup, bench_bulletproof_circuit_teardown, (void *)data, 5, 10);

    data->common->n_proofs = 100;
    sprintf(fname, "bulletproof_verify_%s, %i, ", name, 100);
    run_benchmark(fname, bench_bulletproof_circuit_verify, bench_bulletproof_circuit_setup, bench_bulletproof_circuit_teardown, (void *)data, 5, 10);

    secp256k1_bulletproof_circuit_destroy(data->common->ctx, data->circ[0]);
    secp256k1_bulletproof_circuit_assignment_destroy(data->common->ctx, data->assn);
}

int main(void) {
    bench_bulletproof_t data;
    bench_bulletproof_rangeproof_t rp_data;
    bench_bulletproof_circuit_t c_data;

    data.ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    data.scratch = secp256k1_scratch_space_create(data.ctx, 1024 * 1024 * 1024);
    data.generators = secp256k1_bulletproof_generators_create(data.ctx, 64 * 1024);

    rp_data.common = &data;
    c_data.common = &data;

    run_circuit_test(&c_data, "pedersen-3");
    run_circuit_test(&c_data, "pedersen-6");
    run_circuit_test(&c_data, "pedersen-12");
    run_circuit_test(&c_data, "pedersen-24");
    run_circuit_test(&c_data, "pedersen-48");
    run_circuit_test(&c_data, "pedersen-96");
    run_circuit_test(&c_data, "pedersen-192");
    run_circuit_test(&c_data, "pedersen-384");
    run_circuit_test(&c_data, "pedersen-768");
    run_circuit_test(&c_data, "pedersen-1536");
    run_circuit_test(&c_data, "pedersen-3072");
    run_circuit_test(&c_data, "SHA2");

    run_rangeproof_test(&rp_data, 8, 1);
    run_rangeproof_test(&rp_data, 16, 1);
    run_rangeproof_test(&rp_data, 32, 1);

    run_rangeproof_test(&rp_data, 64, 1);
    run_rangeproof_test(&rp_data, 64, 2);
    run_rangeproof_test(&rp_data, 64, 4);
    run_rangeproof_test(&rp_data, 64, 8);
    run_rangeproof_test(&rp_data, 64, 16);
    run_rangeproof_test(&rp_data, 64, 32);
    run_rangeproof_test(&rp_data, 64, 64);
    run_rangeproof_test(&rp_data, 64, 128);
    run_rangeproof_test(&rp_data, 64, 256);
    run_rangeproof_test(&rp_data, 64, 512);
    /* to add more, increase the number of generators above in `data.generators = ...` */

    secp256k1_bulletproof_generators_destroy(data.ctx, data.generators);
    secp256k1_scratch_space_destroy(data.scratch);
    secp256k1_context_destroy(data.ctx);
    return 0;
}
