/**********************************************************************
 * Copyright (c) 2017 Andrew Poelstra                                 *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef SECP256K1_MODULE_BULLETPROOF_MAIN_IMPL
#define SECP256K1_MODULE_BULLETPROOF_MAIN_IMPL

#include "group.h"
#include "scalar.h"

#include "modules/rangeproof/main_impl.h"
#include "modules/rangeproof/pedersen_impl.h"

#include "modules/bulletproof/inner_product_impl.h"
#include "modules/bulletproof/rangeproof_impl.h"
#include "modules/bulletproof/util.h"

struct secp256k1_bulletproof_generators {
    size_t n;
    secp256k1_ge *gens;
};

secp256k1_bulletproof_generators *secp256k1_bulletproof_generators_create(const secp256k1_context *ctx, size_t n) {
    secp256k1_bulletproof_generators *ret = (secp256k1_bulletproof_generators *)checked_malloc(&ctx->error_callback, sizeof(*ret));
    secp256k1_rfc6979_hmac_sha256 rng;
    unsigned char seed[64];
    size_t i;
    if (ret == NULL) {
        return NULL;
    }

    VERIFY_CHECK(ctx != NULL);

    ret->gens = (secp256k1_ge *)checked_malloc(&ctx->error_callback, n * sizeof(*ret->gens));
    ret->n = n;
    if (ret->gens == NULL) {
        free(ret);
        return NULL;
    }

    secp256k1_fe_get_b32(&seed[0], &secp256k1_ge_const_g.x);
    secp256k1_fe_get_b32(&seed[32], &secp256k1_ge_const_g.y);

    secp256k1_rfc6979_hmac_sha256_initialize(&rng, seed, 64);
    for (i = 0; i < n; i++) {
        unsigned char tmp[32] = { 0 };
        secp256k1_generator gen;
        secp256k1_rfc6979_hmac_sha256_generate(&rng, tmp, 32);
        CHECK(secp256k1_generator_generate(ctx, &gen, tmp));
        secp256k1_generator_load(&ret->gens[i], &gen);
    }
    return ret;
}

void secp256k1_bulletproof_generators_destroy(const secp256k1_context* ctx, secp256k1_bulletproof_generators *gen) {
    (void) ctx;
    if (gen != NULL) {
        free(gen->gens);
        free(gen);
    }
}

int secp256k1_bulletproof_rangeproof_verify(const secp256k1_context* ctx, secp256k1_scratch_space *scratch, const secp256k1_bulletproof_generators *gens, const unsigned char *proof, size_t plen,
 const secp256k1_pedersen_commitment* commit, size_t n_commits, size_t nbits, const secp256k1_generator* gen, const unsigned char *extra_commit, size_t extra_commit_len) {
    int ret;
    size_t i;
    secp256k1_ge genp;
    secp256k1_ge *commitp;
    const secp256k1_ge *commitp_ptr;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(scratch != NULL);
    ARG_CHECK(gens != NULL);
    ARG_CHECK(gens->n >= 2 * nbits * n_commits);
    ARG_CHECK(proof != NULL);
    ARG_CHECK(commit != NULL);
    ARG_CHECK(gen != NULL);
    ARG_CHECK(extra_commit != NULL || extra_commit_len == 0);
    ARG_CHECK(secp256k1_ecmult_context_is_built(&ctx->ecmult_ctx));

    if (!secp256k1_scratch_allocate_frame(scratch, n_commits * sizeof(secp256k1_ge), 1)) {
        return 0;
    }

    secp256k1_generator_load(&genp, gen);
    commitp = (secp256k1_ge *)secp256k1_scratch_alloc(scratch, n_commits * sizeof(secp256k1_ge));
    for (i = 0; i < n_commits; i++) {
        secp256k1_pedersen_commitment_load(&commitp[i], &commit[i]);
    }

    commitp_ptr = commitp;
    ret = secp256k1_bulletproof_rangeproof_verify_impl(&ctx->ecmult_ctx, scratch, &proof, 1, plen, nbits, &commitp_ptr, n_commits, &genp, gens->gens, gens->n, &extra_commit, &extra_commit_len);
    secp256k1_scratch_deallocate_frame(scratch);
    return ret;
}

int secp256k1_bulletproof_rangeproof_verify_multi(const secp256k1_context* ctx, secp256k1_scratch_space *scratch, const secp256k1_bulletproof_generators *gens, const unsigned char **proof, size_t n_proofs, size_t plen, const secp256k1_pedersen_commitment** commit, size_t n_commits, size_t nbits, const secp256k1_generator* gen, const unsigned char **extra_commit, size_t *extra_commit_len) {
    int ret;
    secp256k1_ge **commitp;
    secp256k1_ge genp;
    size_t i;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(scratch != NULL);
    ARG_CHECK(gens != NULL);
    ARG_CHECK(gens->n >= 2 * nbits * n_commits);
    ARG_CHECK(commit != NULL);
    ARG_CHECK(proof != NULL);
    ARG_CHECK(n_proofs > 0);
    ARG_CHECK(gen != NULL);
    if (extra_commit != NULL) {
        for (i = 0; i < n_proofs; i++) {
            ARG_CHECK(extra_commit[i] != NULL || extra_commit_len[i] == 0);
        }
    }
    ARG_CHECK(secp256k1_ecmult_context_is_built(&ctx->ecmult_ctx));

    if (!secp256k1_scratch_allocate_frame(scratch, n_proofs * (sizeof(*commitp) + n_commits * sizeof(**commitp)), 1 + n_proofs)) {
        return 0;
    }

    secp256k1_generator_load(&genp, gen);
    commitp = (secp256k1_ge **)secp256k1_scratch_alloc(scratch, n_proofs * sizeof(*commitp));
    for (i = 0; i < n_proofs; i++) {
        size_t j;
        commitp[i] = (secp256k1_ge *)secp256k1_scratch_alloc(scratch, n_commits * sizeof(*commitp[i]));
        for (j = 0; j < n_commits; j++) {
            secp256k1_pedersen_commitment_load(&commitp[i][j], &commit[i][j]);
        }
    }

    ret = secp256k1_bulletproof_rangeproof_verify_impl(&ctx->ecmult_ctx, scratch, proof, n_proofs, plen, nbits, (const secp256k1_ge **) commitp, n_commits, &genp, gens->gens, gens->n, extra_commit, extra_commit_len);
    secp256k1_scratch_deallocate_frame(scratch);
    return ret;
}

int secp256k1_bulletproof_rangeproof_prove(const secp256k1_context* ctx, secp256k1_scratch_space *scratch, const secp256k1_bulletproof_generators *gens, unsigned char *proof, size_t *plen, uint64_t *value, const unsigned char **blind, size_t n_commits, const secp256k1_generator* gen, size_t nbits, const unsigned char *nonce, const unsigned char *extra_commit, size_t extra_commit_len) {
    int ret;
    secp256k1_ge *commitp;
    secp256k1_scalar *blinds;
    secp256k1_ge genp;
    size_t i;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(scratch != NULL);
    ARG_CHECK(gens != NULL);
    ARG_CHECK(gens->n >= 2 * nbits * n_commits);
    ARG_CHECK(proof != NULL);
    ARG_CHECK(plen != NULL);
    ARG_CHECK(blind != NULL);
    ARG_CHECK(gen != NULL);
    ARG_CHECK(nonce != NULL);
    ARG_CHECK(n_commits > 0 && n_commits);
    ARG_CHECK(nbits <= 64);
    if (nbits < 64) {
        for (i = 0; i < n_commits; i++) {
            ARG_CHECK(value[i] < (1ull << nbits));
            ARG_CHECK(blind[i] != NULL);
        }
    }
    ARG_CHECK(extra_commit != NULL || extra_commit_len == 0);
    ARG_CHECK(secp256k1_ecmult_context_is_built(&ctx->ecmult_ctx));
    ARG_CHECK(secp256k1_ecmult_gen_context_is_built(&ctx->ecmult_gen_ctx));

    if (!secp256k1_scratch_allocate_frame(scratch, n_commits * (sizeof(*commitp) + sizeof(*blinds)), 2)) {
        return 0;
    }
    commitp = (secp256k1_ge *)secp256k1_scratch_alloc(scratch, n_commits * sizeof(*commitp));
    blinds = (secp256k1_scalar *)secp256k1_scratch_alloc(scratch, n_commits * sizeof(*blinds));

    secp256k1_generator_load(&genp, gen);
    for (i = 0; i < n_commits; i++) {
        int overflow;
        secp256k1_gej commitj;
        secp256k1_scalar_set_b32(&blinds[i], blind[i], &overflow);
        if (overflow || secp256k1_scalar_is_zero(&blinds[i])) {
            return 0;
        }
        secp256k1_pedersen_ecmult(&ctx->ecmult_gen_ctx, &commitj, &blinds[i], value[i], &genp);
        secp256k1_ge_set_gej(&commitp[i], &commitj);
    }

    ret = secp256k1_bulletproof_rangeproof_prove_impl(&ctx->ecmult_gen_ctx, &ctx->ecmult_ctx, scratch, proof, plen, nbits, value, blinds, commitp, n_commits, &genp, gens->gens, gens->n, nonce, extra_commit, extra_commit_len);
    secp256k1_scratch_deallocate_frame(scratch);
    return ret;
}

#endif
