/**********************************************************************
 * Copyright (c) 2018 Andrew Poelstra                                 *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef SECP256K1_MODULE_BULLETPROOF_CIRCUIT_COMPRESS_IMPL
#define SECP256K1_MODULE_BULLETPROOF_CIRCUIT_COMPRESS_IMPL

#include "modules/bulletproof/main_impl.h"

typedef struct {
    secp256k1_scalar c_sum;
    secp256k1_scalar *wl_wo;  /* y^-n . (x * WL + WO), gates-many */
    secp256k1_scalar *wr;     /* y^-n . WR, gates-many */
    secp256k1_scalar *wv;     /* WV, commits-many */
    secp256k1_scalar *zn;     /* z^n, constraints-many */
} secp256k1_bulletproof_vfy_compressed_circuit;

typedef struct {
    secp256k1_scalar c_sum;
    secp256k1_scalar *wl;  /* WL */
    secp256k1_scalar *wr;  /* y^-n . WR */
    secp256k1_scalar *wo;  /* WO */
    secp256k1_scalar *wv;  /* WV, commits-many */
    secp256k1_scalar *zn;  /* z^n, constraints + 2-many */
} secp256k1_bulletproof_pf_compressed_circuit;

static void secp256k1_fast_scalar_mul(secp256k1_scalar *r, const secp256k1_fast_scalar *a, const secp256k1_scalar *b) {
    switch (a->special) {
    case -2:
        secp256k1_scalar_add(r, b, b);
        secp256k1_scalar_negate(r, r);
        break;
    case -1:
        secp256k1_scalar_negate(r, b);
        break;
    case 0:
        secp256k1_scalar_clear(r);
        break;
    case 1:
        *r = *b;
        break;
    case 2:
        secp256k1_scalar_add(r, b, b);
        break;
    default:
        secp256k1_scalar_mul(r, &a->scal, b);
        break;
    }
#ifdef VERIFY
{
    secp256k1_scalar mul;
    secp256k1_scalar_mul(&mul, &a->scal, b);
    CHECK(secp256k1_scalar_eq(&mul, r));
}
#endif
}

static void secp256k1_wmatrix_row_compress(secp256k1_scalar *r, const secp256k1_bulletproof_wmatrix_row *row, const secp256k1_scalar *zn) {
    size_t j;
    secp256k1_scalar_clear(r);
    for (j = 0; j < row->size; j++) {
        secp256k1_scalar term;
        secp256k1_fast_scalar_mul(&term, &row->entry[j].scal, &zn[row->entry[j].idx]);
        secp256k1_scalar_add(r, r, &term);
    }
}

int secp256k1_bulletproof_vfy_compressed_circuit_allocate_frame(secp256k1_scratch *scratch, const secp256k1_bulletproof_circuit *circ, size_t n_proofs) {
    return secp256k1_scratch_allocate_frame(
        scratch,
        n_proofs * (sizeof(secp256k1_bulletproof_vfy_compressed_circuit) + (2 * circ->n_gates + circ->n_constraints + circ->n_commits) * sizeof(secp256k1_scalar)),
        n_proofs * 2
    );
}

secp256k1_bulletproof_vfy_compressed_circuit *secp256k1_bulletproof_vfy_compress_circuit(secp256k1_scratch *scratch, const secp256k1_bulletproof_circuit *circ, const secp256k1_scalar *x, const secp256k1_scalar *y, const secp256k1_scalar *yinv, const secp256k1_scalar *z) {
    secp256k1_bulletproof_vfy_compressed_circuit *ret = (secp256k1_bulletproof_vfy_compressed_circuit *)secp256k1_scratch_alloc(scratch, sizeof(*ret));
    secp256k1_scalar *ss = (secp256k1_scalar *)secp256k1_scratch_alloc(scratch, (2 * circ->n_gates + circ->n_commits + circ->n_constraints) * sizeof(*ss));
    secp256k1_scalar yinvn, zyn;
    secp256k1_scalar zsqr;
    secp256k1_scalar tmp;
    size_t i;

    ret->wl_wo = &ss[0 * circ->n_gates];
    ret->wr = &ss[1 * circ->n_gates];
    ret->wv = &ss[2 * circ->n_gates];
    ret->zn = &ss[2 * circ->n_gates + circ->n_commits];

    secp256k1_scalar_sqr(&zsqr, z); /* z^1 and z^2 are reserved for bits */
    secp256k1_scalar_mul(&ret->zn[0], &zsqr, z);
    for (i = 1; i < circ->n_constraints; i++) {
        secp256k1_scalar_mul(&ret->zn[i], &ret->zn[i - 1], z);
    }

    zyn = *z;
    secp256k1_scalar_set_int(&yinvn, 1);
    secp256k1_scalar_clear(&ret->c_sum);

    for (i = 0; i < circ->n_gates; i++) {
        secp256k1_scalar wl;
        secp256k1_wmatrix_row_compress(&wl, &circ->wl[i], ret->zn);

        /* For bits only WL has constraints beyond the bit-constraints */
        if (i < circ->n_bits) {
            secp256k1_scalar_negate(&ret->wr[i], z); /* set WR */

            secp256k1_scalar_mul(&wl, &wl, &yinvn);
            secp256k1_scalar_add(&wl, &wl, z); /* add bit-constraint to WL */

            secp256k1_scalar_mul(&ret->wl_wo[i], &wl, x); /* WO becomes WL*x */
            secp256k1_scalar_add(&ret->wl_wo[i], &ret->wl_wo[i], &zsqr); /* set WLx + WO */

            /* Multiply WL by WR and add to the c sum */
            secp256k1_scalar_mul(&wl, &wl, &zyn);
            secp256k1_scalar_negate(&wl, &wl);

            secp256k1_scalar_add(&ret->c_sum, &ret->c_sum, &wl);
            secp256k1_scalar_add(&ret->c_sum, &ret->c_sum, &zyn);
            secp256k1_scalar_mul(&zyn, &zyn, y);
        } else {
            secp256k1_wmatrix_row_compress(&ret->wr[i], &circ->wr[i], ret->zn);
            secp256k1_wmatrix_row_compress(&ret->wl_wo[i], &circ->wo[i], ret->zn);

            secp256k1_scalar_mul(&tmp, &wl, x);
            secp256k1_scalar_add(&tmp, &tmp, &ret->wl_wo[i]);
            secp256k1_scalar_mul(&ret->wl_wo[i], &tmp, &yinvn);

            secp256k1_scalar_mul(&ret->wr[i], &ret->wr[i], &yinvn);

            secp256k1_scalar_mul(&tmp, &wl, &ret->wr[i]);
            secp256k1_scalar_add(&ret->c_sum, &ret->c_sum, &tmp);
        }

        secp256k1_scalar_mul(&yinvn, &yinvn, yinv);
    }

    for (i = 0; i < circ->n_commits; i++) {
        secp256k1_wmatrix_row_compress(&ret->wv[i], &circ->wv[i], ret->zn);
    }

    for (i = 0; i < circ->n_constraints; i++) {
        secp256k1_scalar term;
        secp256k1_fast_scalar_mul(&term, &circ->c[i], &ret->zn[i]);
        secp256k1_scalar_add(&ret->c_sum, &ret->c_sum, &term);
    }
    secp256k1_scalar_sqr(&tmp, x);
    secp256k1_scalar_mul(&ret->c_sum, &ret->c_sum, &tmp);

    return ret;
}

int secp256k1_bulletproof_pf_compressed_circuit_allocate_frame(secp256k1_scratch *scratch, const secp256k1_bulletproof_circuit *circ) {
    return secp256k1_scratch_allocate_frame(
        scratch,
        (sizeof(secp256k1_bulletproof_pf_compressed_circuit) + (3 * circ->n_gates + circ->n_constraints + circ->n_commits) * sizeof(secp256k1_scalar)),
        2
    );
}

secp256k1_bulletproof_pf_compressed_circuit *secp256k1_bulletproof_pf_compress_circuit(secp256k1_scratch *scratch, const secp256k1_bulletproof_circuit *circ, const secp256k1_scalar *y, const secp256k1_scalar *yinv, const secp256k1_scalar *z) {
    secp256k1_bulletproof_pf_compressed_circuit *ret = (secp256k1_bulletproof_pf_compressed_circuit *)secp256k1_scratch_alloc(scratch, sizeof(*ret));
    secp256k1_scalar *ss = (secp256k1_scalar *)secp256k1_scratch_alloc(scratch, (3 * circ->n_gates + circ->n_commits + circ->n_constraints) * sizeof(*ss));
    secp256k1_scalar yinvn, zyn;
    secp256k1_scalar zsqr;
    size_t i;

    ret->wl = &ss[0 * circ->n_gates];
    ret->wr = &ss[1 * circ->n_gates];
    ret->wo = &ss[2 * circ->n_gates];
    ret->wv = &ss[3 * circ->n_gates];
    ret->zn = &ss[3 * circ->n_gates + circ->n_commits];

    secp256k1_scalar_sqr(&zsqr, z); /* z^1 and z^2 are reserved for bits */
    secp256k1_scalar_mul(&ret->zn[0], &zsqr, z);
    for (i = 1; i < circ->n_constraints; i++) {
        secp256k1_scalar_mul(&ret->zn[i], &ret->zn[i - 1], z);
    }

    zyn = *z;
    secp256k1_scalar_set_int(&yinvn, 1);
    secp256k1_scalar_clear(&ret->c_sum);

    for (i = 0; i < circ->n_gates; i++) {
        secp256k1_wmatrix_row_compress(&ret->wl[i], &circ->wl[i], ret->zn);
        secp256k1_wmatrix_row_compress(&ret->wr[i], &circ->wr[i], ret->zn);
        secp256k1_wmatrix_row_compress(&ret->wo[i], &circ->wo[i], ret->zn);

        /* Add bit constraints to sums, in the randomized form
         * y^i*z*(Li - Ri - 1) + y^i*z^2*Oi = 0 */
        if (i < circ->n_bits) {
            secp256k1_scalar tmp;
            secp256k1_scalar_negate(&tmp, &zyn);

            secp256k1_scalar_add(&ret->wl[i], &ret->wl[i], &zyn);
            secp256k1_scalar_add(&ret->wr[i], &ret->wr[i], &tmp);

            secp256k1_scalar_add(&ret->c_sum, &ret->c_sum, &zyn);

            secp256k1_scalar_mul(&tmp, &zyn, z);
            secp256k1_scalar_add(&ret->wo[i], &ret->wo[i], &tmp);

            secp256k1_scalar_mul(&zyn, &zyn, y);
        }

        /* Otherwise our only modification is to multiply WR by y^-n */
        secp256k1_scalar_mul(&ret->wr[i], &ret->wr[i], &yinvn);
        secp256k1_scalar_mul(&yinvn, &yinvn, yinv);
    }

    for (i = 0; i < circ->n_commits; i++) {
        secp256k1_wmatrix_row_compress(&ret->wv[i], &circ->wv[i], ret->zn);
    }

    return ret;
}

#endif
