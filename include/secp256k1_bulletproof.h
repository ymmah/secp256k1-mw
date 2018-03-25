#ifndef _SECP256K1_BULLETPROOF_
# define _SECP256K1_BULLETPROOF_

# include "secp256k1.h"
# include "secp256k1_generator.h"
# include "secp256k1_rangeproof.h"

# ifdef __cplusplus
extern "C" {
# endif

/** Opaque structure representing a large number of NUMS generators */
typedef struct secp256k1_bulletproof_generators secp256k1_bulletproof_generators;

/** Opaque type representing an arithmetic circuit */
typedef struct secp256k1_bulletproof_circuit secp256k1_bulletproof_circuit;

/** Opaque type representing an assignment to the wires of an arithmetic circuit */
typedef struct secp256k1_bulletproof_circuit_assignment secp256k1_bulletproof_circuit_assignment;

/** Version number used in header of circuit and circuit-assignment binary files */
#define SECP256K1_BULLETPROOF_CIRCUIT_VERSION	1

/* Maximum depth of 31 lets us validate an aggregate of 2^25 64-bit proofs */
#define SECP256K1_BULLETPROOF_MAX_DEPTH 60

/* Size of a hypothetical 31-depth rangeproof, in bytes */
#define SECP256K1_BULLETPROOF_MAX_PROOF (160 + 66*32 + 7)

/* Maximum memory, in bytes, that may be allocated to store a circuit representation */
#define SECP256K1_BULLETPROOF_MAX_CIRCUIT (1024 * 1024 * 1024)

/** Allocates and initializes a list of NUMS generators
 *  Returns a list of generators, or NULL if allocation failed.
 *  Args:   ctx: pointer to a context object (cannot be NULL)
 */
SECP256K1_API secp256k1_bulletproof_generators *secp256k1_bulletproof_generators_create(
    const secp256k1_context* ctx,
    size_t n
) SECP256K1_ARG_NONNULL(1);

/** Destroys a list of NUMS generators
 *  Args:   ctx: pointer to a context object (cannot be NULL)
 *          gen: pointer to the generator set to be destroyed
 */
SECP256K1_API void secp256k1_bulletproof_generators_destroy(
    const secp256k1_context* ctx,
    secp256k1_bulletproof_generators *gen
) SECP256K1_ARG_NONNULL(1);

/** Verifies a single bulletproof (aggregate) rangeproof
 *  Returns: 1: rangeproof was valid
 *           0: rangeproof was invalid, or out of memory
 *  Args:       ctx: pointer to a context object initialized for verification (cannot be NULL)
 *          scratch: scratch space with enough memory for verification (cannot be NULL)
 *             gens: generator set with at least 2*nbits*n_commits many generators (cannot be NULL)
 *  In:       proof: byte-serialized rangeproof (cannot be NULL)
 *             plen: length of the proof
 *           commit: array of pedersen commitment that this rangeproof is over (cannot be NULL)
 *        n_commits: number of commitments in the above array
 *            nbits: number of bits proven for each range
 *              gen: second generator used in pedersen commitments (cannot be NULL)
 *     extra_commit: additonal data committed to by the rangeproof
 * extra_commit_len: length of additional data
 */
SECP256K1_API int secp256k1_bulletproof_rangeproof_verify(
    const secp256k1_context* ctx,
    secp256k1_scratch_space* scratch,
    const secp256k1_bulletproof_generators *gens,
    const unsigned char* proof,
    size_t plen,
    const secp256k1_pedersen_commitment* commit,
    size_t n_commits,
    size_t nbits,
    const secp256k1_generator* gen,
    const unsigned char* extra_commit,
    size_t extra_commit_len
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(4) SECP256K1_ARG_NONNULL(6) SECP256K1_ARG_NONNULL(9);

/** Batch-verifies multiple bulletproof (aggregate) rangeproofs of the same size using same generator
 *  Returns: 1: all rangeproofs were valid
 *           0: some rangeproof was invalid, or out of memory
 *  Args:       ctx: pointer to a context object initialized for verification (cannot be NULL)
 *          scratch: scratch space with enough memory for verification (cannot be NULL)
 *             gens: generator set with at least 2*nbits*n_commits many generators (cannot be NULL)
 *  In:       proof: array of byte-serialized rangeproofs (cannot be NULL)
 *         n_proofs: number of proofs in the above array, and number of arrays in the `commit` array
 *             plen: length of every individual proof
 *           commit: array of arrays of pedersen commitment that the rangeproofs is over (cannot be NULL)
 *        n_commits: number of commitments in each element of the above array
 *            nbits: number of bits in each proof
 *              gen: alternate generator for every pedersen commit
 *     extra_commit: array of additonal data committed to by the rangeproof
 * extra_commit_len: array of lengths of additional data
 */
SECP256K1_API int secp256k1_bulletproof_rangeproof_verify_multi(
    const secp256k1_context* ctx,
    secp256k1_scratch_space* scratch,
    const secp256k1_bulletproof_generators *gens,
    const unsigned char** proof,
    size_t n_proofs,
    size_t plen,
    const secp256k1_pedersen_commitment** commit,
    size_t n_commits,
    size_t nbits,
    const secp256k1_generator* gen,
    const unsigned char** extra_commit,
    size_t *extra_commit_len
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(4) SECP256K1_ARG_NONNULL(7);


/** Produces an aggregate Bulletproof rangeproof for a set of Pedersen commitments
 *  Returns: 1: rangeproof was successfully created
 *           0: rangeproof could not be created, or out of memory
 *  Args:       ctx: pointer to a context object initialized for signing and verification (cannot be NULL)
 *          scratch: scratch space with enough memory for verification (cannot be NULL)
 *             gens: generator set with at least 2*nbits*n_commits many generators (cannot be NULL)
 *  Out:      proof: byte-serialized rangeproof (cannot be NULL)
 *  In/out:    plen: pointer to size of `proof`, to be replaced with actual length of proof (cannot be NULL)
 *  In:       value: array of values committed by the Pedersen commitments (cannot be NULL)
 *            blind: array of blinding factors of the Pedersen commitments (cannot be NULL)
 *        n_commits: number of entries in the `value` and `blind` arrays
 *              gen: second generator used in pedersen commitments (cannot be NULL)
 *            nbits: number of bits proven for each range
 *            nonce: random 32-byte seed used to derive blinding factors (cannot be NULL)
 *     extra_commit: additonal data committed to by the rangeproof
 * extra_commit_len: length of additional data
 */
SECP256K1_API int secp256k1_bulletproof_rangeproof_prove(
    const secp256k1_context* ctx,
    secp256k1_scratch_space* scratch,
    const secp256k1_bulletproof_generators *gens,
    unsigned char* proof,
    size_t* plen,
    uint64_t *value,
    const unsigned char** blind,
    size_t n_commits,
    const secp256k1_generator* gen,
    size_t nbits,
    const unsigned char* nonce,
    const unsigned char* extra_commit,
    size_t extra_commit_len
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(4) SECP256K1_ARG_NONNULL(5) SECP256K1_ARG_NONNULL(6) SECP256K1_ARG_NONNULL(7) SECP256K1_ARG_NONNULL(9) SECP256K1_ARG_NONNULL(11);


/* General ZKP functionality */

/** Parses a circuit from an ad-hoc text string format
 *  Returns a circuit, or NULL on failure
 *  Args:         ctx: pointer to a context object (cannot be NULL)
 *  In:   description: description of the circuit
 */
SECP256K1_API secp256k1_bulletproof_circuit *secp256k1_bulletproof_circuit_parse(
    const secp256k1_context *ctx,
    const char *description
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2);

/** Decodes a circuit which is serialized in an opaque binary format
 *  Returns a circuit, or NULL on failure
 *  Args:         ctx: pointer to a context object (cannot be NULL)
 *  In:         fname: path to a file containing the circuit
 */
secp256k1_bulletproof_circuit *secp256k1_bulletproof_circuit_decode(const secp256k1_context *ctx, const char *fname);

/** Destroys a circuit
 *  Args:   ctx: pointer to a context object (cannot be NULL)
 *          gen: pointer to the circuit to be destroyed
 */
SECP256K1_API void secp256k1_bulletproof_circuit_destroy(
    const secp256k1_context *ctx,
    secp256k1_bulletproof_circuit *circ
) SECP256K1_ARG_NONNULL(1);

/** Decodes an accepting wire assignment which is serialized in an opaque binary format
 *  Returns a circuit assignment, or NULL on failure
 *  Args:         ctx: pointer to a context object (cannot be NULL)
 *  In:         fname: path to a file containing the circuit
 */
SECP256K1_API secp256k1_bulletproof_circuit_assignment *secp256k1_bulletproof_circuit_assignment_decode(
    const secp256k1_context *ctx,
    const char *fname
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2);

/** Destroys a circuit assignment
 *  Args:   ctx: pointer to a context object (cannot be NULL)
 *          gen: pointer to the assignment to be destroyed
 */
SECP256K1_API void secp256k1_bulletproof_circuit_assignment_destroy(
    const secp256k1_context *ctx,
    secp256k1_bulletproof_circuit_assignment *assn
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2);

/** Verifies a single bulletproof zero-knowledge proof (zkp)
 *  Returns: 1: zkp accepted
 *           0: zkp did not accept, or out of memory
 *  Args:       ctx: pointer to a context object initialized for verification (cannot be NULL)
 *          scratch: scratch space with enough memory for verification (cannot be NULL)
 *             gens: generator set with at least 2*n_gates many generators (cannot be NULL)
 *             circ: circuit that the zkp is over (cannot be NULL)
 *  In:       proof: byte-serialized proof (cannot be NULL)
 *             plen: length of the proof
 *     extra_commit: additonal data committed to by the zkp
 * extra_commit_len: length of additional data
 */
SECP256K1_API int secp256k1_bulletproof_circuit_verify(
    const secp256k1_context* ctx,
    secp256k1_scratch_space* scratch,
    const secp256k1_bulletproof_generators* gens,
    const secp256k1_bulletproof_circuit* circ,
    const unsigned char* proof,
    size_t plen,
    const unsigned char* extra_commit,
    size_t extra_commit_len
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(4) SECP256K1_ARG_NONNULL(5);

/** Batch-verifies multiple bulletproof zero-knowledge proofs of equally-sized circuits (zkp)
 *  Returns: 1: all zkps accepted
 *           0: some zkp did not accept, or out of memory
 *  Args:       ctx: pointer to a context object initialized for verification (cannot be NULL)
 *          scratch: scratch space with enough memory for verification (cannot be NULL)
 *             gens: generator set with at least 2*n_gates many generators (cannot be NULL)
 *            circs: array of circuits, one per proof
 *  In:       proof: array of byte-serialized proofs (cannot be NULL)
 *         n_proofs: number of proofs in above array
 *             plen: length of the all proofs
 *     extra_commit: additonal data committed to by the zkp
 * extra_commit_len: length of additional data
 */
SECP256K1_API int secp256k1_bulletproof_circuit_verify_multi(
    const secp256k1_context* ctx,
    secp256k1_scratch_space* scratch,
    const secp256k1_bulletproof_generators* gens,
    const secp256k1_bulletproof_circuit* const* circ,
    const unsigned char* const* proof,
    size_t n_proofs,
    size_t plen
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(4) SECP256K1_ARG_NONNULL(5);

/** Produces a bulletproof zero-knowledge proof (zkp)
 *  Returns: 1: proof was successfully created	
 *           0: proof failed to create
 *  Args:       ctx: pointer to a context object initialized for signing and verification (cannot be NULL)
 *          scratch: scratch space with enough memory for verification (cannot be NULL)
 *             gens: generator set with at least 2*n_gates many generators (cannot be NULL)
 *             circ: circuit that the zkp is over (cannot be NULL)
 *  Out:      proof: byte-serialized rangeproof (cannot be NULL)
 *  In/Out:    plen: pointer to length of the proof, initially set to length of buffer (cannot be NULL)
 *  In:        assn: wire assignment to prove in zero knowledge (cannot be NULL)
 *            nonce: seed used for random number generation (cannot be NULL)
 *     extra_commit: additonal data committed to by the zkp
 * extra_commit_len: length of additional data
 */
SECP256K1_API int secp256k1_bulletproof_circuit_prove(
    const secp256k1_context* ctx,
    secp256k1_scratch_space* scratch,
    const secp256k1_bulletproof_generators* gens,
    const secp256k1_bulletproof_circuit* circ,
    unsigned char* proof,
    size_t* plen,
    const secp256k1_bulletproof_circuit_assignment *assn,
    const unsigned char* nonce,
    const unsigned char* extra_commit,
    size_t extra_commit_len
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(4) SECP256K1_ARG_NONNULL(5) SECP256K1_ARG_NONNULL(6) SECP256K1_ARG_NONNULL(7) SECP256K1_ARG_NONNULL(8);

# ifdef __cplusplus
}
# endif

#endif
