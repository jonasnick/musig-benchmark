#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <limits.h>
#include <assert.h>
#include <stdlib.h>

#include <secp256k1.h>
#include <secp256k1_extrakeys.h>
#include <secp256k1_musig.h>

void help() {
    printf("args: keygen|sign <n_signers>\n");
}

void gen_pks_brute_force(secp256k1_context *ctx, secp256k1_xonly_pubkey *pubkey, size_t n_signers) {
    uint32_t n_keys = 0, ctr = 1;
    while (n_keys < n_signers) {
        unsigned char input32[32] = { 0 };
        input32[0] = *((unsigned char*)&ctr);
        if (secp256k1_xonly_pubkey_parse(ctx, &pubkey[n_keys], input32)) {
            n_keys += 1;
        }
        ctr += 1;
    }
}

/* TODO */
static const unsigned char seckey[32] = { 1, 2, 3, 0 };

void gen_pks(secp256k1_context *ctx, secp256k1_keypair *keypair, size_t n_signers) {
    size_t i;
    unsigned char tweak[32] = { 0 };
    tweak[31] = 1;

    assert(secp256k1_keypair_create(ctx, &keypair[0], seckey));
    for (i = 1; i < n_signers; i++) {
        memcpy(&keypair[i], &keypair[i-1], sizeof(keypair[i]));
        assert(secp256k1_keypair_xonly_tweak_add(ctx, &keypair[i], tweak));
    }
}

void keygen_inner(secp256k1_context *ctx, secp256k1_keypair *keypair, secp256k1_musig_pre_session *pre_session, secp256k1_xonly_pubkey *combined_pk, size_t n_signers) {
    secp256k1_xonly_pubkey *pubkey;
    unsigned char pubkey_ser[33];
    secp256k1_scratch_space *scratch;
    size_t i;

    pubkey = malloc(n_signers * sizeof(*pubkey));

    gen_pks(ctx, keypair, n_signers);
    for (i = 0; i < n_signers; i++) {
        assert(secp256k1_keypair_xonly_pub(ctx, &pubkey[i], NULL, &keypair[i]));
    }

    scratch = secp256k1_scratch_space_create(ctx, 10000000);
    assert(secp256k1_musig_pubkey_combine(ctx, scratch, combined_pk, pre_session, pubkey, n_signers));
    assert(secp256k1_xonly_pubkey_serialize(ctx, pubkey_ser, combined_pk));
    printf("pubkey: ");
    for (size_t i = 0; i < 32; i++) {
        printf("%02X", pubkey_ser[i]);
    }
    printf("\n");

    secp256k1_scratch_space_destroy(ctx, scratch);
    free(pubkey);
}

int keygen(size_t n_signers) {
    secp256k1_context *ctx;
    secp256k1_keypair *keypair;
    secp256k1_xonly_pubkey combined_pk;
    ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    keypair = malloc(n_signers * sizeof(*keypair));
    keygen_inner(ctx, keypair, NULL, &combined_pk, n_signers);
    free(keypair);
    secp256k1_context_destroy(ctx);
    return 1;
}

int sign(size_t n_signers) {
    secp256k1_context *ctx;
    secp256k1_keypair *keypair;
    secp256k1_musig_pre_session pre_session;
    secp256k1_xonly_pubkey combined_pk;
    secp256k1_musig_session *musig_session;
    unsigned char **nonce_commitment;
    const unsigned char **nonce_commitment_ptr;
    secp256k1_musig_session_signer_data **signer_data;
    unsigned char **nonce;
    size_t i, j;
    secp256k1_musig_partial_signature *partial_sig;
    unsigned char msg32[32] = "fupa";
    unsigned char sig[64];

    musig_session = malloc(n_signers * sizeof(*musig_session));
    partial_sig = malloc(n_signers * sizeof(*partial_sig));
    nonce_commitment = malloc(n_signers * sizeof(*nonce_commitment));
    nonce_commitment_ptr = malloc(n_signers * sizeof(*nonce_commitment_ptr));
    signer_data = malloc(n_signers * sizeof(*signer_data));
    nonce = malloc(n_signers * sizeof(*nonce));
    for (i = 0; i < n_signers; i++) {
        nonce_commitment[i] = malloc(32);
        signer_data[i] = malloc(n_signers * sizeof(**signer_data));
        nonce[i] = malloc(32);
    }

    ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    keypair = malloc(n_signers * sizeof(*keypair));
    keygen_inner(ctx, keypair, &pre_session, &combined_pk, n_signers);

    for (i = 0; i < n_signers; i++) {
        unsigned char seckey[32];
        unsigned char session_id[32] = { 0 };

        memcpy(seckey, keypair[i].data, sizeof(seckey));
        session_id[0] = *((unsigned char*)&i);

        if (!secp256k1_musig_session_init(ctx, &musig_session[i], signer_data[i], nonce_commitment[i], session_id, msg32, &combined_pk, &pre_session, n_signers, i, seckey)) {
            return 0;
        }
        nonce_commitment_ptr[i] = &nonce_commitment[i][0];
    }
    /* Communication round 1: Exchange nonce commitments */
    for (i = 0; i < n_signers; i++) {
        if (!secp256k1_musig_session_get_public_nonce(ctx, &musig_session[i], signer_data[i], nonce[i], nonce_commitment_ptr, n_signers, NULL)) {
            return 0;
        }
    }
    /* Communication round 2: Exchange nonces */
    for (i = 0; i < n_signers; i++) {
        for (j = 0; j < n_signers; j++) {
            if (!secp256k1_musig_set_nonce(ctx, &signer_data[i][j], nonce[j])) {
                return 0;
            }
        }
        if (!secp256k1_musig_session_combine_nonces(ctx, &musig_session[i], signer_data[i], n_signers, NULL, NULL)) {
            return 0;
        }
    }
    for (i = 0; i < n_signers; i++) {
        if (!secp256k1_musig_partial_sign(ctx, &musig_session[i], &partial_sig[i])) {
            return 0;
        }
    }
#ifdef DEBUG
    /* Communication round 3: Exchange partial signatures */
    for (i = 0; i < n_signers; i++) {
        for (j = 0; j < n_signers; j++) {
            secp256k1_xonly_pubkey pubkey;
            assert(secp256k1_keypair_xonly_pub(ctx, &pubkey, NULL, &keypair[j]));
            if (!secp256k1_musig_partial_sig_verify(ctx, &musig_session[i], &signer_data[i][j], &partial_sig[j], &pubkey)) {
                return 0;
            }
        }
    }
#endif

    assert(secp256k1_musig_partial_sig_combine(ctx, &musig_session[0], sig, partial_sig, n_signers));
    printf("sig: ");
    for (size_t i = 0; i < 64; i++) {
        printf("%02X", sig[i]);
    }
    printf("\n");


    free(keypair);
    free(musig_session);
    free(partial_sig);
    for (i = 0; i < n_signers; i++) {
        free(nonce_commitment[i]);
        free(signer_data[i]);
        free(nonce[i]);
    }
    free(nonce_commitment);
    free(nonce_commitment_ptr);
    free(signer_data);
    free(nonce);
    secp256k1_context_destroy(ctx);
    return 1;
}

int main(int argc, char** argv) {
    size_t n_signers;
    if (argc < 3) {
        help(argv);
        return 1;
    }

    assert(sscanf(argv[2], "%zu", &n_signers));
    if (strcmp(argv[1], "keygen") == 0) {
        return !keygen(n_signers);
    } else if (strcmp(argv[1], "sign") == 0) {
        return !sign(n_signers);
    } else {
        help(argv);
        return 1;
    }
    return 0;
}
