#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <limits.h>
#include <assert.h>
#include <stdlib.h>

#include <secp256k1.h>
#include <secp256k1_extrakeys.h>
#include <secp256k1_musig.h>
#if DEBUG
    #include <secp256k1_schnorrsig.h>
#endif

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
    const secp256k1_xonly_pubkey **pubkey_ptr;
    unsigned char pubkey_ser[33];
    secp256k1_scratch_space *scratch;
    size_t i;

    pubkey = malloc(n_signers * sizeof(*pubkey));
    pubkey_ptr = malloc(n_signers * sizeof(*pubkey_ptr));

    gen_pks(ctx, keypair, n_signers);
    for (i = 0; i < n_signers; i++) {
        assert(secp256k1_keypair_xonly_pub(ctx, &pubkey[i], NULL, &keypair[i]));
        pubkey_ptr[i] = &pubkey[i];
    }

    scratch = secp256k1_scratch_space_create(ctx, 10000000);
    assert(secp256k1_musig_pubkey_combine(ctx, scratch, combined_pk, pre_session, pubkey_ptr, n_signers));
    assert(secp256k1_xonly_pubkey_serialize(ctx, pubkey_ser, combined_pk));
    printf("pubkey: ");
    for (i = 0; i < 32; i++) {
        printf("%02X", pubkey_ser[i]);
    }
    printf("\n");

    secp256k1_scratch_space_destroy(ctx, scratch);
    free(pubkey);
    free(pubkey_ptr);
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
    secp256k1_musig_secnonce *secnonce;
    unsigned char **pubnonce;
    const unsigned char **pubnonce_ptr;
    unsigned char combined_pubnonce[66];
    const unsigned char *combined_pubnonce_ptr[1];
    secp256k1_musig_session_cache *session_cache;
    secp256k1_musig_template sig_template;
    size_t i;
    secp256k1_musig_partial_signature *partial_sig;
    const secp256k1_musig_partial_signature **partial_sig_ptr;
    unsigned char msg32[32] = "fupa";
    unsigned char sig[64];

    secnonce = malloc(n_signers * sizeof(*secnonce));
    pubnonce = malloc(n_signers * sizeof(*pubnonce));
    pubnonce_ptr = malloc(n_signers * sizeof(*pubnonce_ptr));
    combined_pubnonce_ptr[0] = combined_pubnonce;
    session_cache = malloc(n_signers * sizeof(*session_cache));
    partial_sig = malloc(n_signers * sizeof(*partial_sig));
    partial_sig_ptr = malloc(n_signers * sizeof(*partial_sig_ptr));
    for (i = 0; i < n_signers; i++) {
        pubnonce[i] = malloc(66);
        pubnonce_ptr[i] = pubnonce[i];
        partial_sig_ptr[i] = &partial_sig[i];
    }

    ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    keypair = malloc(n_signers * sizeof(*keypair));
    keygen_inner(ctx, keypair, &pre_session, &combined_pk, n_signers);

    for (i = 0; i < n_signers; i++) {
        unsigned char seckey[32];
        unsigned char session_id[32] = { 0 };

        memcpy(seckey, keypair[i].data, sizeof(seckey));
        session_id[0] = *((unsigned char*)&i);
        assert(secp256k1_musig_session_init(ctx, &secnonce[i], pubnonce[i], session_id, seckey, msg32, &combined_pk, NULL));
    }
    /* Communication round 1: Exchange nonces */
    assert(secp256k1_musig_nonces_combine(ctx, combined_pubnonce, pubnonce_ptr, n_signers));
    for (i = 0; i < n_signers; i++) {
        assert(secp256k1_musig_process_nonces(ctx, &session_cache[i], &sig_template, NULL, combined_pubnonce_ptr, 1, msg32, &combined_pk, &pre_session, NULL));
        assert(secp256k1_musig_partial_sign(ctx, &partial_sig[i], &secnonce[i], &keypair[i], &pre_session, &session_cache[i]));
    }
#ifdef DEBUG
    /* Communication round 2: Exchange partial signatures */
    for (i = 0; i < n_signers; i++) {
        size_t j;
        for (j = 0; j < n_signers; j++) {
            secp256k1_xonly_pubkey pubkey;
            assert(secp256k1_keypair_xonly_pub(ctx, &pubkey, NULL, &keypair[j]));
            if (!secp256k1_musig_partial_sig_verify(ctx, &partial_sig[j], pubnonce[j], &pubkey, &pre_session, &session_cache[i])) {
                return 0;
            }
        }
    }
#endif

    assert(secp256k1_musig_partial_sig_combine(ctx, sig, &sig_template, partial_sig_ptr, n_signers));
    printf("sig: ");
    for (size_t i = 0; i < 64; i++) {
        printf("%02X", sig[i]);
    }
    printf("\n");

#ifdef DEBUG
    assert(secp256k1_schnorrsig_verify(ctx, sig, msg32, &combined_pk));
#endif

    for (i = 0; i < n_signers; i++) {
        free(pubnonce[i]);
    }
    free(keypair);
    free(secnonce);
    free(pubnonce);
    free(pubnonce_ptr);
    free(session_cache);
    free(partial_sig);
    free(partial_sig_ptr);

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
