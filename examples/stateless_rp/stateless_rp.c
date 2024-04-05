/*
 * Copyright (c) 2022 Felix Gohla, Konrad Hanff, Tobias Kantusch,
 *                    Quentin Kuth, Felix Roth. All rights reserved.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file.
 */

#include "stateless_rp.h"

#include <string.h>
#include <stdio.h>

#ifndef log
    #if defined(__ZEPHYR__)
        #include <zephyr/zephyr.h>
        #define log printk
    #elif defined(ESP_PLATFORM)
        #define log printf
    #else
        #define log(...) do {} while(0);
    #endif
#endif

int stateless_assert(fido_dev_t *dev, const char *rp_id, const uint8_t *updater_public_key) {
    int error = FIDO_OK;

    log("[stateless-rp] Opening FIDO device...\n");

    // Open the device. This also gets the device info.
    if ((error = fido_dev_open(dev)) != FIDO_OK) {
        return error;
    }

    log("[stateless-rp] FIDO device opened.\n");

    // Prepare assertion.
    fido_assert_t assert;
    fido_assert_reset(&assert);
    uint8_t client_data_hash[ASSERTION_CLIENT_DATA_HASH_LEN];

    // Just use a constant client data hash for now.
    memset(client_data_hash, 42, sizeof(client_data_hash));

    fido_assert_set_rp(&assert, rp_id);
    fido_assert_set_extensions(&assert, FIDO_ASSERT_EXTENSION_LARGE_BLOB_KEY);
    fido_assert_set_client_data_hash(&assert, client_data_hash);

    log("[stateless-rp] Getting assertion...\n");

    // Perform assertion. It is not verified yet, as this credential public key is unknown at this point in time.
    if ((error = fido_dev_get_assert(dev, &assert)) != FIDO_OK) {
        log("[stateless-rp] ERROR getting assertion\n");
        return error;
    } else if (!assert.reply.has_large_blob_key) {
        log("[stateless-rp] ERROR assertion reply does not have large blob key\n");
        return FIDO_ERR_UNSUPPORTED_EXTENSION;
    }


    // Read the per-credential large blob for this credential.
    fido_blob_t blob;
    uint8_t blob_buffer[1024] = {0};
    fido_blob_reset(&blob, blob_buffer, sizeof(blob_buffer));

    log("[stateless-rp] Getting largeblob...\n");
    if ((error = fido_dev_largeblob_get(dev, assert.reply.large_blob_key, LARGEBLOB_KEY_SIZE, &blob)) != FIDO_OK) {
        log("[stateless-rp] ERROR getting largetblob....\n");
        return error;
    }
    log("[stateless-rp] Got largeblob...\n");

    // blob = credential_public_key (32) | signature(credential_public_key) (64)
    uint8_t *credential_public_key = blob.buffer;
    uint8_t *credential_public_key_signature = blob.buffer + 32;

    log("[stateless-rp] Verifying assertion signature...\n");
    // Verify the signature of the credential public key stored in the large blob.
    if((error = fido_ed25519_verify(credential_public_key_signature, updater_public_key, credential_public_key, 32)) != 0) {
        log("[stateless-rp] Assertion signature verification error...\n");
        return error;
    }

    log("[stateless-rp] Assertion signature verified\n");

    log("[stateless-rp] Verifying assertion using largeblob-stored pubkey...\n");
    // Now, verify the assertion with the public key from the large blob.
    if ((error = fido_assert_verify(&assert, COSE_ALGORITHM_EdDSA, credential_public_key)) != FIDO_OK) {
        log("[stateless-rp] ERROR verifying assertion using largeblob-stored pubkey...\n");
        return error;
    }
    log("[stateless-rp] VERIFIED assertion using largeblob-stored pubkey...\n");

    if ((error = fido_dev_close(dev)) != FIDO_OK) {
        log("[stateless-rp] Error closing fido device.\n");
        return error;
    }
    log("[stateless-rp] FIDO device closed.\n");

    return error;
}
