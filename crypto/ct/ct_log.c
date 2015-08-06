/* crypto/ct/ct_log.c */
/* Author: Adam Eijdenberg <adam.eijdenberg@gmail.com>.
 */
/* ====================================================================
 * Copyright (c) 1998-2007 The OpenSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit. (http://www.openssl.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    openssl-core@openssl.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.openssl.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE OpenSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE OpenSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 *
 * This product includes cryptographic software written by Eric Young
 * (eay@cryptsoft.com).  This product includes software written by Tim
 * Hudson (tjh@cryptsoft.com).
 *
 */

#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include <openssl/err.h>
#include <openssl/objects.h>
#include <openssl/ocsp.h>
#include <openssl/x509.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/objects.h>
#include <openssl/opensslconf.h>
#include "ssl/ssl_locl.h"
#include "internal/cryptlib.h"
#include "crypto/ct/ct_local.h"

#define READ_BUFFER 8192

void CTLOG_STORE_free(CTLOG_STORE *store)
{
    if (store) {
        sk_CTLOG_pop_free(store->logs, CTLOG_free);
        OPENSSL_free(store);
    }
}

CTLOG_STORE *CTLOG_STORE_new(void)
{
    CTLOG_STORE *rv = OPENSSL_malloc(sizeof(CTLOG_STORE));
    if (rv == NULL)
        goto err;
    rv->logs = sk_CTLOG_new_null();
    if (rv->logs == NULL)
        goto err;
    return rv;
err:
    CTLOG_STORE_free(rv);

    return NULL;
}

int CTLOG_write_bio(BIO *out, const CTLOG *log)
{
    int rv = -1;
    int byte_count = 0;
    int written;
    BIO *tmp = NULL;
    BUF_MEM *res = NULL;
    BUF_MEM *tmpptr = NULL;

    if ((out == NULL) || (log == NULL)) {
        CTerr(CT_F_CTLOG_WRITE_BIO, CT_R_NULL_INPUT);
        goto err;
    }
    written = BIO_write(out, "{\"description\": ", 16);
    if (written != 16) {
        CTerr(CT_F_CTLOG_WRITE_BIO, CT_R_ENCODE_ERROR);
        goto err;
    }
    byte_count += written;

    byte_count += CT_json_write_string(out, (char *)log->name, log->name_len);

    written = BIO_write(out, ", \"key\": ", 8);
    if (written != 8) {
        CTerr(CT_F_CTLOG_WRITE_BIO, CT_R_ENCODE_ERROR);
        goto err;
    }
    byte_count += written;

    tmp = BIO_new(BIO_s_mem());
    if (tmp == NULL) {
        CTerr(CT_F_CTLOG_WRITE_BIO, CT_R_ENCODE_ERROR);
        goto err;
     }
    if (i2d_PUBKEY_bio(tmp, log->public_key) < 1) {
        CTerr(CT_F_CTLOG_WRITE_BIO, CT_R_ENCODE_ERROR);
        goto err;
    }

    BIO_get_mem_ptr(tmp, &tmpptr);
    if (tmpptr == NULL) {
        CTerr(CT_F_CTLOG_WRITE_BIO, CT_R_ENCODE_ERROR);
        goto err;
    }

    res = CT_base64_encode(tmpptr);
    if (res == NULL) {
        CTerr(CT_F_CTLOG_WRITE_BIO, CT_R_ENCODE_ERROR);
        goto err;
    }

    byte_count += CT_json_write_string(out, res->data, res->length);

    written = BIO_write(out, "}", 1);
    if (written != 1) {
        CTerr(CT_F_CTLOG_WRITE_BIO, CT_R_ENCODE_ERROR);
        goto err;
    }
    byte_count += written;

    rv = byte_count;

err:
    BIO_free_all(tmp);
    BUF_MEM_free(res);

    return rv;
}

CTLOG *CTLOG_create_log_from_json_fragment(const JSON_FRAGMENT *log)
{
    CTLOG *rv = NULL;
    char *derpk = NULL;
    if (log) {
        const JSON_FRAGMENT *name = CT_json_get_value(log, "description");
        const JSON_FRAGMENT *pk = CT_json_get_value(log, "key");

        if (name && pk && name->type == VAL_STRING &&
            pk->type == VAL_STRING && name->buffer && pk->buffer) {
            uint16_t lenderpk = 0;
            CT_base64_decode(pk->buffer->data,
                             pk->buffer->length, &derpk, &lenderpk);
            if (derpk == NULL) {
                CTerr(CT_F_CTLOG_CREATE_LOG_FROM_JSON_FRAGMENT, CT_R_LOG_ERROR);
                goto err;
            } else {
                rv = CTLOG_new(derpk, lenderpk, name->buffer->data, name->buffer->length);
                if (rv == NULL) {
                    CTerr(CT_F_CTLOG_CREATE_LOG_FROM_JSON_FRAGMENT, CT_R_LOG_ERROR);
                    goto err;
                }
                OPENSSL_free(derpk);
                derpk = NULL;
                return rv;
            }
        }
    }
err:
    OPENSSL_free(derpk);
    CTLOG_free(rv);

    return NULL;
}

int CTLOG_STORE_load_file(SSL_CTX *ctx, char *fpath)
{
    int rv = 0;
    BIO *in = NULL;
    BIO *mem = NULL;
    JSON_FRAGMENT *json = NULL;
    BUF_MEM *ptr;
    char buf[READ_BUFFER];
    int amt_read;
    const JSON_FRAGMENT *logs;

    if (fpath == NULL)
        goto err;

    mem = BIO_new(BIO_s_mem());
    if (mem == NULL) {
        CTerr(CT_F_CTLOG_STORE_LOAD_FILE, ERR_R_SYS_LIB);
        goto err;
    }

    in = BIO_new(BIO_s_file_internal());
    if ((in == NULL) || (BIO_read_filename(in, fpath) <= 0)) {
        CTerr(CT_F_CTLOG_STORE_LOAD_FILE, ERR_R_SYS_LIB);
        goto err;
    }

    while ((amt_read = BIO_read(in, buf, READ_BUFFER)) > 0) {
        if (BIO_write(mem, buf, amt_read) != amt_read) {
            CTerr(CT_F_CTLOG_STORE_LOAD_FILE, ERR_R_SYS_LIB);
            goto err;
        }
    }

    BIO_get_mem_ptr(mem, &ptr);
    if (ptr == NULL) {
        CTerr(CT_F_CTLOG_STORE_LOAD_FILE, ERR_R_SYS_LIB);
        goto err;
    }

    json = CT_parse_json(ptr->data, ptr->length);
    if (json == NULL)
        goto err;

    logs = CT_json_get_value(json, "logs");
    if (logs && (logs->type == OBJ_ARRAY) && logs->children) {
        int i;
        for (i = 0; i < sk_JSON_FRAGMENT_num(logs->children); i++) {
            CTLOG *ctlog = CTLOG_create_log_from_json_fragment(
                                    sk_JSON_FRAGMENT_value(logs->children, i));
            if (ctlog == NULL)
                goto err;

            sk_CTLOG_push(ctx->ctlog_store->logs, ctlog);
        }
    }

    rv = 1;
err:
    JSON_FRAGMENT_free(json);
    BIO_free_all(in);
    BIO_free_all(mem);

    return rv;
}

/*
 * Set and load file log path
 */
int CTLOG_STORE_set_default_paths(SSL_CTX *ctx)
{
    char *fpath = (char *)getenv(CTLOG_FILE_EVP);
    if (fpath == NULL)
      fpath = CTLOG_FILE;
    return CTLOG_STORE_load_file(ctx, fpath);
}

/*
 * Initialize a new CTLOG object. Copies all needed data.
 */
CTLOG *CTLOG_new(const char *pk, uint16_t pkey_len,
                 const char *name, uint16_t name_len)
{
    const unsigned char *p = (const unsigned char *)pk;
    CTLOG *rv = OPENSSL_malloc(sizeof(CTLOG));
    if (rv == NULL)
        goto err;
    rv->public_key = d2i_PUBKEY(NULL, &p, pkey_len);
    if (rv->public_key == NULL)
        goto err;
    SHA256((const unsigned char *)pk, pkey_len, rv->log_id);
    rv->name = OPENSSL_malloc(name_len);
    if (rv->name == NULL)
        goto err;
    memcpy(rv->name, name, name_len);
    rv->name_len = name_len;
    return rv;
err:
    CTLOG_free(rv);
    return NULL;
}

/* Frees CT log and associated structures */
void CTLOG_free(CTLOG *log)
{
    if (log) {
        EVP_PKEY_free(log->public_key);
        log->public_key = NULL;

        OPENSSL_free(log->name);
        log->name = NULL;

        OPENSSL_free(log);
    }
}

/*
 * Given a log ID, find a pointer to a matching log.
 * Return NULL if none found. Do not attempt to free the result.
 */
CTLOG *CT_get_log_by_id(const SSL_CTX *ctx, const uint8_t *id)
{
    int i;
    for (i = 0; i < sk_CTLOG_num(ctx->ctlog_store->logs); i++) {
        CTLOG *child = sk_CTLOG_value(ctx->ctlog_store->logs, i);
        if (memcmp(child->log_id, id, SCT_LOG_ID_LENGTH) == 0)
            return child;
    }
    return NULL;
}
