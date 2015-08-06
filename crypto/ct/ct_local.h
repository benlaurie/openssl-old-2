/* ct_local.h */
/*
 * Written by Adam Eijdenberg <adam.eijdenberg@gmail.com>
 */
/* ====================================================================
 * Copyright (c) 1998-2000 The OpenSSL Project.  All rights reserved.
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

#ifndef HEADER_SCT_LOCAL_H
# define HEADER_SCT_LOCAL_H

# include <openssl/ossl_typ.h>
# include <openssl/safestack.h>
# include <openssl/crypto.h>
# include <openssl/buffer.h>
# include <openssl/bio.h>
# include <openssl/err.h>
# include <openssl/ct.h>
# include <openssl/x509.h>
# include "crypto/ct/ct_internal.h"


#ifdef    __cplusplus
extern "C" {
#endif

/*
 * The intent is that this file contains definitions that should not be used
 * outside of the CT module.
 */
 
#define SCT_LOG_ID_LENGTH 32


typedef enum {CT_STATUS_NONE, CT_STATUS_UNKNOWN_LOG, CT_STATUS_VALID,
              CT_STATUS_INVALID, CT_STATUS_UNVERIFIED,
              CT_STATUS_UNKNOWN_VERSION} sct_validation;

typedef enum {OBJ_ARRAY, OBJ_DICT, DICT_BEG, ARR_BEG, VAL_TRUE, VAL_FALSE,
              VAL_NULL, VAL_NUMBER, VAL_STRING, SEP_NAME, SEP_VAL,
              NAME_VAL} json_token_type;


DECLARE_STACK_OF(JSON_FRAGMENT)
DECLARE_STACK_OF(CTLOG)

struct certificate_transparency_log_st {
    uint8_t                 log_id[SCT_LOG_ID_LENGTH];
    EVP_PKEY                *public_key;
    unsigned char           *name;
    uint16_t                name_len;
};

struct ctlog_store_st {
    STACK_OF(CTLOG) *logs;
};

struct signed_certificate_timestamp_st {
    sct_source              source;
    uint8_t                 version;
    uint8_t                 log_id[SCT_LOG_ID_LENGTH];
    uint64_t                timestamp;
    uint8_t                 hash_algorithm;
    uint8_t                 signature_algorithm;
    uint16_t                signature_length;
    unsigned char           *signature;
    uint16_t                extensions_length;
    unsigned char           *extensions;
    sct_validation          validation_status;
    CTLOG                   *log;
};

struct jf_st {
    json_token_type type;
    BUF_MEM *buffer;
    struct jf_st *name;
    struct jf_st *value;
    STACK_OF(JSON_FRAGMENT) *children;
};

CTLOG *CT_get_log_by_id(const SSL_CTX *ctx, const uint8_t *id);

void CT_base64_decode(char *in, uint16_t in_len,
                      char **out, uint16_t *out_len);
const JSON_FRAGMENT *CT_json_get_value(const JSON_FRAGMENT *par,
                                       const char *key);

int CT_parse_sct_list(uint8_t *data, unsigned short size,
                      STACK_OF(CTSCT) **results, sct_source src);
int CT_extract_tls_extension_scts(SSL *s);
int CT_extract_ocsp_response_scts(SSL *s);
int CT_extract_x509v3_extension_scts(SSL *s);
int CT_validate_signature(const CTLOG *log, const uint8_t *data,
                          uint32_t data_len, const uint8_t *sig,
                          uint32_t sig_len, uint8_t hash_alg);
int CT_validate_sct(CTSCT *sct, X509 *cert, EVP_PKEY *pkey,
                    const SSL_CTX *ctx);
int CT_parse_sct_list_from_x509_extension(const X509_EXTENSION *ext,
                                          STACK_OF(CTSCT) **results,
                                          sct_source src);
int CT_tls_encode_sct_bio(BIO *out, const CTSCT *sct);

JSON_FRAGMENT *JSON_FRAGMENT_alloc(json_token_type t);
int CT_json_complete_array(STACK_OF(JSON_FRAGMENT) *frags);
int CT_json_complete_dict(STACK_OF(JSON_FRAGMENT) *frags);


#ifdef  __cplusplus
}
#endif
#endif
