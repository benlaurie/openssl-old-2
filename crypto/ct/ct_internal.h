/* ct_internal.h */
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

#ifndef HEADER_SCT_INTERNAL_H
# define HEADER_SCT_INTERNAL_H

# include <openssl/ossl_typ.h>
# include <openssl/safestack.h>
# include <openssl/crypto.h>
# include <openssl/buffer.h>
# include <openssl/bio.h>
# include <openssl/err.h>
# include <openssl/ct.h>


#ifdef    __cplusplus
extern "C" {
#endif

/*
 * The intent is that this file contains definitions needed by other parts of
 * openssl, but not part of the public API.
 */

typedef struct ctlog_store_st CTLOG_STORE;
typedef struct certificate_transparency_log_st CTLOG;
typedef struct jf_st JSON_FRAGMENT;


typedef enum {CT_TLS_EXTENSION, CT_X509V3_EXTENSION,
              CT_OCSP_STAPLED_RESPONSE, CT_SOURCE_UNKNOWN} sct_source;

/* Called after ServerHelloDone */
int CT_validate_connection(SSL *s);

/* SCT management */
CTSCT *CTSCT_alloc(void);
void CTSCT_free(CTSCT *sct);
int CT_parse_sct_bio(BIO *in, CTSCT *sct, sct_source src);
int CT_parse_sct(unsigned char *data, unsigned short size,
                 CTSCT *sct, sct_source src);
int CT_server_info_encode_sct_list_bio(BIO *out, STACK_OF(CTSCT) *scts);
int CT_tls_encode_sct_list_bio(BIO *out, STACK_OF(CTSCT) *scts);
EVP_PKEY *CT_get_public_key_that_signed(X509_STORE_CTX *ctx);

/* Log store management */
CTLOG_STORE *CTLOG_STORE_new(void);
void CTLOG_STORE_free(CTLOG_STORE *store);
int CTLOG_write_bio(BIO *out, CTLOG *log);

/* JSON stuff */
int CT_json_write_string(BIO *out, char *data, int len);
BUF_MEM *CT_base64_encode(BUF_MEM *in);
void JSON_FRAGMENT_free(JSON_FRAGMENT *f);
JSON_FRAGMENT *CT_parse_json(char *data, uint32_t len);

/* Create / free a CT log */
CTLOG *CTLOG_new(char *pk, uint16_t pkey_len, char *name, uint16_t name_len);
void CTLOG_free(CTLOG *log);
CTLOG *CTLOG_create_log_from_json_fragment(JSON_FRAGMENT *log);


#ifdef  __cplusplus
}
#endif
#endif
