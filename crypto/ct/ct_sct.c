/* crypto/ct/ct_sct.c */
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
#include <openssl/tls1.h>
#include "ssl/ssl_locl.h"
#include "internal/cryptlib.h"
#include "crypto/ct/ct_local.h"

#define MAX_CTLOG_SIZE 65535



int CT_parse_sct(unsigned char *data, unsigned short size,
                 CTSCT *sct, sct_source src)
{
    int rv = 0;
    BIO *mem = BIO_new_mem_buf(data, size);
    if (mem == NULL) {
        CTerr(CT_F_CT_PARSE_SCT, CT_R_MEM_ERR);
        goto err;
    }
    rv = CT_parse_sct_bio(mem, sct, src);
err:
    if (mem) {
        BIO_free_all(mem);
        mem = NULL;
    }
    return rv;
}

int CT_server_info_encode_sct_list_bio(BIO *out, STACK_OF(CTSCT) *scts)
{
    int rv = -1;
    int tentative_rv;
    uint8_t t;
    int i;
    int child_size;

    if (scts == NULL) {
        CTerr(CT_F_CT_SERVER_INFO_ENCODE_SCT_LIST_BIO, CT_R_NULL_INPUT);
        goto err;
    }

    child_size = CT_tls_encode_sct_list_bio(NULL, scts);
    if (child_size < 0) {
        CTerr(CT_F_CT_SERVER_INFO_ENCODE_SCT_LIST_BIO, CT_R_ENCODE_FAILURE);
        goto err;
    }

    tentative_rv = 2 + 2 + child_size;

    if (out == NULL) {
        rv = tentative_rv;
        goto end;
    }

    for (i = 8; i >= 0; i -= 8) {
        t = (TLSEXT_TYPE_signed_certificate_timestamp >> i) & 0xff;
        if (BIO_write(out, &t, 1) != 1) {
            CTerr(CT_F_CT_SERVER_INFO_ENCODE_SCT_LIST_BIO, CT_R_BAD_WRITE);
            goto err;
        }
    }

    for (i = 8; i >= 0; i -= 8) {
        t = (child_size >> i) & 0xff;
        if (BIO_write(out, &t, 1) != 1) {
            CTerr(CT_F_CT_SERVER_INFO_ENCODE_SCT_LIST_BIO, CT_R_BAD_WRITE);
            goto err;
        }
    }

    if (CT_tls_encode_sct_list_bio(out, scts) != child_size) {
        CTerr(CT_F_CT_SERVER_INFO_ENCODE_SCT_LIST_BIO, CT_R_BAD_WRITE);
        goto err;
    }

    rv = tentative_rv;

err:
end:
    return rv;
}


int CT_tls_encode_sct_list_bio(BIO *out, STACK_OF(CTSCT) *scts)
{
    int rv = -1;
    int tentative_rv;
    int child_list_size;
    uint8_t t;
    int i, j;

    if (scts == NULL) {
        CTerr(CT_F_CT_TLS_ENCODE_SCT_LIST_BIO, CT_R_NULL_INPUT);
        goto err;
    }

    /* First, figure out our size, we need it anyway */
    child_list_size = 0;
    for (i = 0; i < sk_CTSCT_num(scts); i++) {
        int child = CT_tls_encode_sct_bio(NULL, sk_CTSCT_value(scts, i));
        if (child < 1) {
            CTerr(CT_F_CT_TLS_ENCODE_SCT_LIST_BIO, CT_R_ENCODE_FAILURE);
            goto err;
        }
        child_list_size += 2 + child;
    }

    tentative_rv = 2 + child_list_size;
    if (out == NULL) {
        rv = tentative_rv;
        goto end;
    }

    /* Write list len */
    for (i = 8; i >= 0; i -= 8) {
        t = (child_list_size >> i) & 0xff;
        if (BIO_write(out, &t, 1) != 1) {
            CTerr(CT_F_CT_TLS_ENCODE_SCT_LIST_BIO, CT_R_BAD_WRITE);
            goto err;
        }
    }

    for (j = 0; j < sk_CTSCT_num(scts); j++) {
        int child = CT_tls_encode_sct_bio(NULL, sk_CTSCT_value(scts, j));
        if (child < 1) {
            CTerr(CT_F_CT_TLS_ENCODE_SCT_LIST_BIO, CT_R_ENCODE_FAILURE);
            goto err;
        }
        /* Write child len */
        for (i = 8; i >= 0; i -= 8) {
            t = (child >> i) & 0xff;
            if (BIO_write(out, &t, 1) != 1) {
                CTerr(CT_F_CT_TLS_ENCODE_SCT_LIST_BIO, CT_R_BAD_WRITE);
                goto err;
            }
        }
        /* Write child */
        if (CT_tls_encode_sct_bio(out, sk_CTSCT_value(scts, j)) != child) {
            CTerr(CT_F_CT_TLS_ENCODE_SCT_LIST_BIO, CT_R_ENCODE_FAILURE);
            goto err;
        }
    }

    rv = tentative_rv;

err:
end:
    return rv;
}


int CT_tls_encode_sct_bio(BIO *out, CTSCT *sct)
{
    int rv = -1;
    int tentative_rv;
    uint8_t t;
    int i;

    if (sct == NULL) {
        CTerr(CT_F_CT_TLS_ENCODE_SCT_BIO, CT_R_NULL_INPUT);
        goto err;
    }

    tentative_rv = 1 + SCT_LOG_ID_LENGTH + 8 + 2 + sct->extensions_length + \
                   1 + 1 + 2 + sct->signature_length;
    if (out == NULL) {
        rv = tentative_rv;
        goto end;
    }

    /* Write Version */
    t = sct->version;
    if (BIO_write(out, &t, 1) != 1) {
        CTerr(CT_F_CT_TLS_ENCODE_SCT_BIO, CT_R_BAD_WRITE);
        goto err;
    }

    /* Write log ID to out only */
    if (BIO_write(out, sct->log_id, SCT_LOG_ID_LENGTH) != SCT_LOG_ID_LENGTH) {
        CTerr(CT_F_CT_TLS_ENCODE_SCT_BIO, CT_R_BAD_WRITE);
        goto err;
    }

    /* Write timestamp to both */
    for (i = 56; i >= 0; i -= 8) {
        t = (sct->timestamp >> i) & 0xff;
        if (BIO_write(out, &t, 1) != 1) {
            CTerr(CT_F_CT_TLS_ENCODE_SCT_BIO, CT_R_BAD_WRITE);
            goto err;
        }
    }

    /* Write extensions */
    for (i = 8; i >= 0; i -= 8) {
        t = (sct->extensions_length >> i) & 0xff;
        if (BIO_write(out, &t, 1) != 1) {
            CTerr(CT_F_CT_TLS_ENCODE_SCT_BIO, CT_R_BAD_WRITE);
            goto err;
        }
    }
    if (sct->extensions_length) {
        if (BIO_write(out, sct->extensions, sct->extensions_length) != (signed int)sct->extensions_length) {
            CTerr(CT_F_CT_TLS_ENCODE_SCT_BIO, CT_R_BAD_WRITE);
            goto err;
        }
    }

    /* Write hash and sig alg to out only */
    if (BIO_write(out, &sct->hash_algorithm, 1) != 1) {
        CTerr(CT_F_CT_TLS_ENCODE_SCT_BIO, CT_R_BAD_WRITE);
        goto err;
    }
    if (BIO_write(out, &sct->signature_algorithm, 1) != 1) {
        CTerr(CT_F_CT_TLS_ENCODE_SCT_BIO, CT_R_BAD_WRITE);
        goto err;
    }

    for (i = 8; i >= 0; i -= 8) {
        t = (sct->signature_length >> i) & 0xff;
        if (BIO_write(out, &t, 1) != 1) {
            CTerr(CT_F_CT_TLS_ENCODE_SCT_BIO, CT_R_BAD_WRITE);
            goto err;
        }
    }

    if (sct->signature_length) {
        if (BIO_write(out, sct->signature, sct->signature_length) != (signed int)sct->signature_length) {
            CTerr(CT_F_CT_TLS_ENCODE_SCT_BIO, CT_R_BAD_WRITE);
            goto err;
        }
    }

    rv = tentative_rv;

err:
end:
    return rv;
}


/*
 * Parse a single SCT, store in sct.
 * data can be discarded after parsing.
 * Return 1 on success, 0 on failure.
 */
int CT_parse_sct_bio(BIO *in, CTSCT *sct, sct_source src)
{
    uint8_t t;
    int i;
    int rv = 0;

    sct->source = src;
    sct->validation_status = CT_STATUS_NONE;

    if (BIO_read(in, &sct->version, 1) != 1) {
        CTerr(CT_F_CT_PARSE_SCT_BIO, CT_R_SCT_UNEXPECTED_EOF);
        goto err;
    }

    if (BIO_read(in, &sct->log_id, SCT_LOG_ID_LENGTH) != SCT_LOG_ID_LENGTH) {
        CTerr(CT_F_CT_PARSE_SCT_BIO, CT_R_SCT_UNEXPECTED_EOF);
        goto err;
    }

    sct->timestamp = 0;
    for (i = 0; i < 8; i++) {
        if (BIO_read(in, &t, 1) != 1) {
            CTerr(CT_F_CT_PARSE_SCT_BIO, CT_R_SCT_UNEXPECTED_EOF);
            goto err;
        }
        sct->timestamp <<= 8;
        sct->timestamp += t;
    }

    sct->extensions_length = 0;
    for (i = 0; i < 2; i++) {
        if (BIO_read(in, &t, 1) != 1) {
            CTerr(CT_F_CT_PARSE_SCT_BIO, CT_R_SCT_UNEXPECTED_EOF);
            goto err;
        }
        sct->extensions_length <<= 8;
        sct->extensions_length += t;
    }

    if (sct->extensions != NULL)
        OPENSSL_free(sct->extensions);

    if (sct->extensions_length) {
        sct->extensions = OPENSSL_malloc(sct->extensions_length);
        if (sct->extensions == NULL) {
            CTerr(CT_F_CT_PARSE_SCT_BIO, CT_R_SCT_MALLOC_FAILED);
            goto err;
        }
        if (BIO_read(in, sct->extensions, sct->extensions_length) != sct->extensions_length) {
            CTerr(CT_F_CT_PARSE_SCT_BIO, CT_R_SCT_UNEXPECTED_EOF);
            goto err;
        }
    } else {
        sct->extensions = NULL;
    }

    if (BIO_read(in, &sct->hash_algorithm, 1) != 1) {
        CTerr(CT_F_CT_PARSE_SCT_BIO, CT_R_SCT_UNEXPECTED_EOF);
        goto err;
    }
    switch (sct->hash_algorithm) {
    case 4: /* SHA-256 */
        break;
    default:
        CTerr(CT_F_CT_PARSE_SCT_BIO, CT_R_SCT_UNRECOGNIZED_HASH_ALGORITHM);
        goto err;
    }

    if (BIO_read(in, &sct->signature_algorithm, 1) != 1) {
        CTerr(CT_F_CT_PARSE_SCT_BIO, CT_R_SCT_UNEXPECTED_EOF);
        goto err;
    }
    switch (sct->signature_algorithm) {
    case 1: /* RSA */
        break;
    case 3: /* ECSDA */
        break;
    default:
        CTerr(CT_F_CT_PARSE_SCT_BIO, CT_R_SCT_UNRECOGNIZED_SIGNATURE_ALGORITHM);
        goto err;
    }

    sct->signature_length = 0;
    for (i = 0; i < 2; i++) {
        if (BIO_read(in, &t, 1) != 1) {
            CTerr(CT_F_CT_PARSE_SCT_BIO, CT_R_SCT_UNEXPECTED_EOF);
            goto err;
        }
        sct->signature_length <<= 8;
        sct->signature_length += t;
    }

    if (sct->signature != NULL)
        OPENSSL_free(sct->signature);

    if (sct->signature_length) {
        sct->signature = OPENSSL_malloc(sct->signature_length);
        if (sct->signature == NULL) {
            CTerr(CT_F_CT_PARSE_SCT_BIO, CT_R_SCT_MALLOC_FAILED);
            goto err;
        }
        if (BIO_read(in, sct->signature, sct->signature_length) != sct->signature_length) {
            CTerr(CT_F_CT_PARSE_SCT_BIO, CT_R_SCT_UNEXPECTED_EOF);
            goto err;
        }
    } else {
        sct->signature = NULL;
    }

     rv = 1;
err:
    return rv;
}

/*
 * Parse a list of SCTs (such as encoded in ASN1 string, or supplied in TLS
 * extension. Results can be NULL, if NULL it will be lazily created.
 * Data can be discarded after parsing.
 *
 * Return 1 on success, 0 on failure.
 */
int CT_parse_sct_list(uint8_t *data, unsigned short size,
                      STACK_OF(CTSCT) **results, sct_source src)
{
    CTSCT *sct = NULL;
    uint16_t offset = 0;
    uint16_t tot_len;

    if (size < 2) {
        CTerr(CT_F_CT_PARSE_SCT_LIST, CT_R_SCT_LIST_UNEXPECTED_EOF);
        goto err;
    }

    tot_len = data[offset++];
    tot_len <<= 8;
    tot_len += data[offset++];
    if ((offset + tot_len) != size) {
        CTerr(CT_F_CT_PARSE_SCT_LIST, CT_R_SCT_LIST_UNEXPECTED_EOF);
        goto err;
    }
    while (offset < size) {
        uint16_t next_len = data[offset++];
        next_len <<= 8;
        next_len += data[offset++];
        if (next_len == 0) {
            CTerr(CT_F_CT_PARSE_SCT_LIST, CT_R_SCT_LIST_INVALID_SCT);
            goto err;
        }
        if ((offset + next_len) > size) {
            CTerr(CT_F_CT_PARSE_SCT_LIST, CT_R_SCT_LIST_UNEXPECTED_EOF);
            goto err;
        }
        sct = CTSCT_alloc();
        if (sct == NULL)
            goto err;

        if (CT_parse_sct(data + offset, next_len, sct, src) != 1)
            goto err;

        if (*results == NULL) {
            *results = sk_CTSCT_new_null();
            if (*results == NULL) {
                CTerr(CT_F_CT_PARSE_SCT_LIST, CT_R_SCT_LIST_MALLOC_FAILED);
                goto err;
            }
        }
        sk_CTSCT_push(*results, sct);
        sct = NULL;
        offset += next_len;
    }

    return 1;
err:
    if (sct != NULL) {
        CTSCT_free(sct);
        sct = NULL;
    }
    return 0;
}

/*
 * Free an SCT and associated data structures.
 */
void CTSCT_free(CTSCT *sct)
{
    if (sct) {
        if (sct->signature)
            OPENSSL_free(sct->signature);
        if (sct->extensions)
            OPENSSL_free(sct->extensions);
        OPENSSL_free(sct);
    }
}

/*
 * Allocate a new SCT
 * Return ptr on success, NULL on failure.
 */
CTSCT *CTSCT_alloc()
{
    CTSCT *rv = OPENSSL_malloc(sizeof(CTSCT));
    if (rv == NULL) {
        CTerr(CT_F_CTSCT_ALLOC, CT_R_SCT_MALLOC_FAILED);
        goto err;
    }
    memset(rv, 0, sizeof(CTSCT));
    rv->validation_status = CT_STATUS_NONE;
    rv->log = NULL;
    return rv;
err:
    return NULL;
}

/*
 * Given an X509 extension, extract SCT list from ASN1 string and parse.
 * *results can be NULL, and stack will be lazily created if so.
 * Return 1 on success, 0 on failure.
 */
int CT_parse_sct_list_from_x509_extension(X509_EXTENSION *ext,
                                    STACK_OF(CTSCT) **results, sct_source src)
{
    ASN1_OCTET_STRING *real_octets = NULL;
    int rv = 0;
    if (ext == NULL) {
        CTerr(CT_F_CT_PARSE_SCT_LIST_FROM_X509_EXTENSION, CT_R_X509V3_INVALID_EXTENSION);
        goto err;
    } else {
        ASN1_OCTET_STRING *os = X509_EXTENSION_get_data(ext);
        if (os->length > 0) {
            const unsigned char *p = os->data;
            if (d2i_ASN1_OCTET_STRING(&real_octets, &p, os->length) == NULL) {
                goto err;
            } else {
                if (CT_parse_sct_list(real_octets->data, real_octets->length,
                                      results, src) != 1) {
                    goto err;
                }
            }
        }
    }
    rv = 1;
err:
    if (real_octets) {
        ASN1_OCTET_STRING_free(real_octets);
        real_octets = NULL;
    }
    return rv;
}

/*
 * Look for data collected during ServerHello and parse if found.
 * Return 1 on success, 0 on failure.
 */
int CT_extract_tls_extension_scts(SSL *s)
{
    int rv = 0;
    if (s && s->tls_ext_sct_data) {
        if (CT_parse_sct_list(s->tls_ext_sct_data, s->tls_ext_sct_data_len,
                              &s->tlsext_scts, CT_TLS_EXTENSION) != 1)
            goto err;
    }
    rv = 1;
err:
    return rv;
}

/*
 * Look for X509 SCT extension provided if an OCSP stapled response can be found
 * and parse if found.
 * Return 1 on success, 0 on failure.
 */
int CT_extract_ocsp_response_scts(SSL *s)
{
    int rv = 0;
    OCSP_BASICRESP *br = NULL;
    OCSP_RESPONSE *rsp = NULL;
    if (s && s->tlsext_ocsp_resp && (s->tlsext_ocsp_resplen > 0)) {
        const unsigned char *p = s->tlsext_ocsp_resp;
        rsp = d2i_OCSP_RESPONSE(NULL, &p, s->tlsext_ocsp_resplen);
        if (rsp == NULL) {
            goto err;
        } else {
            br = OCSP_response_get1_basic(rsp);
            if (br == NULL) {
                goto err;
            } else {
                int i; /* TODO(aeijdenberg): not too sure about this part... */
                for (i = 0; i < OCSP_resp_count(br); i++) {
                    OCSP_SINGLERESP *single = OCSP_resp_get0(br, i);
                    if (single) {
                        int next_pos = OCSP_SINGLERESP_get_ext_by_NID(single,
                                                          NID_ct_cert_scts, -1);
                        if (next_pos >= 0) {
                            if (CT_parse_sct_list_from_x509_extension(
                                OCSP_SINGLERESP_get_ext(single, next_pos),
                                &s->tlsext_scts,
                                CT_OCSP_STAPLED_RESPONSE) != 1) {
                                goto err;
                            }
                        }
                    }
                }
            }
        }
    }
    rv = 1;
err:
    if (br != NULL) {
        OCSP_BASICRESP_free(br);
        br = NULL;
    }
    if (rsp != NULL) {
        OCSP_RESPONSE_free(rsp);
        rsp = NULL;
    }
    return rv;
}

/*
 * Look for X509 SCT extension in certificate itself and parse if found.
 * Return 1 on success, 0 on failure.
 */
int CT_extract_x509v3_extension_scts(SSL *s)
{
    int rv = 0;
    if (s && s->session && s->session->peer) {
        X509 *x = s->session->peer;
        int next_pos = X509_get_ext_by_NID(x, NID_ct_precert_scts, -1);
        if (next_pos >= 0) {
            if (CT_parse_sct_list_from_x509_extension(X509_get_ext(x,
                next_pos),&s->tlsext_scts, CT_X509V3_EXTENSION) != 1) {
                goto err;
            }
        }
    }
    rv = 1;
err:
    return rv;
}

/*
 * Attempt to find all SCTs present in request via TLS extension, X509v3
 * extension and OCSP response.
 * Return pointer to stack on success (do not try to free this), NULL on failure.
 */
STACK_OF(CTSCT) *SSL_get_peer_scts(SSL *s)
{
    if (s == NULL) {
        CTerr(CT_F_SSL_GET_PEER_SCTS, CT_R_NULL_INPUT);
        goto err;
    }
    if (!s->tlsext_ct_have_parsed) {
        CT_extract_tls_extension_scts(s); /* TODO(aeijdenberg): handle failure? */
        CT_extract_ocsp_response_scts(s); /* TODO(aeijdenberg): handle failure? */
        CT_extract_x509v3_extension_scts(s); /* TODO(aeijdenberg): handle failure? */
        s->tlsext_ct_have_parsed = 1;
    }
    return s->tlsext_scts;
err:
    return NULL;
}

/*
 * Call this before beginning handshake. Sets the policy for the connection, which
 * is applied upon receipt of ServerHelloDone. If the policy causes the connection to
 * be invalid (such as by not providing enough SCTs, or providing invalid SCTs), then the
 * connection is terminated.
 * NOTE: setting a policy that requests SCTs has the side-effect of requesting an OCSP stapled
 *       response.
 */
int SSL_apply_certificate_transparency_policy(SSL *s, ct_policy policy)
{
    int rv = 0;
    if (s == NULL) {
        CTerr(CT_F_SSL_APPLY_CERTIFICATE_TRANSPARENCY_POLICY, CT_R_NULL_INPUT);
        goto err;
    }
    /*
     * Since code exists that uses the custom extension handler for CT, look for
     * this and throw an error if they have already registered to use CT.
     */
    if (policy != CT_POLICY_NONE && SSL_CTX_has_client_custom_ext(s->ctx,
                                    TLSEXT_TYPE_signed_certificate_timestamp)) {
        CTerr(CT_F_SSL_APPLY_CERTIFICATE_TRANSPARENCY_POLICY,
              CT_R_CUSTOM_EXT_HANDLER_ALREADY_INSTALLED);
        goto err;
    }
    s->tlsext_ct_policy = policy;
    if (policy != CT_POLICY_NONE)
        /* If we are requesting or requiring CT, then we MUST accept SCTs served via OCSP */
        SSL_set_tlsext_status_type(s, TLSEXT_STATUSTYPE_ocsp);
    rv = 1;
err:
    return rv;
}

/*
 * Call this before beginning handshake. Sets the policy for the connection, which
 * is applied upon receipt of ServerHelloDone. If the policy causes the connection to
 * be invalid (such as by not providing enough SCTs, or providing invalid SCTs), then the
 * connection is terminated.
 * NOTE: setting a policy that requests SCTs has the side-effect of requesting an OCSP stapled
 *       response.
 */
int SSL_CTX_apply_certificate_transparency_policy(SSL_CTX *ctx, ct_policy policy)
{
    int rv = 0;
    if (ctx == NULL) {
        CTerr(CT_F_SSL_CTX_APPLY_CERTIFICATE_TRANSPARENCY_POLICY, CT_R_NULL_INPUT);
        goto err;
    }
    /*
     * Since code exists that uses the custom extension handler for CT, look for
     * this and throw an error if they have already registered to use CT.
     */
    if (policy != CT_POLICY_NONE && SSL_CTX_has_client_custom_ext(ctx,
                                    TLSEXT_TYPE_signed_certificate_timestamp)) {
        CTerr(CT_F_SSL_CTX_APPLY_CERTIFICATE_TRANSPARENCY_POLICY,
              CT_R_CUSTOM_EXT_HANDLER_ALREADY_INSTALLED);
        goto err;
    }
    ctx->tlsext_ct_policy = policy;
    rv = 1;
err:
    return rv;
}

ct_policy SSL_CTX_get_certificate_transparency_policy(SSL_CTX *ctx)
{
    if (ctx == NULL)
        return CT_POLICY_NONE; /* any better ideas for failing? */
    else
        return ctx->tlsext_ct_policy;
}


/*
 * Given a log, some data, a sig, and a hash algorithm, attempt to verify the signature.
 * Return 1 if valid, 0 otherwise.
 */
int CT_validate_signature(CTLOG *log, uint8_t *data, uint32_t data_len,
                          uint8_t *sig, uint32_t sig_len, uint8_t hash_alg)
{
    int rv = 0;
    EVP_MD_CTX ctx;
    EVP_PKEY_CTX *pctx = NULL;
    const EVP_MD *halg = NULL;
    ENGINE *impl = NULL;

    switch (hash_alg) {
    case 4:
        halg = EVP_sha256();
        break;
    default:
        CTerr(CT_F_CT_VALIDATE_SIGNATURE,
              CT_R_SCT_UNRECOGNIZED_HASH_ALGORITHM);
        goto err;
    }

    EVP_MD_CTX_init(&ctx);
    if (EVP_DigestVerifyInit(&ctx, &pctx, halg, impl, log->public_key) != 1) {
        CTerr(CT_F_CT_VALIDATE_SIGNATURE, CT_R_SCT_DIGEST_VERIFY_ERROR);
        goto err;
    }

    if (EVP_DigestVerifyUpdate(&ctx, data, data_len) != 1) {
        CTerr(CT_F_CT_VALIDATE_SIGNATURE, CT_R_SCT_DIGEST_VERIFY_ERROR);
        goto err;
    }

    if (EVP_DigestVerifyFinal(&ctx, sig, sig_len))
        rv = 1;
    else
        rv = 0;

    /* TODO(aeijdenberg): am I meant to free EVP_PKEY_CTX? */
err:
    EVP_MD_CTX_cleanup(&ctx);
    return rv;
}



/*
 * Given an SCT, a cert, and a stack of peers, attempt to validate it.
 * Return 1 if valid, 0 otherwise.
 */
int CT_validate_sct(CTSCT *sct, X509 *cert, EVP_PKEY *pkey, SSL_CTX *ctx)
{
    int rv = 0;
    uint8_t *data = NULL;
    int total_len = 0;
    int cert_len;
    int len_needed;
    unsigned char *copybuffer = NULL;
    X509 *tbs = NULL;
    unsigned char *pkeybuffer = NULL;
    int pkeylen;
    CTLOG *log;

    if (sct == NULL) {
        CTerr(CT_F_CT_VALIDATE_SCT, CT_R_NULL_INPUT);
        goto err;
    }
    if (cert == NULL) {
        CTerr(CT_F_CT_VALIDATE_SCT, CT_R_NULL_INPUT);
        goto err;
    }

    log = CT_get_log_by_id(ctx, sct->log_id);
    if (log == NULL) {
        sct->validation_status = CT_STATUS_UNKNOWN_LOG;
        goto end;
    } else {
        unsigned char *p;
        uint16_t entry_type;
        sct->log = log;
        if (sct->version != 0) {
            sct->validation_status = CT_STATUS_UNKNOWN_VERSION;
            goto end;
        }
        if (sct->source == CT_X509V3_EXTENSION) {
            int tbs_cert_len = i2d_X509(cert, &copybuffer);
            entry_type = 1;
            if (tbs_cert_len < 1) {
                CTerr(CT_F_CT_VALIDATE_SCT, CT_R_X509_ERROR);
                goto err;
            } else {
                const unsigned char *pp = copybuffer;
                /* cheap trick to get a copy */
                tbs = d2i_X509(NULL, &pp, tbs_cert_len);
                if (tbs == NULL) {
                    CTerr(CT_F_CT_VALIDATE_SCT, CT_R_X509_ERROR);
                    goto err;
                } else {
                    int count_exts = tbs->cert_info->extensions ?
                          sk_X509_EXTENSION_num(tbs->cert_info->extensions) : 0;
                    int i;
                    for (i = 0; i < count_exts; i++) {
                        X509_EXTENSION *ext = sk_X509_EXTENSION_value(
                                                 tbs->cert_info->extensions, i);
                        if (ext) {
                            ASN1_OBJECT *obj = X509_EXTENSION_get_object(ext);
                            if (obj) {
                                if (OBJ_obj2nid(obj) == NID_ct_precert_scts) {
                                    sk_X509_EXTENSION_delete(
                                               tbs->cert_info->extensions, i--);
                                    count_exts -= 1;
                                    X509_EXTENSION_free(ext);
                                }
                            }
                        }
                    }
                    cert_len = i2d_re_X509_tbs(tbs, NULL);
                    len_needed = 32 + 3 + cert_len;
                }
            }
        } else {
            entry_type = 0;
            cert_len = i2d_X509(cert, NULL);
            if (cert_len < 1) {
                CTerr(CT_F_CT_VALIDATE_SCT, CT_R_X509_ERROR);
                goto err;
            }
            len_needed = 3 + cert_len;
        }
        total_len = 1 + 1 + 8 + 2 + len_needed + 2 + sct->extensions_length;
        data = OPENSSL_malloc(total_len);
        if (data == NULL) {
            CTerr(CT_F_CT_VALIDATE_SCT, CT_R_SCT_MALLOC_FAILED);
            goto err;
        }
        p = data;
        *p++ = sct->version; /* version */
        *p++ = 0; /* sig type */
        *p++ = (sct->timestamp >> 56) & 0xff;
        *p++ = (sct->timestamp >> 48) & 0xff;
        *p++ = (sct->timestamp >> 40) & 0xff;
        *p++ = (sct->timestamp >> 32) & 0xff;
        *p++ = (sct->timestamp >> 24) & 0xff;
        *p++ = (sct->timestamp >> 16) & 0xff;
        *p++ = (sct->timestamp >> 8) & 0xff;
        *p++ = sct->timestamp & 0xff;
        *p++ = (entry_type >> 8) & 0xff; /* entry type (2 bytes) */
        *p++ = entry_type & 0xff;
        if (sct->source == CT_X509V3_EXTENSION) {
            if (pkey == NULL) {
                /*
                 * TODO(aeijdenberg): should we throw error or not?
                 * pubkey is not set if "-verify" is not called.
                 * For now, let's say no, but call the SCT unverified.
                 */
                sct->validation_status = CT_STATUS_UNVERIFIED;
                goto end;
            } else {
                pkeylen = i2d_PUBKEY(pkey, &pkeybuffer);
                if (pkeylen < 1) {
                    CTerr(CT_F_CT_VALIDATE_SCT, CT_R_X509_ERROR);
                    goto err;
                } else {
                    SHA256(pkeybuffer, pkeylen, p);
                    p += 32;
                }
            }
        }
        *p++ = (cert_len >> 16) & 0xff;
        *p++ = (cert_len >> 8) & 0xff;
        *p++ = cert_len & 0xff;
        if (sct->source == CT_X509V3_EXTENSION) {
            if (i2d_re_X509_tbs(tbs, &p) != cert_len) {
                CTerr(CT_F_CT_VALIDATE_SCT, CT_R_X509_ERROR);
                goto err;
            }
        } else {
            if (i2d_X509(cert, &p) != cert_len) {
                CTerr(CT_F_CT_VALIDATE_SCT, CT_R_X509_ERROR);
                goto err;
            }
        }
        *p++ = (sct->extensions_length >> 8) & 0xff; /* extension data */
        *p++ = sct->extensions_length & 0xff;
        if (sct->extensions_length) {
            memcpy(p, sct->extensions, sct->extensions_length);
            p += sct->extensions_length;
        }

        if (sct->signature_length && CT_validate_signature(log, data, total_len,
            sct->signature, sct->signature_length, sct->hash_algorithm))
            sct->validation_status = CT_STATUS_VALID;
        else
            sct->validation_status = CT_STATUS_INVALID;
    }

end:
    rv = 1;
err:
    if (data) {
        OPENSSL_free(data);
        data = NULL;
    }
    if (copybuffer) {
        OPENSSL_free(copybuffer);
        copybuffer = NULL;
    }
    if (tbs) {
        X509_free(tbs);
        tbs = NULL;
    }
    if (pkeybuffer) {
        OPENSSL_free(pkeybuffer);
        pkeybuffer = NULL;
    }
    return rv;
}

EVP_PKEY *CT_get_public_key_that_signed(X509_STORE_CTX *ctx)
{
    EVP_PKEY *rv = NULL;
    X509 *cert = NULL;
    int i;

    if (ctx == NULL)
        goto err;

    cert = ctx->cert;
    if (cert == NULL)
        goto err;
    rv = X509_get_pubkey(cert);
    if (rv && (X509_verify(cert, rv) == 1))
        goto end;
    else
        ERR_clear_error(); /* big whoop, didn't expect this to pass anyway */

    if (rv != NULL) {
        EVP_PKEY_free(rv);
        rv = NULL;
    }

    if (ctx->chain == NULL)
        goto end;

    for (i = 0; i < sk_X509_num(ctx->chain); i++) {
        rv = X509_get_pubkey(sk_X509_value(ctx->chain, i));
        if (rv && (X509_verify(cert, rv) == 1)) {
            goto end;
        } else
            ERR_clear_error(); /* no biggie, though curious why first doesn't pass */
        if (rv != NULL) {
            EVP_PKEY_free(rv);
            rv = NULL;
        }
    }
end:
err:
    return rv;
}

/*
 * Called after ServerHelloDone. If 1 is not returned, connection is failed.
 */
int CT_validate_connection(SSL *s)
{
    int fail_on_err = 0;
    int rv = 0;
    int parse_scts = 0;
    int min_needed = 0;
    int bad_count = 0;

    /* This shouldn't be called if policy is NONE, but just in case,
         and just in case the rest don't evaluate to the same... */
    if ((s == NULL) || s->tlsext_ct_policy == CT_POLICY_NONE)
        return 1;

    /* Enforce policy */
    switch (s->tlsext_ct_policy) {
    case CT_POLICY_REQUIRE_ONE:
        min_needed = 1;
        /* deliberately no break, should inherit what request gives you */
    case CT_POLICY_REQUEST:
        parse_scts = 1;
        fail_on_err = 1;
    case CT_POLICY_NONE:
         break; /* nothing */
    }
    if (s == NULL) {
        CTerr(CT_F_CT_VALIDATE_CONNECTION, CT_R_NULL_INPUT);
    } else {
        int successful_validated_count = 0;
        if (parse_scts) {
            STACK_OF(CTSCT) *scts = SSL_get_peer_scts(s);
            int count_scts = scts ? sk_CTSCT_num(scts) : 0;
            int i;
            for (i = 0; i < count_scts; i++) {
                CTSCT *sct = sk_CTSCT_value(scts, i);
                if (sct && s->session && s->session->peer) {
                    if (CT_validate_sct(sct, s->session->peer, s->tlsext_sct_par_pkey,
                                        s->ctx) != 1)
                        goto err;
                    switch (sct->validation_status) {
                    case CT_STATUS_VALID:
                        /* TODO(aeijdenberg): de-dupe? */
                        successful_validated_count += 1;
                    break;
                    case CT_STATUS_INVALID:
                        bad_count += 1;
                    break;
                    default: /* do nothing */
                    break;
                    }
                }
            }
        }
        if (successful_validated_count < min_needed) {
            CTerr(CT_F_CT_VALIDATE_CONNECTION, CT_R_NOT_ENOUGH_SCTS);
            goto err;
        }
    }

    rv = bad_count ? 0 : 1;
err:
    return fail_on_err ? rv : 1;
}

/* Written by Rob Stradling (rob@comodo.com) "v3_scts.c" */
static void tls12_signature_print(BIO *out, const unsigned char hash_alg,
                                  const unsigned char sig_alg)
{
    int nid = NID_undef;
    /* RFC6962 only permits two signature algorithms */
    if (hash_alg == TLSEXT_hash_sha256) {
        if (sig_alg == TLSEXT_signature_rsa)
            nid = NID_sha256WithRSAEncryption;
        else if (sig_alg == TLSEXT_signature_ecdsa)
            nid = NID_ecdsa_with_SHA256;
    }
    if (nid == NID_undef)
        BIO_printf(out, "%02X%02X", hash_alg, sig_alg);
    else
        BIO_printf(out, "%s", OBJ_nid2ln(nid));
}

/* Written by Rob Stradling (rob@comodo.com) "v3_scts.c" */
static void timestamp_print(BIO *out, uint64_t timestamp)
{
    ASN1_GENERALIZEDTIME *gen;
    char genstr[20];
    gen = ASN1_GENERALIZEDTIME_new();
    ASN1_GENERALIZEDTIME_adj(gen, (time_t)0,
                             (int)(timestamp / 86400000),
                             (timestamp % 86400000) / 1000);
    /*
     * Note GeneralizedTime from ASN1_GENERALIZETIME_adj is always 15
     * characters long with a final Z. Update it with fractional seconds.
     */
    BIO_snprintf(genstr, sizeof(genstr), "%.14s.%03dZ",
                 ASN1_STRING_data(gen), (unsigned int)(timestamp % 1000));
    ASN1_GENERALIZEDTIME_set_string(gen, genstr);
    ASN1_GENERALIZEDTIME_print(out, gen);
    ASN1_GENERALIZEDTIME_free(gen);
}

/* Adopted from code by Rob Stradling (rob@comodo.com) "v3_scts.c" */
void CT_print_sct(BIO *out, CTSCT *sct)
{
    int indent = 0;

    BIO_printf(out, "%*sVersion   : v%i(%i)", indent + 4, "", sct->version + 1,
               sct->version);

    switch (sct->source) {
    case CT_TLS_EXTENSION:
        BIO_printf(out, "\n%*sSource    : TLS Extension", indent + 4, "");
        break;
    case CT_X509V3_EXTENSION:
        BIO_printf(out, "\n%*sSource    : X509v3 Extension", indent + 4, "");
        break;
    case CT_OCSP_STAPLED_RESPONSE:
        BIO_printf(out, "\n%*sSource    : OCSP Stapled Response",
                                                            indent + 4, "");
        break;
    case CT_SOURCE_UNKNOWN:
        BIO_printf(out, "\n%*sSource    : Unknown",
                                                            indent + 4, "");
        break;
    }

    BIO_printf(out, "\n%*sLog ID    : ", indent + 4, "");
    BIO_hex_string(out, indent + 16, 16, sct->log_id, SCT_LOG_ID_LENGTH);

    BIO_printf(out, "\n%*sTimestamp : ", indent + 4, "");
    timestamp_print(out, sct->timestamp);
    BIO_printf(out, " (%"PRId64")", sct->timestamp);

    BIO_printf(out, "\n%*sExtensions: ", indent + 4, "");
    BIO_hex_string(out, indent + 16, 16, sct->extensions, sct->extensions_length);

    BIO_printf(out, "\n%*sSignature : ", indent + 4, "");
    tls12_signature_print(out, sct->hash_algorithm, sct->signature_algorithm);
    BIO_printf(out, "\n%*s            ", indent + 4, "");
    BIO_hex_string(out, indent + 16, 16, sct->signature, sct->signature_length);
    BIO_printf(out, "\n%*sLog       : ", indent + 4, "");
    if (sct->log)
        BIO_printf(out, "%.*s", sct->log->name_len, sct->log->name);
    else
        BIO_printf(out, "Unknown");

    BIO_printf(out, "\n%*sStatus    : ", indent + 4, "");
    switch (sct->validation_status) {
    case CT_STATUS_NONE:
        BIO_printf(out, "Unattempted");
        break;
    case CT_STATUS_UNKNOWN_VERSION:
        BIO_printf(out, "Unrecognized SCT version - unable to validate");
        break;
    case CT_STATUS_UNKNOWN_LOG:
        BIO_printf(out, "Unrecognized log - unable to validate");
        break;
    case CT_STATUS_UNVERIFIED:
        BIO_printf(out, "Cert chain not verified - unable to validate");
        break;
    case CT_STATUS_VALID:
        BIO_printf(out, "Valid - success!");
        break;
    case CT_STATUS_INVALID:
        BIO_printf(out, "Invalid - failure!");
        break;
    }
    BIO_printf(out, "\n");
}
