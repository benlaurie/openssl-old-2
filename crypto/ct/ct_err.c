/* crypto/ct/ct_err.c */
/* ====================================================================
 * Copyright (c) 1999-2015 The OpenSSL Project.  All rights reserved.
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
 *    for use in the OpenSSL Toolkit. (http://www.OpenSSL.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    openssl-core@OpenSSL.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.OpenSSL.org/)"
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

/*
 * NOTE: this file was auto generated by the mkerr.pl script: any changes
 * made to it will be overwritten when the script next updates this file,
 * only reason strings will be preserved.
 */

#include <stdio.h>
#include <openssl/err.h>
#include <openssl/ct.h>

/* BEGIN ERROR CODES */
#ifndef OPENSSL_NO_ERR

# define ERR_FUNC(func) ERR_PACK(ERR_LIB_CT,func,0)
# define ERR_REASON(reason) ERR_PACK(ERR_LIB_CT,0,reason)

static ERR_STRING_DATA CT_str_functs[] = {
    {ERR_FUNC(CT_F_CTLOG_CREATE_LOG_FROM_JSON_FRAGMENT),
     "CTLOG_CREATE_LOG_FROM_JSON_FRAGMENT"},
    {ERR_FUNC(CT_F_CTLOG_STORE_LOAD_FILE), "CTLOG_STORE_load_file"},
    {ERR_FUNC(CT_F_CTLOG_WRITE_BIO), "CTLOG_WRITE_BIO"},
    {ERR_FUNC(CT_F_CTSCT_ALLOC), "CTSCT_alloc"},
    {ERR_FUNC(CT_F_CT_BASE64_DECODE), "CT_base64_decode"},
    {ERR_FUNC(CT_F_CT_BASE64_ENCODE), "CT_BASE64_ENCODE"},
    {ERR_FUNC(CT_F_CT_JSON_COMPLETE_ARRAY), "CT_JSON_COMPLETE_ARRAY"},
    {ERR_FUNC(CT_F_CT_JSON_COMPLETE_DICT), "CT_JSON_COMPLETE_DICT"},
    {ERR_FUNC(CT_F_CT_PARSE_JSON), "CT_parse_json"},
    {ERR_FUNC(CT_F_CT_PARSE_SCT), "CT_parse_sct"},
    {ERR_FUNC(CT_F_CT_PARSE_SCT_BIO), "CT_PARSE_SCT_BIO"},
    {ERR_FUNC(CT_F_CT_PARSE_SCT_LIST), "CT_parse_sct_list"},
    {ERR_FUNC(CT_F_CT_PARSE_SCT_LIST_FROM_X509_EXTENSION),
     "CT_PARSE_SCT_LIST_FROM_X509_EXTENSION"},
    {ERR_FUNC(CT_F_CT_SERVER_INFO_ENCODE_SCT_LIST_BIO),
     "CT_SERVER_INFO_ENCODE_SCT_LIST_BIO"},
    {ERR_FUNC(CT_F_CT_TLS_ENCODE_SCT_BIO), "CT_TLS_ENCODE_SCT_BIO"},
    {ERR_FUNC(CT_F_CT_TLS_ENCODE_SCT_LIST_BIO), "CT_TLS_ENCODE_SCT_LIST_BIO"},
    {ERR_FUNC(CT_F_CT_VALIDATE_CONNECTION), "CT_validate_connection"},
    {ERR_FUNC(CT_F_CT_VALIDATE_SCT), "CT_VALIDATE_SCT"},
    {ERR_FUNC(CT_F_CT_VALIDATE_SIGNATURE), "CT_VALIDATE_SIGNATURE"},
    {ERR_FUNC(CT_F_SSL_APPLY_CERTIFICATE_TRANSPARENCY_POLICY),
     "SSL_apply_certificate_transparency_policy"},
    {ERR_FUNC(CT_F_SSL_CTX_APPLY_CERTIFICATE_TRANSPARENCY_POLICY),
     "SSL_CTX_apply_certificate_transparency_policy"},
    {ERR_FUNC(CT_F_SSL_GET_PEER_SCTS), "SSL_get_peer_scts"},
    {0, NULL}
};

static ERR_STRING_DATA CT_str_reasons[] = {
    {ERR_REASON(CT_R_BAD_WRITE), "bad write"},
    {ERR_REASON(CT_R_CT_JSON_PARSE_ERROR), "ct json parse error"},
    {ERR_REASON(CT_R_CT_JSON_PARSE_MORE_THAN_ONE_OBJECT),
     "ct json parse more than one object"},
    {ERR_REASON(CT_R_CT_JSON_PARSE_UNICODE_NOT_SUPPORTED),
     "ct json parse unicode not supported"},
    {ERR_REASON(CT_R_CUSTOM_EXT_HANDLER_ALREADY_INSTALLED),
     "custom ext handler already installed"},
    {ERR_REASON(CT_R_ENCODE_ERROR), "encode error"},
    {ERR_REASON(CT_R_ENCODE_FAILURE), "encode failure"},
    {ERR_REASON(CT_R_LOG_ERROR), "log error"},
    {ERR_REASON(CT_R_MEM_ERR), "mem err"},
    {ERR_REASON(CT_R_NOT_ENOUGH_SCTS), "not enough scts"},
    {ERR_REASON(CT_R_NULL_INPUT), "null input"},
    {ERR_REASON(CT_R_SCT_DIGEST_VERIFY_ERROR), "sct digest verify error"},
    {ERR_REASON(CT_R_SCT_LIST_INVALID_SCT),
     "invalid SCT, even before trying to parse it"},
    {ERR_REASON(CT_R_SCT_LIST_MALLOC_FAILED), "sct list malloc failed"},
    {ERR_REASON(CT_R_SCT_LIST_UNEXPECTED_EOF),
     "remaining SCT list data shorter than amount needed"},
    {ERR_REASON(CT_R_SCT_MALLOC_FAILED), "sct malloc failed"},
    {ERR_REASON(CT_R_SCT_UNEXPECTED_EOF),
     "remaining SCT data shorter than amount needed"},
    {ERR_REASON(CT_R_SCT_UNRECOGNIZED_EXTENSION),
     "unrecognized SCT extension"},
    {ERR_REASON(CT_R_SCT_UNRECOGNIZED_HASH_ALGORITHM),
     "unrecognized hash algorithm in SCT"},
    {ERR_REASON(CT_R_SCT_UNRECOGNIZED_SIGNATURE_ALGORITHM),
     "unrecognized signature algorithm in SCT"},
    {ERR_REASON(CT_R_SCT_UNRECOGNIZED_VERSION), "unrecognized SCT version"},
    {ERR_REASON(CT_R_X509V3_INVALID_EXTENSION), "x509v3 invalid extension"},
    {ERR_REASON(CT_R_X509_ERROR), "x509 error"},
    {0, NULL}
};

#endif

void ERR_load_CT_strings(void)
{
#ifndef OPENSSL_NO_ERR

    if (ERR_func_error_string(CT_str_functs[0].error) == NULL) {
        ERR_load_strings(0, CT_str_functs);
        ERR_load_strings(0, CT_str_reasons);
    }
#endif
}
