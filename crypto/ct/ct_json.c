/* crypto/ct/ct_json.c */
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

#include "crypto/ct/ct_local.h"



int CT_json_write_string(BIO *out, char *data, int len)
{
    int i;

    if ((out == NULL) || (data == NULL) || (len < 0))
        goto err;

    if (BIO_write(out, "\"", 1) != 1)
        goto err;

    for (i = 0; i < len; i++, data++) {
        switch (*data) {
        case 0x22:
            if (BIO_write(out, "\\\"", 2) != 2)
                goto err;
            break;
        case 0x5C:
            if (BIO_write(out, "\\\\", 2) != 2)
                goto err;
            break;
        case 0x08:
            if (BIO_write(out, "\\b", 2) != 2)
                goto err;
            break;
        case 0x0C:
            if (BIO_write(out, "\\f", 2) != 2)
                goto err;
            break;
        case 0x0A:
            if (BIO_write(out, "\\n", 2) != 2)
                goto err;
            break;
        case 0x0D:
            if (BIO_write(out, "\\r", 2) != 2)
                goto err;
            break;
        case 0x09:
            if (BIO_write(out, "\\t", 2) != 2)
                goto err;
            break;
        default:
            if (BIO_write(out, data, 1) != 1)
                goto err;
        }
    }
    if (BIO_write(out, "\"", 1) != 1)
        goto err;
err:
    return 0;
}

void JSON_FRAGMENT_free(JSON_FRAGMENT *f)
{
    if (f) {
        if (f->buffer) {
            BUF_MEM_free(f->buffer);
            f->buffer = NULL;
        }
        if (f->name) {
            JSON_FRAGMENT_free(f->name);
            f->name = NULL;
        }
        if (f->value) {
            JSON_FRAGMENT_free(f->value);
            f->value = NULL;
        }
        if (f->children) {
            sk_JSON_FRAGMENT_pop_free(f->children, JSON_FRAGMENT_free);
            f->children = NULL;
        }
        OPENSSL_free(f);
    }
}


JSON_FRAGMENT *JSON_FRAGMENT_alloc(json_token_type t)
{
    JSON_FRAGMENT *rv = OPENSSL_malloc(sizeof(JSON_FRAGMENT));
    if (rv == NULL)
        goto err;
    rv->type = t;
    rv->buffer = NULL;
    rv->children = NULL;
    rv->name = NULL;
    rv->value = NULL;

    return rv;
err:
    if (rv) {
        JSON_FRAGMENT_free(rv);
        rv = NULL;
    }
    return NULL;
}

/*
 * Pop elements off stack until DICT_BEG to construct object
 * return 1 on success, 0 on failure.
 */
int CT_json_complete_array(STACK_OF(JSON_FRAGMENT) *frags)
{
    JSON_FRAGMENT *p = NULL;
    JSON_FRAGMENT *q = NULL;
    int done = 0;
    int substate = 0;
    int rv = 0;

    p = JSON_FRAGMENT_alloc(OBJ_ARRAY);
    if (p == NULL) {
        CTerr(CT_F_CT_JSON_COMPLETE_ARRAY, CT_R_CT_JSON_PARSE_ERROR);
        goto err;
    }
    p->children = sk_JSON_FRAGMENT_new_null();
    if (p->children == NULL) {
        CTerr(CT_F_CT_JSON_COMPLETE_ARRAY, CT_R_CT_JSON_PARSE_ERROR);
        goto err;
    }

    done = 0;
    substate = 0;
    while (sk_JSON_FRAGMENT_num(frags) && !done) {
        q = sk_JSON_FRAGMENT_pop(frags);
        if (q == NULL) {
            CTerr(CT_F_CT_JSON_COMPLETE_ARRAY, CT_R_CT_JSON_PARSE_ERROR);
            goto err;
        }
        switch (substate) {
        case 0:
            switch (q->type) {
            case ARR_BEG:
                JSON_FRAGMENT_free(q);
                q = NULL;
                sk_JSON_FRAGMENT_push(frags, p);
                p = NULL;
                done = 1;
                break;
            case OBJ_ARRAY:
            case OBJ_DICT:
            case VAL_TRUE:
            case VAL_FALSE:
            case VAL_NULL:
            case VAL_STRING:
            case VAL_NUMBER:
                sk_JSON_FRAGMENT_insert(p->children, q, 0);
                q = NULL;
                substate = 1;
                break;
            default:
                CTerr(CT_F_CT_JSON_COMPLETE_ARRAY,
                      CT_R_CT_JSON_PARSE_ERROR);
                goto err;
            }
            break;
        case 1:
            switch (q->type) {
            case SEP_VAL:
                JSON_FRAGMENT_free(q);
                q = NULL;
                substate = 0;
                break;
            case ARR_BEG:
                sk_JSON_FRAGMENT_push(frags, q);
                q = NULL;
                substate = 0;
                break;
            default:
                CTerr(CT_F_CT_JSON_COMPLETE_ARRAY,
                      CT_R_CT_JSON_PARSE_ERROR);
                goto err;
            }
            break;
        }
    }
    if (!done) {
        CTerr(CT_F_CT_JSON_COMPLETE_ARRAY, CT_R_CT_JSON_PARSE_ERROR);
        goto err;
    }

    rv = 1;
err:
    if (p) {
        JSON_FRAGMENT_free(p);
        p = NULL;
    }
    if (q) {
        JSON_FRAGMENT_free(q);
        q = NULL;
    }

    return rv;
}

/*
 * Pop elements off stack until DICT_BEG to construct object
 * Return 1 on success, 0 on failure.
 */
int CT_json_complete_dict(STACK_OF(JSON_FRAGMENT) *frags)
{
    JSON_FRAGMENT *p = NULL;
    JSON_FRAGMENT *q = NULL;
    JSON_FRAGMENT *nv = NULL;
    int done = 0;
    int substate = 0;
    int rv = 0;

    p = JSON_FRAGMENT_alloc(OBJ_DICT);
    if (p == NULL) {
        CTerr(CT_F_CT_JSON_COMPLETE_DICT, CT_R_CT_JSON_PARSE_ERROR);
        goto err;
    }
    p->children = sk_JSON_FRAGMENT_new_null();
    if (p->children == NULL) {
        CTerr(CT_F_CT_JSON_COMPLETE_DICT, CT_R_CT_JSON_PARSE_ERROR);
        goto err;
    }

    while (sk_JSON_FRAGMENT_num(frags) && !done) {
        q = sk_JSON_FRAGMENT_pop(frags);
        if (q == NULL) {
            CTerr(CT_F_CT_JSON_COMPLETE_DICT, CT_R_CT_JSON_PARSE_ERROR);
            goto err;
        }
        switch (substate) {
        case 0:
            switch (q->type) {
            case DICT_BEG:
                JSON_FRAGMENT_free(q);
                q = NULL;
                sk_JSON_FRAGMENT_push(frags, p);
                p = NULL;
                done = 1;
                break;
            case OBJ_ARRAY:
            case OBJ_DICT:
            case VAL_TRUE:
            case VAL_FALSE:
            case VAL_NULL:
            case VAL_STRING:
            case VAL_NUMBER:
                nv = JSON_FRAGMENT_alloc(NAME_VAL);
                if (nv == NULL) {
                    CTerr(CT_F_CT_JSON_COMPLETE_DICT,
                          CT_R_CT_JSON_PARSE_ERROR);
                    goto err;
                }
                nv->value = q;
                q = NULL;
                substate = 1;
                break;
            default:
                CTerr(CT_F_CT_JSON_COMPLETE_DICT,
                      CT_R_CT_JSON_PARSE_ERROR);
                goto err;
            }
            break;
        case 1:
            switch (q->type) {
            case SEP_NAME:
                JSON_FRAGMENT_free(q);
                q = NULL;
                substate = 2;
                break;
            default:
                CTerr(CT_F_CT_JSON_COMPLETE_DICT,
                      CT_R_CT_JSON_PARSE_ERROR);
                goto err;
            }
            break;
        case 2:
            switch (q->type) {
            case VAL_STRING:
                nv->name = q;
                q = NULL;
                sk_JSON_FRAGMENT_insert(p->children, nv, 0);
                nv = NULL;
                substate = 3;
                break;
            default:
                CTerr(CT_F_CT_JSON_COMPLETE_DICT,
                      CT_R_CT_JSON_PARSE_ERROR);
                goto err;
            }
            break;
        case 3:
            switch (q->type) {
            case SEP_VAL:
                JSON_FRAGMENT_free(q);
                q = NULL;
                substate = 0;
                break;
            case DICT_BEG:
                sk_JSON_FRAGMENT_push(frags, q);
                q = NULL;
                substate = 0;
                break;
            default:
                CTerr(CT_F_CT_JSON_COMPLETE_DICT,
                      CT_R_CT_JSON_PARSE_ERROR);
                goto err;
            }
            break;
        }
    }
    if (!done) {
        CTerr(CT_F_CT_JSON_COMPLETE_DICT, CT_R_CT_JSON_PARSE_ERROR);
        goto err;
    }

    rv = 1;
err:
    if (p) {
        JSON_FRAGMENT_free(p);
        p = NULL;
    }
    if (q) {
        JSON_FRAGMENT_free(q);
        q = NULL;
    }
    if (nv) {
        JSON_FRAGMENT_free(nv);
        nv = NULL;
    }

    return rv;
}

JSON_FRAGMENT *CT_parse_json(char *data, uint32_t len)
{
    JSON_FRAGMENT *rv = NULL;
    uint32_t i;
    int state = 0;
    BIO *curbuf = NULL;
    char add_ch;
    JSON_FRAGMENT *f = NULL;
    STACK_OF(JSON_FRAGMENT) *frags = sk_JSON_FRAGMENT_new_null();
    if (frags == NULL)
        goto err;
    for (i = 0; i < len; i++, data++) {
        switch (state) {
        case 0:
            switch (*data) {
            case '{':
                sk_JSON_FRAGMENT_push(frags,
                                      JSON_FRAGMENT_alloc(DICT_BEG));
                break;
            case '}':
                if (CT_json_complete_dict(frags) != 1)
                    goto err;
                break;
            case '[':
                sk_JSON_FRAGMENT_push(frags,
                                      JSON_FRAGMENT_alloc(ARR_BEG));
                break;
            case ']':
                if (CT_json_complete_array(frags) != 1)
                    goto err;
                break;
            case 0x20: case 0x09: case 0x0a: case 0x0d:
                break;
            case ':':
                sk_JSON_FRAGMENT_push(frags,
                                      JSON_FRAGMENT_alloc(SEP_NAME));
                break;
            case ',':
                sk_JSON_FRAGMENT_push(frags,
                                      JSON_FRAGMENT_alloc(SEP_VAL));
                break;
            case 'f':
                if (((i + 4) < len) && (*(data + 1) == 'a') &&
                    (*(data + 2) == 'l') && (*(data + 3) == 's') &&
                    (*(data + 4) == 'e')) {
                    data += 4;
                    i += 4;
                    sk_JSON_FRAGMENT_push(frags,
                                        JSON_FRAGMENT_alloc(VAL_FALSE));
                } else {
                    CTerr(CT_F_CT_PARSE_JSON, CT_R_CT_JSON_PARSE_ERROR);
                    goto err;
                }
                break;
            case 't':
                if (((i + 3) < len) && (*(data + 1) == 'r') &&
                    (*(data + 2) == 'u') && (*(data + 3) == 'e')) {
                    data += 3;
                    i += 3;
                    sk_JSON_FRAGMENT_push(frags,
                                         JSON_FRAGMENT_alloc(VAL_TRUE));
                } else {
                    CTerr(CT_F_CT_PARSE_JSON, CT_R_CT_JSON_PARSE_ERROR);
                    goto err;
                }
                break;
            case 'n':
                if (((i + 3) < len) && (*(data + 1) == 'u') &&
                    (*(data + 2) == 'l') && (*(data + 3) == 'l')) {
                    data += 3;
                    i += 3;
                    sk_JSON_FRAGMENT_push(frags,
                                         JSON_FRAGMENT_alloc(VAL_NULL));
                } else {
                    CTerr(CT_F_CT_PARSE_JSON, CT_R_CT_JSON_PARSE_ERROR);
                    goto err;
                }
                break;
            case '-': case '0': case '1': case '2': case '3': case '4':
            case '5': case '6': case '7': case '8': case '9':
                if (curbuf) {
                    CTerr(CT_F_CT_PARSE_JSON, CT_R_CT_JSON_PARSE_ERROR);
                    goto err;
                }
                curbuf = BIO_new(BIO_s_mem());
                if (curbuf == NULL) {
                    CTerr(CT_F_CT_PARSE_JSON, CT_R_CT_JSON_PARSE_ERROR);
                    goto err;
                }
                if (BIO_write(curbuf, data, 1) != 1) {
                    CTerr(CT_F_CT_PARSE_JSON, CT_R_CT_JSON_PARSE_ERROR);
                    goto err;
                }
                state = 3;
                break;
            case '"':
                if (curbuf) {
                    CTerr(CT_F_CT_PARSE_JSON, CT_R_CT_JSON_PARSE_ERROR);
                    goto err;
                }
                curbuf = BIO_new(BIO_s_mem());
                if (curbuf == NULL) {
                    CTerr(CT_F_CT_PARSE_JSON, CT_R_CT_JSON_PARSE_ERROR);
                    goto err;
                }
                state = 1;
                break;
            default:
                CTerr(CT_F_CT_PARSE_JSON, CT_R_CT_JSON_PARSE_ERROR);
                goto err;
            }
            break;
        case 1: /* in string */
            switch (*data) {
            case '\\':
                state = 2;
                break;
            case '"':
                f = JSON_FRAGMENT_alloc(VAL_STRING);
                if (f == NULL) {
                    CTerr(CT_F_CT_PARSE_JSON, CT_R_CT_JSON_PARSE_ERROR);
                    goto err;
                }
                BIO_get_mem_ptr(curbuf, &f->buffer);
                /* don't free on close */
                if (BIO_set_close(curbuf, BIO_NOCLOSE) != 1) {
                    CTerr(CT_F_CT_PARSE_JSON, CT_R_CT_JSON_PARSE_ERROR);
                    goto err;
                }
                BIO_free_all(curbuf);
                curbuf = NULL;

                sk_JSON_FRAGMENT_push(frags, f);
                f = NULL;

                curbuf = NULL;
                state = 0;
                break;
            default:
                if (BIO_write(curbuf, data, 1) != 1) {
                    CTerr(CT_F_CT_PARSE_JSON, CT_R_CT_JSON_PARSE_ERROR);
                    goto err;
                }
            }
            break;
        case 2: /* escape string */
            switch (*data) {
            case '"':
                add_ch = '"';
                break;
            case '\\':
                add_ch = '\\';
                break;
            case '/':
                add_ch = '/';
                break;
            case 'b':
                add_ch = '\b';
                break;
            case 'f':
                add_ch = '\f';
                break;
            case 'n':
                add_ch = '\n';
                break;
            case 'r':
                add_ch = '\r';
                break;
            case 't':
                add_ch = '\t';
                break;
            case 'u':
                CTerr(CT_F_CT_PARSE_JSON,
                      CT_R_CT_JSON_PARSE_UNICODE_NOT_SUPPORTED);
                goto err;
            default:
                add_ch = *data;
            }
            if (BIO_write(curbuf, &add_ch, 1) != 1) {
                CTerr(CT_F_CT_PARSE_JSON, CT_R_CT_JSON_PARSE_ERROR);
                goto err;
            }
            state = 1;
            break;
        case 3:
            switch (*data) {
            case '-': case '0': case '1': case '2': case '3': case '4':
            case '5': case '6': case '7': case '8': case '9': case '+':
            case 'E': case 'e': case '.':
                if (BIO_write(curbuf, data, 1) != 1) {
                    CTerr(CT_F_CT_PARSE_JSON, CT_R_CT_JSON_PARSE_ERROR);
                    goto err;
                }
                break;
            default: /* reset and backtrack */
                f = JSON_FRAGMENT_alloc(VAL_NUMBER);
                if (f == NULL) {
                    CTerr(CT_F_CT_PARSE_JSON, CT_R_CT_JSON_PARSE_ERROR);
                    goto err;
                }
                BIO_get_mem_ptr(curbuf, &f->buffer);
                if (BIO_set_close(curbuf, BIO_NOCLOSE) != 1) {
                    CTerr(CT_F_CT_PARSE_JSON, CT_R_CT_JSON_PARSE_ERROR);
                    goto err;
                }
                BIO_free_all(curbuf);
                curbuf = NULL;

                sk_JSON_FRAGMENT_push(frags, f);
                f = NULL;
                data--;
                i--;
                state = 0;
            }
            break;
        }
    }

    if (sk_JSON_FRAGMENT_num(frags) == 1) {
        rv = sk_JSON_FRAGMENT_pop(frags);
    } else {
        printf("elements %i\n", sk_JSON_FRAGMENT_num(frags));
        CTerr(CT_F_CT_PARSE_JSON, CT_R_CT_JSON_PARSE_MORE_THAN_ONE_OBJECT);
        goto err;
    }

err:
    if (frags) {
        sk_JSON_FRAGMENT_pop_free(frags, JSON_FRAGMENT_free);
        frags = NULL;
    }
    if (curbuf) {
        BIO_free_all(curbuf);
        curbuf = NULL;
    }

    return rv;
}

JSON_FRAGMENT *CT_json_get_value(JSON_FRAGMENT *par, char *key)
{
    uint32_t kl = strlen(key);
    if (par && par->type == OBJ_DICT && par->children) {
        int i;
        for (i = 0; i < sk_JSON_FRAGMENT_num(par->children); i++) {
            JSON_FRAGMENT *child = sk_JSON_FRAGMENT_value(par->children, i);
            if (child && child->type == NAME_VAL && child->name &&
                child->name->type == VAL_STRING && child->name->buffer) {
                if (child->name->buffer->length == kl) {
                    if (memcmp(child->name->buffer->data, key, kl) == 0)
                        return child->value;
                }
            }
        }
    }
    return NULL;
}

void CT_base64_decode(char *in, uint16_t in_len,
                      char **out, uint16_t *out_len)
{
    BIO *b64 = NULL, *bmem = NULL;

    b64 = BIO_new(BIO_f_base64());
    if (b64 == NULL) {
        CTerr(CT_F_CT_BASE64_DECODE, ERR_R_SYS_LIB);
        goto err;
    }
    bmem = BIO_new_mem_buf(in, in_len);
    if (bmem == NULL) {
        CTerr(CT_F_CT_BASE64_DECODE, ERR_R_SYS_LIB);
        goto err;
    }
	  BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);

    bmem = BIO_push(b64, bmem);
    b64 = NULL;

    *out = OPENSSL_malloc(in_len);
    if (*out == NULL)
        goto err;
    *out_len = BIO_read(bmem, *out, in_len);
err:
    if (b64) {
        BIO_free_all(b64);
        b64 = NULL;
    }
    if (bmem) {
        BIO_free_all(bmem);
        bmem = NULL;
    }
}

BUF_MEM *CT_base64_encode(BUF_MEM *in)
{
    BIO *b64 = NULL, *bmem = NULL;
    BUF_MEM *rv = NULL;

    b64 = BIO_new(BIO_f_base64());
    if (b64 == NULL) {
        CTerr(CT_F_CT_BASE64_ENCODE, ERR_R_SYS_LIB);
        goto err;
    }
    bmem = BIO_new(BIO_s_mem());
    if (bmem == NULL) {
        CTerr(CT_F_CT_BASE64_ENCODE, ERR_R_SYS_LIB);
        goto err;
    }
	  BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);

    b64 = BIO_push(b64, bmem);
    bmem = NULL;

    if (BIO_write(b64, in->data, in->length) != (signed int)in->length) {
        CTerr(CT_F_CT_BASE64_ENCODE, ERR_R_SYS_LIB);
        goto err;
    }

    if (BIO_flush(b64) != 1) {
        CTerr(CT_F_CT_BASE64_ENCODE, ERR_R_SYS_LIB);
        goto err;
    }
    BIO_get_mem_ptr(b64, &rv);

    /* So BIO_free() leaves BUF_MEM alone */
    if (BIO_set_close(b64, BIO_NOCLOSE) != 1) {
        CTerr(CT_F_CT_BASE64_ENCODE, ERR_R_SYS_LIB);
        goto err;
    }

err:
    if (b64) {
        BIO_free_all(b64);
        b64 = NULL;
    }
    if (bmem) {
        BIO_free_all(bmem);
        bmem = NULL;
    }
    return rv;
}
