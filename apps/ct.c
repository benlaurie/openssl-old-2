/*
 * Written by Adam Eijdenberg
 */
/* Copyright (C) 1995-1998 Eric Young (eay@cryptsoft.com)
 * All rights reserved.
 *
 * This package is an SSL implementation written
 * by Eric Young (eay@cryptsoft.com).
 * The implementation was written so as to conform with Netscapes SSL.
 *
 * This library is free for commercial and non-commercial use as long as
 * the following conditions are aheared to.  The following conditions
 * apply to all code found in this distribution, be it the RC4, RSA,
 * lhash, DES, etc., code; not just the SSL code.  The SSL documentation
 * included with this distribution is covered by the same copyright terms
 * except that the holder is Tim Hudson (tjh@cryptsoft.com).
 *
 * Copyright remains Eric Young's, and as such any Copyright notices in
 * the code are not to be removed.
 * If this package is used in a product, Eric Young should be given attribution
 * as the author of the parts of the library used.
 * This can be in the form of a textual message at program startup or
 * in documentation (online or textual) provided with the package.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *    "This product includes cryptographic software written by
 *     Eric Young (eay@cryptsoft.com)"
 *    The word 'cryptographic' can be left out if the rouines from the library
 *    being used are not cryptographic related :-).
 * 4. If you include any Windows specific code (or a derivative thereof) from
 *    the apps directory (application code) you must include an acknowledgement:
 *    "This product includes software written by Tim Hudson (tjh@cryptsoft.com)"
 *
 * THIS SOFTWARE IS PROVIDED BY ERIC YOUNG ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * The licence and distribution terms for any publically available version or
 * derivative of this code cannot be changed.  i.e. this code cannot simply be
 * copied and put under another distribution licence
 * [including the GNU Public Licence.]
 */

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include "apps.h"
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/asn1.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/objects.h>
#include <openssl/pem.h>
#include <openssl/bn.h>
#include "crypto/ct/ct_internal.h"


#define CT_SCT_PEM   "SIGNED CERTIFICATE TIMESTAMP"
#define CT_SI_PEM    "SERVERINFO FOR CT"
#define CT_CTLOG_PEM "CT LOG METADATA"

#define SECTION         "ct"

static int extract_public_key_hash(const EVP_PKEY *key, unsigned char *buf32);
static BUF_MEM *do_create_sct(X509 *cert, uint64_t ts, EVP_PKEY *key,
                              const X509 *cacert, int bogus_version,
                              int bogus_ext, int bogus_entry);
static STACK_OF(CTLOG) *load_ctlogs(const char *in_path, int in_form);
static int is_precert(const X509 *cert);

typedef enum OPTION_choice {
    OPT_ERR = -1, OPT_EOF = 0, OPT_HELP,
    OPT_CREATESCT, OPT_TEXT, OPT_CREATESERVERINFO, OPT_CREATELOGMETADATA,
    OPT_CREATELOGLIST,
    OPT_OUT, OPT_OUTFORM,
    OPT_IN, OPT_INFORM,
    OPT_KEY, OPT_KEYFORM,
    OPT_CACERT, OPT_CACERTFORM,
    OPT_NAME, OPT_BOGUS_VERSION, OPT_BOGUS_EXTENSIONS, OPT_BOGUS_ENTRYTYPE
} OPTION_CHOICE;

OPTIONS ct_options[] = {
    {"help", OPT_HELP, '-', "Display this summary"},

    {"createsct", OPT_CREATESCT, '-', "Create an SCT based on input cert"},
    {"createlogmetadata", OPT_CREATELOGMETADATA, '-', "Create log metadata based on key"},
    {"createloglist", OPT_CREATELOGLIST, '-', "Create log list based on list of metadata"},
    {"text", OPT_TEXT, '-', "Print an SCT based on input SCT"},
    {"createserverinfo", OPT_CREATESERVERINFO, '-', "Create a ServerInfo file based on input SCT list"},

    {"out", OPT_OUT, '>', "Output file location"},
    {"outform", OPT_OUTFORM, 'f', "Output file format (PEM(default) or TLS)"},

    {"in", OPT_IN, '<', "Input file location"},
    {"inform", OPT_INFORM, 'f', "Input file format (PEM(default) or DER)"},

    {"key", OPT_KEY, '<', "Key file location"},
    {"keyform", OPT_KEYFORM, 'f', "Input file format (PEM(default) or DER)"},

    {"cacert", OPT_CACERT, '<', "Certificate Authority Certificate file location"},
    {"cacertform", OPT_CACERTFORM, 'f', "Input file format (PEM(default) or DER)"},

    {"bogusversion", OPT_BOGUS_VERSION, '-', "Create SCT with a newer version than understood"},
    {"bogusextensions", OPT_BOGUS_EXTENSIONS, '-', "Create SCT bogus undefined extension data"},
    {"bogusentrytype", OPT_BOGUS_ENTRYTYPE, '-', "Create SCT bogus undefined entry type"},

    {"name", OPT_NAME, 's', "Name"},

    {NULL}
};

static int extract_public_key_hash(const EVP_PKEY *key, unsigned char *buf32)
{
    int rv = 0;
    BIO *tmp_key = NULL;
    BUF_MEM *tmp_ptr = NULL;

    if (key == NULL || buf32 == NULL)
        goto end;

    tmp_key = BIO_new(BIO_s_mem());
    if (tmp_key == NULL)
        goto end;

    if (i2d_PUBKEY_bio(tmp_key, key) != 1)
        goto end;

    BIO_get_mem_ptr(tmp_key, &tmp_ptr);
    SHA256((unsigned char *)tmp_ptr->data, tmp_ptr->length, buf32);

    rv = 1;

 end:
    BIO_free_all(tmp_key);

    return rv;
}

static STACK_OF(CTLOG) *load_ctlogs(const char *in_path, int in_form)
{
    STACK_OF(CTLOG) *rv = NULL;
    BIO *in = NULL;
    CTLOG *log = NULL;
    char *name = NULL;
    char *header = NULL;
    unsigned char *data = NULL;
    JSON_FRAGMENT *jf = NULL;

    if (in_path == NULL)
        goto end;

    in = bio_open_default(in_path, RB(in_form));
    if (in == NULL)
        goto end;

    rv = sk_CTLOG_new_null();
    if (rv == NULL)
        goto end;

    if (in_form == FORMAT_PEM) {
        long len = 0;
        while (PEM_read_bio(in, &name, &header, &data, &len) == 1) {
            if (strcmp(name, CT_CTLOG_PEM) == 0) {
                jf = CT_parse_json((char *)data, len);
                if (jf == NULL)
                    goto end;

                log = CTLOG_create_log_from_json_fragment(jf);
                if (log == NULL)
                    goto end;

                JSON_FRAGMENT_free(jf);
                jf = NULL;

                sk_CTLOG_push(rv, log);
                log = NULL;
            }
            OPENSSL_free(name);
            name = NULL;
            OPENSSL_free(header);
            header = NULL;
            OPENSSL_free(data);
            data = NULL;
        }
    }
    
end: 
    JSON_FRAGMENT_free(jf);
    CTLOG_free(log);
    BIO_free_all(in);
    OPENSSL_free(name);
    OPENSSL_free(header);
    OPENSSL_free(data);

    return rv;
}

STACK_OF(CTSCT) *load_scts(char *in_path, int in_form)
{
    STACK_OF(CTSCT) *rv = NULL;
    BIO *in = NULL;
    CTSCT *sct = NULL;
    char *name = NULL;
    char *header = NULL;
    unsigned char *data = NULL;

    if (in_path == NULL)
        goto end;

    in = bio_open_default(in_path, RB(in_form));
    if (in == NULL)
        goto end;

    rv = sk_CTSCT_new_null();
    if (rv == NULL)
        goto end;

    if (in_form == FORMAT_PEM) {
        long len = 0;
        while (PEM_read_bio(in, &name, &header, &data, &len) == 1) {
            if (strcmp(name, CT_SCT_PEM) == 0) {
                sct = CTSCT_alloc();
                if (sct == NULL)
                    goto end;
                if (CT_parse_sct(data, len, sct, CT_SOURCE_UNKNOWN) != 1)
                    goto end;
                sk_CTSCT_push(rv, sct);
                sct = NULL;
            }

            OPENSSL_free(name);
            name = NULL;

            OPENSSL_free(header);
            header = NULL;

            OPENSSL_free(data);
            data = NULL;
        }
    } else {
        sct = CTSCT_alloc();
        if (sct == NULL)
            goto end;
        if (CT_parse_sct_bio(in, sct, CT_SOURCE_UNKNOWN) != 1)
            goto end;
        sk_CTSCT_push(rv, sct);
        sct = NULL;
    }

 end:
    CTSCT_free(sct);
    BIO_free_all(in);
    OPENSSL_free(name);
    OPENSSL_free(header);
    OPENSSL_free(data);

    return rv;
}

static int is_precert(const X509 *cert)
{
    return cert && X509_get_ext_by_NID(cert, NID_ct_precert_poison, -1) >= 0;
}

int precert_strip_poison(X509 *cert)
{
    int ext_pos;
    if (cert == NULL)
        goto err;
    ext_pos = X509_get_ext_by_NID(cert, NID_ct_precert_poison, -1);
    if (ext_pos >= 0) {
        X509_EXTENSION *ex = X509_delete_ext(cert, ext_pos);
        if (ex) {
            X509_EXTENSION_free(ex);
            ex = NULL;
        }
    }
    return 1;
err:
    return 0;
}

BUF_MEM *do_create_sct(X509 *cert, uint64_t ts, EVP_PKEY *key,
                       const X509 *cacert, int bogus_version, int bogus_ext,
                       int bogus_entry)
{
    BIO *out = NULL;
    BIO *tbs = NULL;
    uint8_t t;
    uint8_t pkey_hash[32];
    uint8_t capkey_hash[32];
    uint16_t log_entry_type, ext_len;
    int i;
    int cert_size;
    BUF_MEM *tmp_ptr;
    BUF_MEM *rv = NULL;
    EVP_MD_CTX ctx;
    int md_needs_cleanup = 0;
    EVP_PKEY_CTX *pctx = NULL;
    size_t size_needed;
    unsigned char *sig = NULL;
    int precert = 0;
    EVP_PKEY *capubkey = NULL;
    unsigned char *bogus_ext_data = NULL;
    int bogus_ext_data_len = 0;

    if (cert == NULL || key == NULL)
        goto end;

    if (is_precert(cert)) {
        precert = 1;
        if (cacert == NULL)
            goto end;

        capubkey = X509_get_pubkey(cacert);
        if (capubkey == NULL)
            goto end;

        if (X509_verify(cert, capubkey) != 1) {
            BIO_printf(bio_err, "CA cert didn't verify against signature.\n");
            goto end;
        }

        if (extract_public_key_hash(capubkey, capkey_hash) != 1)
            goto end;

        if (precert_strip_poison(cert) != 1)
            goto end;
    }

    if (bogus_ext) {
        bogus_ext_data_len = 300; /* want more than 256 to test parsing */
        bogus_ext_data = OPENSSL_malloc(bogus_ext_data_len);
        if (bogus_ext_data == NULL)
            goto end;
        for (i = 0; i < bogus_ext_data_len; i++) {
            bogus_ext_data[i] = i & 0xff;
        }
    }

    out = BIO_new(BIO_s_mem());
    if (out == NULL)
        goto end;

    tbs = BIO_new(BIO_s_mem());
    if (tbs == NULL)
        goto end;

    if (extract_public_key_hash(key, pkey_hash) != 1)
        goto end;

    /* Write Version to both */
    t = bogus_version ? 255 : 0;
    if (BIO_write(out, &t, 1) != 1)
        goto end;
    if (BIO_write(tbs, &t, 1) != 1)
        goto end;

    /* Write log ID to out only */
    if (BIO_write(out, pkey_hash, 32) != 32)
        goto end;

    /* Write signature_type to TBS only */
    t = 0;
    if (BIO_write(tbs, &t, 1) != 1)
        goto end;

    /* Write timestamp to both */
    for (i = 56; i >= 0; i -= 8) {
        t = (ts >> i) & 0xff;
        if (BIO_write(out, &t, 1) != 1)
            goto end;
        if (BIO_write(tbs, &t, 1) != 1)
            goto end;
    }

    /* Write entry_type to TBS only */
    log_entry_type = bogus_entry ? 300 : (precert ? 1 : 0);
    for (i = 8; i >= 0; i -= 8) {
        t = (log_entry_type >> i) & 0xff;
        if (BIO_write(tbs, &t, 1) != 1)
            goto end;
    }

    /* Write Cert to TBS only */
    if (precert) {
        if (BIO_write(tbs, capkey_hash, 32) != 32)
            goto end;

        cert_size = i2d_re_X509_tbs(cert, NULL);
        if (cert_size < 0)
            goto end;

        /* Write cert size to TBS only */
        for (i = 16; i >= 0; i -= 8) {
            t = (((unsigned int)cert_size) >> i) & 0xff;
            if (BIO_write(tbs, &t, 1) != 1)
                goto end;
        }

        /* Now really write cert */
        if (i2d_re_X509_tbs_bio(tbs, cert) != 1)
            goto end;
    } else {
        cert_size = i2d_X509(cert, NULL);
        if (cert_size < 0)
            goto end;

        /* Write cert size to TBS only */
        for (i = 16; i >= 0; i -= 8) {
            t = (((unsigned int)cert_size) >> i) & 0xff;
            if (BIO_write(tbs, &t, 1) != 1)
                goto end;
        }

        /* Now really write cert */
        if (i2d_X509_bio(tbs, cert) != 1)
            goto end;
    }

    /* Write extensions to both */
    ext_len = bogus_ext ? bogus_ext_data_len : 0;
    for (i = 8; i >= 0; i -= 8) {
        t = (ext_len >> i) & 0xff;
        if (BIO_write(out, &t, 1) != 1)
            goto end;
        if (BIO_write(tbs, &t, 1) != 1)
            goto end;
    }
    if (bogus_ext) {
        if (BIO_write(out, bogus_ext_data, bogus_ext_data_len) != bogus_ext_data_len)
            goto end;
        if (BIO_write(tbs, bogus_ext_data, bogus_ext_data_len) != bogus_ext_data_len)
            goto end;
    }

    /* Write hash and sig alg to out only */
    t = 4;
    if (BIO_write(out, &t, 1) != 1)
        goto end;
    switch (EVP_PKEY_type(key->type)) {
    case EVP_PKEY_RSA:
        t = 1;
        break;
    case EVP_PKEY_EC:
        t = 3;
        break;
    default:
        BIO_printf(bio_err, "Unknown key type.\n");
        goto end;
    }
    if (BIO_write(out, &t, 1) != 1)
        goto end;

    BIO_get_mem_ptr(tbs, &tmp_ptr);

    EVP_MD_CTX_init(&ctx);
    md_needs_cleanup = 1;

    if (EVP_DigestSignInit(&ctx, &pctx, EVP_sha256(), NULL, key) != 1)
        goto end;

    if (EVP_DigestSignUpdate(&ctx, (unsigned char *)tmp_ptr->data, tmp_ptr->length) != 1)
        goto end;

    if (EVP_DigestSignFinal(&ctx, NULL, &size_needed) != 1)
        goto end;

    if (size_needed < 1)
        goto end;

    sig = OPENSSL_malloc(size_needed);
    if (sig == NULL)
        goto end;

    if (EVP_DigestSignFinal(&ctx, sig, &size_needed) != 1)
        goto end;

    for (i = 8; i >= 0; i -= 8) {
        t = (size_needed >> i) & 0xff;
        if (BIO_write(out, &t, 1) != 1)
            goto end;
    }
    if (BIO_write(out, sig, size_needed) != (signed int)size_needed)
        goto end;

    BIO_get_mem_ptr(out, &rv);
    if (rv) {
        /* So BIO_free() leaves BUF_MEM alone */
        if (BIO_set_close(out, BIO_NOCLOSE) != 1) {
            rv = NULL;
            goto end;
        }
    }

    /* TODO(aeijdenberg): am I meant to free EVP_PKEY_CTX? */
end:
    BIO_free_all(out);
    EVP_PKEY_free(capubkey);
    BIO_free_all(tbs);
    if (md_needs_cleanup) {
        EVP_MD_CTX_cleanup(&ctx);
        md_needs_cleanup = 0;
    }
    OPENSSL_free(sig);
    OPENSSL_free(bogus_ext_data);

    return rv;
}

int ct_main(int argc, char **argv)
{
    char *prog;
    int ret = 1;
    OPTION_CHOICE o;
    int create_sct = 0, show_sct_text = 0, create_server_info = 0;
    int create_log_metadata = 0, create_log_list = 0;
    char *in_path = NULL, *key_path = NULL, *cacert_path = NULL, *out_path = NULL;
    char *name = NULL;
    int out_form = FORMAT_PEM, in_form = FORMAT_PEM, key_form = FORMAT_PEM, cacert_form = FORMAT_PEM;
    X509 *cert = NULL, *cacert = NULL;
    BIO *out = NULL;
    BIO *tmpout = NULL;
    EVP_PKEY *key = NULL;
    BUF_MEM *out_data = NULL;
    STACK_OF(CTSCT) *scts = NULL;
    STACK_OF(CTLOG) *logs = NULL;
    BUF_MEM *tmpptr;
    CTLOG *log = NULL;
    int i;
    int bogus_version = 0, bogus_ext = 0, bogus_entry = 0;

    prog = opt_init(argc, argv, ct_options);
    while ((o = opt_next()) != OPT_EOF) {
        switch (o) {
        case OPT_EOF:
        case OPT_ERR:
            BIO_printf(bio_err, "%s: Use -help for summary.\n", prog);
            goto end;
        case OPT_HELP:
opthelp:
            opt_help(ct_options);
            ret = 0;
            goto end;
        case OPT_TEXT:
            show_sct_text = 1;
            break;
        case OPT_CREATESERVERINFO:
            create_server_info = 1;
            break;
        case OPT_CREATESCT:
            create_sct = 1;
            break;
        case OPT_CREATELOGMETADATA:
            create_log_metadata = 1;
            break;
        case OPT_CREATELOGLIST:
            create_log_list = 1;
            break;
        case OPT_BOGUS_VERSION:
            bogus_version = 1;
            break;
        case OPT_BOGUS_EXTENSIONS:
            bogus_ext = 1;
            break;
        case OPT_BOGUS_ENTRYTYPE:
            bogus_entry = 1;
            break;
        case OPT_IN:
            in_path = opt_arg();
            break;
        case OPT_KEY:
            key_path = opt_arg();
            break;
        case OPT_CACERT:
            cacert_path = opt_arg();
            break;
        case OPT_OUT:
            out_path = opt_arg();
            break;
        case OPT_NAME:
            name = opt_arg();
            break;
        case OPT_OUTFORM:
            if (!opt_format(opt_arg(), OPT_FMT_ANY, &out_form))
                goto opthelp;
            break;
        case OPT_INFORM:
            if (!opt_format(opt_arg(), OPT_FMT_ANY, &in_form))
                goto opthelp;
            break;
        case OPT_KEYFORM:
            if (!opt_format(opt_arg(), OPT_FMT_ANY, &key_form))
                goto opthelp;
            break;
        case OPT_CACERTFORM:
            if (!opt_format(opt_arg(), OPT_FMT_ANY, &cacert_form))
                goto opthelp;
            break;
        }
    }
    argc = opt_num_rest();
    argv = opt_rest();

    if (cacert_path) {
        cacert = load_cert(cacert_path, cacert_form, NULL, NULL, "CA Certificate");
        if (cacert == NULL)
            goto end;
    }
    if (key_path) {
        key = load_key(key_path, key_form, 1, NULL, NULL, "Private key for log");
        if (key == NULL)
            goto end;
    }
    if (out_path) {
        out = bio_open_default(out_path, "wb");
        if (out == NULL)
            goto end;
    } else {
        out = bio_out;
    }

    if (create_sct) {
        if (in_path == NULL) {
            BIO_printf(bio_err, "Need a cert to sign\n");
            goto end;
        } else {
            cert = load_cert(in_path, in_form, NULL, NULL, "Certificate (or precertificate)");
            if (cert == NULL)
                goto end;
        }
        if (key == NULL) {
            BIO_printf(bio_err, "Need a private key to sign with\n");
            goto end;
        }
        if (out == NULL) {
            BIO_printf(bio_err, "Need an output location\n");
            goto end;
        }
        if (is_precert(cert)) {
            if (cacert == NULL) {
                BIO_printf(bio_err, "Need the CA cert when input is a pre-cert\n");
                goto end;
            }
        }

        out_data = do_create_sct(cert, time(NULL) * 1000, key, cacert, bogus_version, bogus_ext, bogus_entry);
        if (out_data == NULL) {
            BIO_printf(bio_err, "Error creating SCT.\n");
            goto end;
        }

        BIO_printf(bio_err, "Success creating SCT.\n");
        if (out_form == FORMAT_PEM) {
            if (PEM_write_bio(out, CT_SCT_PEM, "", (unsigned char *)out_data->data, out_data->length) < 1)
                goto end;
        } else {
            if (BIO_write(out, (unsigned char *)out_data->data, out_data->length) != (signed int)out_data->length)
                goto end;
        }
    } else if (show_sct_text || create_server_info) {
        if (in_path == NULL) {
            BIO_printf(bio_err, "Need an SCT to parse\n");
            goto end;
        }
        scts = load_scts(in_path, in_form);
        if (scts == NULL)
            goto end;

        if (create_server_info) {
            if (out_form == FORMAT_PEM) {
                tmpout = BIO_new(BIO_s_mem());
                if (tmpout == NULL)
                    goto end;
                if (CT_server_info_encode_sct_list_bio(tmpout, scts) < 0)
                    goto end;
                BIO_get_mem_ptr(tmpout, &tmpptr);
                if (tmpptr == NULL)
                    goto end;
                if (PEM_write_bio(out, CT_SI_PEM, "", (unsigned char *)tmpptr->data, tmpptr->length) < 1)
                    goto end;
            } else {
                if (CT_server_info_encode_sct_list_bio(out, scts) != 1)
                    goto end;
            }
        } else if (show_sct_text) {
            for (i = 0; i < sk_CTSCT_num(scts); i++) {
                BIO_printf(out, "---\n");
                CT_print_sct(out, sk_CTSCT_value(scts, i));
            }
        }
    } else if (create_log_metadata) {
        if (key == NULL) {
            BIO_printf(bio_err, "Need the public key for the log (private contains the public key).\n");
            goto end;
        }
        if (name == NULL) {
            BIO_printf(bio_err, "Need a name for the log.\n");
            goto end;
        }

        tmpout = BIO_new(BIO_s_mem());
        if (i2d_PUBKEY_bio(tmpout, key) < 1)
            goto end;

        BIO_get_mem_ptr(tmpout, &tmpptr);

        log = CTLOG_new(tmpptr->data, tmpptr->length, name, strlen(name));
        if (log == NULL)
            goto end;
        BIO_free(tmpout);
        tmpout = NULL;

        if (out_form == FORMAT_PEM) {
            tmpout = BIO_new(BIO_s_mem());
            if (tmpout == NULL)
                goto end;
            if (CTLOG_write_bio(tmpout, log) < 0)
                goto end;
            BIO_get_mem_ptr(tmpout, &tmpptr);
            if (tmpptr == NULL)
                goto end;
            if (PEM_write_bio(out, CT_CTLOG_PEM, "", (unsigned char *)tmpptr->data, tmpptr->length) < 1)
                goto end;
        } else {
            if (CTLOG_write_bio(out, log) != 1)
                goto end;
        }
    } else if (create_log_list) {
        if (in_path == NULL) {
            BIO_printf(bio_err, "Need PEM of log metadata to combine\n");
            goto end;
        }
        logs = load_ctlogs(in_path, in_form);
        if (logs == NULL)
            goto end;

        if (BIO_write(out, "{\n", 2) != 2)
            goto end;
        if (BIO_write(out, "    \"logs\": [\n", 14) != 14)
            goto end;

        for (i = 0; i < sk_CTLOG_num(logs); i++) {
            if (i > 0)
                if (BIO_write(out, ",\n", 2) != 2)
                    goto end;
            if (BIO_write(out, "        ", 8) != 8)
                goto end;
            if (CTLOG_write_bio(out, sk_CTLOG_value(logs, i)) < 1)
                goto end;
        }
        if (BIO_write(out, "\n    ]\n", 7) != 7)
            goto end;
        if (BIO_write(out, "}\n", 2) != 2)
            goto end;
    }

    ret = 0;
 end:
    if (out && (out != bio_out)) {
        BIO_free_all(out);
        out = NULL;
    }
    CTLOG_free(log);
    X509_free(cert);
    X509_free(cacert);
    EVP_PKEY_free(key);
    BIO_free_all(tmpout);
    OPENSSL_free(out_data);
    sk_CTSCT_pop_free(scts, CTSCT_free);
    sk_CTLOG_pop_free(logs, CTLOG_free);

    if (ret) {
        BIO_printf(bio_err, "Error somewhere.\n");
        ERR_print_errors(bio_err);
    }
    return ret;
}
