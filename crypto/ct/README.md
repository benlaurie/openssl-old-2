# Quickstart

    #include <openssl/ct.h>
    
    ... create SSL_CTX ...
    
    /* Ensure verification is enabled, or CT can't get issuer to verify SCTs */
    SSL_CTX_set_verify(...)
    SSL_CTX_set_default_verify_paths(...)
    
    /* One line to enable CT */
    SSL_CTX_apply_certificate_transparency_policy(CT_POLICY_REQUEST);


# Applying Certificate Transparency Policy

The CT module allows a client to apply a Certificate Transparency policy to an `SSL_CTX` (recommended) or an `SSL` object.  This policy is applied immediately after a `ServerHelloDone` message is received (see invocation of `CT_validate_connection`).

    typedef enum {CT_POLICY_NONE, CT_POLICY_REQUEST, CT_POLICY_REQUIRE_ONE} ct_policy;

    int       SSL_CTX_apply_certificate_transparency_policy(SSL_CTX *ctx, ct_policy policy);
    ct_policy SSL_CTX_get_certificate_transparency_policy  (SSL_CTX *ctx);
    
    int       SSL_apply_certificate_transparency_policy    (SSL *s,       ct_policy policy);

There are 3 different policies available:

- `CT_POLICY_NONE` (default for new `SSL_CTX` objects) - This policy preserves the status quo.  It will not change any messages sent to the server, and if set, `CT_validate_connection` will immediately return success and will not attempt to even parse any CT data present.

- `CT_POLICY_REQUEST` (set to default in `openssl s_client`) - This policy modifies the `ClientHello` sent to the server to indicate that the client supports receivning CT data via the TLS extension.  Note that since SCTs may be served as part of an OCSP-stapled response, setting this policy has the side-effect of enabling OCSP-stapled response handling (specifically we set `SSL_set_tlsext_status_type(s, TLSEXT_STATUSTYPE_ocsp);`).  When this policy is in effect `CT_validate_connection` will attempt to parse all SCTs present, and if an SCT is from a trusted log (see below) we will validate that the public key for the log did in fact sign the SCT and that the SCT is in fact valid for the peer certificate associated with the connection.  If the SCT is well-formed but the signature does not validate, the connection will be terminated, however if no SCTs from trusted logs are present, the connection will succeed.

- `CT_POLICY_REQUIRE_ONE` (recommended where able) - This policy builds on top of that implemented for `CT_POLICY_REQUEST` with one addition: it requires that at least 1 valid SCT be presented from a trusted log.  If no SCTs are valid, the connection will be terminated.  However like for `CT_POLICY_REQUEST` is any SCTs are well-formed but the signature does not validate, the connection will be terminated.

## Trusted Logs

In order to validate an SCT, a client must have access to the public key for that log.  This is moral equivalent to a set of trusted roots.  The metadata needed for a log may grow over time, however for now we make use of just the public key (from which the log ID is derived) and a display name used in debug output.

The format of the trust logs is borrowed from the format used by the Certificate Transparency project which can be downloaded from:
http://www.certificate-transparency.org/known-logs

To use the same set of trusted logs that Chrome currently uses, the following command will download a JSON file that can be used without modification:

    curl -O -L http://www.certificate-transparency.org/known-logs/log_list.json

To point the CT module to use this file, the following functions may be called:

    int CTLOG_STORE_load_file        (SSL_CTX *ctx, char *fpath);
    int CTLOG_STORE_set_default_paths(SSL_CTX *ctx);

The former takes a specific path to the JSON file, whereas the latter will first check if the `CTLOG_FILE` environment variable is set, and if so, load from there, else it will attempt to load from `OPENSSLDIR "/log_list.json"`, that is, a peer of `OPENSSLDIR "/cert.pem"`.

In addition, since this is part of the certificate verification process, we call `CTLOG_STORE_set_default_paths` as a side-effect of the client calling `SSL_CTX_set_default_verify_paths` so most clients will not have cause to call this directly.

## Examining SCTs

A side-effect of applying `CT_POLICY_REQUEST` or above is that after the `ServerHelloDone` message is received, the following functions are available:

    STACK_OF(CTSCT) *SSL_get_peer_scts(SSL *s);
    void CT_print_sct(BIO *bio, CTSCT *sct);

You should not attempt to free the stack returned, it will be automically deallocated when the SSL object is disposed of.

`CT_print_sct` will print a human friendly version of the SCT, and this is what is displayed in the `openssl s_client` output.

For now the structure the SCT is opaque - accessors will be added over time as requested.

# Client tool changes

The following tool changes were made to demonstrate the application of Certificate Transparency and to put the pieces in place to be able to generate sample data to test end-to-end.

## `openssl s_client`

The following options have been added to `openssl s_client`:

    -noct                      Do not request SCTs from server or attempt to parse
    -requestct                 (Default) Request SCTs (enables OCSP)
    -requirect                 Require at least 1 SCT (enables OCSP)
    -CTfile infile             JSON format file of CT logs

The first 3 correspond directly to the `ct_policy` enum as documented elsewhere in this document.  `-CTfile` allows a specification of a JSON file to use to retrieve log public keys and display names, overriding the default (which is only enabled if `-verify` if requested).  Outside of tests, we recommending not using `-CTfile` directly, and instead use that set by default when using `-verify`.

For example:

    $ curl -O -L http://www.certificate-transparency.org/known-logs/log_list.json
    $ export CTLOG_FILE=log_list.json
    $ openssl s_client -connect www.google.com:443 -verify 10 -requirect
    ...
    ---
    Signed Certificate Timestamps (5):
    ---
        Version   : v1(0)
        Source    : TLS Extension
        Log ID    : 56:14:06:9A:2F:D7:C2:EC:D3:F5:E1:BD:44:B2:3E:C7:
                    46:76:B9:BC:99:11:5C:C0:EF:94:98:55:D6:89:D0:DD
        Timestamp : Jul 23 16:47:42.829 2015 GMT (1437670062829)
        Extensions: 
        Signature : ecdsa-with-SHA256
                    30:45:02:20:5B:4F:0F:74:A7:11:6A:D0:F6:E4:AB:0A:
                    B9:6C:F7:8F:E9:43:3E:C9:70:3F:7A:39:E4:70:2F:9A:
                    F1:CD:7C:93:02:21:00:EB:63:31:54:49:41:3F:81:70:
                    B0:F3:69:6F:AA:65:37:9B:17:1F:FB:44:45:46:F4:0F:
                    21:A9:0E:4B:A2:5D:42
        Log       : DigiCert Log Server
        Status    : Valid - success!
    ---
    ...
  
## `openssl ca`

The following options have been added to the `ca` tool in order to make it easier to produce test data for the client, however it may be useful for other purposes:

    -precert                Issue a pre-certificate rather than cert.
    -scts infile            Path to PEM file containing SCTs to embed. If present, then input
                            is assumed to be a pre-cert, and is res-signed. Pretty much everything
                            else is ignored.

The `-precert` option should be added to a request that takes a CSR and generates a certificate.  When set the behavior of `ca` is modified so that:
1. The "poision" CT extension is added to the precertificate so that it cannot be used as a real certificate.
2. The "Data Base" is not updated, that is the serial number is written out - it's as if the precertificate was never generated (would welcome feedback on whether this is a good idea).

For example:

    openssl ca -batch -config openssl.cnf -in site.csr.pem -out site.precert.pem -precert

The precertificate generated can be used as input to the `openssl ct` tool further bleow.

The second option `-scts` can be used to file containing a list of SCTs (as produced by `openssl ct` below, specifically it should contain one or more SCTs created based on the precertificate), add them to a precertificate and use that to generate an actual certificate.  Specifically, when specified, the behavior of `ca` is modified so that:
1. The input is assumed to a precertificate, not a CSR.
2. `ca` verifies that the input precertificate is in fact signed by the CAs key.
3. The poison extension is removed, and the embedded SCTs extension is added.
4. The serial number already in the precert is retained.
5. This time the "Data Base" really is updated.

For example:

    openssl ca -batch -config openssl.cnf -in site.precert.pem -out site.cert.pem -scts site-precert.sct.pem

## `openssl ocsp`

The `ocsp` tool is modified to take the additional input flag:

    -scts infile           SCTs to embed in response (useless other than trivial tests).

The format of this file is the same as produced by `openssl ct`.  It should contain one or more PEM encoded SCTs created based on the certificiate itself.  When specified the behavior of `ocsp` is modified so that this list of SCTs is embeeded as an extension in the generated OCSP response.  Since we don't match these against the certificate at all, this isn't much use other than for tests when running in the responder mode.

## `openssl ct`

A new tool `ct` is introduced to allow manipulation of data types useful for Certificate Transparency.  The full set of options exposed are:

    -createsct          Create an SCT based on input cert
    -createlogmetadata  Create log metadata based on key
    -createloglist      Create log list based on list of metadata
    -text               Print an SCT based on input SCT
    -createserverinfo   Create a ServerInfo file based on input SCT list
    -out outfile        Output file location
    -outform format     Output file format (PEM(default) or TLS)
    -in infile          Input file location
    -inform format      Input file format (PEM(default) or DER)
    -key infile         Key file location
    -keyform format     Input file format (PEM(default) or DER)
    -cacert infile      Certificate Authority Certificate file location
    -cacertform format  Input file format (PEM(default) or DER)
    -bogusversion       Create SCT with a newer version than understood
    -bogusextensions    Create SCT bogus undefined extension data
    -bogusentrytype     Create SCT bogus undefined entry type
    -name val           Name

One of `-createsct`, `-createlogmetadata`, `-createloglist` and `-createserverinfo` should always be specified so it makes sense to discuss these 4 discrete operations separately.

### `openssl ct -createsct`

This operation requires as input (`-in`) a certificate or a precertificate. If the poison extension exists, it is assumed to be a precertificate, otherwise it is assumed to be a certificate.

If the input is a precertificate, then the `-cacert` that will be used to issue the final certificate must also be specified as we need to get the public key hash as input to the SCT.

In either case, the private key for the log must be specified and this is used to sign the SCT.

Example usage for a creating an SCT for a certificate:

    $ openssl ct -createsct -in site.cert.pem -key log.key.pem
    -----BEGIN SIGNED CERTIFICATE TIMESTAMP-----
    AJ9dGilLYI+AaUjqPyX62BTc+sYOqAVX307ufldVgKmmAAABTuYSymAAAAQBAQAo
    Hg7o+13f4/hof9ASh2xlrWVUd1+m0JkWaExbgYQv4HJ+FsqlCkgPeryaAzaT0uBm
    8qF4acfv59BtxMRbSTV2vihY2MRykeSwIVBEvQFjxEvWi9UQJUsVHDtfYpoRwpkt
    vDN/wUOzQa9GQGw/EJ7ZN41bc/xeyJMVtyMqCh1QdiqO525JB3FCEJz5qAOfmT05
    nSeVMx71XvKCp0jzZW+Y3RGfAOIycnXM10IkD9fOi3+q3K8nCV3DiEQlVJyMv36P
    YnhY/fVDKOQlAs2x/TfUkQTYyWOiY/8AWUX4uNkbYEcQBfkNnsK+YZYQvGkBwjhC
    WXNm7BwiDHCkvh8XhASo
    -----END SIGNED CERTIFICATE TIMESTAMP-----

Example usage for createing an SCT based on a precertificate:

    $ openssl ct -createsct -in site.precert.pem -cacert ca.cert.pem -key log.key.pem
    -----BEGIN SIGNED CERTIFICATE TIMESTAMP-----
    AJ9dGilLYI+AaUjqPyX62BTc+sYOqAVX307ufldVgKmmAAABTuYU5XAAAAQBAQDB
    +VPHcott2Y//knLvZVWoZRllol+rr43wBah8ek3XP6MSfZbz/8x0r+3v8k+1l1Rp
    BhXs39KCf+vqUfh2M8DC5HyZNVBwUDVkhQL/WSLuyOJuhKS/wID5r9dkrLOWO+Fw
    rvrSVDl+5HDBMfnDcYS4KNIcT8pp17KYiMO2V5MiY3qek78L848Aaztq9H+Z3qae
    uROJTdC5fTOM+A+89aGpILk9F23uPqsfQK5TcTqU/FZDVjNhc98AjkpFigWNNctB
    V7pIZNCssM4WYBBOnQ7RqFFHAmhaSQUHjAySAjOZPass4ImYoqZVZPgcJTTnmhRN
    YJm50zwxFQeW2J3x/6oZ
    -----END SIGNED CERTIFICATE TIMESTAMP-----

`-bogusversion`, `-bogusextensions` and `-bogusentrytype` are useful only for creating test data to verify client behavior under these conditions.

### `openssl ct -createlogmetadata`

The tool is really only useful for test data, and takes a `-key` that refers to the signing key for a log (only the public portion is needed) and `-name` and produces an opaque PEM formatted blob that represents a log.  This is often used in conjunciton with `-createloglist` to create a file suitable for the client.

For example:

    $ openssl ct -createlogmetadata -key log.key.pem -name "Foo Log"
    -----BEGIN CT LOG METADATA-----
    eyJkZXNjcmlwdGlvbiI6ICJGb28gTG9nIiwgImtleSI6Ik1JSUJJakFOQmdrcWhr
    aUc5dzBCQVFFRkFBT0NBUThBTUlJQkNnS0NBUUVBemhmS0FMNFh2RkUzMW14NU0w
    U3ZNZE9LTUR1dWVpaUl2K0hXeGVvOTZuYzFIRnFGTUE5TE9ueEV2Nlk2SUR5dWM0
    Mys4RFJSNHZ4cjBnV3BmUG1PRk9STzlxczB1T25lOVo2UVZMN2xnR0tERmNLRks1
    SUhyZExadk1YSVVkZFJBM09nSVNqMFFTQVAxdVdIYnkyd25JblUrdGtmSzg2eHNh
    bGRjTDcva1BjOFY2OXdtajVtdGhWQmkydW1BdHZxZ1lTbVUvSHVKb2Fnb2J4QzR5
    M1FxRDVscEtUcEIyRWI1b3FpU0xYdDZvZHUwR2F4MXdCcWhreXZUV1J5UnBIUmFR
    VW56TDdhVElIbDRodWhIRE9aemY3ZVZJVGFjckI4RnBVQ1pKaFQ1UE1NRkd1TTNK
    VUZyMm9qTkN0WWJRdVVXSElJdmdOdlR2WmJRSXI5L0dWdUJ3SURBUUFCIn0=
    -----END CT LOG METADATA-----

### `openssl ct -createloglist`

This tool takes as `-in` a PEM file with one or more encoded "LOG METADATA" entries as output by `openssl ct -createlogmetadata`.  It combines these to produce a JSON file suitable for use by the client.

For example:

    $ openssl ct -createloglist -in ct-all.metadata.pem 
    {
        "logs": [
            {"description": "Foo Log", "key":"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAzhfKAL4XvFE31mx5M0SvMdOKMDuueiiIv+HWxeo96nc1HFqFMA9LOnxEv6Y6IDyuc43+8DRR4vxr0gWpfPmOFORO9qs0uOne9Z6QVL7lgGKDFcKFK5IHrdLZvMXIUddRA3OgISj0QSAP1uWHby2wnInU+tkfK86xsaldcL7/kPc8V69wmj5mthVBi2umAtvqgYSmU/HuJoagobxC4y3QqD5lpKTpB2Eb5oqiSLXt6odu0Gax1wBqhkyvTWRyRpHRaQUnzL7aTIHl4huhHDOZzf7eVITacrB8FpUCZJhT5PMMFGuM3JUFr2ojNCtYbQuUWHIIvgNvTvZbQIr9/GVuBwIDAQAB"},
            {"description": "Bar Log", "key":"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1JM/Z8xfPiSH/73kGXu38u9vdHcy+Af1+screjIPnYbr1MbtgpJKs12CBU1S519ORVHsQdF1v6i/DpXA82xpiYVgWHBHeXKuSZSXps8t5/xG/ATWcjSKQbUFOgNSb6Pn6MZjefNa/5TZjci/0RBquMz3IHLrLgoBcErfVLNx7u/+gk688n/4oDXe4uHxyGEDD481ArnStBitjVqU8pSRYr8WhjKi9sHfYOkDAnQrtgZOBB5d/133RPLiT4rswUKYWr8U5Ky3gisQW/WubPGZnu4QFv/yFvc/9esFvfexjSxZAOLn6VearpJxPqjBXp0Y87M82LKxExCLcj+GfLpkKwIDAQAB"}
        ]
    }

### `openssl ct -createserverinfo`

`-createserverinfo` takes as `-in` a PEM file containing one or more "SIGNED CERTIFICATE TIMESTAMPS" as output by `openssl ct -createsct` and turns them into a file suitable for passing to `openssl s_server -serverinfo xxx`.  That serving option allows SCTs to be served by the TLS extension to clients.

Example usage:

    $ openssl ct -createserverinfo -in site-bar.sct.pem 
    -----BEGIN SERVERINFO FOR CT-----
    ABIBMwExAS8ASOI8DHa4JqbHSAayf76FVq+4Vu/xyGq/N+NxYycM/Y8AAAFO1bcA
    KAAABAEBALltB5JAhRg5q3KuD1LOCze62IAQi4bQjh40PnUrZdsh4W6oke+NjtmJ
    KrOLnIj0QCRMxR0S74Dzg62MFxsjlCF94OJr8f5MVHvY0MgK4efR+6LxWJM/aoWk
    vqgXzkXzzmAQ8uZyGrEKbhX3S9Lq9CDZvZDgOYpdQEwksXBsjk1lunZzCOONX5UB
    58UG9ZZDD5LH3FIEPtgznJD1/8YbdPNgzCLgNRdmQAoGRnM8F+5vr/qlFs8ObETl
    7xPtlFFqWtZQBGMdEP/7bCSrw4klv4ra2hRVd7avWmXjJ6ri/ItpjDaXvYD/Si/a
    DJ2wHXu4goQ+YvVtB4ZKN5UTJo0IajQ=
    -----END SERVERINFO FOR CT-----

# Demonstration

The following steps demonstrate CT end to end.

[As a CA] First, create a basic CA configuration:

    $ echo '''[ req ]
    default_bits            = 2048
    default_keyfile         = ca.key.pem
    default_md              = sha1
    prompt                  = no
    distinguished_name      = root_ca_distinguished_name
    x509_extensions = v3_ca
    
    [ root_ca_distinguished_name ]
    countryName             = US
    stateOrProvinceName     = California
    localityName            = Mountain View
    0.organizationName      = CT Team
    commonName              = CT Test
    emailAddress            = eijdenberg@google.com
    
    [ v3_ca ]
    subjectKeyIdentifier=hash
    authorityKeyIdentifier=keyid:always,issuer:always
    basicConstraints = CA:true
    
    [ ca ]
    default_ca              = CA_default
    
    [ CA_default ]
    dir                     = .
    certificate             = ca.cert.pem
    private_key             = ca.key.pem
    x509_extensions         = usr_cert
    name_opt                = ca_default
    cert_opt                = ca_default
    default_days            = 365
    default_md              = sha256
    preserve                = no
    policy                  = policy_match
    database                = index
    serial                  = serial
    new_certs_dir           = .
    
    [ policy_match ]
    countryName             = optional
    stateOrProvinceName     = optional
    organizationName        = optional
    organizationalUnitName  = optional
    commonName              = supplied
    emailAddress            = optional
    
    [ usr_cert ]
    basicConstraints=CA:FALSE
    subjectKeyIdentifier=hash
    authorityKeyIdentifier=keyid,issuer:always
    authorityInfoAccess = OCSP;URI:http://localhost:4445
    
    ''' > openssl.cnf
    $ touch index
    $ echo 01 > serial
    
[As a CA] Create a CA signing key and a CA certificate:

    $ openssl req -nodes -config openssl.cnf -x509 -newkey rsa -out ca.cert.pem
    
[As a log operator] Generate two CT log signing key for logs "Foo Log" and "Bar Log":

    $ openssl genrsa -out ct-foo.key.pem 2048
    $ openssl genrsa -out ct-bar.key.pem 2048
    
[As a log operator] Create CT log metadata, concatenate and produce a JSON log list:

    $ openssl ct -createlogmetadata -key ct-foo.key.pem -name "Foo Log" -out ct-foo.metadata.pem
    $ openssl ct -createlogmetadata -key ct-bar.key.pem -name "Bar Log" -out ct-bar.metadata.pem
    $ cat ct-foo.metadata.pem ct-bar.metadata.pem > ct-all.metadata.pem
    $ openssl ct -createloglist -in ct-all.metadata.pem -out log_list.json
    
[As a site owner] Create standard CSR for "localhost":

    $ openssl req -config openssl.cnf -out site.csr.pem -new -newkey rsa -nodes -keyout site.key.pem -subj "/CN=localhost"
    
[As a CA] Create a precertificate based on the CSR:

    $ openssl ca -batch -config openssl.cnf -in site.csr.pem -out site.precert.pem -precert
    
[As a log operator, requested by CA] Create SCTs based on the precertificate:

    $ openssl ct -createsct -in site.precert.pem -key ct-foo.key.pem -out site-precert-foo.sct.pem -cacert ca.cert.pem
    $ openssl ct -createsct -in site.precert.pem -key ct-bar.key.pem -out site-precert-bar.sct.pem -cacert ca.cert.pem
    $ cat site-precert-foo.sct.pem site-precert-bar.sct.pem > site-precert.sct.pem
    
[As a CA] Make a certificate from the precertificate and SCTs:

    $ openssl ca -batch -config openssl.cnf -in site.precert.pem -out site.cert.pem -scts site-precert.sct.pem
    
[As a log operator, requested by CA or site owner] Make SCTs based on real certificate:

    $ openssl ct -createsct -in site.cert.pem -key ct-foo.key.pem -out site-foo.sct.pem
    $ openssl ct -createsct -in site.cert.pem -key ct-bar.key.pem -out site-bar.sct.pem
    $ cat site-foo.sct.pem site-bar.sct.pem > site-all.sct.pem
    
[As a site owner] Make serverinfo file
    $ openssl ct -createserverinfo -in site-all.sct.pem -out site.serverinfo.pem
    
[As a CA] Start OCSP responder with SCTs:

    $ openssl ocsp -port 4445 -sha256 -index index -CA ca.cert.pem -rkey ca.key.pem -rsigner ca.cert.pem -scts site-all.sct.pem
    
[As a site owner] Start up a server using the certificate with embedded SCTs and the serverinfo file containing extensions:

    $ openssl s_server -cert site.cert.pem -accept 4433 -key site.key.pem -status -CAfile ca.cert.pem -serverinfo site.serverinfo.pem
    
[As a client] Connect to server and see a 6 SCTs returned in response:

    $ openssl s_client -connect localhost:4433 -verify 10 -verify_return_error -CAfile ca.cert.pem -CTfile log_list.json -requirect
    ...
    ---
    Signed Certificate Timestamps (6):
    ---
        Version   : v1(0)
        Source    : TLS Extension
        Log ID    : D8:...:35
        Timestamp : Jul 31 22:06:50.000 2015 GMT (1438380410000)
        Extensions: 
        Signature : sha256WithRSAEncryption
                    D4:1A:...:B1:19
        Log       : Foo Log
        Status    : Valid - success!
    ---
        Version   : v1(0)
        Source    : TLS Extension
        Log ID    : E0:...:A8
        Timestamp : Jul 31 22:06:50.000 2015 GMT (1438380410000)
        Extensions: 
        Signature : sha256WithRSAEncryption
                    3A:55:...:DD:2E
        Log       : Bar Log
        Status    : Valid - success!
    ---
        Version   : v1(0)
        Source    : OCSP Stapled Response
        Log ID    : D8:...:35
        Timestamp : Jul 31 22:06:50.000 2015 GMT (1438380410000)
        Extensions: 
        Signature : sha256WithRSAEncryption
                    D4:1A:...:B1:19
        Log       : Foo Log
        Status    : Valid - success!
    ---
        Version   : v1(0)
        Source    : OCSP Stapled Response
        Log ID    : E0:...:A8
        Timestamp : Jul 31 22:06:50.000 2015 GMT (1438380410000)
        Extensions: 
        Signature : sha256WithRSAEncryption
                    3A:55:...:DD:2E
        Log       : Bar Log
        Status    : Valid - success!
    ---
        Version   : v1(0)
        Source    : X509v3 Extension
        Log ID    : D8:...:35
        Timestamp : Jul 31 22:06:50.000 2015 GMT (1438380410000)
        Extensions: 
        Signature : sha256WithRSAEncryption
                    BB:10:...:12:F0
        Log       : Foo Log
        Status    : Valid - success!
    ---
        Version   : v1(0)
        Source    : X509v3 Extension
        Log ID    : E0:...:A8
        Timestamp : Jul 31 22:06:50.000 2015 GMT (1438380410000)
        Extensions: 
        Signature : sha256WithRSAEncryption
                    87:22:...:5D:97
        Log       : Bar Log
        Status    : Valid - success!
    ---
    ...

## Abridged steps for easy copy and paste

Setup:

    echo '''[ req ]
    default_bits            = 2048
    default_keyfile         = ca.key.pem
    default_md              = sha1
    prompt                  = no
    distinguished_name      = root_ca_distinguished_name
    x509_extensions = v3_ca
    
    [ root_ca_distinguished_name ]
    countryName             = US
    stateOrProvinceName     = California
    localityName            = Mountain View
    0.organizationName      = CT Team
    commonName              = CT Test
    emailAddress            = eijdenberg@google.com
    
    [ v3_ca ]
    subjectKeyIdentifier=hash
    authorityKeyIdentifier=keyid:always,issuer:always
    basicConstraints = CA:true
    
    [ ca ]
    default_ca              = CA_default
    
    [ CA_default ]
    dir                     = .
    certificate             = ca.cert.pem
    private_key             = ca.key.pem
    x509_extensions         = usr_cert
    name_opt                = ca_default
    cert_opt                = ca_default
    default_days            = 365
    default_md              = sha256
    preserve                = no
    policy                  = policy_match
    database                = index
    serial                  = serial
    new_certs_dir           = .
    
    [ policy_match ]
    countryName             = optional
    stateOrProvinceName     = optional
    organizationName        = optional
    organizationalUnitName  = optional
    commonName              = supplied
    emailAddress            = optional
    
    [ usr_cert ]
    basicConstraints=CA:FALSE
    subjectKeyIdentifier=hash
    authorityKeyIdentifier=keyid,issuer:always
    authorityInfoAccess = OCSP;URI:http://localhost:4445
    
    ''' > openssl.cnf
    touch index
    echo 01 > serial
    openssl req -nodes -config openssl.cnf -x509 -newkey rsa -out ca.cert.pem
    openssl genrsa -out ct-foo.key.pem 2048
    openssl genrsa -out ct-bar.key.pem 2048
    openssl ct -createlogmetadata -key ct-foo.key.pem -name "Foo Log" -out ct-foo.metadata.pem
    openssl ct -createlogmetadata -key ct-bar.key.pem -name "Bar Log" -out ct-bar.metadata.pem
    cat ct-foo.metadata.pem ct-bar.metadata.pem > ct-all.metadata.pem
    openssl ct -createloglist -in ct-all.metadata.pem -out log_list.json
    openssl req -config openssl.cnf -out site.csr.pem -new -newkey rsa -nodes -keyout site.key.pem -subj "/CN=localhost"
    openssl ca -batch -config openssl.cnf -in site.csr.pem -out site.precert.pem -precert
    openssl ct -createsct -in site.precert.pem -key ct-foo.key.pem -out site-precert-foo.sct.pem -cacert ca.cert.pem
    openssl ct -createsct -in site.precert.pem -key ct-bar.key.pem -out site-precert-bar.sct.pem -cacert ca.cert.pem
    cat site-precert-foo.sct.pem site-precert-bar.sct.pem > site-precert.sct.pem
    openssl ca -batch -config openssl.cnf -in site.precert.pem -out site.cert.pem -scts site-precert.sct.pem
    openssl ct -createsct -in site.cert.pem -key ct-foo.key.pem -out site-foo.sct.pem
    openssl ct -createsct -in site.cert.pem -key ct-bar.key.pem -out site-bar.sct.pem
    cat site-foo.sct.pem site-bar.sct.pem > site-all.sct.pem
    openssl ct -createserverinfo -in site-all.sct.pem -out site.serverinfo.pem

In new terminal, in same dir, run the OCSP server:

    openssl ocsp -port 4445 -sha256 -index index -CA ca.cert.pem -rkey ca.key.pem -rsigner ca.cert.pem -scts site-all.sct.pem
    
In new terminal, in same dir, run the server:

    openssl s_server -cert site.cert.pem -accept 4433 -key site.key.pem -status -CAfile ca.cert.pem -serverinfo site.serverinfo.pem
    
Run the client:

    openssl s_client -connect localhost:4433 -verify 10 -verify_return_error -CAfile ca.cert.pem -CTfile log_list.json -requirect
    


# Further reading

For more information about Certificate Transparency, see:
- http://www.certificate-transparency.org
- https://tools.ietf.org/html/rfc6962
