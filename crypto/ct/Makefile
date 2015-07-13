#
# OpenSSL/ct/Makefile
#

DIR=	ct
TOP=	../..
CC=	cc
INCLUDES= -I.. -I$(TOP) -I../../include
CFLAG=-g
MAKEFILE=	Makefile
AR=		ar r

CFLAGS= $(INCLUDES) $(CFLAG)

GENERAL=Makefile README

LIB=$(TOP)/libcrypto.a
LIBSRC= ct_sct.c ct_json.c ct_log.c ct_err.c

LIBOBJ= ct_sct.o ct_json.o ct_log.o ct_err.o

SRC= $(LIBSRC)

HEADER=	

ALL=    $(GENERAL) $(SRC) $(HEADER)

top:
	(cd ../..; $(MAKE) DIRS=crypto SDIRS=$(DIR) sub_all)

all:	lib

lib:	$(LIBOBJ)
	$(AR) $(LIB) $(LIBOBJ)
	$(RANLIB) $(LIB) || echo Never mind.
	@touch lib

files:
	$(PERL) $(TOP)/util/files.pl Makefile >> $(TOP)/MINFO

tags:
	ctags $(SRC)

tests:

lint:
	lint -DLINT $(INCLUDES) $(SRC)>fluff

update: depend

depend:
	@[ -n "$(MAKEDEPEND)" ] # should be set by upper Makefile...
	$(MAKEDEPEND) -- $(CFLAG) $(INCLUDES) $(DEPFLAG) -- $(LIBSRC)

dclean:
	$(PERL) -pe 'if (/^# DO NOT DELETE THIS LINE/) {print; exit(0);}' $(MAKEFILE) >Makefile.new
	mv -f Makefile.new $(MAKEFILE)

clean:
	rm -f *.o *.obj lib tags core .pure .nfs* *.old *.bak fluff

# DO NOT DELETE THIS LINE -- make depend depends on it.

ct_err.o: ../../include/openssl/bio.h ../../include/openssl/buffer.h
ct_err.o: ../../include/openssl/crypto.h ../../include/openssl/ct.h
ct_err.o: ../../include/openssl/e_os2.h ../../include/openssl/err.h
ct_err.o: ../../include/openssl/lhash.h ../../include/openssl/opensslconf.h
ct_err.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
ct_err.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
ct_err.o: ../../include/openssl/symhacks.h ct_err.c
ct_json.o: ../../crypto/ct/ct_internal.h ../../crypto/ct/ct_local.h
ct_json.o: ../../include/openssl/asn1.h ../../include/openssl/bio.h
ct_json.o: ../../include/openssl/buffer.h ../../include/openssl/conf.h
ct_json.o: ../../include/openssl/crypto.h ../../include/openssl/ct.h
ct_json.o: ../../include/openssl/e_os2.h ../../include/openssl/ec.h
ct_json.o: ../../include/openssl/ecdh.h ../../include/openssl/ecdsa.h
ct_json.o: ../../include/openssl/err.h ../../include/openssl/evp.h
ct_json.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
ct_json.o: ../../include/openssl/objects.h ../../include/openssl/ocsp.h
ct_json.o: ../../include/openssl/opensslconf.h ../../include/openssl/opensslv.h
ct_json.o: ../../include/openssl/ossl_typ.h ../../include/openssl/pkcs7.h
ct_json.o: ../../include/openssl/safestack.h ../../include/openssl/sha.h
ct_json.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
ct_json.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
ct_json.o: ../../include/openssl/x509v3.h ct_json.c
ct_log.o: ../../crypto/ct/ct_internal.h ../../crypto/ct/ct_local.h ../../e_os.h
ct_log.o: ../../include/openssl/asn1.h ../../include/openssl/bio.h
ct_log.o: ../../include/openssl/bn.h ../../include/openssl/buffer.h
ct_log.o: ../../include/openssl/comp.h ../../include/openssl/conf.h
ct_log.o: ../../include/openssl/crypto.h ../../include/openssl/ct.h
ct_log.o: ../../include/openssl/dsa.h ../../include/openssl/dtls1.h
ct_log.o: ../../include/openssl/e_os2.h ../../include/openssl/ec.h
ct_log.o: ../../include/openssl/ecdh.h ../../include/openssl/ecdsa.h
ct_log.o: ../../include/openssl/err.h ../../include/openssl/evp.h
ct_log.o: ../../include/openssl/hmac.h ../../include/openssl/lhash.h
ct_log.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
ct_log.o: ../../include/openssl/ocsp.h ../../include/openssl/opensslconf.h
ct_log.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
ct_log.o: ../../include/openssl/pem.h ../../include/openssl/pem2.h
ct_log.o: ../../include/openssl/pkcs7.h ../../include/openssl/pqueue.h
ct_log.o: ../../include/openssl/rsa.h ../../include/openssl/safestack.h
ct_log.o: ../../include/openssl/sha.h ../../include/openssl/srtp.h
ct_log.o: ../../include/openssl/ssl.h ../../include/openssl/ssl2.h
ct_log.o: ../../include/openssl/ssl3.h ../../include/openssl/stack.h
ct_log.o: ../../include/openssl/symhacks.h ../../include/openssl/tls1.h
ct_log.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
ct_log.o: ../../include/openssl/x509v3.h ../../ssl/packet_locl.h
ct_log.o: ../../ssl/record/record.h ../../ssl/ssl_locl.h
ct_log.o: ../include/internal/cryptlib.h ct_log.c
ct_sct.o: ../../crypto/ct/ct_internal.h ../../crypto/ct/ct_local.h ../../e_os.h
ct_sct.o: ../../include/openssl/asn1.h ../../include/openssl/bio.h
ct_sct.o: ../../include/openssl/bn.h ../../include/openssl/buffer.h
ct_sct.o: ../../include/openssl/comp.h ../../include/openssl/conf.h
ct_sct.o: ../../include/openssl/crypto.h ../../include/openssl/ct.h
ct_sct.o: ../../include/openssl/dsa.h ../../include/openssl/dtls1.h
ct_sct.o: ../../include/openssl/e_os2.h ../../include/openssl/ec.h
ct_sct.o: ../../include/openssl/ecdh.h ../../include/openssl/ecdsa.h
ct_sct.o: ../../include/openssl/err.h ../../include/openssl/evp.h
ct_sct.o: ../../include/openssl/hmac.h ../../include/openssl/lhash.h
ct_sct.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
ct_sct.o: ../../include/openssl/ocsp.h ../../include/openssl/opensslconf.h
ct_sct.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
ct_sct.o: ../../include/openssl/pem.h ../../include/openssl/pem2.h
ct_sct.o: ../../include/openssl/pkcs7.h ../../include/openssl/pqueue.h
ct_sct.o: ../../include/openssl/rsa.h ../../include/openssl/safestack.h
ct_sct.o: ../../include/openssl/sha.h ../../include/openssl/srtp.h
ct_sct.o: ../../include/openssl/ssl.h ../../include/openssl/ssl2.h
ct_sct.o: ../../include/openssl/ssl3.h ../../include/openssl/stack.h
ct_sct.o: ../../include/openssl/symhacks.h ../../include/openssl/tls1.h
ct_sct.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
ct_sct.o: ../../include/openssl/x509v3.h ../../ssl/packet_locl.h
ct_sct.o: ../../ssl/record/record.h ../../ssl/ssl_locl.h
ct_sct.o: ../include/internal/cryptlib.h ct_sct.c
