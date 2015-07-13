#
#  apps/Makefile
#

DIR=		apps
TOP=		..
CC=		cc
INCLUDES=	-I$(TOP) -I../include
CFLAG=		-g -static -Wswitch
MAKEFILE=	Makefile
PERL=		perl
RM=		rm -f

PEX_LIBS=
EX_LIBS= 
EXE_EXT= 

SHLIB_TARGET=

CFLAGS= $(INCLUDES) $(CFLAG)

GENERAL=Makefile makeapps.com install.com

DLIBCRYPTO=../libcrypto.a
DLIBSSL=../libssl.a
LIBCRYPTO=-L.. -lcrypto
LIBSSL=-L.. -lssl

SCRIPTS=CA.pl tsget
EXE= openssl$(EXE_EXT)

COMMANDS= \
	asn1pars.o ca.o ciphers.o cms.o crl.o crl2p7.o dgst.o dhparam.o \
	dsa.o dsaparam.o ec.o ecparam.o enc.o engine.o errstr.o gendsa.o \
	genpkey.o genrsa.o nseq.o ocsp.o passwd.o pkcs12.o pkcs7.o pkcs8.o \
	pkey.o pkeyparam.o pkeyutl.o prime.o rand.o req.o rsa.o rsautl.o \
	s_client.o s_server.o s_time.o sess_id.o smime.o speed.o spkac.o \
	srp.o ts.o verify.o version.o x509.o ct.o

A_OBJ=apps.o opt.o
A_SRC=apps.c opt.c
S_OBJ=	s_cb.o s_socket.o
S_SRC=	s_cb.c s_socket.c
RAND_OBJ=app_rand.o
RAND_SRC=app_rand.c

OBJ	= \
	asn1pars.o ca.o ciphers.o cms.o crl.o crl2p7.o dgst.o dhparam.o \
	dsa.o dsaparam.o ec.o ecparam.o enc.o engine.o errstr.o gendsa.o \
	genpkey.o genrsa.o nseq.o ocsp.o passwd.o pkcs12.o pkcs7.o pkcs8.o \
	pkey.o pkeyparam.o pkeyutl.o prime.o rand.o req.o rsa.o rsautl.o \
	s_client.o s_server.o s_time.o sess_id.o smime.o speed.o spkac.o \
	srp.o ts.o verify.o version.o x509.o ct.o


SRC	= \
	asn1pars.c ca.c ciphers.c cms.c crl.c crl2p7.c dgst.c dhparam.c \
	dsa.c dsaparam.c ec.c ecparam.c enc.c engine.c errstr.c gendsa.c \
	genpkey.c genrsa.c nseq.c ocsp.c passwd.c pkcs12.c pkcs7.c pkcs8.c \
	pkey.c pkeyparam.c pkeyutl.c prime.c rand.c req.c rsa.c rsautl.c \
	s_client.c s_server.c s_time.c sess_id.c smime.c speed.c spkac.c \
	srp.c ts.c verify.c version.c x509.c ct.c

EXE_OBJ	= openssl.o $(OBJ) $(A_OBJ) $(S_OBJ) $(RAND_OBJ)
EXE_SRC = openssl.c $(SRC) $(A_SRC) $(S_SRC) $(RAND_SRC)

HEADER=	apps.h progs.h s_apps.h \
	testdsa.h testrsa.h timeouts.h

ALL=    $(GENERAL) $(EXE_SRC) $(HEADER)

top:
	@(cd ..; $(MAKE) DIRS=$(DIR) all)

all:	exe

exe:	$(EXE)

openssl-vms.cnf: openssl.cnf
	$(PERL) $(TOP)/VMS/VMSify-conf.pl < openssl.cnf > openssl-vms.cnf

files:
	$(PERL) $(TOP)/util/files.pl Makefile >> $(TOP)/MINFO

install:
	@[ -n "$(INSTALLTOP)" ] # should be set by top Makefile...
	@set -e; for i in $(EXE); \
	do  \
	(echo installing $$i; \
	 cp $$i $(INSTALL_PREFIX)$(INSTALLTOP)/bin/$$i.new; \
	 chmod 755 $(INSTALL_PREFIX)$(INSTALLTOP)/bin/$$i.new; \
	 mv -f $(INSTALL_PREFIX)$(INSTALLTOP)/bin/$$i.new $(INSTALL_PREFIX)$(INSTALLTOP)/bin/$$i ); \
	 done;
	@set -e; for i in $(SCRIPTS); \
	do  \
	(echo installing $$i; \
	 cp $$i $(INSTALL_PREFIX)$(OPENSSLDIR)/misc/$$i.new; \
	 chmod 755 $(INSTALL_PREFIX)$(OPENSSLDIR)/misc/$$i.new; \
	 mv -f $(INSTALL_PREFIX)$(OPENSSLDIR)/misc/$$i.new $(INSTALL_PREFIX)$(OPENSSLDIR)/misc/$$i ); \
	 done
	@cp openssl.cnf $(INSTALL_PREFIX)$(OPENSSLDIR)/openssl.cnf.new; \
	chmod 644 $(INSTALL_PREFIX)$(OPENSSLDIR)/openssl.cnf.new; \
	mv -f  $(INSTALL_PREFIX)$(OPENSSLDIR)/openssl.cnf.new $(INSTALL_PREFIX)$(OPENSSLDIR)/openssl.cnf

uninstall:
	@set -e; for i in $(EXE); \
	do  \
		echo $(RM) $(INSTALL_PREFIX)$(INSTALLTOP)/bin/$$i; \
		$(RM) $(INSTALL_PREFIX)$(INSTALLTOP)/bin/$$i; \
	done;
	@set -e; for i in $(SCRIPTS); \
	do  \
		echo $(RM) $(INSTALL_PREFIX)$(OPENSSLDIR)/misc/$$i; \
		$(RM) $(INSTALL_PREFIX)$(OPENSSLDIR)/misc/$$i; \
	done
	$(RM) $(INSTALL_PREFIX)$(OPENSSLDIR)/openssl.cnf

tags:
	ctags $(EXE_SRC) $(HEADER)

tests:

lint:
	echo nope >fluff

update: openssl-vms.cnf local_depend

depend: local_depend
	@if [ -z "$(THIS)" ]; then $(MAKE) -f $(TOP)/Makefile reflect THIS=$@; fi
local_depend:
	@[ -z "$(THIS)" ] || $(MAKEDEPEND) -- $(CFLAG) $(INCLUDES) $(DEPFLAG) -- $(EXE_SRC)

dclean:
	$(PERL) -pe 'if (/^# DO NOT DELETE THIS LINE/) {print; exit(0);}' $(MAKEFILE) >Makefile.new
	mv -f Makefile.new $(MAKEFILE)

clean:
	rm -f *.o *.obj *.dll lib tags core .pure .nfs* *.old *.bak fluff $(EXE)
	rm -f req

$(DLIBSSL):
	(cd ..; $(MAKE) build_libssl)

$(DLIBCRYPTO):
	(cd ..; $(MAKE) build_libcrypto)

$(EXE): progs.h $(EXE_OBJ) $(DLIBCRYPTO) $(DLIBSSL)
	$(RM) $(EXE)
	shlib_target=; if [ -n "$(SHARED_LIBS)" ]; then \
		shlib_target="$(SHLIB_TARGET)"; \
	fi; \
	LIBRARIES="$(LIBSSL) $(LIBCRYPTO)" ; \
	$(MAKE) -f $(TOP)/Makefile.shared -e \
		APPNAME=$(EXE) OBJECTS="$(EXE_OBJ)" \
		LIBDEPS="$(PEX_LIBS) $$LIBRARIES $(EX_LIBS)" \
		link_app.$${shlib_target}
	@(cd ..; $(MAKE) rehash)

progs.h: progs.pl Makefile
	$(RM) progs.h
	$(PERL) progs.pl $(COMMANDS) >progs.h
	$(RM) openssl.o

# DO NOT DELETE THIS LINE -- make depend depends on it.

app_rand.o: ../crypto/ct/ct_internal.h ../e_os.h ../include/openssl/asn1.h
app_rand.o: ../include/openssl/bio.h ../include/openssl/buffer.h
app_rand.o: ../include/openssl/conf.h ../include/openssl/crypto.h
app_rand.o: ../include/openssl/ct.h ../include/openssl/e_os2.h
app_rand.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
app_rand.o: ../include/openssl/ecdsa.h ../include/openssl/engine.h
app_rand.o: ../include/openssl/err.h ../include/openssl/evp.h
app_rand.o: ../include/openssl/lhash.h ../include/openssl/obj_mac.h
app_rand.o: ../include/openssl/objects.h ../include/openssl/ocsp.h
app_rand.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
app_rand.o: ../include/openssl/ossl_typ.h ../include/openssl/pkcs7.h
app_rand.o: ../include/openssl/rand.h ../include/openssl/safestack.h
app_rand.o: ../include/openssl/sha.h ../include/openssl/stack.h
app_rand.o: ../include/openssl/symhacks.h ../include/openssl/txt_db.h
app_rand.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h
app_rand.o: ../include/openssl/x509v3.h app_rand.c apps.h progs.h
apps.o: ../crypto/ct/ct_internal.h ../e_os.h ../include/openssl/asn1.h
apps.o: ../include/openssl/bio.h ../include/openssl/bn.h
apps.o: ../include/openssl/buffer.h ../include/openssl/comp.h
apps.o: ../include/openssl/conf.h ../include/openssl/crypto.h
apps.o: ../include/openssl/ct.h ../include/openssl/dtls1.h
apps.o: ../include/openssl/e_os2.h ../include/openssl/ec.h
apps.o: ../include/openssl/ecdh.h ../include/openssl/ecdsa.h
apps.o: ../include/openssl/engine.h ../include/openssl/err.h
apps.o: ../include/openssl/evp.h ../include/openssl/hmac.h
apps.o: ../include/openssl/lhash.h ../include/openssl/obj_mac.h
apps.o: ../include/openssl/objects.h ../include/openssl/ocsp.h
apps.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
apps.o: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
apps.o: ../include/openssl/pem2.h ../include/openssl/pkcs12.h
apps.o: ../include/openssl/pkcs7.h ../include/openssl/rsa.h
apps.o: ../include/openssl/safestack.h ../include/openssl/sha.h
apps.o: ../include/openssl/srtp.h ../include/openssl/ssl.h
apps.o: ../include/openssl/ssl2.h ../include/openssl/ssl3.h
apps.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
apps.o: ../include/openssl/tls1.h ../include/openssl/txt_db.h
apps.o: ../include/openssl/ui.h ../include/openssl/x509.h
apps.o: ../include/openssl/x509_vfy.h ../include/openssl/x509v3.h apps.c apps.h
apps.o: progs.h
asn1pars.o: ../crypto/ct/ct_internal.h ../e_os.h ../include/openssl/asn1.h
asn1pars.o: ../include/openssl/bio.h ../include/openssl/buffer.h
asn1pars.o: ../include/openssl/conf.h ../include/openssl/crypto.h
asn1pars.o: ../include/openssl/ct.h ../include/openssl/e_os2.h
asn1pars.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
asn1pars.o: ../include/openssl/ecdsa.h ../include/openssl/engine.h
asn1pars.o: ../include/openssl/err.h ../include/openssl/evp.h
asn1pars.o: ../include/openssl/lhash.h ../include/openssl/obj_mac.h
asn1pars.o: ../include/openssl/objects.h ../include/openssl/ocsp.h
asn1pars.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
asn1pars.o: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
asn1pars.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
asn1pars.o: ../include/openssl/safestack.h ../include/openssl/sha.h
asn1pars.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
asn1pars.o: ../include/openssl/txt_db.h ../include/openssl/x509.h
asn1pars.o: ../include/openssl/x509_vfy.h ../include/openssl/x509v3.h apps.h
asn1pars.o: asn1pars.c progs.h
ca.o: ../crypto/ct/ct_internal.h ../e_os.h ../include/openssl/asn1.h
ca.o: ../include/openssl/bio.h ../include/openssl/bn.h
ca.o: ../include/openssl/buffer.h ../include/openssl/conf.h
ca.o: ../include/openssl/crypto.h ../include/openssl/ct.h
ca.o: ../include/openssl/e_os2.h ../include/openssl/ec.h
ca.o: ../include/openssl/ecdh.h ../include/openssl/ecdsa.h
ca.o: ../include/openssl/engine.h ../include/openssl/err.h
ca.o: ../include/openssl/evp.h ../include/openssl/lhash.h
ca.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
ca.o: ../include/openssl/ocsp.h ../include/openssl/opensslconf.h
ca.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
ca.o: ../include/openssl/pem.h ../include/openssl/pem2.h
ca.o: ../include/openssl/pkcs7.h ../include/openssl/safestack.h
ca.o: ../include/openssl/sha.h ../include/openssl/stack.h
ca.o: ../include/openssl/symhacks.h ../include/openssl/txt_db.h
ca.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h
ca.o: ../include/openssl/x509v3.h apps.h ca.c progs.h
ciphers.o: ../crypto/ct/ct_internal.h ../e_os.h ../include/openssl/asn1.h
ciphers.o: ../include/openssl/bio.h ../include/openssl/buffer.h
ciphers.o: ../include/openssl/comp.h ../include/openssl/conf.h
ciphers.o: ../include/openssl/crypto.h ../include/openssl/ct.h
ciphers.o: ../include/openssl/dtls1.h ../include/openssl/e_os2.h
ciphers.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
ciphers.o: ../include/openssl/ecdsa.h ../include/openssl/engine.h
ciphers.o: ../include/openssl/err.h ../include/openssl/evp.h
ciphers.o: ../include/openssl/hmac.h ../include/openssl/lhash.h
ciphers.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
ciphers.o: ../include/openssl/ocsp.h ../include/openssl/opensslconf.h
ciphers.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
ciphers.o: ../include/openssl/pem.h ../include/openssl/pem2.h
ciphers.o: ../include/openssl/pkcs7.h ../include/openssl/safestack.h
ciphers.o: ../include/openssl/sha.h ../include/openssl/srtp.h
ciphers.o: ../include/openssl/ssl.h ../include/openssl/ssl2.h
ciphers.o: ../include/openssl/ssl3.h ../include/openssl/stack.h
ciphers.o: ../include/openssl/symhacks.h ../include/openssl/tls1.h
ciphers.o: ../include/openssl/txt_db.h ../include/openssl/x509.h
ciphers.o: ../include/openssl/x509_vfy.h ../include/openssl/x509v3.h apps.h
ciphers.o: ciphers.c progs.h
cms.o: ../crypto/ct/ct_internal.h ../e_os.h ../include/openssl/asn1.h
cms.o: ../include/openssl/bio.h ../include/openssl/buffer.h
cms.o: ../include/openssl/cms.h ../include/openssl/conf.h
cms.o: ../include/openssl/crypto.h ../include/openssl/ct.h
cms.o: ../include/openssl/e_os2.h ../include/openssl/ec.h
cms.o: ../include/openssl/ecdh.h ../include/openssl/ecdsa.h
cms.o: ../include/openssl/engine.h ../include/openssl/err.h
cms.o: ../include/openssl/evp.h ../include/openssl/lhash.h
cms.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
cms.o: ../include/openssl/ocsp.h ../include/openssl/opensslconf.h
cms.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
cms.o: ../include/openssl/pem.h ../include/openssl/pem2.h
cms.o: ../include/openssl/pkcs7.h ../include/openssl/safestack.h
cms.o: ../include/openssl/sha.h ../include/openssl/stack.h
cms.o: ../include/openssl/symhacks.h ../include/openssl/txt_db.h
cms.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h
cms.o: ../include/openssl/x509v3.h apps.h cms.c progs.h
crl.o: ../crypto/ct/ct_internal.h ../e_os.h ../include/openssl/asn1.h
crl.o: ../include/openssl/bio.h ../include/openssl/buffer.h
crl.o: ../include/openssl/conf.h ../include/openssl/crypto.h
crl.o: ../include/openssl/ct.h ../include/openssl/e_os2.h
crl.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
crl.o: ../include/openssl/ecdsa.h ../include/openssl/engine.h
crl.o: ../include/openssl/err.h ../include/openssl/evp.h
crl.o: ../include/openssl/lhash.h ../include/openssl/obj_mac.h
crl.o: ../include/openssl/objects.h ../include/openssl/ocsp.h
crl.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
crl.o: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
crl.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
crl.o: ../include/openssl/safestack.h ../include/openssl/sha.h
crl.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
crl.o: ../include/openssl/txt_db.h ../include/openssl/x509.h
crl.o: ../include/openssl/x509_vfy.h ../include/openssl/x509v3.h apps.h crl.c
crl.o: progs.h
crl2p7.o: ../crypto/ct/ct_internal.h ../e_os.h ../include/openssl/asn1.h
crl2p7.o: ../include/openssl/bio.h ../include/openssl/buffer.h
crl2p7.o: ../include/openssl/conf.h ../include/openssl/crypto.h
crl2p7.o: ../include/openssl/ct.h ../include/openssl/e_os2.h
crl2p7.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
crl2p7.o: ../include/openssl/ecdsa.h ../include/openssl/engine.h
crl2p7.o: ../include/openssl/err.h ../include/openssl/evp.h
crl2p7.o: ../include/openssl/lhash.h ../include/openssl/obj_mac.h
crl2p7.o: ../include/openssl/objects.h ../include/openssl/ocsp.h
crl2p7.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
crl2p7.o: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
crl2p7.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
crl2p7.o: ../include/openssl/safestack.h ../include/openssl/sha.h
crl2p7.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
crl2p7.o: ../include/openssl/txt_db.h ../include/openssl/x509.h
crl2p7.o: ../include/openssl/x509_vfy.h ../include/openssl/x509v3.h apps.h
crl2p7.o: crl2p7.c progs.h
ct.o: ../crypto/ct/ct_internal.h ../e_os.h ../include/openssl/asn1.h
ct.o: ../include/openssl/bio.h ../include/openssl/bn.h
ct.o: ../include/openssl/buffer.h ../include/openssl/conf.h
ct.o: ../include/openssl/crypto.h ../include/openssl/ct.h
ct.o: ../include/openssl/e_os2.h ../include/openssl/ec.h
ct.o: ../include/openssl/ecdh.h ../include/openssl/ecdsa.h
ct.o: ../include/openssl/engine.h ../include/openssl/err.h
ct.o: ../include/openssl/evp.h ../include/openssl/lhash.h
ct.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
ct.o: ../include/openssl/ocsp.h ../include/openssl/opensslconf.h
ct.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
ct.o: ../include/openssl/pem.h ../include/openssl/pem2.h
ct.o: ../include/openssl/pkcs7.h ../include/openssl/safestack.h
ct.o: ../include/openssl/sha.h ../include/openssl/stack.h
ct.o: ../include/openssl/symhacks.h ../include/openssl/txt_db.h
ct.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h
ct.o: ../include/openssl/x509v3.h apps.h ct.c progs.h
dgst.o: ../crypto/ct/ct_internal.h ../e_os.h ../include/openssl/asn1.h
dgst.o: ../include/openssl/bio.h ../include/openssl/buffer.h
dgst.o: ../include/openssl/conf.h ../include/openssl/crypto.h
dgst.o: ../include/openssl/ct.h ../include/openssl/e_os2.h
dgst.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
dgst.o: ../include/openssl/ecdsa.h ../include/openssl/engine.h
dgst.o: ../include/openssl/err.h ../include/openssl/evp.h
dgst.o: ../include/openssl/hmac.h ../include/openssl/lhash.h
dgst.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
dgst.o: ../include/openssl/ocsp.h ../include/openssl/opensslconf.h
dgst.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
dgst.o: ../include/openssl/pem.h ../include/openssl/pem2.h
dgst.o: ../include/openssl/pkcs7.h ../include/openssl/safestack.h
dgst.o: ../include/openssl/sha.h ../include/openssl/stack.h
dgst.o: ../include/openssl/symhacks.h ../include/openssl/txt_db.h
dgst.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h
dgst.o: ../include/openssl/x509v3.h apps.h dgst.c progs.h
dhparam.o: ../crypto/ct/ct_internal.h ../e_os.h ../include/openssl/asn1.h
dhparam.o: ../include/openssl/bio.h ../include/openssl/bn.h
dhparam.o: ../include/openssl/buffer.h ../include/openssl/conf.h
dhparam.o: ../include/openssl/crypto.h ../include/openssl/ct.h
dhparam.o: ../include/openssl/dh.h ../include/openssl/dsa.h
dhparam.o: ../include/openssl/e_os2.h ../include/openssl/ec.h
dhparam.o: ../include/openssl/ecdh.h ../include/openssl/ecdsa.h
dhparam.o: ../include/openssl/engine.h ../include/openssl/err.h
dhparam.o: ../include/openssl/evp.h ../include/openssl/lhash.h
dhparam.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
dhparam.o: ../include/openssl/ocsp.h ../include/openssl/opensslconf.h
dhparam.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
dhparam.o: ../include/openssl/pem.h ../include/openssl/pem2.h
dhparam.o: ../include/openssl/pkcs7.h ../include/openssl/safestack.h
dhparam.o: ../include/openssl/sha.h ../include/openssl/stack.h
dhparam.o: ../include/openssl/symhacks.h ../include/openssl/txt_db.h
dhparam.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h
dhparam.o: ../include/openssl/x509v3.h apps.h dhparam.c progs.h
dsa.o: ../crypto/ct/ct_internal.h ../e_os.h ../include/openssl/asn1.h
dsa.o: ../include/openssl/bio.h ../include/openssl/bn.h
dsa.o: ../include/openssl/buffer.h ../include/openssl/conf.h
dsa.o: ../include/openssl/crypto.h ../include/openssl/ct.h
dsa.o: ../include/openssl/dsa.h ../include/openssl/e_os2.h
dsa.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
dsa.o: ../include/openssl/ecdsa.h ../include/openssl/engine.h
dsa.o: ../include/openssl/err.h ../include/openssl/evp.h
dsa.o: ../include/openssl/lhash.h ../include/openssl/obj_mac.h
dsa.o: ../include/openssl/objects.h ../include/openssl/ocsp.h
dsa.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
dsa.o: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
dsa.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
dsa.o: ../include/openssl/safestack.h ../include/openssl/sha.h
dsa.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
dsa.o: ../include/openssl/txt_db.h ../include/openssl/x509.h
dsa.o: ../include/openssl/x509_vfy.h ../include/openssl/x509v3.h apps.h dsa.c
dsa.o: progs.h
dsaparam.o: ../crypto/ct/ct_internal.h ../e_os.h ../include/openssl/asn1.h
dsaparam.o: ../include/openssl/bio.h ../include/openssl/bn.h
dsaparam.o: ../include/openssl/buffer.h ../include/openssl/conf.h
dsaparam.o: ../include/openssl/crypto.h ../include/openssl/ct.h
dsaparam.o: ../include/openssl/dsa.h ../include/openssl/e_os2.h
dsaparam.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
dsaparam.o: ../include/openssl/ecdsa.h ../include/openssl/engine.h
dsaparam.o: ../include/openssl/err.h ../include/openssl/evp.h
dsaparam.o: ../include/openssl/lhash.h ../include/openssl/obj_mac.h
dsaparam.o: ../include/openssl/objects.h ../include/openssl/ocsp.h
dsaparam.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
dsaparam.o: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
dsaparam.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
dsaparam.o: ../include/openssl/safestack.h ../include/openssl/sha.h
dsaparam.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
dsaparam.o: ../include/openssl/txt_db.h ../include/openssl/x509.h
dsaparam.o: ../include/openssl/x509_vfy.h ../include/openssl/x509v3.h apps.h
dsaparam.o: dsaparam.c progs.h
ec.o: ../crypto/ct/ct_internal.h ../e_os.h ../include/openssl/asn1.h
ec.o: ../include/openssl/bio.h ../include/openssl/buffer.h
ec.o: ../include/openssl/conf.h ../include/openssl/crypto.h
ec.o: ../include/openssl/ct.h ../include/openssl/e_os2.h
ec.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
ec.o: ../include/openssl/ecdsa.h ../include/openssl/engine.h
ec.o: ../include/openssl/err.h ../include/openssl/evp.h
ec.o: ../include/openssl/lhash.h ../include/openssl/obj_mac.h
ec.o: ../include/openssl/objects.h ../include/openssl/ocsp.h
ec.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
ec.o: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
ec.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
ec.o: ../include/openssl/safestack.h ../include/openssl/sha.h
ec.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
ec.o: ../include/openssl/txt_db.h ../include/openssl/x509.h
ec.o: ../include/openssl/x509_vfy.h ../include/openssl/x509v3.h apps.h ec.c
ec.o: progs.h
ecparam.o: ../crypto/ct/ct_internal.h ../e_os.h ../include/openssl/asn1.h
ecparam.o: ../include/openssl/bio.h ../include/openssl/bn.h
ecparam.o: ../include/openssl/buffer.h ../include/openssl/conf.h
ecparam.o: ../include/openssl/crypto.h ../include/openssl/ct.h
ecparam.o: ../include/openssl/e_os2.h ../include/openssl/ec.h
ecparam.o: ../include/openssl/ecdh.h ../include/openssl/ecdsa.h
ecparam.o: ../include/openssl/engine.h ../include/openssl/err.h
ecparam.o: ../include/openssl/evp.h ../include/openssl/lhash.h
ecparam.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
ecparam.o: ../include/openssl/ocsp.h ../include/openssl/opensslconf.h
ecparam.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
ecparam.o: ../include/openssl/pem.h ../include/openssl/pem2.h
ecparam.o: ../include/openssl/pkcs7.h ../include/openssl/safestack.h
ecparam.o: ../include/openssl/sha.h ../include/openssl/stack.h
ecparam.o: ../include/openssl/symhacks.h ../include/openssl/txt_db.h
ecparam.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h
ecparam.o: ../include/openssl/x509v3.h apps.h ecparam.c progs.h
enc.o: ../crypto/ct/ct_internal.h ../e_os.h ../include/openssl/asn1.h
enc.o: ../include/openssl/bio.h ../include/openssl/buffer.h
enc.o: ../include/openssl/comp.h ../include/openssl/conf.h
enc.o: ../include/openssl/crypto.h ../include/openssl/ct.h
enc.o: ../include/openssl/e_os2.h ../include/openssl/ec.h
enc.o: ../include/openssl/ecdh.h ../include/openssl/ecdsa.h
enc.o: ../include/openssl/engine.h ../include/openssl/err.h
enc.o: ../include/openssl/evp.h ../include/openssl/lhash.h
enc.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
enc.o: ../include/openssl/ocsp.h ../include/openssl/opensslconf.h
enc.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
enc.o: ../include/openssl/pem.h ../include/openssl/pem2.h
enc.o: ../include/openssl/pkcs7.h ../include/openssl/rand.h
enc.o: ../include/openssl/safestack.h ../include/openssl/sha.h
enc.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
enc.o: ../include/openssl/txt_db.h ../include/openssl/x509.h
enc.o: ../include/openssl/x509_vfy.h ../include/openssl/x509v3.h apps.h enc.c
enc.o: progs.h
engine.o: ../crypto/ct/ct_internal.h ../e_os.h ../include/openssl/asn1.h
engine.o: ../include/openssl/bio.h ../include/openssl/buffer.h
engine.o: ../include/openssl/comp.h ../include/openssl/conf.h
engine.o: ../include/openssl/crypto.h ../include/openssl/ct.h
engine.o: ../include/openssl/dtls1.h ../include/openssl/e_os2.h
engine.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
engine.o: ../include/openssl/ecdsa.h ../include/openssl/engine.h
engine.o: ../include/openssl/err.h ../include/openssl/evp.h
engine.o: ../include/openssl/hmac.h ../include/openssl/lhash.h
engine.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
engine.o: ../include/openssl/ocsp.h ../include/openssl/opensslconf.h
engine.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
engine.o: ../include/openssl/pem.h ../include/openssl/pem2.h
engine.o: ../include/openssl/pkcs7.h ../include/openssl/safestack.h
engine.o: ../include/openssl/sha.h ../include/openssl/srtp.h
engine.o: ../include/openssl/ssl.h ../include/openssl/ssl2.h
engine.o: ../include/openssl/ssl3.h ../include/openssl/stack.h
engine.o: ../include/openssl/symhacks.h ../include/openssl/tls1.h
engine.o: ../include/openssl/txt_db.h ../include/openssl/x509.h
engine.o: ../include/openssl/x509_vfy.h ../include/openssl/x509v3.h apps.h
engine.o: engine.c progs.h
errstr.o: ../crypto/ct/ct_internal.h ../e_os.h ../include/openssl/asn1.h
errstr.o: ../include/openssl/bio.h ../include/openssl/buffer.h
errstr.o: ../include/openssl/comp.h ../include/openssl/conf.h
errstr.o: ../include/openssl/crypto.h ../include/openssl/ct.h
errstr.o: ../include/openssl/dtls1.h ../include/openssl/e_os2.h
errstr.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
errstr.o: ../include/openssl/ecdsa.h ../include/openssl/engine.h
errstr.o: ../include/openssl/err.h ../include/openssl/evp.h
errstr.o: ../include/openssl/hmac.h ../include/openssl/lhash.h
errstr.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
errstr.o: ../include/openssl/ocsp.h ../include/openssl/opensslconf.h
errstr.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
errstr.o: ../include/openssl/pem.h ../include/openssl/pem2.h
errstr.o: ../include/openssl/pkcs7.h ../include/openssl/safestack.h
errstr.o: ../include/openssl/sha.h ../include/openssl/srtp.h
errstr.o: ../include/openssl/ssl.h ../include/openssl/ssl2.h
errstr.o: ../include/openssl/ssl3.h ../include/openssl/stack.h
errstr.o: ../include/openssl/symhacks.h ../include/openssl/tls1.h
errstr.o: ../include/openssl/txt_db.h ../include/openssl/x509.h
errstr.o: ../include/openssl/x509_vfy.h ../include/openssl/x509v3.h apps.h
errstr.o: errstr.c progs.h
gendsa.o: ../crypto/ct/ct_internal.h ../e_os.h ../include/openssl/asn1.h
gendsa.o: ../include/openssl/bio.h ../include/openssl/bn.h
gendsa.o: ../include/openssl/buffer.h ../include/openssl/conf.h
gendsa.o: ../include/openssl/crypto.h ../include/openssl/ct.h
gendsa.o: ../include/openssl/dsa.h ../include/openssl/e_os2.h
gendsa.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
gendsa.o: ../include/openssl/ecdsa.h ../include/openssl/engine.h
gendsa.o: ../include/openssl/err.h ../include/openssl/evp.h
gendsa.o: ../include/openssl/lhash.h ../include/openssl/obj_mac.h
gendsa.o: ../include/openssl/objects.h ../include/openssl/ocsp.h
gendsa.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
gendsa.o: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
gendsa.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
gendsa.o: ../include/openssl/safestack.h ../include/openssl/sha.h
gendsa.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
gendsa.o: ../include/openssl/txt_db.h ../include/openssl/x509.h
gendsa.o: ../include/openssl/x509_vfy.h ../include/openssl/x509v3.h apps.h
gendsa.o: gendsa.c progs.h
genpkey.o: ../crypto/ct/ct_internal.h ../e_os.h ../include/openssl/asn1.h
genpkey.o: ../include/openssl/bio.h ../include/openssl/buffer.h
genpkey.o: ../include/openssl/conf.h ../include/openssl/crypto.h
genpkey.o: ../include/openssl/ct.h ../include/openssl/e_os2.h
genpkey.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
genpkey.o: ../include/openssl/ecdsa.h ../include/openssl/engine.h
genpkey.o: ../include/openssl/err.h ../include/openssl/evp.h
genpkey.o: ../include/openssl/lhash.h ../include/openssl/obj_mac.h
genpkey.o: ../include/openssl/objects.h ../include/openssl/ocsp.h
genpkey.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
genpkey.o: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
genpkey.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
genpkey.o: ../include/openssl/safestack.h ../include/openssl/sha.h
genpkey.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
genpkey.o: ../include/openssl/txt_db.h ../include/openssl/x509.h
genpkey.o: ../include/openssl/x509_vfy.h ../include/openssl/x509v3.h apps.h
genpkey.o: genpkey.c progs.h
genrsa.o: ../crypto/ct/ct_internal.h ../e_os.h ../include/openssl/asn1.h
genrsa.o: ../include/openssl/bio.h ../include/openssl/bn.h
genrsa.o: ../include/openssl/buffer.h ../include/openssl/conf.h
genrsa.o: ../include/openssl/crypto.h ../include/openssl/ct.h
genrsa.o: ../include/openssl/e_os2.h ../include/openssl/ec.h
genrsa.o: ../include/openssl/ecdh.h ../include/openssl/ecdsa.h
genrsa.o: ../include/openssl/engine.h ../include/openssl/err.h
genrsa.o: ../include/openssl/evp.h ../include/openssl/lhash.h
genrsa.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
genrsa.o: ../include/openssl/ocsp.h ../include/openssl/opensslconf.h
genrsa.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
genrsa.o: ../include/openssl/pem.h ../include/openssl/pem2.h
genrsa.o: ../include/openssl/pkcs7.h ../include/openssl/rand.h
genrsa.o: ../include/openssl/rsa.h ../include/openssl/safestack.h
genrsa.o: ../include/openssl/sha.h ../include/openssl/stack.h
genrsa.o: ../include/openssl/symhacks.h ../include/openssl/txt_db.h
genrsa.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h
genrsa.o: ../include/openssl/x509v3.h apps.h genrsa.c progs.h
nseq.o: ../crypto/ct/ct_internal.h ../e_os.h ../include/openssl/asn1.h
nseq.o: ../include/openssl/bio.h ../include/openssl/buffer.h
nseq.o: ../include/openssl/conf.h ../include/openssl/crypto.h
nseq.o: ../include/openssl/ct.h ../include/openssl/e_os2.h
nseq.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
nseq.o: ../include/openssl/ecdsa.h ../include/openssl/engine.h
nseq.o: ../include/openssl/err.h ../include/openssl/evp.h
nseq.o: ../include/openssl/lhash.h ../include/openssl/obj_mac.h
nseq.o: ../include/openssl/objects.h ../include/openssl/ocsp.h
nseq.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
nseq.o: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
nseq.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
nseq.o: ../include/openssl/safestack.h ../include/openssl/sha.h
nseq.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
nseq.o: ../include/openssl/txt_db.h ../include/openssl/x509.h
nseq.o: ../include/openssl/x509_vfy.h ../include/openssl/x509v3.h apps.h nseq.c
nseq.o: progs.h
ocsp.o: ../crypto/ct/ct_internal.h ../e_os.h ../include/openssl/asn1.h
ocsp.o: ../include/openssl/bio.h ../include/openssl/bn.h
ocsp.o: ../include/openssl/buffer.h ../include/openssl/comp.h
ocsp.o: ../include/openssl/conf.h ../include/openssl/crypto.h
ocsp.o: ../include/openssl/ct.h ../include/openssl/dtls1.h
ocsp.o: ../include/openssl/e_os2.h ../include/openssl/ec.h
ocsp.o: ../include/openssl/ecdh.h ../include/openssl/ecdsa.h
ocsp.o: ../include/openssl/engine.h ../include/openssl/err.h
ocsp.o: ../include/openssl/evp.h ../include/openssl/hmac.h
ocsp.o: ../include/openssl/lhash.h ../include/openssl/obj_mac.h
ocsp.o: ../include/openssl/objects.h ../include/openssl/ocsp.h
ocsp.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
ocsp.o: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
ocsp.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
ocsp.o: ../include/openssl/safestack.h ../include/openssl/sha.h
ocsp.o: ../include/openssl/srtp.h ../include/openssl/ssl.h
ocsp.o: ../include/openssl/ssl2.h ../include/openssl/ssl3.h
ocsp.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
ocsp.o: ../include/openssl/tls1.h ../include/openssl/txt_db.h
ocsp.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h
ocsp.o: ../include/openssl/x509v3.h apps.h ocsp.c progs.h
openssl.o: ../crypto/ct/ct_internal.h ../e_os.h ../include/openssl/asn1.h
openssl.o: ../include/openssl/bio.h ../include/openssl/buffer.h
openssl.o: ../include/openssl/comp.h ../include/openssl/conf.h
openssl.o: ../include/openssl/crypto.h ../include/openssl/ct.h
openssl.o: ../include/openssl/dtls1.h ../include/openssl/e_os2.h
openssl.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
openssl.o: ../include/openssl/ecdsa.h ../include/openssl/engine.h
openssl.o: ../include/openssl/err.h ../include/openssl/evp.h
openssl.o: ../include/openssl/hmac.h ../include/openssl/lhash.h
openssl.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
openssl.o: ../include/openssl/ocsp.h ../include/openssl/opensslconf.h
openssl.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
openssl.o: ../include/openssl/pem.h ../include/openssl/pem2.h
openssl.o: ../include/openssl/pkcs7.h ../include/openssl/rand.h
openssl.o: ../include/openssl/safestack.h ../include/openssl/sha.h
openssl.o: ../include/openssl/srtp.h ../include/openssl/ssl.h
openssl.o: ../include/openssl/ssl2.h ../include/openssl/ssl3.h
openssl.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
openssl.o: ../include/openssl/tls1.h ../include/openssl/txt_db.h
openssl.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h
openssl.o: ../include/openssl/x509v3.h apps.h openssl.c progs.h s_apps.h
opt.o: ../crypto/ct/ct_internal.h ../e_os.h ../include/openssl/asn1.h
opt.o: ../include/openssl/bio.h ../include/openssl/buffer.h
opt.o: ../include/openssl/conf.h ../include/openssl/crypto.h
opt.o: ../include/openssl/ct.h ../include/openssl/e_os2.h
opt.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
opt.o: ../include/openssl/ecdsa.h ../include/openssl/engine.h
opt.o: ../include/openssl/err.h ../include/openssl/evp.h
opt.o: ../include/openssl/lhash.h ../include/openssl/obj_mac.h
opt.o: ../include/openssl/objects.h ../include/openssl/ocsp.h
opt.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
opt.o: ../include/openssl/ossl_typ.h ../include/openssl/pkcs7.h
opt.o: ../include/openssl/safestack.h ../include/openssl/sha.h
opt.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
opt.o: ../include/openssl/txt_db.h ../include/openssl/x509.h
opt.o: ../include/openssl/x509_vfy.h ../include/openssl/x509v3.h apps.h opt.c
opt.o: progs.h
passwd.o: ../crypto/ct/ct_internal.h ../e_os.h ../include/openssl/asn1.h
passwd.o: ../include/openssl/bio.h ../include/openssl/buffer.h
passwd.o: ../include/openssl/conf.h ../include/openssl/crypto.h
passwd.o: ../include/openssl/ct.h ../include/openssl/des.h
passwd.o: ../include/openssl/e_os2.h ../include/openssl/ec.h
passwd.o: ../include/openssl/ecdh.h ../include/openssl/ecdsa.h
passwd.o: ../include/openssl/engine.h ../include/openssl/err.h
passwd.o: ../include/openssl/evp.h ../include/openssl/lhash.h
passwd.o: ../include/openssl/md5.h ../include/openssl/obj_mac.h
passwd.o: ../include/openssl/objects.h ../include/openssl/ocsp.h
passwd.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
passwd.o: ../include/openssl/ossl_typ.h ../include/openssl/pkcs7.h
passwd.o: ../include/openssl/rand.h ../include/openssl/safestack.h
passwd.o: ../include/openssl/sha.h ../include/openssl/stack.h
passwd.o: ../include/openssl/symhacks.h ../include/openssl/txt_db.h
passwd.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h
passwd.o: ../include/openssl/x509v3.h apps.h passwd.c progs.h
pkcs12.o: ../crypto/ct/ct_internal.h ../e_os.h ../include/openssl/asn1.h
pkcs12.o: ../include/openssl/bio.h ../include/openssl/buffer.h
pkcs12.o: ../include/openssl/conf.h ../include/openssl/crypto.h
pkcs12.o: ../include/openssl/ct.h ../include/openssl/e_os2.h
pkcs12.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
pkcs12.o: ../include/openssl/ecdsa.h ../include/openssl/engine.h
pkcs12.o: ../include/openssl/err.h ../include/openssl/evp.h
pkcs12.o: ../include/openssl/lhash.h ../include/openssl/obj_mac.h
pkcs12.o: ../include/openssl/objects.h ../include/openssl/ocsp.h
pkcs12.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
pkcs12.o: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
pkcs12.o: ../include/openssl/pem2.h ../include/openssl/pkcs12.h
pkcs12.o: ../include/openssl/pkcs7.h ../include/openssl/safestack.h
pkcs12.o: ../include/openssl/sha.h ../include/openssl/stack.h
pkcs12.o: ../include/openssl/symhacks.h ../include/openssl/txt_db.h
pkcs12.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h
pkcs12.o: ../include/openssl/x509v3.h apps.h pkcs12.c progs.h
pkcs7.o: ../crypto/ct/ct_internal.h ../e_os.h ../include/openssl/asn1.h
pkcs7.o: ../include/openssl/bio.h ../include/openssl/buffer.h
pkcs7.o: ../include/openssl/conf.h ../include/openssl/crypto.h
pkcs7.o: ../include/openssl/ct.h ../include/openssl/e_os2.h
pkcs7.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
pkcs7.o: ../include/openssl/ecdsa.h ../include/openssl/engine.h
pkcs7.o: ../include/openssl/err.h ../include/openssl/evp.h
pkcs7.o: ../include/openssl/lhash.h ../include/openssl/obj_mac.h
pkcs7.o: ../include/openssl/objects.h ../include/openssl/ocsp.h
pkcs7.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
pkcs7.o: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
pkcs7.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
pkcs7.o: ../include/openssl/safestack.h ../include/openssl/sha.h
pkcs7.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
pkcs7.o: ../include/openssl/txt_db.h ../include/openssl/x509.h
pkcs7.o: ../include/openssl/x509_vfy.h ../include/openssl/x509v3.h apps.h
pkcs7.o: pkcs7.c progs.h
pkcs8.o: ../crypto/ct/ct_internal.h ../e_os.h ../include/openssl/asn1.h
pkcs8.o: ../include/openssl/bio.h ../include/openssl/buffer.h
pkcs8.o: ../include/openssl/conf.h ../include/openssl/crypto.h
pkcs8.o: ../include/openssl/ct.h ../include/openssl/e_os2.h
pkcs8.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
pkcs8.o: ../include/openssl/ecdsa.h ../include/openssl/engine.h
pkcs8.o: ../include/openssl/err.h ../include/openssl/evp.h
pkcs8.o: ../include/openssl/lhash.h ../include/openssl/obj_mac.h
pkcs8.o: ../include/openssl/objects.h ../include/openssl/ocsp.h
pkcs8.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
pkcs8.o: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
pkcs8.o: ../include/openssl/pem2.h ../include/openssl/pkcs12.h
pkcs8.o: ../include/openssl/pkcs7.h ../include/openssl/safestack.h
pkcs8.o: ../include/openssl/sha.h ../include/openssl/stack.h
pkcs8.o: ../include/openssl/symhacks.h ../include/openssl/txt_db.h
pkcs8.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h
pkcs8.o: ../include/openssl/x509v3.h apps.h pkcs8.c progs.h
pkey.o: ../crypto/ct/ct_internal.h ../e_os.h ../include/openssl/asn1.h
pkey.o: ../include/openssl/bio.h ../include/openssl/buffer.h
pkey.o: ../include/openssl/conf.h ../include/openssl/crypto.h
pkey.o: ../include/openssl/ct.h ../include/openssl/e_os2.h
pkey.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
pkey.o: ../include/openssl/ecdsa.h ../include/openssl/engine.h
pkey.o: ../include/openssl/err.h ../include/openssl/evp.h
pkey.o: ../include/openssl/lhash.h ../include/openssl/obj_mac.h
pkey.o: ../include/openssl/objects.h ../include/openssl/ocsp.h
pkey.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
pkey.o: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
pkey.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
pkey.o: ../include/openssl/safestack.h ../include/openssl/sha.h
pkey.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
pkey.o: ../include/openssl/txt_db.h ../include/openssl/x509.h
pkey.o: ../include/openssl/x509_vfy.h ../include/openssl/x509v3.h apps.h pkey.c
pkey.o: progs.h
pkeyparam.o: ../crypto/ct/ct_internal.h ../e_os.h ../include/openssl/asn1.h
pkeyparam.o: ../include/openssl/bio.h ../include/openssl/buffer.h
pkeyparam.o: ../include/openssl/conf.h ../include/openssl/crypto.h
pkeyparam.o: ../include/openssl/ct.h ../include/openssl/e_os2.h
pkeyparam.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
pkeyparam.o: ../include/openssl/ecdsa.h ../include/openssl/engine.h
pkeyparam.o: ../include/openssl/err.h ../include/openssl/evp.h
pkeyparam.o: ../include/openssl/lhash.h ../include/openssl/obj_mac.h
pkeyparam.o: ../include/openssl/objects.h ../include/openssl/ocsp.h
pkeyparam.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
pkeyparam.o: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
pkeyparam.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
pkeyparam.o: ../include/openssl/safestack.h ../include/openssl/sha.h
pkeyparam.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
pkeyparam.o: ../include/openssl/txt_db.h ../include/openssl/x509.h
pkeyparam.o: ../include/openssl/x509_vfy.h ../include/openssl/x509v3.h apps.h
pkeyparam.o: pkeyparam.c progs.h
pkeyutl.o: ../crypto/ct/ct_internal.h ../e_os.h ../include/openssl/asn1.h
pkeyutl.o: ../include/openssl/bio.h ../include/openssl/buffer.h
pkeyutl.o: ../include/openssl/conf.h ../include/openssl/crypto.h
pkeyutl.o: ../include/openssl/ct.h ../include/openssl/e_os2.h
pkeyutl.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
pkeyutl.o: ../include/openssl/ecdsa.h ../include/openssl/engine.h
pkeyutl.o: ../include/openssl/err.h ../include/openssl/evp.h
pkeyutl.o: ../include/openssl/lhash.h ../include/openssl/obj_mac.h
pkeyutl.o: ../include/openssl/objects.h ../include/openssl/ocsp.h
pkeyutl.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
pkeyutl.o: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
pkeyutl.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
pkeyutl.o: ../include/openssl/safestack.h ../include/openssl/sha.h
pkeyutl.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
pkeyutl.o: ../include/openssl/txt_db.h ../include/openssl/x509.h
pkeyutl.o: ../include/openssl/x509_vfy.h ../include/openssl/x509v3.h apps.h
pkeyutl.o: pkeyutl.c progs.h
prime.o: ../crypto/ct/ct_internal.h ../e_os.h ../include/openssl/asn1.h
prime.o: ../include/openssl/bio.h ../include/openssl/bn.h
prime.o: ../include/openssl/buffer.h ../include/openssl/conf.h
prime.o: ../include/openssl/crypto.h ../include/openssl/ct.h
prime.o: ../include/openssl/e_os2.h ../include/openssl/ec.h
prime.o: ../include/openssl/ecdh.h ../include/openssl/ecdsa.h
prime.o: ../include/openssl/engine.h ../include/openssl/err.h
prime.o: ../include/openssl/evp.h ../include/openssl/lhash.h
prime.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
prime.o: ../include/openssl/ocsp.h ../include/openssl/opensslconf.h
prime.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
prime.o: ../include/openssl/pkcs7.h ../include/openssl/safestack.h
prime.o: ../include/openssl/sha.h ../include/openssl/stack.h
prime.o: ../include/openssl/symhacks.h ../include/openssl/txt_db.h
prime.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h
prime.o: ../include/openssl/x509v3.h apps.h prime.c progs.h
rand.o: ../crypto/ct/ct_internal.h ../e_os.h ../include/openssl/asn1.h
rand.o: ../include/openssl/bio.h ../include/openssl/buffer.h
rand.o: ../include/openssl/conf.h ../include/openssl/crypto.h
rand.o: ../include/openssl/ct.h ../include/openssl/e_os2.h
rand.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
rand.o: ../include/openssl/ecdsa.h ../include/openssl/engine.h
rand.o: ../include/openssl/err.h ../include/openssl/evp.h
rand.o: ../include/openssl/lhash.h ../include/openssl/obj_mac.h
rand.o: ../include/openssl/objects.h ../include/openssl/ocsp.h
rand.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
rand.o: ../include/openssl/ossl_typ.h ../include/openssl/pkcs7.h
rand.o: ../include/openssl/rand.h ../include/openssl/safestack.h
rand.o: ../include/openssl/sha.h ../include/openssl/stack.h
rand.o: ../include/openssl/symhacks.h ../include/openssl/txt_db.h
rand.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h
rand.o: ../include/openssl/x509v3.h apps.h progs.h rand.c
req.o: ../crypto/ct/ct_internal.h ../e_os.h ../include/openssl/asn1.h
req.o: ../include/openssl/bio.h ../include/openssl/bn.h
req.o: ../include/openssl/buffer.h ../include/openssl/conf.h
req.o: ../include/openssl/crypto.h ../include/openssl/ct.h
req.o: ../include/openssl/dsa.h ../include/openssl/e_os2.h
req.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
req.o: ../include/openssl/ecdsa.h ../include/openssl/engine.h
req.o: ../include/openssl/err.h ../include/openssl/evp.h
req.o: ../include/openssl/lhash.h ../include/openssl/obj_mac.h
req.o: ../include/openssl/objects.h ../include/openssl/ocsp.h
req.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
req.o: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
req.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
req.o: ../include/openssl/rsa.h ../include/openssl/safestack.h
req.o: ../include/openssl/sha.h ../include/openssl/stack.h
req.o: ../include/openssl/symhacks.h ../include/openssl/txt_db.h
req.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h
req.o: ../include/openssl/x509v3.h apps.h progs.h req.c
rsa.o: ../crypto/ct/ct_internal.h ../e_os.h ../include/openssl/asn1.h
rsa.o: ../include/openssl/bio.h ../include/openssl/bn.h
rsa.o: ../include/openssl/buffer.h ../include/openssl/conf.h
rsa.o: ../include/openssl/crypto.h ../include/openssl/ct.h
rsa.o: ../include/openssl/e_os2.h ../include/openssl/ec.h
rsa.o: ../include/openssl/ecdh.h ../include/openssl/ecdsa.h
rsa.o: ../include/openssl/engine.h ../include/openssl/err.h
rsa.o: ../include/openssl/evp.h ../include/openssl/lhash.h
rsa.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
rsa.o: ../include/openssl/ocsp.h ../include/openssl/opensslconf.h
rsa.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
rsa.o: ../include/openssl/pem.h ../include/openssl/pem2.h
rsa.o: ../include/openssl/pkcs7.h ../include/openssl/rsa.h
rsa.o: ../include/openssl/safestack.h ../include/openssl/sha.h
rsa.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
rsa.o: ../include/openssl/txt_db.h ../include/openssl/x509.h
rsa.o: ../include/openssl/x509_vfy.h ../include/openssl/x509v3.h apps.h progs.h
rsa.o: rsa.c
rsautl.o: ../crypto/ct/ct_internal.h ../e_os.h ../include/openssl/asn1.h
rsautl.o: ../include/openssl/bio.h ../include/openssl/buffer.h
rsautl.o: ../include/openssl/conf.h ../include/openssl/crypto.h
rsautl.o: ../include/openssl/ct.h ../include/openssl/e_os2.h
rsautl.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
rsautl.o: ../include/openssl/ecdsa.h ../include/openssl/engine.h
rsautl.o: ../include/openssl/err.h ../include/openssl/evp.h
rsautl.o: ../include/openssl/lhash.h ../include/openssl/obj_mac.h
rsautl.o: ../include/openssl/objects.h ../include/openssl/ocsp.h
rsautl.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
rsautl.o: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
rsautl.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
rsautl.o: ../include/openssl/rsa.h ../include/openssl/safestack.h
rsautl.o: ../include/openssl/sha.h ../include/openssl/stack.h
rsautl.o: ../include/openssl/symhacks.h ../include/openssl/txt_db.h
rsautl.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h
rsautl.o: ../include/openssl/x509v3.h apps.h progs.h rsautl.c
s_cb.o: ../crypto/ct/ct_internal.h ../e_os.h ../include/openssl/asn1.h
s_cb.o: ../include/openssl/bio.h ../include/openssl/bn.h
s_cb.o: ../include/openssl/buffer.h ../include/openssl/comp.h
s_cb.o: ../include/openssl/conf.h ../include/openssl/crypto.h
s_cb.o: ../include/openssl/ct.h ../include/openssl/dh.h
s_cb.o: ../include/openssl/dtls1.h ../include/openssl/e_os2.h
s_cb.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
s_cb.o: ../include/openssl/ecdsa.h ../include/openssl/engine.h
s_cb.o: ../include/openssl/err.h ../include/openssl/evp.h
s_cb.o: ../include/openssl/hmac.h ../include/openssl/lhash.h
s_cb.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
s_cb.o: ../include/openssl/ocsp.h ../include/openssl/opensslconf.h
s_cb.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
s_cb.o: ../include/openssl/pem.h ../include/openssl/pem2.h
s_cb.o: ../include/openssl/pkcs7.h ../include/openssl/rand.h
s_cb.o: ../include/openssl/safestack.h ../include/openssl/sha.h
s_cb.o: ../include/openssl/srtp.h ../include/openssl/ssl.h
s_cb.o: ../include/openssl/ssl2.h ../include/openssl/ssl3.h
s_cb.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
s_cb.o: ../include/openssl/tls1.h ../include/openssl/txt_db.h
s_cb.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h
s_cb.o: ../include/openssl/x509v3.h apps.h progs.h s_apps.h s_cb.c
s_client.o: ../crypto/ct/ct_internal.h ../e_os.h ../include/openssl/asn1.h
s_client.o: ../include/openssl/bio.h ../include/openssl/bn.h
s_client.o: ../include/openssl/buffer.h ../include/openssl/comp.h
s_client.o: ../include/openssl/conf.h ../include/openssl/crypto.h
s_client.o: ../include/openssl/ct.h ../include/openssl/dtls1.h
s_client.o: ../include/openssl/e_os2.h ../include/openssl/ec.h
s_client.o: ../include/openssl/ecdh.h ../include/openssl/ecdsa.h
s_client.o: ../include/openssl/engine.h ../include/openssl/err.h
s_client.o: ../include/openssl/evp.h ../include/openssl/hmac.h
s_client.o: ../include/openssl/lhash.h ../include/openssl/obj_mac.h
s_client.o: ../include/openssl/objects.h ../include/openssl/ocsp.h
s_client.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
s_client.o: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
s_client.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
s_client.o: ../include/openssl/rand.h ../include/openssl/safestack.h
s_client.o: ../include/openssl/sha.h ../include/openssl/srp.h
s_client.o: ../include/openssl/srtp.h ../include/openssl/ssl.h
s_client.o: ../include/openssl/ssl2.h ../include/openssl/ssl3.h
s_client.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
s_client.o: ../include/openssl/tls1.h ../include/openssl/txt_db.h
s_client.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h
s_client.o: ../include/openssl/x509v3.h apps.h progs.h s_apps.h s_client.c
s_client.o: timeouts.h
s_server.o: ../crypto/ct/ct_internal.h ../e_os.h ../include/openssl/asn1.h
s_server.o: ../include/openssl/bio.h ../include/openssl/bn.h
s_server.o: ../include/openssl/buffer.h ../include/openssl/comp.h
s_server.o: ../include/openssl/conf.h ../include/openssl/crypto.h
s_server.o: ../include/openssl/ct.h ../include/openssl/dh.h
s_server.o: ../include/openssl/dtls1.h ../include/openssl/e_os2.h
s_server.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
s_server.o: ../include/openssl/ecdsa.h ../include/openssl/engine.h
s_server.o: ../include/openssl/err.h ../include/openssl/evp.h
s_server.o: ../include/openssl/hmac.h ../include/openssl/lhash.h
s_server.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
s_server.o: ../include/openssl/ocsp.h ../include/openssl/opensslconf.h
s_server.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
s_server.o: ../include/openssl/pem.h ../include/openssl/pem2.h
s_server.o: ../include/openssl/pkcs7.h ../include/openssl/rand.h
s_server.o: ../include/openssl/rsa.h ../include/openssl/safestack.h
s_server.o: ../include/openssl/sha.h ../include/openssl/srp.h
s_server.o: ../include/openssl/srtp.h ../include/openssl/ssl.h
s_server.o: ../include/openssl/ssl2.h ../include/openssl/ssl3.h
s_server.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
s_server.o: ../include/openssl/tls1.h ../include/openssl/txt_db.h
s_server.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h
s_server.o: ../include/openssl/x509v3.h apps.h progs.h s_apps.h s_server.c
s_server.o: timeouts.h
s_socket.o: ../crypto/ct/ct_internal.h ../e_os.h ../include/openssl/asn1.h
s_socket.o: ../include/openssl/bio.h ../include/openssl/buffer.h
s_socket.o: ../include/openssl/comp.h ../include/openssl/conf.h
s_socket.o: ../include/openssl/crypto.h ../include/openssl/ct.h
s_socket.o: ../include/openssl/dtls1.h ../include/openssl/e_os2.h
s_socket.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
s_socket.o: ../include/openssl/ecdsa.h ../include/openssl/engine.h
s_socket.o: ../include/openssl/err.h ../include/openssl/evp.h
s_socket.o: ../include/openssl/hmac.h ../include/openssl/lhash.h
s_socket.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
s_socket.o: ../include/openssl/ocsp.h ../include/openssl/opensslconf.h
s_socket.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
s_socket.o: ../include/openssl/pem.h ../include/openssl/pem2.h
s_socket.o: ../include/openssl/pkcs7.h ../include/openssl/safestack.h
s_socket.o: ../include/openssl/sha.h ../include/openssl/srtp.h
s_socket.o: ../include/openssl/ssl.h ../include/openssl/ssl2.h
s_socket.o: ../include/openssl/ssl3.h ../include/openssl/stack.h
s_socket.o: ../include/openssl/symhacks.h ../include/openssl/tls1.h
s_socket.o: ../include/openssl/txt_db.h ../include/openssl/x509.h
s_socket.o: ../include/openssl/x509_vfy.h ../include/openssl/x509v3.h apps.h
s_socket.o: progs.h s_apps.h s_socket.c
s_time.o: ../crypto/ct/ct_internal.h ../e_os.h ../include/openssl/asn1.h
s_time.o: ../include/openssl/bio.h ../include/openssl/buffer.h
s_time.o: ../include/openssl/comp.h ../include/openssl/conf.h
s_time.o: ../include/openssl/crypto.h ../include/openssl/ct.h
s_time.o: ../include/openssl/dtls1.h ../include/openssl/e_os2.h
s_time.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
s_time.o: ../include/openssl/ecdsa.h ../include/openssl/engine.h
s_time.o: ../include/openssl/err.h ../include/openssl/evp.h
s_time.o: ../include/openssl/hmac.h ../include/openssl/lhash.h
s_time.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
s_time.o: ../include/openssl/ocsp.h ../include/openssl/opensslconf.h
s_time.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
s_time.o: ../include/openssl/pem.h ../include/openssl/pem2.h
s_time.o: ../include/openssl/pkcs7.h ../include/openssl/safestack.h
s_time.o: ../include/openssl/sha.h ../include/openssl/srtp.h
s_time.o: ../include/openssl/ssl.h ../include/openssl/ssl2.h
s_time.o: ../include/openssl/ssl3.h ../include/openssl/stack.h
s_time.o: ../include/openssl/symhacks.h ../include/openssl/tls1.h
s_time.o: ../include/openssl/txt_db.h ../include/openssl/x509.h
s_time.o: ../include/openssl/x509_vfy.h ../include/openssl/x509v3.h apps.h
s_time.o: progs.h s_apps.h s_time.c
sess_id.o: ../crypto/ct/ct_internal.h ../e_os.h ../include/openssl/asn1.h
sess_id.o: ../include/openssl/bio.h ../include/openssl/buffer.h
sess_id.o: ../include/openssl/comp.h ../include/openssl/conf.h
sess_id.o: ../include/openssl/crypto.h ../include/openssl/ct.h
sess_id.o: ../include/openssl/dtls1.h ../include/openssl/e_os2.h
sess_id.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
sess_id.o: ../include/openssl/ecdsa.h ../include/openssl/engine.h
sess_id.o: ../include/openssl/err.h ../include/openssl/evp.h
sess_id.o: ../include/openssl/hmac.h ../include/openssl/lhash.h
sess_id.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
sess_id.o: ../include/openssl/ocsp.h ../include/openssl/opensslconf.h
sess_id.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
sess_id.o: ../include/openssl/pem.h ../include/openssl/pem2.h
sess_id.o: ../include/openssl/pkcs7.h ../include/openssl/safestack.h
sess_id.o: ../include/openssl/sha.h ../include/openssl/srtp.h
sess_id.o: ../include/openssl/ssl.h ../include/openssl/ssl2.h
sess_id.o: ../include/openssl/ssl3.h ../include/openssl/stack.h
sess_id.o: ../include/openssl/symhacks.h ../include/openssl/tls1.h
sess_id.o: ../include/openssl/txt_db.h ../include/openssl/x509.h
sess_id.o: ../include/openssl/x509_vfy.h ../include/openssl/x509v3.h apps.h
sess_id.o: progs.h sess_id.c
smime.o: ../crypto/ct/ct_internal.h ../e_os.h ../include/openssl/asn1.h
smime.o: ../include/openssl/bio.h ../include/openssl/buffer.h
smime.o: ../include/openssl/conf.h ../include/openssl/crypto.h
smime.o: ../include/openssl/ct.h ../include/openssl/e_os2.h
smime.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
smime.o: ../include/openssl/ecdsa.h ../include/openssl/engine.h
smime.o: ../include/openssl/err.h ../include/openssl/evp.h
smime.o: ../include/openssl/lhash.h ../include/openssl/obj_mac.h
smime.o: ../include/openssl/objects.h ../include/openssl/ocsp.h
smime.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
smime.o: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
smime.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
smime.o: ../include/openssl/safestack.h ../include/openssl/sha.h
smime.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
smime.o: ../include/openssl/txt_db.h ../include/openssl/x509.h
smime.o: ../include/openssl/x509_vfy.h ../include/openssl/x509v3.h apps.h
smime.o: progs.h smime.c
speed.o: ../crypto/ct/ct_internal.h ../e_os.h ../include/openssl/aes.h
speed.o: ../include/openssl/asn1.h ../include/openssl/bio.h
speed.o: ../include/openssl/blowfish.h ../include/openssl/bn.h
speed.o: ../include/openssl/buffer.h ../include/openssl/camellia.h
speed.o: ../include/openssl/cast.h ../include/openssl/conf.h
speed.o: ../include/openssl/crypto.h ../include/openssl/ct.h
speed.o: ../include/openssl/des.h ../include/openssl/dsa.h
speed.o: ../include/openssl/e_os2.h ../include/openssl/ec.h
speed.o: ../include/openssl/ecdh.h ../include/openssl/ecdsa.h
speed.o: ../include/openssl/engine.h ../include/openssl/err.h
speed.o: ../include/openssl/evp.h ../include/openssl/hmac.h
speed.o: ../include/openssl/idea.h ../include/openssl/lhash.h
speed.o: ../include/openssl/md4.h ../include/openssl/md5.h
speed.o: ../include/openssl/mdc2.h ../include/openssl/modes.h
speed.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
speed.o: ../include/openssl/ocsp.h ../include/openssl/opensslconf.h
speed.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
speed.o: ../include/openssl/pkcs7.h ../include/openssl/rand.h
speed.o: ../include/openssl/rc2.h ../include/openssl/rc4.h
speed.o: ../include/openssl/ripemd.h ../include/openssl/rsa.h
speed.o: ../include/openssl/safestack.h ../include/openssl/seed.h
speed.o: ../include/openssl/sha.h ../include/openssl/stack.h
speed.o: ../include/openssl/symhacks.h ../include/openssl/txt_db.h
speed.o: ../include/openssl/whrlpool.h ../include/openssl/x509.h
speed.o: ../include/openssl/x509_vfy.h ../include/openssl/x509v3.h apps.h
speed.o: progs.h speed.c testdsa.h testrsa.h
spkac.o: ../crypto/ct/ct_internal.h ../e_os.h ../include/openssl/asn1.h
spkac.o: ../include/openssl/bio.h ../include/openssl/buffer.h
spkac.o: ../include/openssl/conf.h ../include/openssl/crypto.h
spkac.o: ../include/openssl/ct.h ../include/openssl/e_os2.h
spkac.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
spkac.o: ../include/openssl/ecdsa.h ../include/openssl/engine.h
spkac.o: ../include/openssl/err.h ../include/openssl/evp.h
spkac.o: ../include/openssl/lhash.h ../include/openssl/obj_mac.h
spkac.o: ../include/openssl/objects.h ../include/openssl/ocsp.h
spkac.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
spkac.o: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
spkac.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
spkac.o: ../include/openssl/safestack.h ../include/openssl/sha.h
spkac.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
spkac.o: ../include/openssl/txt_db.h ../include/openssl/x509.h
spkac.o: ../include/openssl/x509_vfy.h ../include/openssl/x509v3.h apps.h
spkac.o: progs.h spkac.c
srp.o: ../crypto/ct/ct_internal.h ../e_os.h ../include/openssl/asn1.h
srp.o: ../include/openssl/bio.h ../include/openssl/bn.h
srp.o: ../include/openssl/buffer.h ../include/openssl/conf.h
srp.o: ../include/openssl/crypto.h ../include/openssl/ct.h
srp.o: ../include/openssl/e_os2.h ../include/openssl/ec.h
srp.o: ../include/openssl/ecdh.h ../include/openssl/ecdsa.h
srp.o: ../include/openssl/engine.h ../include/openssl/err.h
srp.o: ../include/openssl/evp.h ../include/openssl/lhash.h
srp.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
srp.o: ../include/openssl/ocsp.h ../include/openssl/opensslconf.h
srp.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
srp.o: ../include/openssl/pkcs7.h ../include/openssl/safestack.h
srp.o: ../include/openssl/sha.h ../include/openssl/srp.h
srp.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
srp.o: ../include/openssl/txt_db.h ../include/openssl/x509.h
srp.o: ../include/openssl/x509_vfy.h ../include/openssl/x509v3.h apps.h progs.h
srp.o: srp.c
ts.o: ../crypto/ct/ct_internal.h ../e_os.h ../include/openssl/asn1.h
ts.o: ../include/openssl/bio.h ../include/openssl/bn.h
ts.o: ../include/openssl/buffer.h ../include/openssl/conf.h
ts.o: ../include/openssl/crypto.h ../include/openssl/ct.h
ts.o: ../include/openssl/dh.h ../include/openssl/dsa.h
ts.o: ../include/openssl/e_os2.h ../include/openssl/ec.h
ts.o: ../include/openssl/ecdh.h ../include/openssl/ecdsa.h
ts.o: ../include/openssl/engine.h ../include/openssl/err.h
ts.o: ../include/openssl/evp.h ../include/openssl/lhash.h
ts.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
ts.o: ../include/openssl/ocsp.h ../include/openssl/opensslconf.h
ts.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
ts.o: ../include/openssl/pem.h ../include/openssl/pem2.h
ts.o: ../include/openssl/pkcs7.h ../include/openssl/rand.h
ts.o: ../include/openssl/rsa.h ../include/openssl/safestack.h
ts.o: ../include/openssl/sha.h ../include/openssl/stack.h
ts.o: ../include/openssl/symhacks.h ../include/openssl/ts.h
ts.o: ../include/openssl/txt_db.h ../include/openssl/x509.h
ts.o: ../include/openssl/x509_vfy.h ../include/openssl/x509v3.h apps.h progs.h
ts.o: ts.c
verify.o: ../crypto/ct/ct_internal.h ../e_os.h ../include/openssl/asn1.h
verify.o: ../include/openssl/bio.h ../include/openssl/buffer.h
verify.o: ../include/openssl/conf.h ../include/openssl/crypto.h
verify.o: ../include/openssl/ct.h ../include/openssl/e_os2.h
verify.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
verify.o: ../include/openssl/ecdsa.h ../include/openssl/engine.h
verify.o: ../include/openssl/err.h ../include/openssl/evp.h
verify.o: ../include/openssl/lhash.h ../include/openssl/obj_mac.h
verify.o: ../include/openssl/objects.h ../include/openssl/ocsp.h
verify.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
verify.o: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
verify.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
verify.o: ../include/openssl/safestack.h ../include/openssl/sha.h
verify.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
verify.o: ../include/openssl/txt_db.h ../include/openssl/x509.h
verify.o: ../include/openssl/x509_vfy.h ../include/openssl/x509v3.h apps.h
verify.o: progs.h verify.c
version.o: ../crypto/ct/ct_internal.h ../e_os.h ../include/openssl/asn1.h
version.o: ../include/openssl/bio.h ../include/openssl/blowfish.h
version.o: ../include/openssl/bn.h ../include/openssl/buffer.h
version.o: ../include/openssl/conf.h ../include/openssl/crypto.h
version.o: ../include/openssl/ct.h ../include/openssl/des.h
version.o: ../include/openssl/e_os2.h ../include/openssl/ec.h
version.o: ../include/openssl/ecdh.h ../include/openssl/ecdsa.h
version.o: ../include/openssl/engine.h ../include/openssl/err.h
version.o: ../include/openssl/evp.h ../include/openssl/idea.h
version.o: ../include/openssl/lhash.h ../include/openssl/obj_mac.h
version.o: ../include/openssl/objects.h ../include/openssl/ocsp.h
version.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
version.o: ../include/openssl/ossl_typ.h ../include/openssl/pkcs7.h
version.o: ../include/openssl/rc4.h ../include/openssl/safestack.h
version.o: ../include/openssl/sha.h ../include/openssl/stack.h
version.o: ../include/openssl/symhacks.h ../include/openssl/txt_db.h
version.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h
version.o: ../include/openssl/x509v3.h apps.h progs.h version.c
x509.o: ../crypto/ct/ct_internal.h ../e_os.h ../include/openssl/asn1.h
x509.o: ../include/openssl/bio.h ../include/openssl/bn.h
x509.o: ../include/openssl/buffer.h ../include/openssl/conf.h
x509.o: ../include/openssl/crypto.h ../include/openssl/ct.h
x509.o: ../include/openssl/dsa.h ../include/openssl/e_os2.h
x509.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
x509.o: ../include/openssl/ecdsa.h ../include/openssl/engine.h
x509.o: ../include/openssl/err.h ../include/openssl/evp.h
x509.o: ../include/openssl/lhash.h ../include/openssl/obj_mac.h
x509.o: ../include/openssl/objects.h ../include/openssl/ocsp.h
x509.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
x509.o: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
x509.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
x509.o: ../include/openssl/rsa.h ../include/openssl/safestack.h
x509.o: ../include/openssl/sha.h ../include/openssl/stack.h
x509.o: ../include/openssl/symhacks.h ../include/openssl/txt_db.h
x509.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h
x509.o: ../include/openssl/x509v3.h apps.h progs.h x509.c
