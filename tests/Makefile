# Host-side regression test for the CTAP2 COSE_Key wire format.
#
# Fidelio used to encode and parse COSE_Key maps by hand; that code is now
# wolfCOSE. Every credential already registered with a device depends on the
# encoding not changing, so this test pins it: it compares wolfCOSE's output
# byte-for-byte against the original hand-rolled encoder, checks the exact
# CTAP2 canonical layout, and asserts that encoding from a key which still
# holds its private scalar never serialises that scalar.
#
#   make -C tests run

TOP      := $(CURDIR)/..
WOLFSSL  := $(TOP)/lib/wolfssl
WOLFCOSE := $(TOP)/lib/wolfcose

CC      ?= gcc
CFLAGS  := -O1 -Wall -DWOLFSSL_USER_SETTINGS -DNO_PWDBASED -DNO_PKCS8 \
           -DNO_PKCS12 -I$(CURDIR) -I$(WOLFSSL) -I$(WOLFCOSE)/include

WC_SRC  := ecc sp_c32 sp_int wolfmath memory misc random hash sha256 hmac \
           error logging wc_port asn coding kdf aes
SRC     := cose_wire_test.c \
           $(WOLFCOSE)/src/wolfcose.c $(WOLFCOSE)/src/wolfcose_cbor.c \
           $(patsubst %,$(WOLFSSL)/wolfcrypt/src/%.c,$(WC_SRC))

all: cose_wire_test

cose_wire_test: $(SRC)
	$(CC) $(CFLAGS) -o $@ $(SRC)

run: cose_wire_test
	./cose_wire_test

clean:
	rm -f cose_wire_test

.PHONY: all run clean
