UNAME_S := $(shell uname -s)

# Set the MOZQUIC variables as below.
# notes in NSSHelper.cpp for tls 1.3 draft version and nss branch
#NSS_ROOT=/Users/ekr/dev/nss-dev/nss-sandbox3/
#NSS_PLATFORM=Darwin15.6.0_cc_64_DBG.OBJ

NSS_ROOT ?= $(realpath $(firstword $(wildcard $(CURDIR)/../nss $(CURDIR)/nss)))
NSS_PLATFORM ?= $(realpath $(NSS_ROOT)/../dist/$(shell cat $(NSS_ROOT)/../dist/latest))
NSS_INCLUDE ?= $(realpath $(NSS_ROOT)/../dist/public/nss)
NSS_LIBDIR ?= $(realpath $(NSS_PLATFORM)/lib)
NSPR_INCLUDE ?= $(NSS_PLATFORM)/include/nspr

CC = clang
CXX = clang++

LDFLAGS += -L$(NSS_LIBDIR) -lnss3 -lnssutil3 -lsmime3 -lssl3 -lplds4 -lplc4 -lnspr4 -lstdc++
CXXFLAGS += -std=c++0x -I$(NSS_INCLUDE) -I$(NSPR_INCLUDE)
CFLAGS += -I$(CURDIR) -Wall
CFLAGS += -Wno-unused-command-line-argument
CXXFLAGS += -Wno-unused-command-line-argument -Wall
CXXFLAGS += -g
CFLAGS += -g

# For .h dependency management
CXXFLAGS += -MP -MD 

ifeq ($(UNAME_S),Darwin)
	CFLAGS += -D OSX
endif

OBJS += Ack.o
OBJS += API.o
OBJS += ClearText.o
OBJS += Logging.o
OBJS += MozQuic.o
OBJS += NSSHelper.o
OBJS += Packetization.o
OBJS += Ping.o
OBJS += StatelessReset.o
OBJS += Streams.o
OBJS += TransportExtension.o

all: client server qdrive-client qdrive-server

-include $(OBJS:.o=.d)

QDRIVESERVEROBJS += tests/qdrive/qdrive-common.o
QDRIVESERVEROBJS += tests/qdrive/qdrive-server-test000.o
QDRIVESERVEROBJS += tests/qdrive/qdrive-server-test001.o
QDRIVESERVEROBJS += tests/qdrive/qdrive-server-test002.o
QDRIVESERVEROBJS += tests/qdrive/qdrive-server-test003.o
QDRIVESERVEROBJS += tests/qdrive/qdrive-server-test004.o
QDRIVESERVEROBJS += tests/qdrive/qdrive-server-test005.o
QDRIVESERVEROBJS += tests/qdrive/qdrive-server-test006.o
QDRIVESERVEROBJS += tests/qdrive/qdrive-server-test007.o
QDRIVESERVEROBJS += tests/qdrive/qdrive-server-test008.o
QDRIVESERVEROBJS += tests/qdrive/qdrive-server-test009.o
QDRIVESERVEROBJS += tests/qdrive/qdrive-server-test010.o

QDRIVECLIENTOBJS += tests/qdrive/qdrive-common.o
QDRIVECLIENTOBJS += tests/qdrive/qdrive-client-test000.o
QDRIVECLIENTOBJS += tests/qdrive/qdrive-client-test001.o
QDRIVECLIENTOBJS += tests/qdrive/qdrive-client-test002.o
QDRIVECLIENTOBJS += tests/qdrive/qdrive-client-test003.o
QDRIVECLIENTOBJS += tests/qdrive/qdrive-client-test004.o
QDRIVECLIENTOBJS += tests/qdrive/qdrive-client-test005.o
QDRIVECLIENTOBJS += tests/qdrive/qdrive-client-test006.o
QDRIVECLIENTOBJS += tests/qdrive/qdrive-client-test007.o
QDRIVECLIENTOBJS += tests/qdrive/qdrive-client-test008.o
QDRIVECLIENTOBJS += tests/qdrive/qdrive-client-test009.o
QDRIVECLIENTOBJS += tests/qdrive/qdrive-client-test010.o

sample/server-files.o: sample/server.jpg sample/index.html sample/main.js
ifeq ($(UNAME_S),Darwin)
	$(CC) -o ./sample/tmp.o -c ./sample/server-files.c
	ld -r -sectcreate binary sampleserver_jpg sample/server.jpg -sectcreate binary sampleindex_html sample/index.html -sectcreate binary samplemain_js sample/main.js -o sample/server-files.o ./sample/tmp.o
else
	ld -r -b binary -o $@ $^
endif

client: $(OBJS) sample/client.o
	$(CC) $(LDFLAGS) -o $@ $^

server: $(OBJS) sample/server.o sample/server-files.o
	$(CC) $(LDFLAGS) -o $@ $^

qdrive-client: $(OBJS) $(QDRIVECLIENTOBJS) tests/qdrive/qdrive-client.o
	$(CC) $(LDFLAGS) -o $@ $^

qdrive-server: $(OBJS) $(QDRIVESERVEROBJS) tests/qdrive/qdrive-server.o
	$(CC) $(LDFLAGS) -o $@ $^

.PHONY: clean
clean:
	rm -f $(OBJS) client server qdrive-client qdrive-server *.d sample/*.o
	rm -f tests/qdrive/qdrive-*.o

NSS_CONFIG=$(CURDIR)/sample/nss-config
.PHONY: run-server run-client
run-server: server
	MOZQUIC_NSS_CONFIG=$(NSS_CONFIG) LD_LIBRARY_PATH=$(NSS_LIBDIR) ./$<

run-client: client
	MOZQUIC_NSS_CONFIG=$(NSS_CONFIG) LD_LIBRARY_PATH=$(NSS_LIBDIR) ./$<

