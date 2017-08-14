# Set the MOZQUIC variables as below.
# notes in NSSHelper.cpp for tls 1.3 draft version and nss branch
#NSS_ROOT=/Users/ekr/dev/nss-dev/nss-sandbox3/
#NSS_PLATFORM=Darwin15.6.0_cc_64_DBG.OBJ

NSS_ROOT ?= $(realpath $(firstword $(wildcard $(CURDIR)/../nss $(CURDIR)/nss)))
NSS_PLATFORM ?= $(realpath $(NSS_ROOT)/../dist/$(shell cat $(NSS_ROOT)/../dist/latest))
NSS_INCLUDE ?= $(realpath $(NSS_ROOT)/../dist/public/nss)
NSS_LIBDIR ?= $(realpath $(NSS_PLATFORM)/lib)
NSPR_INCLUDE ?= $(NSS_PLATFORM)/include

CC = clang
CXX = clang++

LDFLAGS += -L$(NSS_LIBDIR) -lnss3 -lnssutil3 -lsmime3 -lssl3 -lplds4 -lplc4 -lnspr4 -lstdc++
CXXFLAGS += -std=c++0x -I$(NSS_INCLUDE) -I$(NSPR_INCLUDE) -Wno-format
CFLAGS += -Wno-unused-command-line-argument
CXXFLAGS += -Wno-unused-command-line-argument
CXXFLAGS += -g
CFLAGS += -g

# For .h dependency management
CXXFLAGS += -MP -MD 

OBJS += API.o
OBJS += MozQuic.o
OBJS += MozQuicStream.o
OBJS += NSSHelper.o

all: client server qdrive-client qdrive-server

-include $(OBJS:.o=.d)

client: $(OBJS) sample/client.o
	$(CC) $(LDFLAGS) -o $@ $^

qdrive-client: $(OBJS) sample/qdrive-client.o
	$(CC) -o qdrive-client $(OBJS) sample/qdrive-client.o $(LDFLAGS)

server: $(OBJS) sample/server.o
	$(CC) $(LDFLAGS) -o $@ $^

qdrive-server: $(OBJS) sample/qdrive-server.o
	$(CC) -o qdrive-server $(OBJS) sample/qdrive-server.o $(LDFLAGS)

.PHONY: clean
clean:
	rm -f $(OBJS) client server qdrive-client qdrive-server *.d sample/*.o

NSS_CONFIG=$(CURDIR)/sample/nss-config
.PHONY: run-server run-client
run-server: server
	MOZQUIC_NSS_CONFIG=$(NSS_CONFIG) LD_LIBRARY_PATH=$(NSS_LIBDIR) ./$<

run-client: client
	MOZQUIC_NSS_CONFIG=$(NSS_CONFIG) LD_LIBRARY_PATH=$(NSS_LIBDIR) ./$<

