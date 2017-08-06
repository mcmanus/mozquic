# Set the MOZQUIC variables as below.
# notes in NSSHelper.cpp for tls 1.3 draft version and nss branch
#MOZQUIC_NSS_ROOT=/Users/ekr/dev/nss-dev/nss-sandbox3/
#MOZQUIC_NSS_PLATFORM=Darwin15.6.0_cc_64_DBG.OBJ

NSPR_INCLUDE = /usr/include/nspr/

CC = clang
CXX = clang++

LDFLAGS += -L$(MOZQUIC_NSS_ROOT)dist/$(MOZQUIC_NSS_PLATFORM)/lib -lnss3 -lnssutil3 -lsmime3 -lssl3 -lplds4 -lplc4 -lnspr4 -lstdc++
CXXFLAGS +=  -std=c++0x  -I$(MOZQUIC_NSS_ROOT) -I$(MOZQUIC_NSS_ROOT)dist/$(MOZQUIC_NSS_PLATFORM)/include/ -I$(MOZQUIC_NSS_ROOT)dist/public/nss -Wno-format
CXXFLAGS += -I$(NSPR_INCLUDE)
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
	$(CC) -o client $(OBJS) sample/client.o $(LDFLAGS)

qdrive-client: $(OBJS) sample/qdrive-client.o
	$(CC) -o qdrive-client $(OBJS) sample/qdrive-client.o $(LDFLAGS)

server: $(OBJS) sample/server.o
	$(CC) -o server $(OBJS) sample/server.o $(LDFLAGS)

qdrive-server: $(OBJS) sample/qdrive-server.o
	$(CC) -o qdrive-server $(OBJS) sample/qdrive-server.o $(LDFLAGS)

.PHONY: clean
clean:
	rm -f $(OBJS) client server qdrive-client qdrive-server *.d sample/*.o

