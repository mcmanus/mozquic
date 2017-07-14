# Set the MOZQUIC variables as below.
#MOZQUIC_NSS_ROOT=/Users/ekr/dev/nss-dev/nss-sandbox3/
#MOZQUIC_NSS_PLATFORM=Darwin15.6.0_cc_64_DBG.OBJ

NSPR_INCLUDE = /usr/include/nspr/

LDFLAGS += -L$(MOZQUIC_NSS_ROOT)dist/$(MOZQUIC_NSS_PLATFORM)/lib -lnss3 -lnssutil3 -lsmime3 -lssl3 -lplds4 -lplc4 -lnspr4
CXXFLAGS +=  -std=c++0x  -I$(MOZQUIC_NSS_ROOT) -I$(MOZQUIC_NSS_ROOT)dist/$(MOZQUIC_NSS_PLATFORM)/include/ -I$(MOZQUIC_NSS_ROOT)dist/public/nss -Wno-format
CXXFLAGS += -I$(NSPR_INCLUDE)
CXXFLAGS += -g
CFLAGS += -g

# For .h dependency management
CXXFLAGS += -MP -MD 

OBJS += MozQuic.o
OBJS += MozQuicStream.o
OBJS += NSSHelper.o

all: client server

-include $(OBJS:.o=.d)

client: $(OBJS) sample/client.o
	clang++ -o client $(OBJS) sample/client.o $(LDFLAGS)

server: $(OBJS) sample/server.o
	clang++ -o server $(OBJS) sample/server.o $(LDFLAGS)

.PHONY: clean
clean:
	rm -f $(OBJS) client server sample/client.o sample/server.o *.d

