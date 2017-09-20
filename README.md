This is really to test the spec process, its a long way from usable
code and the interface is the least thought out bit (MozQuic.h). It
will set your machine afire if you have the nerve to run it there.

Right now it is capable of both ff000005 and 0xf123f0c5 and some greasing.

See https://github.com/quicwg/base-drafts/wiki/First-Implementation-Draft

based on tls -21

== Build Notes

```
setenv MOZQUIC_BUILD /home/mcmanus/src/mozquic
```

# These are for runtime
```
setenv LD_LIBRARY_PATH $MOZQUIC_BUILD/dist/`cat $MOZQUIC_BUILD/dist/latest`/lib
setenv MOZQUIC_NSS_CONFIG $MOZQUIC_BUILD/mozquic/sample/nss-config/
```

# These are used to build mozquic standalone
```
git clone git@github.com:mcmanus/mozquic.git
git clone -b NSS_TLS13_DRAFT19_BRANCH git@github.com:nss-dev/nss.git
hg clone https://hg.mozilla.org/projects/nspr
nss/build.sh
cd mozquic
make
ls client server
```

# This is useful for running the regression tests
```
MOZQUIC_LOG=all:5 go run qdrive/main.go -shims mozquic/tests/qdrive/mozquic.json -cases mozquic/tests/qdrive/mozquic.cases.json -verbose

rm -f /tmp/get-? ; ./client -get /documentation/nghttpd.1.html -get /stylesheets/screen.css -get /index.html -get /favicon.png -peer nghttp2.org:4433 -send-close -ignorePKI ; ls /tmp/get-?

-rw-rw-rw- 1 mcmanus 21475 Sep 18 16:49 /tmp/get-1
-rw-rw-rw- 1 mcmanus 39082 Sep 18 16:49 /tmp/get-3
-rw-rw-rw- 1 mcmanus  6625 Sep 18 16:49 /tmp/get-5
-rw-rw-rw- 1 mcmanus   400 Sep 18 16:49 /tmp/get-7

```
