/* -*- Mode: C++; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*-
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#define SERVER_NAME "localhost"
#define SERVER_PORT 4434

#if 0

env MOZQUIC_LOG all:9 will turn on a lot of logging. add SSLTRACE 50 and it will be absurd.

  ./client -peer HOSTNAME to use non localhost peer

Basic client connects to server, does a handshake and and waits 1 seconds.. then..

  -streamtest1 will send 3 messages to the server including the keywords PREAMBLE and FIN
               the server will reply with 1 message and close the bidi stream
               after recpt of stream-close client will wait 2 seconds

  -send-close option will send a close before exiting

  -ignorePKI option will allow handshake with untrusted cert. (localhost always implies ignorePKI)

  -get PATH will get the uri. e.g. -get /main.jpg. You can have N of these
      
About Certificate Verifcation::
The sample/nss-config directory is a sample that can be passed
to mozquic_nss_config(). It contains a NSS database with a cert
and key for foo.example.com that is signed by a CA defined by CA.cert.der.
#endif

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <assert.h>
#include "../MozQuic.h"

static uint8_t recvFin = 0;
static int _argc;
static char **_argv;
static int _getCount = 0;
static FILE *fd[256];

static int connEventCB(void *closure, uint32_t event, void *param)
{
  if ((event == MOZQUIC_EVENT_CONNECTED) ||
      (event == MOZQUIC_EVENT_0RTT_POSSIBLE)) {
    if (event == MOZQUIC_EVENT_0RTT_POSSIBLE) {
      fprintf(stderr,"We will send data during 0RTT.\n");
    }
    int j;
    for (j=0; j < _argc - 1; j++) {
      if (!strcasecmp(_argv[j], "-get")) {
        mozquic_stream_t *stream;
        int code = mozquic_start_new_stream(&stream, param, 0, 0, "GET ", 4, 0);
        assert(code == MOZQUIC_OK);
        code = mozquic_send(stream, _argv[j+1], strlen(_argv[j+1]), 0);
        assert(code == MOZQUIC_OK);
        code = mozquic_send(stream, "\r\n", 2, 1);
        assert(code == MOZQUIC_OK);
        _getCount++;
        char pathname[1024];
        snprintf(pathname, 1024, "/tmp/get-%d", mozquic_get_streamid(stream));
        fd[mozquic_get_streamid(stream)] = fopen(pathname, "w");
        assert(fd[mozquic_get_streamid(stream)] != NULL);
      }
    }
    _argc = 1; // in case of 0rtt this state gets called again - don't
    // double up the streams
  }
  
  if (event == MOZQUIC_EVENT_NEW_STREAM_DATA) {
    mozquic_stream_t *stream = param;
    if (mozquic_get_streamid(stream) & 0x3) {
      fprintf(stderr,"ignore non client bidi streams\n");
      return MOZQUIC_OK;
    }

    char buf[1000];
    uint32_t amt = 0;
    int fin = 0;

    uint32_t code = mozquic_recv(stream, buf, 1000, &amt, &fin);
    if (code != MOZQUIC_OK) {
      fprintf(stderr,"recv stream error %d\n", code);
      return MOZQUIC_OK;
    }
    fprintf(stderr,"Data: stream %d %d fin=%d\n",
            mozquic_get_streamid(stream), amt, fin);
    for (size_t j=0; j < amt; ) {
      size_t rv = fwrite(buf + j, 1, amt - j, fd[mozquic_get_streamid(stream)]);
      assert(rv > 0);
      j += rv;
    }
    if (fin) {
      if (fd[mozquic_get_streamid(stream)]) {
        fclose (fd[mozquic_get_streamid(stream)]);
        fd[mozquic_get_streamid(stream)] = NULL;
      }
      recvFin = 1;
      mozquic_end_stream(stream);
      if (_getCount) {
        if (!--_getCount) {
          _getCount = -1;
        }
      }
    }
    return MOZQUIC_OK;
  } else if (event == MOZQUIC_EVENT_IO) {
  } else if (event == MOZQUIC_EVENT_CLOSE_CONNECTION ||
             event == MOZQUIC_EVENT_ERROR) {
    mozquic_destroy_connection(param);
    exit(event == MOZQUIC_EVENT_ERROR ? 2 : 0);
  } else {
//    fprintf(stderr,"unhandled event %X\n", event);
  }
  return MOZQUIC_OK;
}

static int connEventCBDoOnlyConnect(void *closure, uint32_t event, void *param)
{
  if (event == MOZQUIC_EVENT_CLOSE_CONNECTION ||
      event == MOZQUIC_EVENT_ERROR) {
    mozquic_destroy_connection(param);
    exit(event == MOZQUIC_EVENT_ERROR ? 2 : 0);
  }
  return MOZQUIC_OK;
}

int
has_arg(int argc, char **argv, char *test, char **value)
{
  int i;
  *value = NULL;
  for (i=0; i < argc; i++) {
    if (!strcasecmp(argv[i], test)) {
      *value = ((i + 1) < argc) ? argv[i+1] : "";
      return 1;
    }
  }
  return 0;
}

void streamtest1(mozquic_connection_t *c)
{
  fprintf(stderr,"Start sending data.\n");
  char msg[8000];
  memset(msg, 'f', 7999);
  msg[7999] = 0;
  mozquic_stream_t *stream;
  mozquic_start_new_stream(&stream, c, 0, 0, "PREAMBLE", 8, 0);
  mozquic_send(stream, msg, strlen(msg), 0);
  mozquic_send(stream, "FIN", 3, 0);
  do {
    usleep (1000); // this is for handleio todo
    uint32_t code = mozquic_IO(c);
    if (code != MOZQUIC_OK) {
      fprintf(stderr,"IO reported failure\n");
      break;
    }
  } while (!recvFin);
  recvFin = 0;
  int i = 0;
  do {
    usleep (1000); // this is for handleio todo
    uint32_t code = mozquic_IO(c);
    if (code != MOZQUIC_OK) {
      fprintf(stderr,"IO reported failure\n");
      break;
    }
  } while (++i < 2000);
  fprintf(stderr,"streamtest1 complete\n");
}

void connectWaitForSessionTicketAndCloseConnection(struct mozquic_config_t *config)
{
  mozquic_connection_t *c;
  mozquic_new_connection(&c, config);
  mozquic_set_event_callback(c, connEventCBDoOnlyConnect);
  mozquic_start_client(c);
  uint32_t i=0;
  do {
    usleep (1000); // this is for handleio todo
    uint32_t code = mozquic_IO(c);
    if (code != MOZQUIC_OK) {
      fprintf(stderr,"IO reported failure\n");
      break;
    }
  } while (++i < 2000);
  mozquic_destroy_connection(c);
}

int main(int argc, char **argv)
{
  char *argVal;
  struct mozquic_config_t config;
  mozquic_connection_t *c;

  _argc = argc;
  _argv = argv;

  if (has_arg(argc, argv, "-quiet", &argVal)) {
    fclose(stderr);
  }

  char *cdir = getenv ("MOZQUIC_NSS_CONFIG");
  if (mozquic_nss_config(cdir) != MOZQUIC_OK) {
    fprintf(stderr,"MOZQUIC_NSS_CONFIG FAILURE [%s]\n", cdir ? cdir : "");
    exit (-1);
  }
  
  memset(&config, 0, sizeof(config));
  if (has_arg(argc, argv, "-peer", &argVal)) {
    char *tmp = argVal;
    while (*tmp == ':') tmp++;
    char *c = strrchr(tmp, ':');
    if (c) {
      *c++ = 0;
      config.originPort = atoi(c);
    }
    config.originName = strdup(argVal); // leaked
  } else {
    config.originName = SERVER_NAME;
  }
  if (!config.originPort) {
    config.originPort = SERVER_PORT;
  }
  fprintf(stderr,"client connecting to %s port %d\n", config.originName, config.originPort);

  config.handleIO = 0; // todo mvp

  // ingorePKI will allow invalid certs
  // normally they must either be linked to the root store OR on localhost
  assert(mozquic_unstable_api1(&config, "ignorePKI",
                               has_arg(argc, argv, "-ignorePKI", &argVal), 0) == MOZQUIC_OK);
  assert(mozquic_unstable_api1(&config, "greaseVersionNegotiation", 0, 0) == MOZQUIC_OK);
  assert(mozquic_unstable_api1(&config, "tolerateBadALPN", 1, 0) == MOZQUIC_OK);
  assert(mozquic_unstable_api1(&config, "tolerateNoTransportParams", 1, 0) == MOZQUIC_OK);
  assert(mozquic_unstable_api1(&config, "maxSizeAllowed", 1452, 0) == MOZQUIC_OK);

  int test0rtt = has_arg(argc, argv, "-0rtt", &argVal);
  if (test0rtt) {
    assert(mozquic_unstable_api1(&config, "enable0RTT", 1, 0) == MOZQUIC_OK);
  }

  if (has_arg(argc, argv, "-connectionresume", &argVal) ||
      test0rtt) {
    connectWaitForSessionTicketAndCloseConnection(&config);
  }

  mozquic_new_connection(&c, &config);
  mozquic_set_event_callback(c, connEventCB);
  mozquic_start_client(c);

  uint32_t i=0;
  do {
    usleep (1000); // this is for handleio todo
    uint32_t code = mozquic_IO(c);
    if (code != MOZQUIC_OK) {
      fprintf(stderr,"IO reported failure\n");
      break;
    }
    if (_getCount == -1) {
      break;
    }
  } while (++i < 2000 || _getCount);

  if (has_arg(argc, argv, "-streamtest1", &argVal)) {
    streamtest1(c);
  }

  if (has_arg(argc, argv, "-send-close", &argVal)) {
    mozquic_destroy_connection(c);
  }

  return 0;
}
