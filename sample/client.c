/* -*- Mode: C++; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*-
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#define SERVER_NAME "foo.example.com"
#define SERVER_PORT 4433

#if 0

Basic client connects to server, does a handshake and exits after 2 seconds

  -send-close option will send a close before exiting
  
  -streamtest1 will send 3 messages to the server including the keywords PREAMBLE and FIN
               the server will reply with 1 message and close the bidi stream
               after recpt of stream-close client will wait 2 seconds

About Certificate Verifcation::
The sample/nss-config directory is a sample that can be passed
to mozquic_nss_config(). It contains a NSS database with a cert
and key for foo.example.com that is signed by a CA defined by CA.cert.der.
#endif

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include "../MozQuic.h"

mozquic_connection_t *only_child = NULL;

static uint8_t recvFin = 0;

static int connEventCB(void *closure, uint32_t event, void *param)
{
  if (event == MOZQUIC_EVENT_NEW_STREAM_DATA) {
    mozquic_stream_t *stream = param;
    char buf[100];
    int read = 0;
    int fin = 0;
    int line = 0;
    do {
      uint32_t code = mozquic_recv(stream, buf, 100, &read, &fin);
      if (code != MOZQUIC_OK) {
        fprintf(stderr,"Read stream error %d\n", code);
        return MOZQUIC_OK;
      } else if (read > 0) {
        if (!line) {
          fprintf(stderr,"Data:\n");
        }
        line++;
        buf[read] = '\0';
        fprintf(stderr,"[%s] fin=%d\n", buf, fin);
        if (fin) {
          recvFin = 1;
        }
      }
    } while (read > 0);

    mozquic_end_stream(stream);
    return MOZQUIC_OK;
  }
  fprintf(stderr,"unhandled event %X\n", event);
  return MOZQUIC_OK;
}

int
has_arg(int argc, char **argv, char *test)
{
  int i;
  for (i=0; i < argc; i++) {
    if (!strcasecmp(argv[i], test)) {
      return 1;
    }
  }
  return 0;
}

void streamtest1(mozquic_connection_t *c)
{
  fprintf(stderr,"Start sending data.\n");
  char msg[] = "Client is sending some data to a server. This is one message.";
  mozquic_stream_t *stream;
  mozquic_start_new_stream(&stream, c, "PREAMBLE", 8, 0);
  mozquic_send(stream, msg, strlen(msg), 0);
  mozquic_send(stream, "FIN", 3, 0);
  int i = 0;
  do {
    if (!(i++ & 0xf)) {
      fprintf(stderr,".");
      fflush(stderr);
    }
    usleep (1000); // this is for handleio todo
    uint32_t code = mozquic_IO(c);
    if (code != MOZQUIC_OK) {
      fprintf(stderr,"IO reported failure\n");
      break;
    }
  } while (!recvFin);
  recvFin = 0;
  do {
    if (!(i++ & 0xf)) {
      fprintf(stderr,".");
      fflush(stderr);
    }
    usleep (1000); // this is for handleio todo
    uint32_t code = mozquic_IO(c);
    if (code != MOZQUIC_OK) {
      fprintf(stderr,"IO reported failure\n");
      break;
    }
  } while (i < 2000);
}

int main(int argc, char **argv)
{
  struct mozquic_config_t config;
  mozquic_connection_t *c;

  char *cdir = getenv ("MOZQUIC_NSS_CONFIG");
  if (mozquic_nss_config(cdir) != MOZQUIC_OK) {
    fprintf(stderr,"MOZQUIC_NSS_CONFIG FAILURE [%s]\n", cdir ? cdir : "");
    exit (-1);
  }
  
  memset(&config, 0, sizeof(config));
  config.originName = SERVER_NAME;
  config.originPort = SERVER_PORT;
  config.handleIO = 0; // todo mvp
  config.connection_event_callback = connEventCB;

  // ingorePKI will allow invalid certs
  // normally they must either be linked to the root store OR on localhost
  config.ignorePKI = 0; 
  config.greaseVersionNegotiation = 0;
  config.preferMilestoneVersion = 1;

  mozquic_new_connection(&c, &config);
  mozquic_start_connection(c);

  uint32_t i=0;
  do {
    if (!(i++ & 0xf)) {
      fprintf(stderr,".");
      fflush(stderr);
    }
    usleep (1000); // this is for handleio todo
    uint32_t code = mozquic_IO(c);
    if (code != MOZQUIC_OK) {
      fprintf(stderr,"IO reported failure\n");
      break;
    }
  } while (i < 2000);

  if (has_arg(argc, argv, "-streamtest1")) {
    streamtest1(c);
  }
  if (has_arg(argc, argv, "-send-close")) {
    mozquic_destroy_connection(c);
  }
  return 0;
}
