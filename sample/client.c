/* -*- Mode: C++; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*-
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#define SERVER_NAME "localhost"
#define SERVER_PORT 4433

#if 0

  ./client -peer HOSTNAME to use non localhost peer

Basic client connects to server, does a handshake and and waits 2 seconds.. then..

  -streamtest1 will send 3 messages to the server including the keywords PREAMBLE and FIN
               the server will reply with 1 message and close the bidi stream
               after recpt of stream-close client will wait 2 seconds

  -send-close option will send a close before exiting

  -ignorePKI option will allow handshake with untrusted cert. (localhost always implies ignorePKI)

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

static uint8_t recvFin = 0;

static int connEventCB(void *closure, uint32_t event, void *param)
{
  if (event == MOZQUIC_EVENT_NEW_STREAM_DATA) {
    mozquic_stream_t *stream = param;
    char buf[100];
    uint32_t read = 0;
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
  } else if (event == MOZQUIC_EVENT_IO) {
  } else if (event == MOZQUIC_EVENT_CLOSE_CONNECTION ||
             event == MOZQUIC_EVENT_ERROR) {
    mozquic_destroy_connection(param);
    exit(event == MOZQUIC_EVENT_ERROR ? 2 : 0);
  } else {
    fprintf(stderr,"unhandled event %X\n", event);
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
  fprintf(stderr,"streamtest1 complete\n");
}

int main(int argc, char **argv)
{
  char *argVal;
  struct mozquic_config_t config;
  mozquic_connection_t *c;

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
    config.originName = strdup(argVal); // leaked
  } else {
    config.originName = SERVER_NAME;
  }
  config.originPort = SERVER_PORT;
  fprintf(stderr,"client connecting to %s port %d\n", config.originName, config.originPort);

  config.handleIO = 0; // todo mvp
  config.connection_event_callback = connEventCB;

  // ingorePKI will allow invalid certs
  // normally they must either be linked to the root store OR on localhost
  config.ignorePKI = has_arg(argc, argv, "-ignorePKI", &argVal);

  config.greaseVersionNegotiation = 0;
  config.preferMilestoneVersion = 1;
  config.tolerateBadALPN = 1;

  mozquic_new_connection(&c, &config);
  mozquic_start_client(c);

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

  if (has_arg(argc, argv, "-streamtest1", &argVal)) {
    streamtest1(c);
  }
  if (has_arg(argc, argv, "-send-close", &argVal)) {
    mozquic_destroy_connection(c);
  }
  return 0;
}
