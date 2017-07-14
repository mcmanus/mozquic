/* -*- Mode: C++; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*-
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include "../MozQuic.h"

#define SERVER_NAME "foo.example.com"
#define SERVER_PORT 4433

#if 0

Basic server, does a handshake and waits forever.. it can only handle 1
  session at a time right now.. it will ignore stream data it recvs
  except if it contains a msg of FIN, in which case it will respond
  with a single message and close the stream

  -send-close option will send a close before exiting at 1.5sec
  
About Certificate Verifcation::
The sample/nss-config directory is a sample that can be passed
to mozquic_nss_config(). It contains a NSS database with a cert
and key for foo.example.com that is signed by a CA defined by CA.cert.der.

#endif

mozquic_connection_t *only_child = NULL;

uint32_t i=0;
static int connEventCB(void *closure, uint32_t event, void *param)
{
  switch (event) {
  case MOZQUIC_EVENT_NEW_STREAM_DATA:
  {
    mozquic_stream_t *stream = param;
    char buf[100];
    int finStream = 0;
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
        if (strcmp(buf, "FIN") == 0) {
          finStream = 1;
        }
        fprintf(stderr,"[%s] fin=%d\n", buf, fin);
      }
    } while (read > 0);
    if (finStream) {
      char msg[] = "Server sending data.";
      mozquic_send(stream, msg, strlen(msg), 1);
    }
    return MOZQUIC_OK;
  }
  case MOZQUIC_EVENT_STREAM_RESET:
  {
    // todo not implemented yet.
    mozquic_stream_t *stream = param;
    fprintf(stderr,"Stream was reset\n");
    return MOZQUIC_OK;
  }
  default:
    fprintf(stderr,"unhandled event %X\n", event);
  }
  return MOZQUIC_OK;
}

static int accept_new_connection(void *closure, mozquic_connection_t *nc)
{
  if (only_child) {
    mozquic_destroy_connection(only_child);
  }
  only_child = nc;
  mozquic_set_event_callback( only_child, connEventCB);
  i = 0;
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
  config.tolerateBadALPN = 1;
  config.handleIO = 0; // todo mvp

  mozquic_new_connection(&c, &config);
  mozquic_start_server(c, accept_new_connection);

  do {
    usleep (1000); // this is for handleio todo
    if (!(i++ & 0xf)) {
      fprintf(stderr,".");
      fflush(stderr);
    }
    mozquic_IO(c);
    if (only_child) {
      mozquic_IO(only_child); // todo mvp do we need this?
      if ((i == 1500) && has_arg(argc, argv, "-send-close")) {
        mozquic_destroy_connection(only_child);
        only_child = NULL;
      }
    }
  } while (1);
  
}
