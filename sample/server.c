/* -*- Mode: C++; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*-
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include "../MozQuic.h"
#include "assert.h"

#define SERVER_NAME "foo.example.com"
#define SERVER_PORT 4433

#if 0

  ./server -cert ORIGIN to use cert for ORIGIN in nss-config DB

Basic server, does a handshake and waits forever.. it can only handle 1
  session at a time right now.. it will ignore stream data it recvs
  except if it contains a msg of FIN, in which case it will respond
  with a single message and close the stream

  -send-close option will send a close before exiting at 1.5sec

  all connected sessions will be be ping at 30 sec interval.. no response after
  2 seconds closes connection

  About Certificate Verifcation::
The sample/nss-config directory is a sample that can be passed
to mozquic_nss_config(). It contains a NSS database with a cert
and key for foo.example.com that is signed by a CA defined by CA.cert.der.

#endif

#define SEND_CLOSE_TIMEOUT_MS 1500
#define TIMEOUT_CLIENT_MS 30000

int send_close = 0;
int connected = 0;

static int accept_new_connection(mozquic_connection_t *nc);
static void respond(mozquic_stream_t *stream, char *uri, unsigned int uriLen);

#ifdef OSX
void readBinaryData();
void cleanUpBinaryData();
#endif

// closure is per connection, state is per stream
struct closure_t
{
  int i;
  int state[128];
  char buf[128][1024];
  int accum[128];
  int shouldClose;
};

int close_connection(mozquic_connection_t *c)
{
  connected--;
  assert(connected >= 0);
  return mozquic_destroy_connection(c);
}

static void do09(struct closure_t *data, int idx, mozquic_stream_t *stream,
                 const char *buf, unsigned int len)
{
  if (data->accum[idx] + len > sizeof(data->buf[idx])) {
    return;
  }
  memcpy(data->buf[idx] + data->accum[idx], buf, len);
  data->accum[idx] += len;

  char *p = NULL;
  
  p = memchr(data->buf[idx], ' ', data->accum[idx]);
  if (!p) {
    p = memchr(data->buf[idx], '\r', data->accum[idx]);
  }
  if (!p) {
    p = memchr(data->buf[idx], '\n', data->accum[idx]);
  }
  if (!p) {
    return;
  }
  *p = 0;
  assert(data->state[idx] == 7);
  data->state[idx] = 8;
  respond(stream, data->buf[idx], p - data->buf[idx]);
}

static int connEventCB(void *closure, uint32_t event, void *param)
{
  switch (event) {
  case MOZQUIC_EVENT_NEW_STREAM_DATA:
  {
    mozquic_stream_t *stream = param;
 
    char buf;
    int streamtest1 = 0;
    uint32_t amt = 0;
    int fin = 0;
    int line = 0;
    struct closure_t *data = (struct closure_t *)closure;
    assert(closure);
    if (!closure) {
      return MOZQUIC_ERR_GENERAL;
    }
    int id = mozquic_get_streamid(stream);
    if (id >= 128) {
      return MOZQUIC_ERR_GENERAL;
    }
    do {
      uint32_t code = mozquic_recv(stream, &buf, 1, &amt, &fin);
      if (code != MOZQUIC_OK) {
        fprintf(stderr,"Read stream error %d\n", code);
        return MOZQUIC_OK;
      } else if (amt > 0) {
        assert(amt == 1);
        if (!line) {
          fprintf(stderr,"Data:\n");
        }
        line++;
        switch (data->state[id]) {
        case 0:
          data->state[id] = (buf == 'F') ? 1 : 0;
          data->state[id] = (buf == 'G') ? 4 : 0;
            break;
          case 1:
            data->state[id] = (buf == 'I') ? 2 : 0;
            break;
          case 2:
            data->state[id] = (buf == 'N') ? 3 : 0;
            streamtest1 = 1;
            data->shouldClose = 1;
            break;
          case 4:
            data->state[id] = (buf == 'E') ? 5 : 0;
            break;
          case 5:
            data->state[id] = (buf == 'T') ? 6 : 0;
            break;
          case 6:
            data->state[id] = (buf == ' ') ? 7 : 0;
            break;
          case 7:
            do09(data, id, stream, &buf, amt);
            break;
          }
        fprintf(stderr,"state %d [%c] fin=%d\n", data->state[id], buf, fin);
      }
    } while (amt > 0 && !fin && !streamtest1);
    if (streamtest1) {
      char msg[] = "Server sending data.";
      mozquic_send(stream, msg, strlen(msg), 1);
    }
  }
  break;

  case MOZQUIC_EVENT_RESET_STREAM:
  {
    // todo not implemented yet.
    // mozquic_stream_t *stream = param;
    fprintf(stderr,"Stream was reset\n");
    return MOZQUIC_OK;
  }

  case MOZQUIC_EVENT_ACCEPT_NEW_CONNECTION:
    return accept_new_connection(param);

  case MOZQUIC_EVENT_CLOSE_CONNECTION:
  case MOZQUIC_EVENT_ERROR:
    // todo this leaks the 64bit int allocation
    return close_connection(param);

  case MOZQUIC_EVENT_IO:
    if (!closure) {
      return MOZQUIC_OK;
    }
    {
      struct closure_t *data = (struct closure_t *)closure;
      // mozquic_connection_t *conn = param;
      data->i += 1;
      if (send_close && (data->i == SEND_CLOSE_TIMEOUT_MS)) {
        fprintf(stderr,"server terminating connection\n");
        close_connection(param);
        free(data);
        exit(0);
      } else if (data->shouldClose == 3) {
        fprintf(stderr,"server closing based on fin\n");
        close_connection(param);
        free(data);
      } else if (!(data->i % TIMEOUT_CLIENT_MS)) {
        fprintf(stderr,"server testing conn\n");
        mozquic_check_peer(param, 2000);
      }
      return MOZQUIC_OK;
    }

//  default:
//    fprintf(stderr,"unhandled event %X\n", event);
  }
  return MOZQUIC_OK;
}

static int accept_new_connection(mozquic_connection_t *nc)
{
  struct closure_t *closure = malloc(sizeof(struct closure_t));
  memset(closure, 0, sizeof (*closure));
  mozquic_set_event_callback(nc, connEventCB);
  mozquic_set_event_callback_closure(nc, closure);
  connected++;
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

int main(int argc, char **argv)
{
  char *argVal;
  uint32_t i = 0;
  uint32_t delay = 1000;
  struct mozquic_config_t config;
  mozquic_connection_t *c, *c6, *hrr, *hrr6;

  if (has_arg(argc, argv, "-quiet", &argVal)) {
    fclose(stderr);
  }

  if (has_arg(argc, argv, "-qdrive", &argVal)) {
    fprintf(stdout,"%d\n", SERVER_PORT);
    fflush(stdout);
  }
  
  send_close = has_arg(argc, argv, "-send-close", &argVal);
  
  char *cdir = getenv ("MOZQUIC_NSS_CONFIG");
  if (mozquic_nss_config(cdir) != MOZQUIC_OK) {
    fprintf(stderr,"MOZQUIC_NSS_CONFIG FAILURE [%s]\n", cdir ? cdir : "");
    exit (-1);
  }

#ifdef OSX
  readBinaryData();
#endif

  memset(&config, 0, sizeof(config));
  if (has_arg(argc, argv, "-cert", &argVal)) {
    config.originName = strdup(argVal); // leaked
  } else {
    config.originName = SERVER_NAME;
  }
  config.originPort = SERVER_PORT;
  fprintf(stderr,"server using certificate for %s on port %d\n", config.originName, config.originPort);

  config.handleIO = 0; // todo mvp
  config.appHandlesLogging = 0;

  assert(mozquic_unstable_api1(&config, "tolerateBadALPN", 1, 0) == MOZQUIC_OK);
  assert(mozquic_unstable_api1(&config, "tolerateNoTransportParams", 1, 0) == MOZQUIC_OK);
  assert(mozquic_unstable_api1(&config, "sabotageVN", 0, 0) == MOZQUIC_OK);
  assert(mozquic_unstable_api1(&config, "forceAddressValidation", 0, 0) == MOZQUIC_OK);
  assert(mozquic_unstable_api1(&config, "streamWindow", 4906, 0) == MOZQUIC_OK);
  assert(mozquic_unstable_api1(&config, "connWindow", 8192, 0) == MOZQUIC_OK);
  assert(mozquic_unstable_api1(&config, "enable0RTT", 1, 0) == MOZQUIC_OK);

  // assert(mozquic_unstable_api1(&config, "dropRate", 5, 0) == MOZQUIC_OK);

  config.ipv6 = 0;
  mozquic_new_connection(&c, &config);
  mozquic_set_event_callback(c, connEventCB);
  mozquic_start_server(c);

  config.ipv6 = 1;
  mozquic_new_connection(&c6, &config);
  mozquic_set_event_callback(c6, connEventCB);
  mozquic_start_server(c6);
  
  config.originPort = SERVER_PORT + 1;
  config.ipv6 = 0;
  assert(mozquic_unstable_api1(&config, "forceAddressValidation", 1, 0) == MOZQUIC_OK);
  mozquic_new_connection(&hrr, &config);
  mozquic_set_event_callback(hrr, connEventCB);
  mozquic_start_server(hrr);
  fprintf(stderr,"server using certificate (HRR) for %s on port %d\n", config.originName, config.originPort);

  config.ipv6 = 1;
  mozquic_new_connection(&hrr6, &config);
  mozquic_set_event_callback(hrr6, connEventCB);
  mozquic_start_server(hrr6);

  do {
    usleep (delay); // this is for handleio todo
    if (!(i++ & 0xf)) {
      assert(connected >= 0);
      if (!connected) {
        delay = 5000;
      } else if (connected < 10) {
        delay = 1000;
      } else {
        delay = 1000;
      }
    }
    mozquic_IO(c);
    mozquic_IO(c6);
    mozquic_IO(hrr);
    mozquic_IO(hrr6);
  } while (1);

#ifdef OSX
  cleanUpBinaryData();
#endif
}

static const char *js = "/main.js";
static const char *jpg = "/main.jpg";

#ifndef OSX

extern const unsigned char _binary_sample_index_html_start[];
extern const unsigned char _binary_sample_index_html_end[];
extern const unsigned char _binary_sample_main_js_start[];
extern const unsigned char _binary_sample_main_js_end[];
extern const unsigned char _binary_sample_server_jpg_start[];
extern const unsigned char _binary_sample_server_jpg_end[];

#else

#include <mach-o/getsect.h>
#include <mach-o/ldsyms.h>

unsigned char *_binary_sample_index_html_start;
unsigned char *_binary_sample_index_html_end;
unsigned char *_binary_sample_main_js_start;
unsigned char *_binary_sample_main_js_end;
unsigned char *_binary_sample_server_jpg_start;
unsigned char *_binary_sample_server_jpg_end;

void readBinaryData()
{
  size_t size;
  unsigned char *data = getsectiondata(&_mh_execute_header, "binary", "sampleindex_html", &size);
  _binary_sample_index_html_start = calloc(1, size);
  memcpy(_binary_sample_index_html_start, data, size);
  _binary_sample_index_html_end = _binary_sample_index_html_start + size;

  data = getsectiondata(&_mh_execute_header, "binary", "samplemain_js", &size);
  _binary_sample_main_js_start = calloc(1, size);
  memcpy(_binary_sample_main_js_start, data, size);
  _binary_sample_main_js_end = _binary_sample_main_js_start + size;

  data = getsectiondata(&_mh_execute_header, "binary", "sampleserver_jpg", &size);
  _binary_sample_server_jpg_start = calloc(1, size);
  memcpy(_binary_sample_server_jpg_start, data, size);
  _binary_sample_server_jpg_end = _binary_sample_server_jpg_start + size;
}

void cleanUpBinaryData()
{
  free(_binary_sample_index_html_start);
  free(_binary_sample_main_js_start);
  free(_binary_sample_server_jpg_start);
}

#endif

static void respondWith(mozquic_stream_t *stream,
                        const unsigned char *start, const unsigned char *end)
{
  mozquic_send(stream, (void *) start, end - start, 1);
}

static void respond(mozquic_stream_t *stream, char *uri, unsigned int uriLen)
{
  if (uriLen == strlen(js) && !memcmp(js, uri, uriLen) ) {
    respondWith(stream, _binary_sample_main_js_start, _binary_sample_main_js_end);
  } else if (uriLen == strlen(jpg) && !memcmp(jpg, uri, uriLen) ) {
    respondWith(stream, _binary_sample_server_jpg_start, _binary_sample_server_jpg_end);
  } else {
    respondWith(stream, _binary_sample_index_html_start, _binary_sample_index_html_end);
  }
}

