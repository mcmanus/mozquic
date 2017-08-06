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

// -qdrive -addr localhost:port -qdrive-test1

#define SERVER_NAME "foo.example.com"

#if 0

  -qdrive-test1 connects, sends "GET N [CHAR]" and expects N CHAR in response on 3 different streams followed by stream fin and client generated close

  About Certificate Verifcation::
The sample/nss-config directory is a sample that can be passed
to mozquic_nss_config(). It contains a NSS database with a cert
and key for foo.example.com that is signed by a CA defined by CA.cert.der.

#endif

static void test_assert(int test_assertion) 
{
  assert(test_assertion);
  // ndebug too
  if (!test_assertion) {
    void *ptr = 0;
    *((int *)ptr) =  0xdeadbeef;
    exit (-1); // rather un-necessary
  }
}

struct closure
{
  int test;
  int test_state;
  int stream_state[3];
  unsigned char test1_char[3];
  int test1_iters[3];
  mozquic_stream_t *test1_stream[3];
  mozquic_connection_t *child;
} testState;

static int test1FindIdx(mozquic_stream_t *t)
{
  for (int i = 0; i < 3; i++) {
    if (testState.test1_stream[i] == t) {
      return i;
    }
  }
  for (int i = 0; i < 3; i++) {
    if (!testState.test1_stream[i]) {
      testState.test1_stream[i] = t;
      return i;
    }
  }
  fprintf(stderr,"unkown stream\n");
  test_assert(0);
  return 0;
}

static int test1Event(void *closure, uint32_t event, void *param)
{
  test_assert(closure == &testState);
  test_assert(event != MOZQUIC_EVENT_ERROR);
  test_assert(event != MOZQUIC_EVENT_STREAM_RESET);

  if (event == MOZQUIC_EVENT_ACCEPT_NEW_CONNECTION) {
    test_assert(testState.test_state == 0);
    testState.test_state = 1;
    testState.child = (mozquic_connection_t *) param;
    mozquic_set_event_callback(testState.child, test1Event);
    mozquic_set_event_callback_closure(testState.child, &testState);

    return MOZQUIC_OK;
  }
  
  if (event == MOZQUIC_EVENT_NEW_STREAM_DATA) {
    mozquic_stream_t *stream = param;
    char buf[1024];
    uint32_t read = 0;
    int fin = 0;
    test_assert(testState.test_state >= 1);
    test_assert(testState.test_state <= 4);
    int idx = test1FindIdx(stream);
    if (testState.test_state == 4) {
      test_assert(testState.stream_state[idx] == 8);
      uint32_t code = mozquic_recv(stream, buf, 1, &read, &fin);
      test_assert(code == MOZQUIC_OK);
      test_assert(read == 0);
      test_assert(fin);
      return MOZQUIC_OK;
    }
    test_assert(testState.stream_state[idx] >= 0);
    test_assert(testState.stream_state[idx] < 8);

    do {
      uint32_t code = mozquic_recv(stream, buf, 1, &read, &fin);
      test_assert(code == MOZQUIC_OK);
      test_assert(!fin);
      switch(testState.stream_state[idx]) {
      case 0:
        test_assert(buf[0] == 'G');
        testState.stream_state[idx]++;
        break;
      case 1:
        test_assert(buf[0] == 'E');
        testState.stream_state[idx]++;
        break;
      case 2:
        test_assert(buf[0] == 'T');
        testState.stream_state[idx]++;
        break;
      case 3:
        test_assert(buf[0] == ' ');
        testState.stream_state[idx]++;
        break;
      case 4:
        test_assert(buf[0] >= '0');
        test_assert(buf[0] <= '9');
        testState.stream_state[idx]++;
        testState.test1_iters[idx] = buf[0] - '0';
        break;
      case 5:
        test_assert(buf[0] == ' ');
        testState.stream_state[idx]++;
        break;
      case 6:
        testState.stream_state[idx]++;
        testState.test1_char[idx] = buf[0];
        break;
      case 7:
        test_assert(buf[0] == '\n');
        testState.stream_state[idx]++;
        code = mozquic_recv(stream, buf, 1024, &read, &fin);
        test_assert(code == MOZQUIC_OK);
        test_assert(!fin);
        test_assert(read == 0);
        
        char buf[3000];
        memset(buf, testState.test1_char[idx], 3000);
        int tosend = testState.test1_iters[idx] * 1024;
        fprintf(stderr,"QDRIVE SERVER %p expect %d\n", stream, tosend);
        assert(tosend < 10240);
        while (tosend > 0) {
          int actual = (tosend > 3000) ? 3000 : tosend;
          tosend -= actual;
          mozquic_send(stream, buf, actual, !tosend);
        }
        testState.test_state++;
        break;
      }
    } while (read > 0);
    return MOZQUIC_OK;
  }
  
  if (event == MOZQUIC_EVENT_CLOSE_CONNECTION) {
    test_assert (testState.test_state == 4);
    mozquic_destroy_connection(testState.child);
    exit (0);
    return MOZQUIC_OK;
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

int main(int argc, char **argv)
{
  char *argVal, *t;
  uint32_t i = 0;
  struct mozquic_config_t config;
  mozquic_connection_t *c;

  if (has_arg(argc, argv, "-quiet", &argVal)) {
    fclose(stderr);
  }

  char *cdir = getenv ("MOZQUIC_NSS_CONFIG");
  if (mozquic_nss_config(cdir) != MOZQUIC_OK) {
    fprintf(stderr,"MOZQUIC_NSS_CONFIG FAILURE [%s]\n", cdir ? cdir : "");
    test_assert(0);
  }
  
  memset(&config, 0, sizeof(config));

  if (has_arg(argc, argv, "-addr", &argVal)) {
    config.originName = strdup(argVal);
    t = strchr(config.originName, ':');
    if (t) {
      *t = 0;
      config.originPort = atoi(t + 1);
    }
  }
  if (!config.originPort) {
    fprintf(stderr,"-addr hostname:port required\n");
    test_assert(0);
  }

  if (has_arg(argc, argv, "-qdrive", &argVal)) {
    fprintf(stdout,"%d\n", config.originPort);
    fflush(stdout);
  }

  config.originName = SERVER_NAME;
  fprintf(stderr,"server using certificate for %s on port %d\n", config.originName, config.originPort);

  config.tolerateBadALPN = 1;
  config.handleIO = 0; // todo mvp

  mozquic_new_connection(&c, &config);
  if (has_arg(argc, argv, "-qdrive-test1", &argVal)) {
    testState.test = 1;
    testState.test_state = 0;
    mozquic_set_event_callback(c, test1Event);
    mozquic_set_event_callback_closure(c, &testState);
  } else {
    fprintf(stderr,"need to specify a test\n");
    test_assert(0);
  }

  mozquic_start_server(c);

  do {
    usleep (1000); // this is for handleio todo
    if (!(i++ & 0xf)) {
      fprintf(stderr,".");
      fflush(stderr);
    }
    mozquic_IO(c);
  } while (1);
  
}
