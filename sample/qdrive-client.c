/* -*- Mode: C++; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*-
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

// -qdrive -addr localhost:port -qdrive-test1

#if 0
  -qdrive-test1 connects, sends "GET N [CHAR]\n" and expects N * 1024 CHAR in response on 3 different streams followed by stream fin and client generated close. N < 10

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
#include <time.h>
#include <assert.h>
#include "../MozQuic.h"

mozquic_connection_t *c;

struct closure
{
  int test;
  int test_state;
  unsigned char test1_char[3];
  int test1_iters[3];
  mozquic_stream_t *test1_stream[3];
  int test1_fin[3];
} testState;

static void test_assert(int test_assertion) 
{
  assert(test_assertion);
  // ndebug too
  if (!test_assertion) {
    void *ptr = 0;
    *((int *)ptr) =  0xdeadbeef;
    exit(-1); // rather un-necessary
  }
}

static void test1(mozquic_connection_t *c)
{
  memset(&testState, 0, sizeof(testState));
  testState.test = 1;
  testState.test_state = 0;
  
  srandom(time(NULL));
  for (int i = 0; i < 3; i++) {
    testState.test1_char[i] = 'a' + (random() % 26);
    testState.test1_iters[i] = (random() % 10) * 1024;
    char buf[1024];
    snprintf(buf, 1024, "GET %d %c\n", testState.test1_iters[i] / 1024, testState.test1_char[i]);
    mozquic_start_new_stream(testState.test1_stream + i, c, buf, strlen(buf), 0);
    
    fprintf(stderr,"QDRIVE CLIENT %p expect %d\n", testState.test1_stream[i],
            testState.test1_iters[i]);
  }
}

static int test1FindIdx(mozquic_stream_t *t)
{
  for (int i = 0; i < 3; i++) {
    if (testState.test1_stream[i] == t) {
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
  test_assert(event != MOZQUIC_EVENT_CLOSE_CONNECTION);
  test_assert(event != MOZQUIC_EVENT_ERROR);
  test_assert(event != MOZQUIC_EVENT_ACCEPT_NEW_CONNECTION);
  test_assert(event != MOZQUIC_EVENT_STREAM_RESET);
  
  if (event == MOZQUIC_EVENT_CONNECTED) {
    test_assert(testState.test_state == 0);
    test1(param);
    testState.test_state = 1;
    return MOZQUIC_OK;
  }
  if (event == MOZQUIC_EVENT_NEW_STREAM_DATA) {
    mozquic_stream_t *stream = param;
    test_assert(testState.test_state == 1);
    int idx = test1FindIdx(stream);
    test_assert(!testState.test1_fin[idx]);

    char buf[500];
    uint32_t read = 0;
    int fin = 0;
    do {
      uint32_t code = mozquic_recv(stream, buf, 500, &read, &fin);
      fprintf(stderr,"QDRIVE CLIENT RECV %d fin %d %p expect %d\n",
              read, fin, stream, testState.test1_iters[idx]);
      test_assert(code == MOZQUIC_OK);
      test_assert(testState.test1_iters[idx] >= read);
      testState.test1_iters[idx] -= read;
      for (int i = 0; i < read; i++) {
        test_assert(testState.test1_char[idx] == buf[i]);
      }
      if (fin) {
        test_assert(testState.test1_iters[idx] == 0);
        mozquic_end_stream(stream);
        testState.test1_fin[idx] = 1;
        if ((testState.test1_fin[0]) &&
            (testState.test1_fin[1]) &&
            (testState.test1_fin[2])) {
          testState.test_state = 2;
        }
      }
    } while (!fin && read > 0);
    return MOZQUIC_OK;
  }

  if (testState.test_state == 2) {
    mozquic_destroy_connection (c);
    exit(0);
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
  struct mozquic_config_t config;

  if (has_arg(argc, argv, "-quiet", &argVal)) {
    fclose(stderr);
  }

  if (!has_arg(argc, argv, "-qdrive", &argVal)) {
    fprintf(stderr, "-qdrive required\n");
    test_assert(0);
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
  
  fprintf(stderr,"client connecting to %s port %d\n", config.originName, config.originPort);

  config.handleIO = 0;

  // ingorePKI will allow invalid certs
  // normally they must either be linked to the root store OR on localhost
  config.ignorePKI = has_arg(argc, argv, "-ignorePKI", &argVal);

  config.greaseVersionNegotiation = 0;
  config.preferMilestoneVersion = 1;
  config.tolerateBadALPN = 1;

  testState.test_state = 0;

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
  } while (1);

  return 0;
}
