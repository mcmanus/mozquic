/* -*- Mode: C++; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*-
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

// -qdrive -addr localhost:port -qdrive-test1

#if 0
  -qdrive-test0 connects, client sends ping, gets ack, exits (without sending close), 500ms later server sends ack, times out and exits

  -qdrive-test1 connects, sends "GET N [CHAR]\n" and expects N * 1024 CHAR in response on 3 different streams followed by stream fin and client generated close. N < 10

  -qdrive-test2 connects, sends until stream is reset closes connection
                                                                                                                                                                     
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

struct closure0
{
  int test_state;
} testState0;

struct closure1
{
  int test_state;
  unsigned char test1_char[3];
  int test1_iters[3];
  mozquic_stream_t *test1_stream[3];
  int test1_fin[3];
} testState1;

struct closure2
{
  int test_state;
  mozquic_stream_t *stream;
} testState2;

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

static int test0Event(void *closure, uint32_t event, void *param)
{
  test_assert(closure == &testState0);
  test_assert(event != MOZQUIC_EVENT_CLOSE_CONNECTION);
  test_assert(event != MOZQUIC_EVENT_ERROR);

  if (event == MOZQUIC_EVENT_CONNECTED) {
    test_assert(testState0.test_state == 0);
    testState0.test_state = 1;
    return MOZQUIC_OK;
  }
  
  if (testState0.test_state == 1) {
    testState0.test_state = 2;
    test_assert(mozquic_check_peer(c, 200) == MOZQUIC_OK);
    return MOZQUIC_OK;
  }
  if (testState0.test_state == 2 && event == MOZQUIC_EVENT_PING_OK) {
    testState0.test_state = 3;
    // do not destroy connection
    test_assert(1);
    exit (0);
  }
  
  return MOZQUIC_OK;
}

static void test1(mozquic_connection_t *c)
{
  memset(&testState1, 0, sizeof(testState1));
  testState1.test_state = 0;
  
  srandom(time(NULL));
  for (int i = 0; i < 3; i++) {
    testState1.test1_char[i] = 'a' + (random() % 26);
    testState1.test1_iters[i] = (random() % 10) * 1024;
    char buf[1024];
    snprintf(buf, 1024, "GET %d %c\n", testState1.test1_iters[i] / 1024, testState1.test1_char[i]);
    mozquic_start_new_stream(testState1.test1_stream + i, c, buf, strlen(buf), 0);
    
    fprintf(stderr,"QDRIVE CLIENT %p expect %d\n", testState1.test1_stream[i],
            testState1.test1_iters[i]);
  }
}

static int test1FindIdx(mozquic_stream_t *t)
{
  for (int i = 0; i < 3; i++) {
    if (testState1.test1_stream[i] == t) {
      return i;
    }
  }
  fprintf(stderr,"unkown stream\n");
  test_assert(0);
  return 0;
}

static int test1Event(void *closure, uint32_t event, void *param)
{
  test_assert(closure == &testState1);
  test_assert(event != MOZQUIC_EVENT_CLOSE_CONNECTION);
  test_assert(event != MOZQUIC_EVENT_ERROR);
  test_assert(event != MOZQUIC_EVENT_ACCEPT_NEW_CONNECTION);
  test_assert(event != MOZQUIC_EVENT_STREAM_RESET);
  
  if (event == MOZQUIC_EVENT_CONNECTED) {
    test_assert(testState1.test_state == 0);
    test1(param);
    testState1.test_state = 1;
    return MOZQUIC_OK;
  }
  if (event == MOZQUIC_EVENT_NEW_STREAM_DATA) {
    mozquic_stream_t *stream = param;
    test_assert(testState1.test_state == 1);
    int idx = test1FindIdx(stream);
    test_assert(!testState1.test1_fin[idx]);

    char buf[500];
    uint32_t read = 0;
    int fin = 0;
    do {
      uint32_t code = mozquic_recv(stream, buf, 500, &read, &fin);
      fprintf(stderr,"QDRIVE CLIENT RECV %d fin %d %p expect %d\n",
              read, fin, stream, testState1.test1_iters[idx]);
      test_assert(code == MOZQUIC_OK);
      test_assert(testState1.test1_iters[idx] >= read);
      testState1.test1_iters[idx] -= read;
      for (int i = 0; i < read; i++) {
        test_assert(testState1.test1_char[idx] == buf[i]);
      }
      if (fin) {
        test_assert(testState1.test1_iters[idx] == 0);
        mozquic_end_stream(stream);
        testState1.test1_fin[idx] = 1;
        if ((testState1.test1_fin[0]) &&
            (testState1.test1_fin[1]) &&
            (testState1.test1_fin[2])) {
          testState1.test_state = 2;
        }
      }
    } while (!fin && read > 0);
    return MOZQUIC_OK;
  }

  if (testState1.test_state == 2) {
    mozquic_destroy_connection (c);
    exit(0);
  }
      
  return MOZQUIC_OK;
}

static int test2Event(void *closure, uint32_t event, void *param)
{
  test_assert(closure == &testState2);
  test_assert(event != MOZQUIC_EVENT_CLOSE_CONNECTION);

  if (event == MOZQUIC_EVENT_CONNECTED) {
    test_assert(testState2.test_state == 0);
    testState2.test_state = 1;
    return MOZQUIC_OK;
  }
  
  if (testState2.test_state == 1) {
    testState2.test_state = 2;
    test_assert(mozquic_start_new_stream(&testState2.stream, c, NULL, 0, 0) == MOZQUIC_OK);
    return MOZQUIC_OK;
  }

  if (testState2.test_state == 2) {
    char buf[2000];
    memset(buf, 0, 2000);
    if (mozquic_send(testState2.stream, buf, 2000, 0) == MOZQUIC_ERR_IO) {
      test_assert(1);
      testState2.test_state = 3;
      return MOZQUIC_OK;
    }
  }

  if (testState2.test_state == 3) {
    mozquic_destroy_connection(c);
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

  testState1.test_state = 0;

  mozquic_new_connection(&c, &config);

  if (has_arg(argc, argv, "-qdrive-test0", &argVal)) {
    testState0.test_state = 0;
    mozquic_set_event_callback(c, test0Event);
    mozquic_set_event_callback_closure(c, &testState0);
  } else if (has_arg(argc, argv, "-qdrive-test1", &argVal)) {
    testState1.test_state = 0;
    mozquic_set_event_callback(c, test1Event);
    mozquic_set_event_callback_closure(c, &testState1);
  } else if (has_arg(argc, argv, "-qdrive-test2", &argVal)) {
    testState2.test_state = 0;
    mozquic_set_event_callback(c, test2Event);
    mozquic_set_event_callback_closure(c, &testState2);
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
