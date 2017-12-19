/* -*- Mode: C++; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*-
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

// -qdrive-test1 connects, sends "GET N [CHAR]\n" and expects N * 1024 CHAR in response on 3 different streams followed by stream fin and client generated close. N < 10

#include <string.h>
#include <time.h>
#include <stdio.h>
#include "qdrive-common.h"

static struct closure
{
  int test_state;
  unsigned char test1_char[3];
  unsigned int test1_iters[3];
  mozquic_stream_t *test1_stream[3];
  int test1_fin[3];
} testState;

void *testGetClosure1()
{
  return &testState;
}

void testConfig1(struct mozquic_config_t *_c)
{
  testState.test_state = 0;
}

static void onConnected(mozquic_connection_t *localConnection)
{
  memset(&testState, 0, sizeof(testState));
  testState.test_state = 0;
  
  srandom(time(NULL));
  for (int i = 0; i < 3; i++) {
    testState.test1_char[i] = 'a' + (random() % 26);
    testState.test1_iters[i] = (random() % 10) * 1024;
    char buf[1024];
    snprintf(buf, 1024, "GET %d %c\n", testState.test1_iters[i] / 1024, testState.test1_char[i]);
    mozquic_start_new_stream(testState.test1_stream + i, localConnection, 0, 0, buf, strlen(buf), 0);
    
    fprintf(stderr,"QDRIVE CLIENT %p expect %d\n", testState.test1_stream[i],
            testState.test1_iters[i]);
  }
}

static int FindIdx(mozquic_stream_t *t)
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

int testEvent1(void *closure, uint32_t event, void *param)
{
  test_assert(closure == &testState);
  test_assert(event != MOZQUIC_EVENT_CLOSE_CONNECTION);
  test_assert(event != MOZQUIC_EVENT_ERROR);
  test_assert(event != MOZQUIC_EVENT_ACCEPT_NEW_CONNECTION);
  test_assert(event != MOZQUIC_EVENT_RESET_STREAM);
  
  if (event == MOZQUIC_EVENT_CONNECTED) {
    test_assert(testState.test_state == 0);
    onConnected(param);
    testState.test_state = 1;
    return MOZQUIC_OK;
  }
  if (event == MOZQUIC_EVENT_NEW_STREAM_DATA) {
    mozquic_stream_t *stream = param;
    test_assert(testState.test_state == 1);
    int idx = FindIdx(stream);
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
      for (unsigned int i = 0; i < read; i++) {
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
    mozquic_destroy_connection (parentConnection);
    exit(0);
  }
      
  return MOZQUIC_OK;
}

