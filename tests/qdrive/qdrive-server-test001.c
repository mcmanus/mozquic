/* -*- Mode: C++; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*-
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

// -qdrive-test1 connects, sends "GET N [CHAR]" and expects N CHAR in response on 3 different streams followed by stream fin and client generated close

#include "qdrive-common.h"
#include <stdio.h>
#include <string.h>
#include <assert.h>

static struct closure
{
  int test_state;
  int stream_state[3];
  unsigned char test1_char[3];
  int test1_iters[3];
  mozquic_stream_t *test1_stream[3];
  mozquic_connection_t *child;
} testState;

void testConfig1(struct mozquic_config_t *_c)
{
  testState.test_state = 0;
}

void *testGetClosure1()
{
  return &testState;
}

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

int testEvent1(void *closure, uint32_t event, void *param)
{
  test_assert(closure == &testState);
  test_assert(event != MOZQUIC_EVENT_ERROR);
  test_assert(event != MOZQUIC_EVENT_RESET_STREAM);

  if (event == MOZQUIC_EVENT_ACCEPT_NEW_CONNECTION) {
    test_assert(testState.test_state == 0);
    testState.test_state = 1;
    testState.child = (mozquic_connection_t *) param;
    mozquic_set_event_callback(testState.child, testEvent1);
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
        do {
          int actual = (tosend > 3000) ? 3000 : tosend;
          tosend -= actual;
          mozquic_send(stream, buf, actual, !tosend);
        } while (tosend > 0);

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


