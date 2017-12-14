/* -*- Mode: C++; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*-
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

//  -qdrive-test14 connects, client and server exchange data, client closes the connection and reconnect again. On the second connect 0RTT should be used.

#include "qdrive-common.h"
#include <string.h>
#include <stdio.h>

static struct closure
{
  int test_state;
  mozquic_stream_t *test14_stream;
  int stream_state[2];
  int test14_iters[2];
  mozquic_connection_t *child;
  int connection;
} testState;

void *testGetClosure14()
{
  return &testState;
}

void testConfig14(struct mozquic_config_t *_c)
{
  testState.test_state = 0;
  test_assert(mozquic_unstable_api1(_c, "enable0RTT", 1, 0) == MOZQUIC_OK);
}

int testEvent14(void *closure, uint32_t event, void *param)
{
  test_assert(closure == &testState);
  test_assert(event != MOZQUIC_EVENT_ERROR);
  test_assert(event != MOZQUIC_EVENT_RESET_STREAM);

  if (event == MOZQUIC_EVENT_ACCEPT_NEW_CONNECTION) {
    testState.connection++;
    if (testState.connection == 1) {
      test_assert(testState.test_state == 0);
    } else if (testState.connection == 2) {
      test_assert(testState.test_state == 3);
    } else {
      test_assert(0);
    }
    testState.test_state++;
    testState.child = (mozquic_connection_t *) param;
    mozquic_set_event_callback(testState.child, testEvent14);
    mozquic_set_event_callback_closure(testState.child, &testState);

    return MOZQUIC_OK;
  }

  if (event == MOZQUIC_EVENT_NEW_STREAM_DATA) {
    mozquic_stream_t *stream = param;
    test_assert(testState.test_state >= 1);
    test_assert(testState.test_state <= 5);
    test_assert(testState.test_state != 3);
    char buf[50];
    uint32_t read = 0;
    int fin = 0;
    
    if ((testState.test_state == 2) ||
        (testState.test_state == 5)) {
      testState.test_state++;
      test_assert(testState.stream_state[testState.connection - 1] == 6);
      uint32_t code = mozquic_recv(stream, buf, 1, &read, &fin);
      test_assert(code == MOZQUIC_OK);
      test_assert(read == 0);
      test_assert(fin);
      return MOZQUIC_OK;
    }

    do {
      uint32_t code = mozquic_recv(stream, buf, 1, &read, &fin);
      test_assert(code == MOZQUIC_OK);
      test_assert(!fin);
      switch(testState.stream_state[testState.connection - 1]) {
      case 0:
        test_assert(buf[0] == 'G');
        testState.stream_state[testState.connection - 1]++;
        break;
      case 1:
        test_assert(buf[0] == 'E');
        testState.stream_state[testState.connection - 1]++;
        break;
      case 2:
        test_assert(buf[0] == 'T');
        testState.stream_state[testState.connection - 1]++;
        break;
      case 3:
        test_assert(buf[0] == ' ');
        testState.stream_state[testState.connection - 1]++;
        break;
      case 4:
        test_assert(buf[0] >= '0');
        test_assert(buf[0] <= '9');
        testState.stream_state[testState.connection - 1]++;
        testState.test14_iters[testState.connection - 1] = buf[0] - '0';
        break;
      case 5:
        test_assert(buf[0] == '\n');
        testState.stream_state[testState.connection - 1]++;
        char buf[10];
        memset(buf, 'A', 10);
        fprintf(stderr,"QDRIVE SERVER %p expect %d\n", stream, testState.test14_iters[testState.connection - 1]);
        mozquic_send(stream, buf, testState.test14_iters[testState.connection - 1], 1);
        testState.test_state++;
        break;
      }
    } while (read > 0);
    return MOZQUIC_OK;
  }

  if (event == MOZQUIC_EVENT_CLOSE_CONNECTION) {
    if (testState.test_state == 3) {
      mozquic_destroy_connection(testState.child);
    } else {
      test_assert(testState.test_state == 6);
      exit (0);
    }
    return MOZQUIC_OK;
  }

  return MOZQUIC_OK;
}
