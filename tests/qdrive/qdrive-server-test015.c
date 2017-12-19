/* -*- Mode: C++; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*-
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

//  -qdrive-test15 this is the same as test14 only 0RTT data will be rejected by the server - connects, client and server exchange data, client closes the connection and reconnect again. On the second connect 0RTT should be used but it will not be accepted by the server.

#include "qdrive-common.h"
#include <string.h>
#include <stdio.h>

static struct closure
{
  int test_state;
  mozquic_stream_t *test15_stream[2];
  int shouldRead[2];
  mozquic_connection_t *child[2];
  int connection;
} testState;

void *testGetClosure15()
{
  return &testState;
}

static unsigned char gbuf[4048];

void testConfig15(struct mozquic_config_t *_c)
{
  memset(&testState, 0, sizeof(testState));
  testState.shouldRead[0] = 3 * 4048;
  testState.shouldRead[1] = 3 * 4048;

  test_assert(mozquic_unstable_api1(_c, "enable0RTT", 1, 0) == MOZQUIC_OK);
  test_assert(mozquic_unstable_api1(_c, "reject0RTTData", 1, 0) == MOZQUIC_OK);

  memset(gbuf, 0x30, sizeof(gbuf));
}

int testEvent15(void *closure, uint32_t event, void *param)
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
    testState.child[testState.connection - 1] = (mozquic_connection_t *) param;
    mozquic_set_event_callback(testState.child[testState.connection - 1], testEvent15);
    mozquic_set_event_callback_closure(testState.child[testState.connection - 1], &testState);

    return MOZQUIC_OK;
  }

  if (event == MOZQUIC_EVENT_NEW_STREAM_DATA) {
    mozquic_stream_t *stream = param;
    test_assert((testState.test_state == 1) ||
                (testState.test_state == 4));

    char buf[1024];
    uint32_t read = 0;
    int fin = 0;

    do {
      uint32_t code = mozquic_recv(stream, buf, 1024, &read, &fin);
      test_assert(code == MOZQUIC_OK);
      testState.shouldRead[testState.connection -1] -= read;

      if (fin) {
        test_assert(testState.shouldRead[testState.connection -1] == 0);
        mozquic_send(stream, gbuf, 4048, 0);
        mozquic_send(stream, gbuf, 4048, 0);
        mozquic_send(stream, gbuf, 4048, 1);
        testState.test_state++;
        break;
      }
    } while ((read > 0) && !fin);
    return MOZQUIC_OK;
  }

  if (event == MOZQUIC_EVENT_CLOSE_CONNECTION) {
    test_assert(testState.test_state == 2 ||
                testState.test_state == 5);
    testState.test_state++;
    mozquic_destroy_connection(testState.child[testState.connection -1]);
    if (testState.test_state == 6) {
      exit (0);
    }
    return MOZQUIC_OK;
  }

  return MOZQUIC_OK;
}
