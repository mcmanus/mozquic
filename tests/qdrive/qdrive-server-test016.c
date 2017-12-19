/* -*- Mode: C++; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*-
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

//  -qdrive-test16 client sends 0RTT data on no-replay and replay streams that will be rejected by the server - connects, client and server exchange data, client closes the connection and reconnect again. On the second connect 0RTT should be used but it will not be accepted by the server. The no-replay streams will produce an error.

#include "qdrive-common.h"
#include <string.h>
#include <stdio.h>

static struct closure
{
  int test_state;
  int32_t test16_stream[2][3];
  int shouldRead[2][3];
  mozquic_connection_t *child[2];
  int connection;
} testState;

void *testGetClosure16()
{
  return &testState;
}

static unsigned char gbuf[4048];

void testConfig16(struct mozquic_config_t *_c)
{
  memset(&testState, 0, sizeof(testState));
  testState.shouldRead[0][0] = 3 * 4048;
  testState.shouldRead[0][1] = 3 * 4048;
  testState.shouldRead[0][2] = 3 * 4048;
  testState.shouldRead[1][0] = 3 * 4048;
  testState.shouldRead[1][1] = 3 * 4048; // this one will not be replayed.
  testState.shouldRead[1][2] = 0;

  test_assert(mozquic_unstable_api1(_c, "enable0RTT", 1, 0) == MOZQUIC_OK);
  test_assert(mozquic_unstable_api1(_c, "reject0RTTData", 1, 0) == MOZQUIC_OK);

  memset(gbuf, 0x32, sizeof(gbuf));
}

int  findStreamIndex(mozquic_stream_t *stream)
{
  int32_t streamID = mozquic_get_streamid(stream);
  for (int i = 0; i < 3; i++) {
    if (!testState.test16_stream[testState.connection - 1][i]) {
      testState.test16_stream[testState.connection - 1][i] = streamID;
      return i;
    } else if (testState.test16_stream[testState.connection - 1][i] == streamID) {
      return i;
    }
  }
  return -1;
}


int testEvent16(void *closure, uint32_t event, void *param)
{
  test_assert(closure == &testState);
  test_assert(event != MOZQUIC_EVENT_ERROR);
  test_assert(event != MOZQUIC_EVENT_RESET_STREAM);

  if (event == MOZQUIC_EVENT_ACCEPT_NEW_CONNECTION) {
    testState.connection++;
    if (testState.connection == 1) {
      test_assert(testState.test_state == 0);
    } else if (testState.connection == 2) {
      test_assert(testState.test_state == 5);
    } else {
      test_assert(0);
    }
    testState.test_state++;
    testState.child[testState.connection - 1] = (mozquic_connection_t *) param;
    mozquic_set_event_callback(testState.child[testState.connection - 1], testEvent16);
    mozquic_set_event_callback_closure(testState.child[testState.connection - 1], &testState);

    return MOZQUIC_OK;
  }

  if (event == MOZQUIC_EVENT_NEW_STREAM_DATA) {
    mozquic_stream_t *stream = param;
    test_assert(testState.test_state >= 1);
    test_assert(testState.test_state <= 7);
    test_assert(testState.test_state != 4);
    test_assert(testState.test_state != 5);
    char buf[1024];
    uint32_t read = 0;
    int fin = 0;
    int streamIndex = findStreamIndex(stream);
    test_assert(streamIndex != -1);

    if (testState.connection == 1) {
      test_assert((testState.test_state >= 1) &&
                  (testState.test_state <= 3));
      test_assert((streamIndex >= 0) && (streamIndex <= 2));
      test_assert((mozquic_get_streamid(stream) == 4) ||
                  (mozquic_get_streamid(stream) == 8) ||
                  (mozquic_get_streamid(stream) == 12));
    } else {
      test_assert((testState.test_state == 6) ||
                  (testState.test_state == 7));
      test_assert((streamIndex == 0) || (streamIndex == 1));
      test_assert((mozquic_get_streamid(stream) == 4) ||
                  (mozquic_get_streamid(stream) == 8));
    }

    do {
      uint32_t code = mozquic_recv(stream, buf, 1024, &read, &fin);
      test_assert(code == MOZQUIC_OK);
      testState.shouldRead[testState.connection -1][streamIndex] -= read;

      if (fin) {
        test_assert(testState.shouldRead[testState.connection -1][streamIndex] == 0);
        mozquic_send(stream, NULL, 0, 1);
        testState.test_state++;
        break;
      }
    } while (read > 0 && !fin);
    return MOZQUIC_OK;
  }

  if (event == MOZQUIC_EVENT_CLOSE_CONNECTION) {
    test_assert(testState.test_state == 4 ||
                testState.test_state == 8);
    mozquic_destroy_connection(testState.child[testState.connection -1]);
    testState.test_state++;
    if (testState.test_state == 9) {
      exit (0);
    }
    return MOZQUIC_OK;
  }

  return MOZQUIC_OK;
}
