/* -*- Mode: C++; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*-
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

//  -qdrive-test16 client sends 0RTT data on no-replay and replay streams that will be rejected by the server - connects, client and server exchange data, client closes the connection and reconnect again. On the second connect 0RTT should be used but it will not be accepted by the server. The no-replay streams will produce an error.

#include "qdrive-common.h"
#include <string.h>
#include <stdio.h>
#include <unistd.h>

static struct closure
{
  int test_state;
  mozquic_stream_t *test16_stream[2][3];
  int test16_fin[2][3];
  int connection;
} testState;

static unsigned char gbuf[4048];

void testConfig16(struct mozquic_config_t *_c)
{
  memset(&testState, 0, sizeof(testState));
  test_assert(mozquic_unstable_api1(_c, "enable0RTT", 1, 0) == MOZQUIC_OK);
  memset(gbuf, 0x16, sizeof(gbuf));
}

void *testGetClosure16()
{
  return &testState;
}

static void onConnected(mozquic_connection_t *localConnection)
{
  mozquic_start_new_stream(&testState.test16_stream[testState.connection - 1][0], localConnection, 0, 0, gbuf, sizeof(gbuf), 0);
  mozquic_send(testState.test16_stream[testState.connection - 1][0], gbuf, sizeof(gbuf), 0);
  mozquic_send(testState.test16_stream[testState.connection - 1][0], gbuf, sizeof(gbuf), 1);
  test_assert(mozquic_get_streamid(testState.test16_stream[testState.connection - 1][0]) == 4);

  mozquic_start_new_stream(&testState.test16_stream[testState.connection - 1][1], localConnection, 0, 1, gbuf, sizeof(gbuf), 0);
  mozquic_send(testState.test16_stream[testState.connection - 1][1], gbuf, sizeof(gbuf), 0);
  mozquic_send(testState.test16_stream[testState.connection - 1][1], gbuf, sizeof(gbuf), 1);
  test_assert(mozquic_get_streamid(testState.test16_stream[testState.connection - 1][1]) == 8);

  mozquic_start_new_stream(&testState.test16_stream[testState.connection - 1][2], localConnection, 0, 0, gbuf, sizeof(gbuf), 0);
  mozquic_send(testState.test16_stream[testState.connection - 1][2], gbuf, sizeof(gbuf), 0);
  mozquic_send(testState.test16_stream[testState.connection - 1][2], gbuf, sizeof(gbuf), 1);
  test_assert(mozquic_get_streamid(testState.test16_stream[testState.connection - 1][2]) == 12);
}

int  findStreamIndex(mozquic_stream_t *stream)
{
  for (int i = 0; i < 3; i++) {
    if (testState.test16_stream[testState.connection - 1][i] == stream) {
      return i;
    }
  }
  return -1;
}

int testEvent16(void *closure, uint32_t event, void *param)
{
  test_assert(closure == &testState);
  test_assert(event != MOZQUIC_EVENT_CLOSE_CONNECTION);
  test_assert(event != MOZQUIC_EVENT_ERROR);
  test_assert(event != MOZQUIC_EVENT_ACCEPT_NEW_CONNECTION);
  test_assert(event != MOZQUIC_EVENT_RESET_STREAM);

  if (event == MOZQUIC_EVENT_CONNECTED) {
    if (testState.connection == 0) {
      test_assert(testState.test_state == 0);
      testState.connection++;
      onConnected(param);
      testState.test_state++;
    } else {
      // MOZQUIC_EVENT_0RTT_POSSIBLE has already fired and streams were connected.
      test_assert(testState.connection == 2);
      test_assert(testState.test_state == 7);
      test_assert(testState.test16_fin[testState.connection - 1][1]);
      testState.test_state++;
    }
    return MOZQUIC_OK;
  }

  if ((testState.connection == 1) && (event == MOZQUIC_EVENT_0RTT_POSSIBLE)) {
    test_assert(testState.test_state == 5);
    testState.connection++;
    onConnected(param);
    testState.test_state++;
    return MOZQUIC_OK;
  }

  if (event == MOZQUIC_EVENT_STREAM_NO_REPLAY_ERROR) {
    test_assert(testState.connection == 2);
    test_assert(testState.test_state == 6);
    test_assert(testState.test16_stream[testState.connection - 1][1] == param);
    testState.test16_fin[testState.connection - 1][1] = 1;
    testState.test_state++;
  }

  if (event == MOZQUIC_EVENT_NEW_STREAM_DATA) {
    mozquic_stream_t *stream = param;
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
      test_assert((testState.test_state == 8) ||
                  (testState.test_state == 9));
      test_assert((streamIndex == 0) || (streamIndex == 2));
      test_assert((mozquic_get_streamid(stream) == 4) ||
                  (mozquic_get_streamid(stream) == 8));
    }

    test_assert(!testState.test16_fin[testState.connection - 1][streamIndex]);

    char buf[1024];
    uint32_t read = 0;
    int fin = 0;

    uint32_t code = mozquic_recv(stream, buf, 1024, &read, &fin);
    test_assert(code == MOZQUIC_OK);
    test_assert(!read);
    test_assert(fin);
    mozquic_end_stream(stream);
        
    testState.test16_fin[testState.connection - 1][streamIndex] = 1;
    testState.test_state++;
  }
  
  if (testState.test_state == 4) {
    parentConnection = NULL;
    testState.test_state++;
  } else if (testState.test_state == 10) {
    mozquic_destroy_connection (parentConnection);
    testState.test_state++;
    fprintf(stderr,"exit ok\n");
    exit(0);
  }

  return MOZQUIC_OK;
}
