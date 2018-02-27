/* -*- Mode: C++; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*-
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

//  -qdrive-test14 connects, client and server exchange data, client closes the connection and reconnect again. On the second connect 0RTT should be used.

#include "qdrive-common.h"
#include <string.h>
#include <stdio.h>
#include <unistd.h>

static struct closure
{
  int test_state;
  mozquic_stream_t *test14_stream[2];
  uint32_t shouldRead[2];
  int test14_fin[2];
  int connection;
} testState;

static unsigned char gbuf[4048];

void testConfig14(struct mozquic_config_t *_c)
{
  memset(&testState, 0, sizeof(testState));
  testState.shouldRead[0] = 3 * 4048;
  testState.shouldRead[1] = 3 * 4048;
  test_assert(mozquic_unstable_api1(_c, "enable0RTT", 1, 0) == MOZQUIC_OK);
  memset(gbuf, 0x14, sizeof(gbuf));
}

void *testGetClosure14()
{
  return &testState;
}

static void onConnected(mozquic_connection_t *localConnection)
{
  mozquic_start_new_stream(&testState.test14_stream[testState.connection - 1], localConnection, 0, 0, gbuf, sizeof(gbuf), 0);
  mozquic_send(testState.test14_stream[testState.connection - 1], gbuf, sizeof(gbuf), 0);
  mozquic_send(testState.test14_stream[testState.connection - 1], gbuf, sizeof(gbuf), 1);
}

int testEvent14(void *closure, uint32_t event, void *param)
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
      // MOZQUIC_EVENT_0RTT_POSSIBLE has already fired and a stream is connected.
      test_assert(testState.connection == 2);
      test_assert(testState.test_state == 4);
    }
    return MOZQUIC_OK;
  }

  if ((testState.connection == 1) && (event == MOZQUIC_EVENT_0RTT_POSSIBLE)) {
    test_assert(testState.test_state == 3);
    testState.connection++;
    onConnected(param);
    testState.test_state++;
    return MOZQUIC_OK;
  }
  
  if (event == MOZQUIC_EVENT_NEW_STREAM_DATA) {
    mozquic_stream_t *stream = param;
    if (testState.connection == 1) {
      test_assert(testState.test_state == 1);
    } else {
      test_assert(testState.test_state == 4);
    }
    test_assert(!testState.test14_fin[testState.connection - 1]);
    test_assert(stream == testState.test14_stream[testState.connection - 1]);

    char buf[1024];
    uint32_t read = 0;
    int fin = 0;

    do {
      uint32_t code = mozquic_recv(stream, buf, 1024, &read, &fin);
      test_assert(code == MOZQUIC_OK);
      test_assert(testState.shouldRead[testState.connection - 1] >= read);
      testState.shouldRead[testState.connection - 1] -= read;
      if (fin) {
        test_assert(testState.shouldRead[testState.connection - 1] == 0);
        
        testState.test14_fin[testState.connection - 1] = 1;
        testState.test_state++;
      }
    } while (!fin && read > 0);
  }

  if (testState.test_state == 2) {
    parentConnection = NULL;
    testState.test_state++;
  } else if (testState.test_state == 5) {
    mozquic_shutdown_connection (parentConnection);
    testState.test_state++;
  }

  if (testState.test_state >= 6) {
    testState.test_state++;
  }

  if (testState.test_state == 20) {
    fprintf(stderr,"exit ok\n");
    exit(0);
  }

  return MOZQUIC_OK;
}
