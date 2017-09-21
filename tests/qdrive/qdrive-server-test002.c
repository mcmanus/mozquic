/* -*- Mode: C++; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*-
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

// -qdrive-test2 connects, recvs 10KB, resests stream, waits for client generated close

#include "qdrive-common.h"

static struct closure
{
  int test_state;
  int rx;
  mozquic_connection_t *child;
} testState;

void testConfig2(struct mozquic_config_t *_c)
{
  testState.test_state = 0;
}

void *testGetClosure2()
{
  return &testState;
}

int testEvent2(void *closure, uint32_t event, void *param)
{
  test_assert(closure == &testState);
  test_assert(event != MOZQUIC_EVENT_ERROR);

  if (event == MOZQUIC_EVENT_ACCEPT_NEW_CONNECTION) {
    test_assert(testState.test_state == 0);
    testState.test_state = 1;
    testState.rx = 0;
    testState.child = (mozquic_connection_t *) param;
    mozquic_set_event_callback(testState.child, testEvent2);
    mozquic_set_event_callback_closure(testState.child, &testState);

    return MOZQUIC_OK;
  }

  if (event == MOZQUIC_EVENT_NEW_STREAM_DATA) {
    test_assert(testState.test_state == 1 || testState.test_state == 2);
    mozquic_stream_t *stream = param;
    char buf[1024];
    uint32_t read = 0;
    int fin = 0;
    uint32_t code = mozquic_recv(stream, buf, 1024, &read, &fin);
    test_assert(code == MOZQUIC_OK);
    test_assert(!fin);
    testState.rx += read;
    if (testState.test_state == 1 && testState.rx >= 10240) {
      testState.test_state = 2;
      test_assert(mozquic_stop_sending(stream) == MOZQUIC_OK);
    }
  }

  if (event == MOZQUIC_EVENT_CLOSE_CONNECTION) {
    test_assert (testState.test_state == 2);
    mozquic_destroy_connection(testState.child);
    exit (0);
    return MOZQUIC_OK;
  }

  return MOZQUIC_OK;
}

