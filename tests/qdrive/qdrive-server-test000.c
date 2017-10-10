/* -*- Mode: C++; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*-
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

// -qdrive-test0 connects, client sends ping, gets ack, exits (without sending close), 500ms later server sends ack, times out and exits

#include "qdrive-common.h"

static struct closure
{
  int test_state;
  mozquic_connection_t *child;
} testState;

void testConfig0(struct mozquic_config_t *_c)
{
  testState.test_state = 0;
}

void *testGetClosure0()
{
  return &testState;
}

int testEvent0(void *closure, uint32_t event, void *param)
{
  test_assert(closure == &testState);
  test_assert(event != MOZQUIC_EVENT_CLOSE_CONNECTION);

  if (event == MOZQUIC_EVENT_ACCEPT_NEW_CONNECTION) {
    test_assert(testState.test_state == 0);
    testState.test_state = 1;
    testState.child = (mozquic_connection_t *) param;
    mozquic_set_event_callback(testState.child, testEvent0);
    mozquic_set_event_callback_closure(testState.child, &testState);
    return MOZQUIC_OK;
  }
  if (event == MOZQUIC_EVENT_CONNECTED) {
    test_assert(testState.test_state == 1);
    testState.test_state = 2;
  }
  if (event == MOZQUIC_EVENT_IO && testState.test_state > 1 && testState.test_state < 700) {
    testState.test_state++;
    test_assert(1);
    return MOZQUIC_OK;
  }
  if (event == MOZQUIC_EVENT_IO && testState.test_state == 700) {
    testState.test_state++;
    test_assert(mozquic_check_peer(testState.child, 200) == MOZQUIC_OK);
  }
  if (event == MOZQUIC_EVENT_ERROR) {
    test_assert(testState.test_state == 701);
    exit(0);
  }
  return MOZQUIC_OK;
}


