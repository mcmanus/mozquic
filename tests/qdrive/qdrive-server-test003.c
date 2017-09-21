/* -*- Mode: C++; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*-
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

// -qdrive-test3 client connects with greased version negotiation, server sends a broken version neg list (Reordered), client generates close based on broken transport parameter in handshake

#include "qdrive-common.h"

struct closure
{
  int test_state;
  mozquic_connection_t *child;
} testState;

void testConfig3(struct mozquic_config_t *_c)
{
  testState.test_state = 0;
  test_assert(mozquic_unstable_api1(_c, "sabotageVN", 1, 0) == MOZQUIC_OK);
}

void *testGetClosure3()
{
  return &testState;
}

int testEvent3(void *closure, uint32_t event, void *param)
{
  test_assert(closure == &testState);
  test_assert(event != MOZQUIC_EVENT_ERROR);

  if (event == MOZQUIC_EVENT_ACCEPT_NEW_CONNECTION) {
    test_assert(testState.test_state == 0);
    testState.test_state = 1;
    testState.child = (mozquic_connection_t *) param;
    mozquic_set_event_callback(testState.child, testEvent3);
    mozquic_set_event_callback_closure(testState.child, &testState);
    return MOZQUIC_OK;
  }

  if (event == MOZQUIC_EVENT_CLOSE_CONNECTION) {
    test_assert (testState.test_state == 1);
    mozquic_destroy_connection(testState.child);
    exit (0);
    return MOZQUIC_OK;
  }

  return MOZQUIC_OK;
}

