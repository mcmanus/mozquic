/* -*- Mode: C++; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*-
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

//  -qdrive-test0 connects, client sends ping, gets ack, exits (without sending close), 500ms later server sends ack, times out and exits

#include "qdrive-common.h"

static struct closure
{
  int test_state;
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
  test_assert(event != MOZQUIC_EVENT_ERROR);

  if (event == MOZQUIC_EVENT_CONNECTED) {
    test_assert(testState.test_state == 0);
    testState.test_state = 1;
    return MOZQUIC_OK;
  }
  
  if (testState.test_state == 1) {
    testState.test_state = 2;
    test_assert(mozquic_check_peer(parentConnection, 200) == MOZQUIC_OK);
    return MOZQUIC_OK;
  }
  if (testState.test_state == 2 && event == MOZQUIC_EVENT_PING_OK) {
    testState.test_state = 3;
    // do not destroy connection
    test_assert(1);
    exit (0);
  }
  
  return MOZQUIC_OK;
}

