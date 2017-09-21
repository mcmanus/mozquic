/* -*- Mode: C++; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*-
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

// -qdrive-test3 connects with greased version negotiation.. expects server to send a version neg list different than the one actually used, generates close based on that failure

#include "qdrive-common.h"
#include <stdio.h>

static struct closure
{
  int test_state;
} testState;

void *testGetClosure3()
{
  return &testState;
}

void testConfig3(struct mozquic_config_t *_c)
{
  testState.test_state = 0;
  test_assert(mozquic_unstable_api1(_c, "greaseVersionNegotiation", 1, 0) == MOZQUIC_OK);
}

int testEvent3(void *closure, uint32_t event, void *param)
{
  test_assert(closure == &testState);
  test_assert(event != MOZQUIC_EVENT_CLOSE_CONNECTION);
  test_assert(event != MOZQUIC_EVENT_CONNECTED);

  if (event == MOZQUIC_EVENT_ERROR) {
    test_assert(testState.test_state == 0);
    testState.test_state = 1;
    return MOZQUIC_OK;
  }

  if (testState.test_state == 1) {
    mozquic_destroy_connection(parentConnection);
    fprintf(stderr,"exit ok\n");
    exit(0);
  }
  
  return MOZQUIC_OK;
}
