/* -*- Mode: C++; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*-
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

// -qdrive-test2 connects, sends until stream is reset closes connection

#include <string.h>
#include "qdrive-common.h"

static struct closure
{
  int test_state;
  mozquic_stream_t *stream;
} testState;

void *testGetClosure2()
{
  return &testState;
}

void testConfig2(struct mozquic_config_t *_c)
{
  testState.test_state = 0;
}

int testEvent2(void *closure, uint32_t event, void *param)
{
  test_assert(closure == &testState);
  test_assert(event != MOZQUIC_EVENT_CLOSE_CONNECTION);

  if (event == MOZQUIC_EVENT_CONNECTED) {
    test_assert(testState.test_state == 0);
    testState.test_state = 1;
    return MOZQUIC_OK;
  }
  
  if (testState.test_state == 1) {
    testState.test_state = 2;
    test_assert(mozquic_start_new_stream(&testState.stream, parentConnection, 0, 0, NULL, 0, 0) == MOZQUIC_OK);
    return MOZQUIC_OK;
  }

  if (testState.test_state == 2) {
    char buf[2000];
    memset(buf, 0, 2000);
    if (mozquic_send(testState.stream, buf, 2000, 0) == MOZQUIC_ERR_IO) {
      test_assert(1);
      testState.test_state = 3;
      return MOZQUIC_OK;
    }
  }

  if (testState.test_state == 3) {
    mozquic_destroy_connection(parentConnection);
    exit(0);
  }
  
  return MOZQUIC_OK;
}
