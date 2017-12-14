/* -*- Mode: C++; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*-
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

// -qdrive-test1 connects, tries ping with data and confirms the response

#include <string.h>
#include <time.h>
#include <stdio.h>
#include "qdrive-common.h"

static unsigned char test12data[] = {
  0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
  0x21, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
  0x31, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
  0x41, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18
};
  
static struct closure
{
  int test_state;
} testState;

void *testGetClosure12()
{
  return &testState;
}

void testConfig12(struct mozquic_config_t *_c)
{
}

static void onConnected(mozquic_connection_t *localConnection)
{
  memset(&testState, 0, sizeof(testState));
  test_assert(mozquic_unstable_api2(localConnection, "pingWithData",
                                    sizeof(test12data), test12data) == MOZQUIC_OK);
}

int testEvent12(void *closure, uint32_t event, void *param)
{
  test_assert(closure == &testState);
  test_assert(event != MOZQUIC_EVENT_CLOSE_CONNECTION);
  test_assert(event != MOZQUIC_EVENT_ERROR);
  
  if (event == MOZQUIC_EVENT_CONNECTED) {
    onConnected(param);
    testState.test_state = 1;
    return MOZQUIC_OK;
  }
  if (event == MOZQUIC_EVENT_PONG) {
    struct mozquic_eventdata_raw *raw = param;
    test_assert(testState.test_state == 1);
    test_assert(raw->len == sizeof(test12data));
    test_assert(!memcmp(raw->data, test12data, sizeof(test12data)));
    testState.test_state = 2;
    return MOZQUIC_OK;
  }

  if (testState.test_state == 2) {
    mozquic_destroy_connection (parentConnection);
    exit(0);
  }
      
  return MOZQUIC_OK;
}

