/* -*- Mode: C++; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*-
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

// -qdrive-test6 connects to a server. Then it
// sends 1 byte messages at ~62HZ. The server waits until it
// has recvd 1 and then simply destroys the mozquic context (without
// sending a close). it then starts back up and upon recving a new packet
// generates a stateless reset. The client confirms the error.

#include "qdrive-common.h"
#include <stdio.h>

static struct closure
{
  int test_state;
  mozquic_stream_t *stream;
} testState;

void *testGetClosure6()
{
  return &testState;
}

void testConfig6(struct mozquic_config_t *_c)
{
  testState.test_state = 0;
}

int testEvent6(void *closure, uint32_t event, void *param)
{
  test_assert(closure == &testState);
  test_assert(event != MOZQUIC_EVENT_CLOSE_CONNECTION);

  if (event == MOZQUIC_EVENT_CONNECTED) {
    test_assert(testState.test_state == 0);
    testState.test_state = 1;
    return MOZQUIC_OK;
  }

  if (event == MOZQUIC_EVENT_ERROR) {
    test_assert(testState.test_state >= 2);
    mozquic_destroy_connection(parentConnection);
    fprintf(stderr,"exit ok\n");
    exit(0);
  }

  if (testState.test_state == 1) {
    unsigned char buf = 0;
    mozquic_start_new_stream(&testState.stream, param, 0, 0, &buf, 1, 0);
    testState.test_state = 2;
    return MOZQUIC_OK;
  }

  if (testState.test_state > 1 && !(testState.test_state & 0xf)) {
    unsigned char buf = testState.test_state & 0xff;
    mozquic_send(testState.stream, &buf, 1, 0);
  }

  if (testState.test_state > 1) {
    testState.test_state++;
  }
  return MOZQUIC_OK;
}
