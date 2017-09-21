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
#include "string.h"

static int starts = 0;

static struct closure
{
  int test_state;
  mozquic_connection_t *child;
  mozquic_stream_t *stream;
} testState;

void testConfig6(struct mozquic_config_t *_c)
{
  starts++;
  testState.test_state = 0;
  unsigned char keymaterial[128] =
    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
  
  memcpy(_c->statelessResetKey, keymaterial, 128);
}

void *testGetClosure6()
{
  return &testState;
}

extern int qdrive_server_crash;

int testEvent6(void *closure, uint32_t event, void *param)
{
  test_assert(closure == &testState);
  test_assert(event != MOZQUIC_EVENT_ERROR);
  test_assert(event != MOZQUIC_EVENT_CLOSE_CONNECTION);
  test_assert(event != MOZQUIC_EVENT_RESET_STREAM);

  if (event == MOZQUIC_EVENT_ACCEPT_NEW_CONNECTION) {
    test_assert(starts == 1);
    test_assert(testState.test_state == 0);
    testState.test_state++;
    testState.child = (mozquic_connection_t *) param;
    mozquic_set_event_callback(testState.child, testEvent6);
    mozquic_set_event_callback_closure(testState.child, &testState);
    return MOZQUIC_OK;
  }

  if (event == MOZQUIC_EVENT_CONNECTED) {
    test_assert(starts == 1);
    test_assert(testState.test_state == 1);
    testState.test_state++;
    return MOZQUIC_OK;
  }

  if (event == MOZQUIC_EVENT_NEW_STREAM_DATA) {
    test_assert(starts == 1);
    test_assert(testState.test_state >= 2);
    mozquic_stream_t *stream = param;
    char buf[1024];
    uint32_t read = 0;
    int fin = 0;
    uint32_t code = mozquic_recv(stream, buf, 1024, &read, &fin);
    test_assert(code == MOZQUIC_OK);
    testState.test_state++;
    qdrive_server_crash = 1;
    return MOZQUIC_OK;
  }

  test_assert(starts <= 2);
  if (starts == 2) {
    testState.test_state++;
    if (testState.test_state > 100) {
      exit(0);
    }
  }
  return MOZQUIC_OK;
}

