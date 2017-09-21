/* -*- Mode: C++; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*-
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

// -qdrive-test7 the client connects and announces small flow control
// windows to the server. Upon recving a go signal from the client the
// server sends 16KB of data to the client, exercising the flow control
// logic. That's phase1. The client then turns on backpressure (i.e.
// it will not send flow control credits) and repeats the process causing
// a stall in the sending of the second 16KB. After a 1000ms timer, the
// client releases the backpressure allowing the second phase of 16KB to
// complete. The test asserts that the second phase is at least 500ms
// slower than the first one.

#include "qdrive-common.h"
#include "string.h"


static struct closure
{
  int state;
  mozquic_connection_t *child;
  mozquic_stream_t *stream1;
  mozquic_stream_t *stream2;
} state;

void testConfig7(struct mozquic_config_t *_c)
{
  memset(&state, 0, sizeof(state));
}

void *testGetClosure7()
{
  return &state;
}

int testEvent7(void *closure, uint32_t event, void *param)
{
  test_assert(closure == &state);
  test_assert(event != MOZQUIC_EVENT_ERROR);
  test_assert(event != MOZQUIC_EVENT_RESET_STREAM);

  if (event == MOZQUIC_EVENT_ACCEPT_NEW_CONNECTION) {
    test_assert(state.state == 0);
    state.state++;
    state.child = (mozquic_connection_t *) param;
    mozquic_set_event_callback(state.child, testEvent7);
    mozquic_set_event_callback_closure(state.child, &state);
    return MOZQUIC_OK;
  }

  if (event == MOZQUIC_EVENT_CONNECTED) {
    test_assert(state.state == 1);
    state.state++;
    return MOZQUIC_OK;
  }

  if (event == MOZQUIC_EVENT_NEW_STREAM_DATA) {
    test_assert(state.state == 2 ||
                state.state == 4);
    mozquic_stream_t *stream = param;
    char buf[1024];
    uint32_t read = 0;
    int fin = 0;
    uint32_t code = mozquic_recv(stream, buf, 1024, &read, &fin);
    test_assert(code == MOZQUIC_OK);
    test_assert(!fin);
    test_assert(read == 1);
    if (state.state == 2) {
      test_assert(buf[0] == 1);
      test_assert(!state.stream1);
      state.stream1 = stream;
    } else {
      test_assert(buf[0] == 2);
      test_assert(state.stream1 != NULL);
      test_assert(!state.stream2);
      state.stream2 = stream;
    }
    state.state++;
    return MOZQUIC_OK;
  }

  if (state.state == 3 || state.state == 5) {
    char buf[16000];
    memset(buf, state.state, sizeof(buf));
    int code = mozquic_send(
      state.state == 3 ? state.stream1 : state.stream2,
      buf, sizeof(buf), 0);
    test_assert(code == MOZQUIC_OK);
    state.state++;
  }

  if (event == MOZQUIC_EVENT_CLOSE_CONNECTION) {
    test_assert(state.state == 6);
    exit (0);
  }

  return MOZQUIC_OK;
}

