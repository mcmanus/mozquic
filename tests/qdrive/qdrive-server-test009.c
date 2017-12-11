/* -*- Mode: C++; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*-
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

// -qdrive-test9 client sends 3 bytes and fin on stream create
// server replies with 4 bytes and fin. (tests fin on create)

#include "qdrive-common.h"
#include "string.h"

static struct closure
{
  int state;
  mozquic_connection_t *child;
  mozquic_stream_t *stream;
} state;

void *testGetClosure9()
{
  return &state;
}

void testConfig9(struct mozquic_config_t *_c)
{
  memset(&state, 0, sizeof(state));
}

int testEvent9(void *closure, uint32_t event, void *param)
{
  test_assert(closure == &state);
  test_assert(event != MOZQUIC_EVENT_ERROR);
  test_assert(event != MOZQUIC_EVENT_RESET_STREAM);

  if (event == MOZQUIC_EVENT_ACCEPT_NEW_CONNECTION) {
    test_assert(state.state == 0);
    state.state++;
    state.child = (mozquic_connection_t *) param;
    mozquic_set_event_callback(state.child, testEvent9);
    mozquic_set_event_callback_closure(state.child, &state);
    return MOZQUIC_OK;
  }

  if (event == MOZQUIC_EVENT_CONNECTED) {
    test_assert(state.state == 1);
    state.state++;
    return MOZQUIC_OK;
  }

  if (event == MOZQUIC_EVENT_NEW_STREAM_DATA) {
    test_assert(state.state >= 2 && state.state <= 4);
    mozquic_stream_t *stream = param;
    state.stream = stream;
    test_assert(mozquic_get_streamid(stream) == 4);

    uint32_t amt = 0;
    unsigned char buf;
    int fin = 0;

    uint32_t code = mozquic_recv(stream, &buf, 1, &amt, &fin);
    test_assert(code == MOZQUIC_OK);
    test_assert((state.state != 4) || fin);
    test_assert(amt || fin);
    state.state++;
    return MOZQUIC_OK;
  }

  if (state.state == 5) {
    char buf[4] = {0x00, 0x01, 0x02, 0x03};
    mozquic_send(state.stream, buf, 4, 1);
    state.state++;
  }

  if (event == MOZQUIC_EVENT_CLOSE_CONNECTION) {
    test_assert(state.state == 6);
    exit (0);
  }

  return MOZQUIC_OK;
}

