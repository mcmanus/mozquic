/* -*- Mode: C++; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*-
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

// -qdrive-test1

#include "qdrive-common.h"
#include "string.h"

static struct closure
{
  int state;
  mozquic_connection_t *child;
  mozquic_stream_t *stream;
  uint32_t amt;
} state;

void *testGetClosure11()
{
  return &state;
}

void testConfig11(struct mozquic_config_t *_c)
{
  memset(&state, 0, sizeof(state));
  test_assert(mozquic_unstable_api1(_c, "dropRate", 3, 0) == MOZQUIC_OK);
}

int testEvent11(void *closure, uint32_t event, void *param)
{
  test_assert(closure == &state);
  test_assert(event != MOZQUIC_EVENT_ERROR);
  test_assert(event != MOZQUIC_EVENT_RESET_STREAM);

  if (event == MOZQUIC_EVENT_ACCEPT_NEW_CONNECTION) {
    if ((state.state & 3) != 0) {
      test_assert((state.state & 3) == 2); // close conn is not reliable
      test_assert(state.state < 397);
      state.state++;
      state.state++;
    }
    test_assert((state.state & 3) == 0);
    
    state.state++;
    state.child = (mozquic_connection_t *) param;
    mozquic_set_event_callback(state.child, testEvent11);
    mozquic_set_event_callback_closure(state.child, &state);
    return MOZQUIC_OK;
  }

  if (event == MOZQUIC_EVENT_CONNECTED) {
    test_assert((state.state & 3) == 1);
    test_assert (state.state <= 397);
    test_assert(mozquic_start_new_stream(&state.stream, param, NULL, 0, (state.state != 397)) == MOZQUIC_OK);
    if (state.state == 397) {
      unsigned char buf[1000];
      memset(buf,1000,0x22);
      int i = 0;
      for (i = 0; i < 250; i++)
        mozquic_send(state.stream, buf, 1000, 0);
    }
    state.state++;
    return MOZQUIC_OK;
  }

  if (event == MOZQUIC_EVENT_CLOSE_CONNECTION) {
    test_assert((state.state & 3) == 2);
    test_assert(state.state < 397);
    state.state++;
    state.state++;
    return MOZQUIC_OK;
  }
      
  if (event == MOZQUIC_EVENT_NEW_STREAM_DATA) {
    test_assert(state.state == 398);
    mozquic_stream_t *stream = param;
    state.stream = stream;
    test_assert(mozquic_get_streamid(stream) == 2);

    uint32_t amt = 0;
    unsigned char buf;
    int fin = 0;

    uint32_t code = mozquic_recv(stream, &buf, 1, &amt, &fin);
    test_assert(code == MOZQUIC_OK);
    state.amt += amt;
    if (fin) {
      test_assert(state.amt == 250000);
      mozquic_send(state.stream, NULL, 0, 1);
      state.state++;
    }
    return MOZQUIC_OK;
  }
  if (state.state == 399) {
    if (mozquic_get_allacked(state.child)) {
      exit (0);
    }
    return MOZQUIC_OK;
  }
  
  test_assert(event == MOZQUIC_EVENT_IO);
  return MOZQUIC_OK;
}

