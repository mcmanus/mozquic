/* -*- Mode: C++; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*-
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#define AMOUNT 1000000

// -qdrive-test11.. with high drop rate..
// after conn open a stream on server. each side sends 1,000,000 bytes.
// client sends 'A', server sends 'B'

#include "qdrive-common.h"
#include "string.h"
#include "stdio.h"

static struct closure
{
  int state;
  int amtR, amtW;
  mozquic_connection_t *conn;
  mozquic_stream_t *stream;
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
    test_assert(state.state == 0);
    state.state++;
    state.conn = param;
    mozquic_set_event_callback(state.conn, testEvent11);
    mozquic_set_event_callback_closure(state.conn, &state);
    return MOZQUIC_OK;
  }

  char buf[500];
  if (event == MOZQUIC_EVENT_CONNECTED) {
    test_assert (state.state == 1);
    test_assert (state.conn == param);
    state.state++;
    memset(buf, 'B', sizeof(buf));
    test_assert(mozquic_start_new_stream(&state.stream, state.conn, 0, 0, buf, sizeof(buf), 0) == MOZQUIC_OK);
    state.amtW += sizeof(buf);
    return MOZQUIC_OK;
  }
      
  if (event == MOZQUIC_EVENT_NEW_STREAM_DATA) {
    test_assert(state.stream == param);
    test_assert(mozquic_get_streamid(state.stream) == 1);
    test_assert (state.state == 2);

    uint32_t amt = 0;
    int fin = 0;
    uint32_t code = mozquic_recv(state.stream, buf, sizeof(buf), &amt, &fin);
    test_assert(code == MOZQUIC_OK);
    test_assert(!fin);
    for (unsigned int i=0; i < amt; i++) {
      test_assert(buf[i] == 'A');
    }
    state.amtR += amt;
    test_assert( state.amtR <= AMOUNT);
  }

  if (state.state == 2) {
    if (state.amtW < AMOUNT) {
      memset(buf, 'B', sizeof(buf));
      test_assert(mozquic_send(state.stream, buf, sizeof(buf), 0) == MOZQUIC_OK);
      state.amtW += sizeof(buf);
      test_assert(state.amtW <= AMOUNT);
    }
    if (state.amtR == AMOUNT && state.amtW == AMOUNT &&
        mozquic_get_allacked(state.conn)) {
      state.state++;
      mozquic_destroy_connection(state.conn);
      state.conn = NULL;
    }
  }

  if (state.state > 2) {
    state.state++;
  }

  if (state.state == 20) {
      fprintf(stderr,"server OK\n");
      exit(0);
  }

  return MOZQUIC_OK;
}

