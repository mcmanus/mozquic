/* -*- Mode: C++; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*-
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

// -qdrive-test8 pushes 2 streams in parallel and
// recvs another 2 in parallel. each should be 250K + streamid
// long. when server has done its reading it sends a 3rd stream
// when client has read all 3 streams it closes session

#include "qdrive-common.h"
#include "string.h"
#include <stdio.h>

static struct closure
{
  int state;
  mozquic_connection_t *child;
  mozquic_stream_t *stream1;
  mozquic_stream_t *stream2;
  mozquic_stream_t *stream3;
  int read1, read2;
  int fin1, fin2;
  mozquic_connection_t *conn;
} state;

void *testGetClosure8()
{
  return &state;
}

static unsigned char gbuf[1024];

void testConfig8(struct mozquic_config_t *_c)
{
  memset(&state, 0, sizeof(state));
  memset(gbuf, 0x22, sizeof(gbuf));
}

int testEvent8(void *closure, uint32_t event, void *param)
{
  test_assert(closure == &state);
  test_assert(event != MOZQUIC_EVENT_ERROR);
  test_assert(event != MOZQUIC_EVENT_RESET_STREAM);

  if (event == MOZQUIC_EVENT_ACCEPT_NEW_CONNECTION) {
    test_assert(state.state == 0);
    state.state++;
    state.child = (mozquic_connection_t *) param;
    mozquic_set_event_callback(state.child, testEvent8);
    mozquic_set_event_callback_closure(state.child, &state);
    return MOZQUIC_OK;
  }

  if (event == MOZQUIC_EVENT_CONNECTED) {
    test_assert(state.state == 1);
    test_assert(state.child == param);
    state.conn = param;
    
    mozquic_start_new_stream(&state.stream1, param, 0, 0, gbuf, sizeof(gbuf), 0);
    mozquic_start_new_stream(&state.stream2, param, 0, 0, gbuf, sizeof(gbuf), 0);
    for (int j=1; j<250; j++) {
      mozquic_send(state.stream1, gbuf, sizeof(gbuf), 0);
      mozquic_send(state.stream2, gbuf, sizeof(gbuf), 0);
    }
    mozquic_send(state.stream1, gbuf, mozquic_get_streamid(state.stream1), 1);
    mozquic_send(state.stream2, gbuf, mozquic_get_streamid(state.stream2), 1);
    state.state++;
    return MOZQUIC_OK;
  }

  if (event == MOZQUIC_EVENT_NEW_STREAM_DATA) {
    test_assert(state.state == 2 ||
                state.state == 3);
    mozquic_stream_t *stream = param;
    test_assert(mozquic_get_streamid(stream) == 4 ||
                mozquic_get_streamid(stream) == 8);

    uint32_t amt = 0;
    unsigned char buf[760];

    int fin = 0;
    uint32_t code = mozquic_recv(stream, buf, sizeof(buf), &amt, &fin);
    test_assert(code == MOZQUIC_OK);
    int *finptr;
    if(mozquic_get_streamid(stream) == 4) {
      state.read1 += amt;
      finptr = &state.fin1;
    } else {
      state.read2 += amt;
      finptr = &state.fin2;
    }
    if (fin) {
      test_assert(!(*finptr));
      if (!(*finptr)) {
        state.state++;
      }
      *finptr = 1;
    }

    return MOZQUIC_OK;
  }

  if (state.state == 4) {
    mozquic_start_new_stream(&state.stream3, state.child, 0, 0, gbuf, sizeof(gbuf), 1);
    state.state++;
  }
  if (state.state >= 5) {
    state.state++;
  }
  if (state.state >= 20 &&
      mozquic_get_allacked(state.conn)) {
    fprintf(stderr,"exit ok\n");
    exit (0);
  }

  return MOZQUIC_OK;
}

