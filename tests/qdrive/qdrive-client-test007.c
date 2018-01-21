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
#include <stdio.h>
#include <string.h>

static struct closure
{
  int state;
  uint64_t time0;
  uint64_t time1;
  uint64_t time2;
  uint32_t ctr;
  mozquic_stream_t *stream1;
  mozquic_stream_t *stream2;
  int bpOn;
} state;

void *testGetClosure7()
{
  return &state;
}

void testConfig7(struct mozquic_config_t *_c)
{
  test_assert(mozquic_unstable_api1(_c, "streamWindow", 3750, 0) == MOZQUIC_OK);
  test_assert(mozquic_unstable_api1(_c, "connWindow", 8192, 0) == MOZQUIC_OK);
  memset(&state, 0, sizeof(state));
}

int testEvent7(void *closure, uint32_t event, void *param)
{
  test_assert(closure == &state);
  test_assert(event != MOZQUIC_EVENT_CLOSE_CONNECTION);
  test_assert(event != MOZQUIC_EVENT_ERROR);

  if (!state.time0) {
    test_assert(state.state == 0);
    state.state++;
    state.time0 = Timestamp();
  }

  if (event == MOZQUIC_EVENT_CONNECTED) {
    test_assert(state.state == 1);
    state.state++;
    return MOZQUIC_OK;
  }

  if (state.state == 2) {
    unsigned char buf = 1;
    mozquic_start_new_stream(&state.stream1, param, 0, 0, &buf, 1, 0);
    state.state++;
    return MOZQUIC_OK;
  }

  if (event == MOZQUIC_EVENT_NEW_STREAM_DATA) {
    test_assert(state.state == 3 ||
                state.state == 5);
    test_assert(state.ctr < 16000);
    mozquic_stream_t *stream = param;
    char buf[32000];
    uint32_t read = 0;
    int fin = 0;
    uint32_t code = mozquic_recv(stream, buf, sizeof(buf), &read, &fin);
    test_assert(code == MOZQUIC_OK);
    test_assert(!fin);
    test_assert(buf[0] == state.state);
    state.ctr += read;
    fprintf(stderr,"test7 client read %d now at %d state %d\n",
            read, state.ctr, state.state);
    test_assert(state.ctr <= 16000);
    if (state.ctr == 16000) {
      if (state.state == 3) {
        state.time1 = Timestamp();
      } else {
        state.time2 = Timestamp();
      }
      state.state++;
    }
    return MOZQUIC_OK;
  }

  if (state.state == 4) {
    test_assert(state.ctr == 16000);
    test_assert(state.time1 > state.time0);
    unsigned char buf = 2;
    state.ctr = 0;
    state.bpOn = 1;
    mozquic_start_backpressure(parentConnection);
    mozquic_start_new_stream(&state.stream2, param, 0, 0, &buf, 1, 0);
    state.state++;
    return MOZQUIC_OK;
  }

  if (state.bpOn) {
    test_assert(state.state >= 5);
    if (Timestamp() - state.time1 > 1000) {
      test_assert(1);
      state.bpOn = 0;
      mozquic_release_backpressure(parentConnection);
    }
  }

  if (state.state == 6) {
    test_assert(state.ctr == 16000);
    test_assert(state.time2 > state.time1);
    // todo flowcontrol timings
    state.state++;
    return MOZQUIC_OK;
  }

  if (state.state == 7) {
    test_assert(1);
    fprintf(stderr,"test7 client timing1 %lld timing2 %lld\n",
            state.time1 - state.time0, state.time2 - state.time1);
    // assert that the backpressure version was at least 500ms slower
    // than the non backpressure version
    test_assert((state.time2 - state.time1) - (state.time1 - state.time0) > 500);

    mozquic_destroy_connection(parentConnection);
    fprintf(stderr,"exit ok\n");
    exit(0);
  }

  return MOZQUIC_OK;
}
