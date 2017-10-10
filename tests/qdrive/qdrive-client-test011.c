/* -*- Mode: C++; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*-
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

// -qdrive-test11.. with high drop rate..
// after conn server opens a stream, upon receipt client closes conn
// repeat 100 times.
// then after conn server opens a stream each side sends 250KB and
// when server recvs 250KB it closes stream.. client will exit when
// it gets that close

#include "qdrive-common.h"
#include <stdio.h>
#include <string.h>

static struct closure
{
  int state;
  int amt;
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

  if (event == MOZQUIC_EVENT_CONNECTED) {
    test_assert((state.state & 1) == 0);
    state.state++;
    return MOZQUIC_OK;
  }

  if (event == MOZQUIC_EVENT_NEW_STREAM_DATA) {
    test_assert((state.state & 1) == 1);
    mozquic_stream_t *stream = param;
    test_assert(mozquic_get_streamid(stream) == 2);

    if (state.state < 199) {
      state.state++;
      uint32_t amt = 0;
      unsigned char buf[500];
      int fin = 0;
      uint32_t code = mozquic_recv(stream, buf, sizeof(buf), &amt, &fin);
      test_assert(code == MOZQUIC_OK);
      test_assert(fin);
      test_assert(amt == 0);
      parentConnection = NULL;
      return MOZQUIC_OK;
    }

    if (state.state == 199) {
      unsigned char buf[1000];
      memset(buf,1000,0x11);
      int i = 0;
      for (i = 0; i < 249; i++)
        mozquic_send(stream, buf, 1000, 0);
      mozquic_send(stream, buf, 1000, 1);
      state.state += 2;
    }
  
    unsigned char buf[600];
    int fin = 0;
    uint32_t amt;
    uint32_t code = mozquic_recv(stream, buf, sizeof(buf), &amt, &fin);
    state.amt += amt;
    test_assert(code == MOZQUIC_OK);
    if (fin) {
      test_assert(state.amt == 250000);
      state.state += 2;
    }
    return MOZQUIC_OK;
  }

  if (event == MOZQUIC_EVENT_IO) {
    if (state.state >= 5000) {
      fprintf(stderr,"exit ok\n");
      exit(0);
    }
    if (state.state >= 203) {
      state.state += 2;
    }
    return MOZQUIC_OK;
  }
  
  test_assert(0);
  return MOZQUIC_OK;
}
