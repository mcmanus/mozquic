/* -*- Mode: C++; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*-
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

// -qdrive-test9 client sends 3 bytes and fin on stream create
// server replies with 4 bytes and fin. (tests fin on create)

#include "qdrive-common.h"
#include <stdio.h>
#include <string.h>

static struct closure
{
  int state;
  int amt;
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
  test_assert(event != MOZQUIC_EVENT_CLOSE_CONNECTION);
  test_assert(event != MOZQUIC_EVENT_ERROR);

  if (event == MOZQUIC_EVENT_CONNECTED) {
    test_assert(state.state == 0);
    state.state++;
    return MOZQUIC_OK;
  }

  if (state.state == 1) {
    char buf[3] = { 0x10, 0x11, 0x12 };

    mozquic_start_new_stream(&state.stream, param, 0, 0, buf, 3, 1);
    state.state++;
    return MOZQUIC_OK;
  }

  if (event == MOZQUIC_EVENT_NEW_STREAM_DATA) {
    test_assert(state.state == 2);
    mozquic_stream_t *stream = param;
    test_assert(mozquic_get_streamid(stream) == 4);
    
    uint32_t amt = 0;
    unsigned char buf[500];
    int fin = 0;
    uint32_t code = mozquic_recv(stream, buf, sizeof(buf), &amt, &fin);
    test_assert(code == MOZQUIC_OK);
    state.amt += amt;
    if (fin) {
      test_assert(state.amt == 4);
      state.state++;
    }
    return MOZQUIC_OK;
  }
  
  if (state.state == 3) {
    mozquic_destroy_connection(parentConnection);
    fprintf(stderr,"exit ok\n");
    exit(0);
  }

  return MOZQUIC_OK;
}
