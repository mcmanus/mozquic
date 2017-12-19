/* -*- Mode: C++; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*-
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

// -qdrive-test13 pushes 2 bidirectional and 2 unidirectional streams in
// parallel and recvs another 2 bidirectional and 2 unidirectional streams
// in parallel.
// each should be 1K + streamid bytes long. The bidirectional streams are
// sending data in both directions, therefore each side will receive 6 streams.
// when the server has read all 6 streams it sends one more unidirectional
// stream and when the client receives this last stream it closes session.
// Test also checks that a client/server cannot send data on unidirectional
// streams initiated by the peer.


#include "qdrive-common.h"
#include "string.h"

static struct closure
{
  int state;
  mozquic_connection_t *child;
  mozquic_stream_t *streamBidi1;
  mozquic_stream_t *streamBidi2;
  mozquic_stream_t *streamUni1;
  mozquic_stream_t *streamUni2;
  mozquic_stream_t *streamUni3;
  int readBidi1, readBidi2, readBidi3, readBidi4, readUni1, readUni2;
  int finBidi1, finBidi2, finBidi3, finBidi4, finUni1, finUni2;
} state;

void *testGetClosure13()
{
  return &state;
}

static unsigned char gbuf[1024];

void testConfig13(struct mozquic_config_t *_c)
{
  memset(&state, 0, sizeof(state));
  memset(gbuf, 0x26, sizeof(gbuf));
}

int testEvent13(void *closure, uint32_t event, void *param)
{
  test_assert(closure == &state);
  test_assert(event != MOZQUIC_EVENT_ERROR);
  test_assert(event != MOZQUIC_EVENT_RESET_STREAM);

  if (event == MOZQUIC_EVENT_ACCEPT_NEW_CONNECTION) {
    test_assert(state.state == 0);
    state.state++;
    state.child = (mozquic_connection_t *) param;
    mozquic_set_event_callback(state.child, testEvent13);
    mozquic_set_event_callback_closure(state.child, &state);
    return MOZQUIC_OK;
  }

  if (event == MOZQUIC_EVENT_CONNECTED) {
    test_assert(state.state == 1);

    mozquic_start_new_stream(&state.streamBidi1, param, 0, 0, gbuf, sizeof(gbuf), 0);
    mozquic_start_new_stream(&state.streamBidi2, param, 0, 0, gbuf, sizeof(gbuf), 0);

    mozquic_start_new_stream(&state.streamUni1, param, 1, 0, gbuf, sizeof(gbuf), 0);
    mozquic_start_new_stream(&state.streamUni2, param, 1, 0, gbuf, sizeof(gbuf), 0);

    mozquic_send(state.streamBidi1, gbuf, mozquic_get_streamid(state.streamBidi1), 1);
    mozquic_send(state.streamBidi2, gbuf, mozquic_get_streamid(state.streamBidi2), 1);
    mozquic_send(state.streamUni1, gbuf, mozquic_get_streamid(state.streamUni1), 1);
    mozquic_send(state.streamUni2, gbuf, mozquic_get_streamid(state.streamUni2), 1);

    state.state++;
    return MOZQUIC_OK;
  }

  if (event == MOZQUIC_EVENT_NEW_STREAM_DATA) {
    test_assert(state.state == 2 ||
                state.state == 3 ||
                state.state == 4 ||
                state.state == 5 ||
                state.state == 6 ||
                state.state == 7);
    mozquic_stream_t *stream = param;
    test_assert(mozquic_get_streamid(stream) == 4 ||
                mozquic_get_streamid(stream) == 8 ||
                mozquic_get_streamid(stream) == 2 ||
                mozquic_get_streamid(stream) == 6 ||
                mozquic_get_streamid(stream) == 1 ||
                mozquic_get_streamid(stream) == 5);

    uint32_t amt = 0;
    unsigned char buf[760];

    int fin = 0;
    uint32_t code = mozquic_recv(stream, buf, sizeof(buf), &amt, &fin);
    test_assert(code == MOZQUIC_OK);
    int *finptr;

    if(mozquic_get_streamid(stream) == 4) {
      state.readBidi1 += amt;
      finptr = &state.finBidi1;
      if (fin) {
        test_assert(mozquic_send(stream, gbuf, sizeof(gbuf), 0) == MOZQUIC_OK);
        test_assert(mozquic_send(stream, gbuf, mozquic_get_streamid(stream), 1) == MOZQUIC_OK);
      }
    } else if(mozquic_get_streamid(stream) == 8) {
      state.readBidi2 += amt;
      finptr = &state.finBidi2;
      if (fin) {
        test_assert(mozquic_send(stream, gbuf, sizeof(gbuf), 0) == MOZQUIC_OK);
        test_assert(mozquic_send(stream, gbuf, mozquic_get_streamid(stream), 1) == MOZQUIC_OK);
      }
    } else if(mozquic_get_streamid(stream) == 1) {
      state.readBidi3 += amt;
      finptr = &state.finBidi3;
    } else if(mozquic_get_streamid(stream) == 5) {
      state.readBidi4 += amt;
      finptr = &state.finBidi4;
    } else if(mozquic_get_streamid(stream) == 2) {
      state.readUni1 += amt;
      finptr = &state.finUni1;
      test_assert(mozquic_send(stream, gbuf, 2, 0) == MOZQUIC_ERR_IO);
    } else if(mozquic_get_streamid(stream) == 6) {
      state.readUni2 += amt;
      finptr = &state.finUni2;
      test_assert(mozquic_send(stream, gbuf, 6, 0) == MOZQUIC_ERR_IO);
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

  if (state.state == 8) {
    mozquic_start_new_stream(&state.streamUni3, state.child, 1, 0, gbuf, sizeof(gbuf), 0);
    mozquic_send(state.streamUni3, gbuf, mozquic_get_streamid(state.streamUni3), 1);
    state.state++;
  }

  if (event == MOZQUIC_EVENT_CLOSE_CONNECTION) {
    test_assert(state.state == 9);
    exit (0);
  }

  return MOZQUIC_OK;
}
