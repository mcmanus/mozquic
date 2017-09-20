/* -*- Mode: C++; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*-
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "Logging.h"
#include "MozQuic.h"
#include "MozQuicInternal.h"

#include <assert.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>

namespace mozquic  {
  
uint32_t
MozQuic::CheckPeer(uint32_t deadline)
{
  if (mPingDeadline) {
    return MOZQUIC_OK;
  }
  if ((mConnectionState != CLIENT_STATE_CONNECTED) &&
      (mConnectionState != SERVER_STATE_CONNECTED)) {
    ConnectionLog1("check peer not connected\n");
    return MOZQUIC_ERR_GENERAL;
  }

  mPingDeadline = Timestamp() + deadline;

  assert(mMTU <= kMaxMTU);
  unsigned char plainPkt[kMaxMTU];
  uint32_t used = 0;

  CreateShortPacketHeader(plainPkt, mMTU - kTagLen, used);
  uint32_t headerLen = used;
  plainPkt[used] = FRAME_TYPE_PING;
  used++;

  return ProtectedTransmit(plainPkt, headerLen, plainPkt + headerLen, 1,
                           mMTU - headerLen - kTagLen, true);
}

void
MozQuic::StartPMTUD1()
{
  if (mPMTUD1PacketNumber) {
    return;
  }
  if ((mConnectionState != CLIENT_STATE_CONNECTED) &&
      (mConnectionState != SERVER_STATE_CONNECTED)) {
    return;
  }

  if (mMTU >= kMaxMTU) {
    return;
  }
  unsigned char plainPkt[kMaxMTU];
  uint32_t used = 0;

  CreateShortPacketHeader(plainPkt, kMaxMTU - kTagLen, used);
  uint32_t headerLen = used;
  plainPkt[used] = FRAME_TYPE_PING;
  used++;
  uint32_t room = kMaxMTU - used - kTagLen;
  memset(plainPkt + used, FRAME_TYPE_PADDING, room);
  used += room;

  ConnectionLog5("pmtud1: %d MTU test started\n", kMaxMTU);
  mPMTUD1PacketNumber = mNextTransmitPacketNumber;
  mPMTUD1Deadline = Timestamp() + 3000; // 3 seconds to ack the ping
  if (ProtectedTransmit(plainPkt, headerLen,
                        plainPkt + headerLen, room + 1,
                        kMaxMTU - headerLen - kTagLen, false, kMaxMTU) != MOZQUIC_OK) {
    mPMTUD1PacketNumber = 0;
  }
}

void
MozQuic::CompletePMTUD1()
{
  assert (mPMTUD1PacketNumber);
  ConnectionLog5("pmtud1: %d MTU CONFIRMED.\n", kMaxMTU);
  mPMTUD1PacketNumber = 0;
  mPMTUD1Deadline = 0;
  mMTU = kMaxMTU;
}

void
MozQuic::AbortPMTUD1()
{
  assert (mPMTUD1PacketNumber);
  ConnectionLog1("pmtud1: %d MTU CHECK Failed.\n", kMaxMTU);
  mPMTUD1PacketNumber = 0;
  mPMTUD1Deadline = 0;
}

}

