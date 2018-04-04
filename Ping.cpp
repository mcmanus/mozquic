/* -*- Mode: C++; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*-
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "Logging.h"
#include "MozQuic.h"
#include "MozQuicInternal.h"
#include "Streams.h"

#include <assert.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>

namespace mozquic  {
  
uint32_t
MozQuic::CheckPeer(uint32_t deadline)
{
  if (mPingDeadline->Armed()) {
    return MOZQUIC_OK;
  }
  if ((mConnectionState != CLIENT_STATE_CONNECTED) &&
      (mConnectionState != SERVER_STATE_CONNECTED)) {
    ConnectionLog1("check peer not connected\n");
    return MOZQUIC_ERR_GENERAL;
  }

  mPingDeadline->Arm(deadline);

  assert(mMTU <= kMaxMTU);
  unsigned char plainPkt[kMaxMTU];
  uint32_t used = 0;

  CreateShortPacketHeader(plainPkt, mMTU - kTagLen, used);
  uint32_t headerLen = used;
  plainPkt[used++] = FRAME_TYPE_PING;

  return ProtectedTransmit(plainPkt, headerLen, plainPkt + headerLen, FRAME_TYPE_PING_LENGTH,
                           mMTU - headerLen - kTagLen, true, true);
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
  if (mMTU >= mMaxPacketConfig) {
    return;
  }
  unsigned char plainPkt[kMaxMTU];
  mPMTUDTarget = (kMaxMTU < mMaxPacketConfig) ? kMaxMTU : mMaxPacketConfig;

  uint32_t headerLen;
  CreateShortPacketHeader(plainPkt, mPMTUDTarget - kTagLen, headerLen);
  uint32_t padAmt = mPMTUDTarget - headerLen - kTagLen;
  memset(plainPkt + headerLen, FRAME_TYPE_PADDING, padAmt);
  plainPkt[headerLen] = FRAME_TYPE_PING; // make the first frame a ping frame

  ConnectionLog5("pmtud1: %d MTU test started\n", mPMTUDTarget);
  mPMTUD1PacketNumber = mNextTransmitPacketNumber;
  mPMTUD1Deadline->Arm(3000); // 3 seconds to ack the ping

  uint32_t bytesOut = 0;
  if (ProtectedTransmit(plainPkt, headerLen,
                        plainPkt + headerLen, padAmt, kMaxMTU,
                        false, true, false,
                        mPMTUDTarget, &bytesOut) != MOZQUIC_OK) {
    mPMTUD1PacketNumber = 0;
  } else {
    mStreamState->TrackPacket(mPMTUD1PacketNumber, bytesOut);
  }
}
 
void
MozQuic::CompletePMTUD1()
{
  assert (mPMTUD1PacketNumber);
  ConnectionLog5("pmtud1: %d MTU CONFIRMED.\n", mPMTUDTarget);
  mPMTUD1Deadline->Cancel();
  mMTU = mPMTUDTarget;
}

void
MozQuic::AbortPMTUD1()
{
  assert (mPMTUD1PacketNumber);
  ConnectionLog1("pmtud1: %d MTU CHECK Failed.\n", mPMTUDTarget);
  mPMTUD1PacketNumber = 0;
  mPMTUD1Deadline->Cancel();
}

}

