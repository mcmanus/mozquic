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
  plainPkt[used++] = FRAME_TYPE_PING;
  plainPkt[used++] = 0; // data len

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
  uint32_t used = 0;
  mPMTUDTarget = (kMaxMTU < mMaxPacketConfig) ? kMaxMTU : mMaxPacketConfig;

  CreateShortPacketHeader(plainPkt, mPMTUDTarget - kTagLen, used);
  uint32_t headerLen = used;
  plainPkt[used++] = FRAME_TYPE_PING;
  plainPkt[used++] = 0; // datalen
  uint32_t room = mPMTUDTarget - used - kTagLen;
  memset(plainPkt + used, FRAME_TYPE_PADDING, room);
  used += room;

  ConnectionLog5("pmtud1: %d MTU test started\n", mPMTUDTarget);
  mPMTUD1PacketNumber = mNextTransmitPacketNumber;
  mPMTUD1Deadline = Timestamp() + 3000; // 3 seconds to ack the ping
  uint32_t bytesOut = 0;
  if (ProtectedTransmit(plainPkt, headerLen,
                        plainPkt + headerLen, room + 1,
                        mPMTUDTarget - headerLen - kTagLen, false, true, false,
                        mPMTUDTarget, &bytesOut) != MOZQUIC_OK) {
    mPMTUD1PacketNumber = 0;
  }
  else {
    mStreamState->TrackPacket(mPMTUD1PacketNumber, bytesOut);
  }
}

void
MozQuic::MakePong(uint8_t len, const unsigned char *data)
{
  ConnectionLog5("MakePong %d\n", len);
  assert(len);
  std::unique_ptr<ReliableData> tmp(new ReliableData(0, 0, data, len, 0));
  tmp->MakePong();
  mStreamState->ConnectionWrite(tmp);
}

uint32_t
MozQuic::MakePingWithData(uint8_t len, const unsigned char *data)
{
  ConnectionLog5("MakePingWithData %d\n", len);
  assert(len);
  std::unique_ptr<ReliableData> tmp(new ReliableData(0, 0, data, len, 0));
  tmp->MakePing();
  mStreamState->ConnectionWrite(tmp);
  return MOZQUIC_OK;
}

uint32_t
MozQuic::HandlePingFrame(FrameHeaderData *result, bool fromCleartext,
                         const unsigned char *pkt, const unsigned char *endpkt,
                         uint32_t &_ptr)
{
  if (fromCleartext) {
    ConnectionLog1("ping frames not allowed in cleartext\n");
    return MOZQUIC_ERR_GENERAL;
  }

  if (result->u.mPing.mDataLen) {
    assert(pkt + _ptr + result->u.mPing.mDataLen <= endpkt); // runtime checked during frame parse
    MakePong(result->u.mPing.mDataLen, pkt + _ptr);
    _ptr += result->u.mPing.mDataLen;
  }
  return MOZQUIC_OK;
}
  

uint32_t
MozQuic::HandlePongFrame(FrameHeaderData *result, bool fromCleartext,
                         const unsigned char *pkt, const unsigned char *endpkt,
                         uint32_t &_ptr)
{
  if (fromCleartext) {
    ConnectionLog1("pong frames not allowed in cleartext\n");
    return MOZQUIC_ERR_GENERAL;
  }

  if (result->u.mPong.mDataLen) {
    assert(pkt + _ptr + result->u.mPong.mDataLen <= endpkt); // runtime checked during frame parse

    struct mozquic_eventdata_raw raw;
    raw.data = pkt + _ptr;
    raw.len = result->u.mPong.mDataLen;
    mConnEventCB(mClosure, MOZQUIC_EVENT_PONG, &raw);

    _ptr += result->u.mPong.mDataLen;
    return MOZQUIC_OK;
  }
  Shutdown(STREAM_ID_ERROR, "unsolicited pong");
  RaiseError(MOZQUIC_ERR_GENERAL, "unsolicited pong\n");
  return MOZQUIC_ERR_GENERAL;
}

void
MozQuic::CompletePMTUD1()
{
  assert (mPMTUD1PacketNumber);
  ConnectionLog5("pmtud1: %d MTU CONFIRMED.\n", mPMTUDTarget);
  mPMTUD1PacketNumber = 0;
  mPMTUD1Deadline = 0;
  mMTU = mPMTUDTarget;
}

void
MozQuic::AbortPMTUD1()
{
  assert (mPMTUD1PacketNumber);
  ConnectionLog1("pmtud1: %d MTU CHECK Failed.\n", mPMTUDTarget);
  mPMTUD1PacketNumber = 0;
  mPMTUD1Deadline = 0;
}

}

