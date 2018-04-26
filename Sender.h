/* -*- Mode: C++; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*-
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#pragma once

#include <stdint.h>
#include "Timer.h"

namespace mozquic {

class BufferedPacket
{
  // todo a version that creates this in one allocation
public:

  BufferedPacket(const unsigned char *pkt, uint32_t pktSize, uint32_t headerSize,
                 uint64_t packetNumber)
    : mData(new unsigned char[pktSize])
    , mLen(pktSize)
    , mHeaderSize(headerSize)
    , mPacketNumber(packetNumber)
    , mExplicitPeer(false)
    , mBareAck(false)
  {
    memcpy((void *)mData.get(), pkt, mLen);
  }

  BufferedPacket(const unsigned char *pkt, uint32_t pktSize,
                 const struct sockaddr *sin, size_t soSin,
                 uint64_t packetNumber, bool bareAck);

  ~BufferedPacket()
  {
  }

  std::unique_ptr<const unsigned char []>mData;
  uint32_t mLen;
  uint32_t mHeaderSize;
  uint32_t mPacketNumber;
  bool     mExplicitPeer;
  bool     mBareAck;
  struct sockaddr_in6 mSockAddr;
};

const uint32_t kDefaultMSS = 1460;
const uint32_t kMinWindow = 2 * kDefaultMSS;

class Sender
 : public TimerNotification
{
public:
  Sender(MozQuic *session);
  virtual ~Sender() {}
  void Alarm(Timer *) override;

  uint32_t Transmit(uint64_t packetNumber, bool bareAck, bool zeroRTT, bool queueOnly,
                    const unsigned char *, uint32_t len, const struct sockaddr *peer);
  void RTTSample(uint64_t xmit, uint64_t delay);
  void Ack(uint64_t packetNumber, uint32_t packetLength);
  void ReportLoss(uint64_t packetNumber, uint32_t packetLength);
  void Dismissed0RTTPackets(uint32_t bytes);
  void Flush();
  void Connected();
  bool CanSendNow(uint64_t amt, bool zeroRtt);
  uint16_t SmoothedRTT() { return mSmoothedRTT; }
  uint16_t RTTVar() { return mRTTVar; }
  
  bool EmptyQueue() 
  {
    return mQueue.empty();
  }

  void EstablishPTOTimer();

private:
  
  uint64_t PTODeadline();
  uint64_t RTODeadline(uint32_t numTimesFired);
  void SendProbeData(bool fromRTO);
  uint32_t SendOne(bool fromRTO);
  void     LossTimerTick(const uint64_t now);

  MozQuic *mMozQuic;
  std::list<std::unique_ptr<BufferedPacket>> mQueue;
  uint16_t mSmoothedRTT;
  uint16_t mRTTVar;

  bool mCCState;
  std::unique_ptr<Timer> mPacingTimer;

  // 0 is no unacked data no timer set
  // 1 tlp set no expirations yet
  // 2 tlp set one tlp probe sent
  // 3 rto set two tlp probes sent
  // 4 rto set N-3 rto expirations with N-3 rto retrans
  uint32_t mTimerState;
  std::unique_ptr<Timer> mDeadline;

  uint64_t mMaxAckDelay;
  uint64_t mMinRTT;

  uint64_t mWindow; // bytes
  uint64_t mWindowUsed; // bytes

  uint64_t mUnPacedPacketCredits;
  uint64_t mLastSend;
  uint64_t mSSThresh;
  uint64_t mEndOfRecovery; // packet #
};

} //namespace
