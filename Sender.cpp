/* -*- Mode: C++; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*-
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include <assert.h>

#include "Logging.h"
#include "MozQuicInternal.h"
#include "Sender.h"

namespace mozquic {

#define SenderLog1(...) Log::sDoLog(Log::SENDER, 1, mMozQuic, __VA_ARGS__);
#define SenderLog2(...) Log::sDoLog(Log::SENDER, 2, mMozQuic, __VA_ARGS__);
#define SenderLog3(...) Log::sDoLog(Log::SENDER, 3, mMozQuic, __VA_ARGS__);
#define SenderLog4(...) Log::sDoLog(Log::SENDER, 4, mMozQuic, __VA_ARGS__);
#define SenderLog5(...) Log::sDoLog(Log::SENDER, 5, mMozQuic, __VA_ARGS__);
#define SenderLog6(...) Log::sDoLog(Log::SENDER, 6, mMozQuic, __VA_ARGS__);
#define SenderLog7(...) Log::sDoLog(Log::SENDER, 7, mMozQuic, __VA_ARGS__);
#define SenderLog8(...) Log::sDoLog(Log::SENDER, 8, mMozQuic, __VA_ARGS__);
#define SenderLog9(...) Log::sDoLog(Log::SENDER, 9, mMozQuic, __VA_ARGS__);
#define SenderLog10(...) Log::sDoLog(Log::SENDER, 10, mMozQuic, __VA_ARGS__);

Sender::Sender(MozQuic *session)
  : mMozQuic(session)
  , mSmoothedRTT(100)
  , mRTTVar(50)
  , mDropRate(0)
  , mCCState(false)
  , mPacingTicker(0)
  , mWindow(kDefaultMSS * 10) // bytes
  , mWindowUsed(0)
  , mUnPacedPacketCredits(10)
  , mLastSend(0)
  , mSSThresh(0xffffffff)
  , mEndOfRecovery(0)
{
}

void
Sender::Connected()
{
  SenderLog5("Connected - slow start\n");
  mCCState = true;
}
  
bool
Sender::CanSendNow(uint64_t amt, bool zeroRtt)
{
  // 4.6. Pacing Rate
  
  // The pacing rate is a function of the mode, the congestion window,
  // and the smoothed rtt. Specifically, the pacing rate is 2 times
  // the congestion window divided by the smoothed RTT during slow
  // start and 1.25 times the congestion window divided by the
  // smoothed RTT during congestion avoidance. In order to fairly
  // compete with flows that are not pacing, it is recommended to not
  // pace the first 10 sent packets when exiting quiescence.

  mPacingTicker = 0;
  if (mCCState == false) {
    if (!zeroRtt) {
      return true;
    }
    if ((mWindowUsed + amt) < mWindow) {
      return true;
    } else {
      return false;
    }
  }
  if (mWindowUsed < mWindow) {
    // window ok. check pacing.
    if (mUnPacedPacketCredits) {
      return true;
    }
    uint64_t window;
    if (mWindow < mSSThresh) { // slowstart
      window = 2 * mWindow;
    } else {
      window = mWindow + (mWindow >> 2);
    }
    uint64_t rate = window / mSmoothedRTT; // bytes per ms
    if (rate < 15) { // min
      rate = 15;
    }
    uint64_t spaceNeeded = amt / rate; // ms
    if (spaceNeeded > 25) {
      spaceNeeded = 25; // max gap
    }
    assert(MozQuic::Timestamp() >= mLastSend);
    uint64_t actualSpace = MozQuic::Timestamp() - mLastSend;
    if (actualSpace < spaceNeeded) {
      SenderLog8("Pacing requires %ld ms gap (have %ld)\n", spaceNeeded, actualSpace);
      mPacingTicker = mLastSend + spaceNeeded;
      return false;
    }
    return true;
  }
  return false;
}

uint32_t
Sender::Tick(const uint64_t now)
{
  if (mQueue.empty()) {
    return MOZQUIC_OK;
  }
  
  if ((now < mPacingTicker) || !CanSendNow(mQueue.front()->mLen, false)) {
    return MOZQUIC_OK;
  }

  do {
    mLastSend = MozQuic::Timestamp();
    mWindowUsed += mQueue.front()->mBareAck ? 0 : mQueue.front()->mLen;
    if (mUnPacedPacketCredits) {
      mUnPacedPacketCredits--;
    }
    SenderLog7("Packet Sent from Queue Tick #%lX %ld (now %ld/%ld)\n",
               mQueue.front()->mPacketNum,
               mQueue.front()->mLen, mWindowUsed, mWindow);
    mMozQuic->RealTransmit(mQueue.front()->mData.get(),
                           mQueue.front()->mLen,
                           mQueue.front()->mExplicitPeer ? &(mQueue.front()->mSockAddr) : nullptr);
    mQueue.pop_front();
    
  } while (!mQueue.empty() && CanSendNow(mQueue.front()->mLen, false));
  return MOZQUIC_OK;
}

uint32_t
Sender::Transmit(uint64_t packetNumber, bool bareAck, bool zeroRTT,
                 const unsigned char *pkt, uint32_t len, struct sockaddr_in *explicitPeer)
{
  // in order to queue we need to copy the packet, as its probably on the stack of
  // the caller. So avoid that if possible.
  assert (mQueue.empty() || (mCCState == true));

  if (mDropRate && ((random() % 100) <  mDropRate)) {
    SenderLog2("Transmit dropped due to drop rate\n");
    return MOZQUIC_OK;
  }

  SenderLog8("Sender::Transmit %ld %d\n", len, bareAck);
  bool canSendNow = zeroRTT || CanSendNow(len, zeroRTT) || bareAck; // Do not queue zeroRTT packets.
  if (mQueue.empty() && canSendNow) {
    mLastSend = MozQuic::Timestamp();
    mWindowUsed += bareAck ? 0 : len;
    if (mUnPacedPacketCredits) {
      mUnPacedPacketCredits--;
    }
    SenderLog7("Packet Sent Without Queue #%lX %d now (%ld/%ld)\n",
               packetNumber, len, mWindowUsed, mWindow);
    return mMozQuic->RealTransmit(pkt, len, explicitPeer);
  }
  mQueue.emplace_back(new BufferedPacket(pkt, len, explicitPeer, packetNumber, bareAck));
  SenderLog7("Packet Queued %lX (gateok=%d)\n", packetNumber, canSendNow);
  if (!canSendNow) {
    return MOZQUIC_OK;
  }
  do {
    mLastSend = MozQuic::Timestamp();
    mWindowUsed += bareAck ? 0 : mQueue.front()->mLen;
    if (mUnPacedPacketCredits) {
      mUnPacedPacketCredits--;
    }
    SenderLog7("Packet Sent from Queue #%lX %d now (%ld/%ld)\n",
               mQueue.front()->mPacketNum,
               mQueue.front()->mLen, mWindowUsed, mWindow);
    mMozQuic->RealTransmit(mQueue.front()->mData.get(),
                           mQueue.front()->mLen,
                           mQueue.front()->mExplicitPeer ? &(mQueue.front()->mSockAddr) : nullptr);
    mQueue.pop_front();
    
  } while (!mQueue.empty() && (CanSendNow(mQueue.front()->mLen, false) || mQueue.front()->mBareAck));
  
  return MOZQUIC_OK;
}

void
Sender::Ack(uint64_t packetNumber, uint32_t bytes)
{
  if (mWindowUsed >= bytes) {
    mWindowUsed -= bytes;
  } else {
    mWindowUsed = 0;
  }

  if (packetNumber < mEndOfRecovery) {
    SenderLog6("Acknowledgment of %ld (now %ld/%ld) [recovery]\n",
               bytes, mWindowUsed, mWindow);
    return;
  }

  if (mEndOfRecovery) {
    // leaving recovery
    mEndOfRecovery = 0;
    SenderLog5("leaving recovery\n");
    mUnPacedPacketCredits = 10;
  }

  if (mWindow < mSSThresh) {
    mWindow += bytes;
  } else {
    mWindow = kDefaultMSS * bytes / mWindow;
  }
  if (mWindow < kMinWindow) {
    mWindow = kMinWindow;
  }
  
  SenderLog6("Acknowledgment [%lX] %lu (now %lu/%lu) ssthresh=%lu\n",
             packetNumber, bytes, mWindowUsed, mWindow, mSSThresh);
}

void
Sender::ReportLoss(uint64_t packetNumber, uint32_t bytes)
{
  SenderLog6("Report Loss [%lX] %lu endRecovery=%lX\n",
             packetNumber, bytes, mEndOfRecovery);

  if (mWindowUsed >= bytes) {
    mWindowUsed -= bytes;
  } else {
    mWindowUsed = 0;
  }

  if (mEndOfRecovery < packetNumber) {
    mEndOfRecovery = packetNumber;
    mWindow = mWindow >> 1;
    if (mWindow < kMinWindow) {
      mWindow = kMinWindow;
    }
    mSSThresh = mWindow;
    SenderLog6("Report Loss (now %lu/%lu) ssthresh=%lu\n",
               mWindowUsed, mWindow, mSSThresh);
  }
}

void
Sender::Dismissed0RTTPackets(uint32_t bytes)
{
  if (mWindowUsed >= bytes) {
    mWindowUsed -= bytes;
  } else {
    mWindowUsed = 0;
  }
}

void
Sender::RTTSample(uint64_t xmit, uint64_t delay)
{
  uint64_t now = MozQuic::Timestamp();
  assert(now >= xmit);
  uint64_t rtt = now - xmit;
  if (rtt < delay) {
    return;
  }
  rtt -= delay;
  rtt = std::min(rtt, 0xffffUL);

  if (mCCState) {
    uint64_t diff = (mSmoothedRTT > rtt) ?
      (mSmoothedRTT - rtt) : (rtt - mSmoothedRTT);
    mRTTVar = (mRTTVar - (mRTTVar >> 2)) + (diff >> 2);
    mSmoothedRTT = (mSmoothedRTT - (mSmoothedRTT >> 3)) + (rtt >> 3);
  } else {
    mRTTVar = rtt >> 1;
    mSmoothedRTT = rtt;
  }
  mSmoothedRTT = std::max((uint16_t)1, mSmoothedRTT);
  mSmoothedRTT = std::max((uint16_t)1, mRTTVar);

  SenderLog6("New RTT Sample %u now smoothed %u rttvar %u\n",
             rtt, mSmoothedRTT, mRTTVar);
}

}
