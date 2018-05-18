/* -*- Mode: C++; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*-
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include <assert.h>

#include "Logging.h"
#include "MozQuicInternal.h"
#include "Sender.h"

#include <algorithm>

namespace mozquic {

static const uint64_t kMinRTO = 50;
static const uint64_t kMinTLP = 10;
static const uint64_t kMaxAckDelay = 250;

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
  , mCCState(false)
  , mPacingTimer(new Timer(this))
  , mTimerState(0)
  , mDeadline(new Timer(this)) // timerstate expiration (assuming state != 0)
  , mMaxAckDelay(0)
  , mMinRTT(-1)
  , mWindow(kDefaultMSS * 10) // bytes
  , mWindowUsed(0)
  , mUnPacedPacketCredits(10)
  , mLastSend(0)
  , mSSThresh(0xffffffff)
  , mEndOfRecovery(0) // a packet number
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

  mPacingTimer->Cancel();
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
    uint64_t now = MozQuic::Timestamp();
    uint64_t actualSpace = now - mLastSend;
    if (actualSpace < spaceNeeded) {
      SenderLog8("Pacing requires %ld ms gap (have %ld)\n", spaceNeeded, actualSpace);
      mPacingTimer->Arm(mLastSend + spaceNeeded - now);
      return false;
    }
    return true;
  }
  return false;
}

uint64_t
Sender::PTODeadline()
{
  uint64_t ptoDeadline = mSmoothedRTT + (mSmoothedRTT >> 1) + mMaxAckDelay;

  // min pto is 10ms
  ptoDeadline = std::max(ptoDeadline, kMinTLP);

  //  If RTO (Section 3.3.2) is earlier, schedule a TLP alarm in its place.
  // That is, PTO SHOULD be scheduled for min(RTO, PTO).
  uint64_t rtoDeadline = RTODeadline(0);
  return std::min(ptoDeadline, rtoDeadline);
}

uint64_t
Sender::RTODeadline(uint32_t numTimesFired)
{
  uint64_t rtoDeadline = mSmoothedRTT + 4 * mRTTVar + mMaxAckDelay;
  rtoDeadline = rtoDeadline << numTimesFired;
  rtoDeadline = std::max(rtoDeadline, kMinRTO);
  return rtoDeadline;
}

void
Sender::EstablishPTOTimer()
{
  uint64_t ptoDeadline = PTODeadline();
  
  if (mTimerState >= 2) {
    // an rto is scheduled, keep the deadline if its earlier
    // than the ptoDeadline
    uint64_t untilExpiration = mDeadline->Expires();
    ptoDeadline = std::min(ptoDeadline, untilExpiration);
  }
  mDeadline->Arm(ptoDeadline);
  mTimerState = 1;
}

void
Sender::SendProbeData(bool fromRTO)
{
  // send probe: data, if not oldest unacked
  // never blocked - but does count on window

  // maybe some non prioritized application data can be promoted
  if (mQueue.empty()) {
    mMozQuic->FlushOnce(false, true);
  }

  // retransmit some old data
  if (mQueue.empty()) {
    mMozQuic->RetransmitOldestUnackedData(fromRTO);
  }

  if (!mQueue.empty()) {
    SendOne(fromRTO);
  }
}

void
Sender::Alarm(Timer *alarm)
{
  if (alarm == mPacingTimer.get()) {
    Flush();
    return;
  }

  assert(alarm == mDeadline.get());
  assert(mTimerState);

  if (!mMozQuic->AnyUnackedPackets()) {
    // this is the normal state of things
    mDeadline->Cancel();
    mTimerState = 0;
    return;
  }

  if (mTimerState == 1) { // 1st pto expired
    SendProbeData(false);
    // rearm timer for another pto
    mDeadline->Arm(PTODeadline());
    mTimerState = 2;
  } else if (mTimerState == 2) { // 2nd pto expired
    SendProbeData(false);
    // rearm timer for rto
    mDeadline->Arm(RTODeadline(0));
    mTimerState = 3;
  } else if (mTimerState >= 3) { // rto expired
    SendProbeData(true);
    SendProbeData(true); // 2 packets
    // rearm timer for more rto
    mDeadline->Arm(RTODeadline(mTimerState - 2));
    mTimerState++;
  }
}

uint32_t
Sender::SendOne(bool fromRTO)
{
  assert (!mQueue.empty());
  
  mLastSend = MozQuic::Timestamp();
  mWindowUsed += mQueue.front()->mBareAck ? 0 : mQueue.front()->mLen;
  if (mUnPacedPacketCredits) {
    mUnPacedPacketCredits--;
  }
  SenderLog6("Packet Sent from Queue Tick #%lX %ld (now %ld/%ld)\n",
             mQueue.front()->mPacketNumber,
             mQueue.front()->mBareAck ? 0 : mQueue.front()->mLen,
             mWindowUsed, mWindow);
  mMozQuic->RealTransmit(mQueue.front()->mData.get(),
                         mQueue.front()->mLen,
                         mQueue.front()->mExplicitPeer ? (const struct sockaddr *)&(mQueue.front()->mSockAddr) : nullptr,
                         false);
  mQueue.pop_front();
  return MOZQUIC_OK;
}

void
Sender::Flush()
{
  if (mQueue.empty()) {
    return;
  }
  
  if (!CanSendNow(mQueue.front()->mLen, false)) {
    return;
  }

  do {
    uint32_t rv = SendOne(false);
    if (rv != MOZQUIC_OK) {
      break;
    }
  } while (!mQueue.empty() && CanSendNow(mQueue.front()->mLen, false));
}

BufferedPacket::BufferedPacket(const unsigned char *pkt, uint32_t pktSize,
                               const struct sockaddr *sin, size_t soSin,
                               uint64_t packetNumber, bool bareAck)
  : mData(new unsigned char[pktSize])
  , mLen(pktSize)
  , mHeaderSize(0)
  , mPacketNumber(packetNumber)
  , mExplicitPeer(false)
  , mBareAck(bareAck)
{
  memcpy((void *)mData.get(), pkt, mLen);
  if (sin) {
    mExplicitPeer = true;
    memcpy(&mSockAddr, sin, soSin);
  }
}

uint32_t
Sender::Transmit(uint64_t packetNumber, bool bareAck, bool clientZeroRTT, bool queueOnly,
                 const unsigned char *pkt, uint32_t len, const struct sockaddr *explicitPeer)
{
  // in order to queue we need to copy the packet, as its probably on the stack of
  // the caller. So avoid that if possible.
  SenderLog8("Sender::Transmit %ld %d\n", len, bareAck);
  bool canSendNow =
    (!queueOnly) && (clientZeroRTT || CanSendNow(len, clientZeroRTT) || bareAck); // Do not queue clientZeroRTT packets.
  if (mQueue.empty() && canSendNow) {
    mLastSend = MozQuic::Timestamp();
    mWindowUsed += bareAck ? 0 : len;
    if (mUnPacedPacketCredits) {
      mUnPacedPacketCredits--;
    }
    SenderLog6("Packet Sent Without Queue #%lX %d now (%ld/%ld)\n",
               packetNumber, bareAck ? 0 : len, mWindowUsed, mWindow);
    return mMozQuic->RealTransmit(pkt, len, explicitPeer, true);
  }
  size_t soSin =
    mMozQuic->IsV6() ? sizeof (struct sockaddr_in6) : sizeof (struct sockaddr_in);
  mQueue.emplace_back(new BufferedPacket(pkt, len, explicitPeer,
                                         soSin, packetNumber, bareAck));
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
    SenderLog6("Packet Sent from Queue #%lX %d now (%ld/%ld)\n",
               mQueue.front()->mPacketNumber,
               bareAck ? 0 : mQueue.front()->mLen,
               mWindowUsed, mWindow);
    mMozQuic->RealTransmit(mQueue.front()->mData.get(),
                           mQueue.front()->mLen,
                           mQueue.front()->mExplicitPeer ? (const struct sockaddr *)&(mQueue.front()->mSockAddr) : nullptr,
                           true);
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
    SenderLog6("Acknowledgment %lX of %ld (now %ld/%ld) [recovery %lX]\n",
               packetNumber, bytes, mWindowUsed, mWindow, mEndOfRecovery);
    return;
  }

  if (mEndOfRecovery) {
    // leaving recovery
    mEndOfRecovery = 0;
    SenderLog5("leaving recovery\n");
    mUnPacedPacketCredits = 10;
  }

  if (mWindow < mSSThresh) {
    // slow start.. grow exponentially!
    mWindow += bytes;
  } else {
    // AIMD - add one mss per ack'd window
    // so that means the ack'd proportion of window is
    // the propotion of mss we add to window
    mWindow += kDefaultMSS * bytes / mWindow;
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
  SenderLog4("Report Loss [%lX] %lu endRecovery=%lX%s\n",
             packetNumber, bytes, mEndOfRecovery,
             (mEndOfRecovery >= packetNumber) ? " In Recovery" : "");

  if (mWindowUsed >= bytes) {
    mWindowUsed -= bytes;
  } else {
    mWindowUsed = 0;
  }

  if (mEndOfRecovery < packetNumber) {
    assert(packetNumber <= (mMozQuic->HighestTransmittedAckable()));
    mEndOfRecovery = mMozQuic->HighestTransmittedAckable();
    mWindow = mWindow >> 1;
    if (mWindow < kMinWindow) {
      mWindow = kMinWindow;
    }
    mSSThresh = mWindow;
    SenderLog4("Report Loss (now %lu/%lu) ssthresh=%lu\n",
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
  mMinRTT = std::min(mMinRTT, rtt);

  if ((rtt >= delay) && ((rtt - delay) >= mMinRTT)) {
    rtt -= delay;
    mMaxAckDelay = std::max(delay, mMaxAckDelay);
    mMaxAckDelay = std::min(kMaxAckDelay, mMaxAckDelay); // cap the 'max'
  }

  rtt = std::min(rtt, (uint64_t)0xffff);

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
  mRTTVar = std::max((uint16_t)1, mRTTVar);

  SenderLog7("New RTT Sample %u now smoothed %u rttvar %u\n",
             rtt, mSmoothedRTT, mRTTVar);
}

}
