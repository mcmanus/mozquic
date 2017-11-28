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
  , mSmoothedRTT(0)
{
}
  
void
Sender::RTTSample(uint64_t xmit, uint16_t delay)
{
  uint64_t now = MozQuic::Timestamp();
  assert(now >= xmit);
  uint64_t rtt = now - xmit;
  if (rtt < delay) {
    return;
  }
  rtt -= delay;
  if (rtt > 0xffff) {
    rtt = 0xffff;
  }
  mSmoothedRTT = (mSmoothedRTT - (mSmoothedRTT >> 3)) + (rtt >> 3);
  SenderLog7("New RTT Sample %u now smoothed %u\n",
             rtt, mSmoothedRTT);
}

}
