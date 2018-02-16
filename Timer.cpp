/* -*- Mode: C++; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*-
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include <assert.h>

#include "MozQuicInternal.h"
#include "Timer.h"

namespace mozquic {

std::list<Timer *> timerList;

Timer::Timer(TimerNotification *notification)
  : mDeadline(0)
  , mNotification(notification)
  , mData(nullptr)
  , mList(timerList.end())
{
}

Timer::~Timer()
{
  Cancel();
}

void Timer::InsertIntoMasterList(Timer *newTimer)
{
  assert(newTimer->mDeadline);
  assert(newTimer->mList == timerList.end());

  if (timerList.empty()) {
    timerList.push_front(newTimer);
    newTimer->mList = timerList.begin();
    return;
  }

  // work from the back under the asumption that new timers are later
  auto iter = timerList.end();
  iter--;
  do {
    if ((*iter)->mDeadline < newTimer->mDeadline) {
      iter++;
      newTimer->mList = timerList.insert(iter, newTimer);
      return;
    }
    if (iter == timerList.begin()) {
      break;
    }
    iter--;
  } while (1);
  timerList.push_front(newTimer);
  newTimer->mList = timerList.begin();
}

void Timer::Tick()
{
  uint64_t now = MozQuic::Timestamp();
  // iterate from the start calling notify as necessary
  for (auto iter = timerList.begin();
       (iter != timerList.end()) && ((*iter)->mDeadline <= now);
       iter = timerList.erase(iter)) {
    (*iter)->mDeadline = 0;
    (*iter)->mList = timerList.end();
    (*iter)->mNotification->Alarm((*iter));
  }
}

uint64_t Timer::NextTimerInMsec()
{
  auto timer = timerList.begin();
  if (timerList.end() == timer) {
    return 0;
  }
  uint64_t now = MozQuic::Timestamp();
  if ((*timer)->mDeadline <= now) {
    return 0;
  }
  return (*timer)->mDeadline - now;
}

void Timer::Cancel()
{
  if (!mDeadline) {
    return;
  }

  mDeadline = 0;
  assert(mList != timerList.end());
  timerList.erase(mList);
  mList = timerList.end();
}

bool Timer::Armed()
{
  return !!mDeadline;
}

bool Timer::Expired()
{
  return mDeadline && (mDeadline <= MozQuic::Timestamp());
}

uint64_t Timer::Expires()
{
  uint64_t now = MozQuic::Timestamp();
  if (mDeadline <= now) {
    return 0;
  }
  return mDeadline - now;
}

void Timer::Arm(uint64_t deadline)
{
  if (!mDeadline) {
    mDeadline = deadline + MozQuic::Timestamp();
    InsertIntoMasterList(this);
    return;
  }

  assert (mList != timerList.end());
  auto next = mList;
  if (++next == timerList.end()) {
    next = mList;
  }
  auto prev = mList;
  if (prev != timerList.begin()) {
    prev--;
  }

  uint64_t newDeadline = deadline + MozQuic::Timestamp();
  if (newDeadline >= (*prev)->mDeadline &&
      newDeadline <= (*next)->mDeadline) {
    // update in place
    mDeadline = newDeadline;
    return;
  }

  // find a new home
  Cancel();
  mDeadline = deadline + MozQuic::Timestamp();
  InsertIntoMasterList(this);
}
  
}
