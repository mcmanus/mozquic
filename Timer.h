/* -*- Mode: C++; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*-
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#pragma once

#include <list>
#include <stdint.h>

namespace mozquic {

class Timer;
class TimerNotification
{
public:
  virtual void Alarm(Timer *) = 0;
};
  
class Timer
{
public:
  Timer(TimerNotification *notification);
  virtual ~Timer();

  void Cancel();
  bool Expired();
  uint64_t Expires(); // ms til expiration
  bool Armed();
  void Arm(uint64_t deadline);
  void SetData(void *data) { mData = data; }
  void *Data() { return mData; }
    
  static void Tick();
  static uint64_t NextTimerInMsec();

private:
  static void InsertIntoMasterList(Timer *);

  uint64_t mDeadline; // 0 if not armed
  TimerNotification *mNotification;
  void *mData;
  std::list<Timer *>::iterator mList;
};

}

