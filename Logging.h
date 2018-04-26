/* -*- Mode: C++; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*-
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#pragma once

#include <stdarg.h>
#include <stdint.h>

namespace mozquic  {

class MozQuic;
class CID;

class Log 
{
public:
  Log();
  static uint32_t sDoLog(unsigned int cat, unsigned int level, MozQuic *m, const char *fmt, ...);
  static uint32_t sDoLogCID(unsigned int cat, unsigned int level, MozQuic *m,
                            CID *localCID, CID *peerCID,
                            const char *fmt, ...);
  static uint32_t sDoLog(unsigned int cat, unsigned int level, MozQuic *m,
                         CID *localCID, CID *peerCID,
                         const char *fmt, va_list paramList);
  static void sParseSubscriptions(char *envStr);
  enum 
  {
    ACK, STREAM, CONNECTION, TLS, HANDSHAKE, SENDER,
    kCategoryCount
  };

private:
  uint32_t DoLog(unsigned int cat, unsigned int level, MozQuic *m,
                 CID *localCID, CID *peerCID,
                 const char *fmt, va_list paramList);
  void ParseSubscriptions(char *envStr);
                            
  int NameToNumber(const char *type);
  uint32_t Subscribe(const char *type, int level);

  uint32_t mCategory[kCategoryCount];
  static const char *mCategoryName[kCategoryCount + 1];
};

#define AckLog1(...) Log::sDoLog(Log::ACK, 1, this, __VA_ARGS__);
#define AckLog2(...) Log::sDoLog(Log::ACK, 2, this, __VA_ARGS__);
#define AckLog3(...) Log::sDoLog(Log::ACK, 3, this, __VA_ARGS__);
#define AckLog4(...) Log::sDoLog(Log::ACK, 4, this, __VA_ARGS__);
#define AckLog5(...) Log::sDoLog(Log::ACK, 5, this, __VA_ARGS__);
#define AckLog6(...) Log::sDoLog(Log::ACK, 6, this, __VA_ARGS__);
#define AckLog7(...) Log::sDoLog(Log::ACK, 7, this, __VA_ARGS__);
#define AckLog8(...) Log::sDoLog(Log::ACK, 8, this, __VA_ARGS__);
#define AckLog9(...) Log::sDoLog(Log::ACK, 9, this, __VA_ARGS__);
#define AckLog10(...) Log::sDoLog(Log::ACK, 10, this, __VA_ARGS__);

#define ConnectionLog1(...) Log::sDoLog(Log::CONNECTION, 1, this, __VA_ARGS__);
#define ConnectionLogCID1(local, remote, ...) Log::sDoLogCID(Log::CONNECTION, 1, this, local, remote, __VA_ARGS__);
#define ConnectionLog2(...) Log::sDoLog(Log::CONNECTION, 2, this, __VA_ARGS__);
#define ConnectionLog3(...) Log::sDoLog(Log::CONNECTION, 3, this, __VA_ARGS__);
#define ConnectionLog4(...) Log::sDoLog(Log::CONNECTION, 4, this, __VA_ARGS__);
#define ConnectionLog5(...) Log::sDoLog(Log::CONNECTION, 5, this, __VA_ARGS__);
#define ConnectionLogCID5(local, remote, ...) Log::sDoLogCID(Log::CONNECTION, 5, this, local, remote, __VA_ARGS__);
#define ConnectionLog6(...) Log::sDoLog(Log::CONNECTION, 6, this, __VA_ARGS__);
#define ConnectionLog7(...) Log::sDoLog(Log::CONNECTION, 7, this, __VA_ARGS__);
#define ConnectionLog8(...) Log::sDoLog(Log::CONNECTION, 8, this, __VA_ARGS__);
#define ConnectionLog9(...) Log::sDoLog(Log::CONNECTION, 9, this, __VA_ARGS__);
#define ConnectionLog10(...) Log::sDoLog(Log::CONNECTION, 10, this, __VA_ARGS__);

}

  
