/* -*- Mode: C++; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*-
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#pragma once

#include <stdarg.h>
#include <stdint.h>

namespace mozquic  {

class Log 
{
public:
  Log();
  static uint32_t sDoLog(int cat, int level, const char *p, ...);
  static void sParseSubscriptions(const char *envStr);
  enum 
  {
    ACK, STREAM, HANDSHAKE
  };

private:
  uint32_t DoLog(int cat, int level, const char *p, va_list foo);
  void ParseSubscriptions(const char *envStr);
                            
  int NameToNumber(const char *type);
  uint32_t Subscribe(const char *type, int level);
  static const int kCategoryCount = 3;

  uint32_t mCategory[kCategoryCount];
  static const char *mCategoryName[kCategoryCount];
};

#define AckLog1(...) Log::sDoLog(Log::ACK, 1, __VA_ARGS__);
#define AckLog2(...) Log::sDoLog(Log::ACK, 2, __VA_ARGS__);
#define AckLog3(...) Log::sDoLog(Log::ACK, 3, __VA_ARGS__);
#define AckLog4(...) Log::sDoLog(Log::ACK, 4, __VA_ARGS__);
#define AckLog5(...) Log::sDoLog(Log::ACK, 5, __VA_ARGS__);
#define AckLog6(...) Log::sDoLog(Log::ACK, 6, __VA_ARGS__);
#define AckLog7(...) Log::sDoLog(Log::ACK, 7, __VA_ARGS__);
#define AckLog8(...) Log::sDoLog(Log::ACK, 8, __VA_ARGS__);
#define AckLog9(...) Log::sDoLog(Log::ACK, 9, __VA_ARGS__);
#define AckLog10(...) Log::sDoLog(Log::ACK, 10, __VA_ARGS__);

#define StreamLog1(...) Log::sDoLog(Log::STREAM, 1, __VA_ARGS__);
#define StreamLog2(...) Log::sDoLog(Log::STREAM, 2, __VA_ARGS__);
#define StreamLog3(...) Log::sDoLog(Log::STREAM, 3, __VA_ARGS__);
#define StreamLog4(...) Log::sDoLog(Log::STREAM, 4, __VA_ARGS__);
#define StreamLog5(...) Log::sDoLog(Log::STREAM, 5, __VA_ARGS__);
#define StreamLog6(...) Log::sDoLog(Log::STREAM, 6, __VA_ARGS__);
#define StreamLog7(...) Log::sDoLog(Log::STREAM, 7, __VA_ARGS__);
#define StreamLog8(...) Log::sDoLog(Log::STREAM, 8, __VA_ARGS__);
#define StreamLog9(...) Log::sDoLog(Log::STREAM, 9, __VA_ARGS__);
#define StreamLog10(...) Log::sDoLog(Log::STREAM, 10, __VA_ARGS__);

#define HandshakeLog1(...) Log::sDoLog(Log::HANDSHAKE, 1, __VA_ARGS__);
#define HandshakeLog2(...) Log::sDoLog(Log::HANDSHAKE, 2, __VA_ARGS__);
#define HandshakeLog3(...) Log::sDoLog(Log::HANDSHAKE, 3, __VA_ARGS__);
#define HandshakeLog4(...) Log::sDoLog(Log::HANDSHAKE, 4, __VA_ARGS__);
#define HandshakeLog5(...) Log::sDoLog(Log::HANDSHAKE, 5, __VA_ARGS__);
#define HandshakeLog6(...) Log::sDoLog(Log::HANDSHAKE, 6, __VA_ARGS__);
#define HandshakeLog7(...) Log::sDoLog(Log::HANDSHAKE, 7, __VA_ARGS__);
#define HandshakeLog8(...) Log::sDoLog(Log::HANDSHAKE, 8, __VA_ARGS__);
#define HandshakeLog9(...) Log::sDoLog(Log::HANDSHAKE, 9, __VA_ARGS__);
#define HandshakeLog10(...) Log::sDoLog(Log::HANDSHAKE, 10, __VA_ARGS__);


}

  
