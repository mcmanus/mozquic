/* -*- Mode: C++; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*-
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

// env variable MOZQUIC_LOG is a set of csv. each var is type:level, with
// a default level of 5. 0 is off, 10 is max... 1 is most impt, 10 least

// MOZQUIC_LOG=all:5 or MOZQUIC_LOG=ack:8,stream:10,conn

// default log is stderr.. but
// MOZQUIC_LOG_TARGET=/tmp/logfile works too (todo)
// todo parse env

#include <assert.h>
#include <strings.h>
#include "Logging.h"
#include "MozQuicInternal.h"

namespace mozquic  {
  
const char *Log::mCategoryName[] = {
    "ack", "stream", "handshake"
};

Log gLogger;

uint32_t
Log::sDoLog(int cat, int level, const char *p, ...)
{
  va_list a;
  va_start(a, p);
  uint32_t rv = gLogger.DoLog(cat, level, p, a);
  va_end(a);
  return rv;
}

uint32_t
Log::DoLog(int cat, int level, const char *p, va_list foo)
{
  assert (cat >= 0);
  assert (cat <kCategoryCount);
  if (mCategory[cat] < level) {
    return MOZQUIC_OK;
  }

  vfprintf(stderr, p, foo);
  return MOZQUIC_OK;
}

Log::Log()
{
  memset(mCategory, 0, sizeof (uint32_t) * kCategoryCount);
}

int
Log::NameToNumber(const char *type)
{
  for (int i = 0; i < kCategoryCount; i++) {
    if (!strcasecmp(mCategoryName[i], type)) {
      return i;
    }
  }
  return -1;
}

uint32_t
Log::Subscribe(const char *type, int level)
{
  if (!strcasecmp(type, "all")) {
    for (int i = 0; i < kCategoryCount; i++) {
      mCategory[i] = level;
    }
    return MOZQUIC_OK;
  }

  int idx = NameToNumber(type);
  if (idx < 0) {
    return MOZQUIC_ERR_GENERAL;
  }
  mCategory[idx] = level;
  return MOZQUIC_OK;
}

void
Log::sParseSubscriptions(const char *envStr)
{
  static int parsed = 0;
  if (!envStr || parsed) {
    return;
  }
  parsed = 1;
  gLogger.ParseSubscriptions(envStr);
}

void
Log::ParseSubscriptions(const char *envStr)
{
  int level = 5;
  const char *s = envStr;
  char oldEof;
  do {
    char *e = strchr(s, ',');
    if (!e) {
      e = strchr (s, 0);
    }
    char *eof = e;
    oldEof = *eof;
    *eof = 0;
    while ((s < e) && (*s == ' ')) {
      s++;
    }
    while ((e > s) && (*e == ' ')) {
      e--;
    }
    if (e == s) {
      return;
    }
    char *colon = strchr (s, ':');
    if (colon) {
      *colon = 0;
      level = atoi(colon+1);
      Subscribe(s, level);
      *colon = ':';
    }
    s = eof + 1;
  } while (oldEof);
}

}
