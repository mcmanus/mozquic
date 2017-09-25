/* -*- Mode: C++; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*-
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

// env variable MOZQUIC_LOG is a set of csv. each var is type:level, with
// a default level of 5. 0 is off, 10 is max... 1 is most impt, 10 least

// MOZQUIC_LOG=all:5 or MOZQUIC_LOG=ack:8,stream:10,conn

#include <assert.h>
#include <strings.h>
#include "Logging.h"
#include "MozQuicInternal.h"

namespace mozquic  {

const char *Log::mCategoryName[] = {
    "ack", "stream", "handshake"
};

static Log gLogger;

uint32_t
Log::sDoLog(int cat, int level, MozQuic *m, const char *fmt, ...)
{
  va_list a;
  va_start(a, fmt);
  uint32_t rv = gLogger.DoLog(cat, level, m, 0, fmt, a);
  va_end(a);
  return rv;
}

uint32_t
Log::sDoLog(int cat, int level, MozQuic *m, uint64_t cid,
            const char *fmt, va_list paramList)
{
  return gLogger.DoLog(cat, level, m, cid, fmt, paramList);
}

uint32_t
Log::sDoLogCID(int cat, int level, MozQuic *m, uint64_t cid,
               const char *fmt, ...)
{
  va_list a;
  va_start(a, fmt);
  uint32_t rv = gLogger.DoLog(cat, level, m, cid, fmt, a);
  va_end(a);
  return rv;
}

uint32_t
Log::DoLog(int cat, int level, MozQuic *m, uint64_t cid, const char *fmt, va_list paramList)
{
  assert (cat >= 0);
  assert (cat <kCategoryCount);
  if (mCategory[cat] < level) {
    return MOZQUIC_OK;
  }

  uint64_t useCid = 0;
  if (cid) {
    useCid = cid;
  } else if (m) {
    useCid = m->mConnectionID;
  }

  if (!m || !m->mAppHandlesLogging) {
    fprintf(stderr,"%06ld:%016lx ", MozQuic::Timestamp() % 1000000, useCid);
    vfprintf(stderr, fmt, paramList);
  }
  else if (m && m->mConnEventCB && m->mClosure) {
    char buffer[2048];
    int used = snprintf(buffer, 2048, "%06ld: ", MozQuic::Timestamp() % 1000000);
    if (used >= 2047) {
      return MOZQUIC_OK;
    }
    used += vsnprintf(buffer + used, 2048 - used, fmt, paramList);
    if (used >= 2047) {
      return MOZQUIC_OK;
    }
    m->mConnEventCB(m->mClosure, MOZQUIC_EVENT_LOG, buffer);
  }

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
Log::sParseSubscriptions(char *envStr)
{
  static int parsed = 0;
  if (!envStr || parsed) {
    return;
  }
  parsed = 1;
  gLogger.ParseSubscriptions(envStr);
}

void
Log::ParseSubscriptions(char *envStr)
{
  char *s = envStr;
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
      int level = atoi(colon+1);
      Subscribe(s, level);
      *colon = ':';
    } else {
      Subscribe(s, 5);
    }
    s = eof + 1;
  } while (oldEof);
}

}
