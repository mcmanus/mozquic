/* -*- Mode: C++; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*-
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include <stdlib.h>
#include <strings.h>
#include "qdrive-common.h"
#include "MozQuic.h"
#include <sys/time.h>

#define TEST_PARAMS(N) {"-qdrive-test"#N, testConfig##N, testEvent##N, testGetClosure##N}
#define TEST_EXPORT(N) void testConfig##N(struct mozquic_config_t *_c);\
  int  testEvent##N(void *closure, uint32_t event, void *param);       \
  void *testGetClosure##N();

TEST_EXPORT(0)  TEST_EXPORT(1)  TEST_EXPORT(2)  TEST_EXPORT(3)  TEST_EXPORT(4)
TEST_EXPORT(5)  TEST_EXPORT(6)  TEST_EXPORT(7)  TEST_EXPORT(8)  TEST_EXPORT(9)
TEST_EXPORT(10) TEST_EXPORT(11) TEST_EXPORT(13) TEST_EXPORT(14)
TEST_EXPORT(15) TEST_EXPORT(16)

struct testParam testList[] =
{
  TEST_PARAMS(0),  TEST_PARAMS(1),  TEST_PARAMS(2),  TEST_PARAMS(3),  TEST_PARAMS(4),
  TEST_PARAMS(5),  TEST_PARAMS(6),  TEST_PARAMS(7),  TEST_PARAMS(8),  TEST_PARAMS(9),
  TEST_PARAMS(10), TEST_PARAMS(11), TEST_PARAMS(13), TEST_PARAMS(14),
  TEST_PARAMS(15), TEST_PARAMS(16),

  { NULL, NULL, NULL, NULL } // eof sentinel
};

int
has_arg(int argc, char **argv, const char *test, char **value)
{
  int i;
  if (value) {
    *value = NULL;
  }
  for (i=0; i < argc; i++) {
    if (!strcasecmp(argv[i], test)) {
      if (value) {
        *value = ((i + 1) < argc) ? argv[i+1] : "";
      }
      return 1;
    }
  }
  return 0;
}

void
config_tests(struct testParam *testList, int numTests, int argc, char **argv, struct mozquic_config_t *c)
{
  for (int j = 0; j < numTests; j++) {
    if (has_arg(argc, argv, testList[j].name, NULL)) {
      testList[j].configFx(c);
      return;
    }
  }
}

int
setup_tests(struct testParam *testList, int numTests, int argc, char **argv, struct mozquic_connection_t *c)
{
  int rv = 0;
  for (int j = 0; j < numTests; j++) {
    if (has_arg(argc, argv, testList[j].name, NULL)) {
      rv = 1;
      mozquic_set_event_callback(c, testList[j].eventFx);
      mozquic_set_event_callback_closure(c, testList[j].getClosureFx());
      break;
    }
  }
  test_assert(rv);
  return rv;
}

uint64_t
Timestamp()
{
  // ms since epoch
  struct timeval tv;
  gettimeofday(&tv, NULL);
  return (tv.tv_sec * 1000) + (tv.tv_usec / 1000);
}

