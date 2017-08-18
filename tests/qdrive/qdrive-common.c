/* -*- Mode: C++; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*-
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include <stdlib.h>
#include <assert.h>
#include <strings.h>
#include "qdrive-common.h"
#include "MozQuic.h"

void test_assert(int test_assertion) 
{
  assert(test_assertion);
  // ndebug too
  if (!test_assertion) {
    void *ptr = 0;
    *((int *)ptr) =  0xdeadbeef;
    exit (-1); // rather un-necessary
  }
}

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
  
