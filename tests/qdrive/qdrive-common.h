/* -*- Mode: C++; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*-
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#pragma once

#include <stdlib.h>
#include <stdint.h>
#include "MozQuic.h"
#include <assert.h>

struct mozquic_config_t;
struct mozquic_connection_t;

extern mozquic_connection_t *parentConnection;

struct testParam 
{
  const char *name;
  void (*configFx)(struct mozquic_config_t *);
  int (*eventFx)(void *closure, uint32_t event, void * param);
  void *(*getClosureFx)();
};

#undef TE

extern struct testParam testList[];
int has_arg(int argc, char **argv, const char *test, char **value);

void config_tests(struct testParam *testList, int numTests,
                  int argc, char **argv, struct mozquic_config_t *c);
int setup_tests(struct testParam *testList, int numTests,
                int argc, char **argv, struct mozquic_connection_t *c);
uint64_t Timestamp();

#include <stdio.h>

#define test_assert(assertion) \
  do { \
   if (!(assertion)) {\
    fprintf(stderr,"assert failed %s:%d\n", __FILE__, __LINE__);\
    fflush(stderr);                                             \
    __builtin_trap();                                           \
   } \
  } while (0)
