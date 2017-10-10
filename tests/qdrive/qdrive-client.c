/* -*- Mode: C++; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*-
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

// -qdrive -addr localhost:port -qdrive-testN

/* -ignorePKI option will allow handshake with untrusted cert. (localhost always implies ignorePKI)

   About Certificate Verifcation::
   The sample/nss-config directory is a sample that can be passed
   to mozquic_nss_config(). It contains a NSS database with a cert
   and key for foo.example.com that is signed by a CA defined by CA.cert.der.
*/

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <time.h>
#include <assert.h>
#include "MozQuic.h"
#include "qdrive-common.h"

mozquic_connection_t *parentConnection;

int main(int argc, char **argv)
{
  char *argVal, *t;
  struct mozquic_config_t config;

  if (has_arg(argc, argv, "-quiet", &argVal)) {
    fclose(stderr);
  }

  if (!has_arg(argc, argv, "-qdrive", &argVal)) {
    fprintf(stderr, "-qdrive required\n");
    test_assert(0);
  }

  char *cdir = getenv ("MOZQUIC_NSS_CONFIG");
  if (mozquic_nss_config(cdir) != MOZQUIC_OK) {
    fprintf(stderr,"MOZQUIC_NSS_CONFIG FAILURE [%s]\n", cdir ? cdir : "");
    test_assert(0);
  }

  memset(&config, 0, sizeof(config));

  if (has_arg(argc, argv, "-addr", &argVal)) {
    config.originName = strdup(argVal);
    t = strchr(config.originName, ':');
    if (t) {
      *t = 0;
      config.originPort = atoi(t + 1);
    }
  }
  if (!config.originPort) {
    fprintf(stderr,"-addr hostname:port required\n");
    test_assert(0);
  }
  
  fprintf(stderr,"client connecting to %s port %d\n", config.originName, config.originPort);

  config.handleIO = 0;

  // ingorePKI will allow invalid certs
  // normally they must either be linked to the root store OR on localhost
  test_assert(mozquic_unstable_api1(&config, "ignorePKI",
                                    has_arg(argc, argv, "-ignorePKI", &argVal), 0) == MOZQUIC_OK);
  test_assert(mozquic_unstable_api1(&config, "tolerateBadALPN", 1, 0) == MOZQUIC_OK);
  test_assert(mozquic_unstable_api1(&config, "clientPort", 2776, 0) == MOZQUIC_OK);
  
  int numTests = 0;
  while (testList[numTests].name) {
    numTests++;
  }
  config_tests(testList, numTests, argc, argv, &config);
  do {
    mozquic_new_connection(&parentConnection, &config);
    mozquic_connection_t *p = parentConnection;

    setup_tests(testList, numTests, argc, argv, parentConnection);
    test_assert(mozquic_start_client(parentConnection) == MOZQUIC_OK);

    do {
      usleep (1000); // this is for handleio todo
      uint32_t code = mozquic_IO(p);
      if (code != MOZQUIC_OK) {
        fprintf(stderr,"IO reported failure\n");
      }
    } while (!mozquic_get_allacked(p) || parentConnection);
        
    mozquic_destroy_connection(p);
  } while (1);
  return 0;
}
