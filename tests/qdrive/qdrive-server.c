/* -*- Mode: C++; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*-
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <assert.h>
#include <netinet/ip.h>
#include "MozQuic.h"
#include "qdrive-common.h"

// -qdrive -qdrive-testN

#define SERVER_NAME "foo.example.com"

/*  About Certificate Verifcation::
    The sample/nss-config directory is a sample that can be passed
    to mozquic_nss_config(). It contains a NSS database with a cert
    and key for foo.example.com that is signed by a CA defined by CA.cert.der.
*/

struct testParam testList[] =
{
  TEST_PARAMS(0),  TEST_PARAMS(1), TEST_PARAMS(2),  TEST_PARAMS(3), TEST_PARAMS(4),
};

int main(int argc, char **argv)
{
  char *argVal, *t;
  uint32_t i = 0;
  struct mozquic_config_t config;
  mozquic_connection_t *c;

  if (has_arg(argc, argv, "-quiet", &argVal)) {
    fclose(stderr);
  }

  char *cdir = getenv ("MOZQUIC_NSS_CONFIG");
  if (mozquic_nss_config(cdir) != MOZQUIC_OK) {
    fprintf(stderr,"MOZQUIC_NSS_CONFIG FAILURE [%s]\n", cdir ? cdir : "");
    test_assert(0);
  }
  
  memset(&config, 0, sizeof(config));

  {
    struct sockaddr_in sin;
    socklen_t slen;
    int tfd = socket(AF_INET, SOCK_DGRAM, 0);
    memset (&sin, 0, sizeof (sin));
    sin.sin_family = AF_INET;
    slen = sizeof(sin);
    if (!bind(tfd, (const struct sockaddr *)&sin, sizeof (sin)) &&
        !getsockname(tfd, (struct sockaddr *) &sin,  &slen)) {
      config.originPort = ntohs(sin.sin_port);
    }
    close(tfd);
  }
  test_assert(config.originPort);

  if (has_arg(argc, argv, "-qdrive", &argVal)) {
    fprintf(stdout,"%d\n", config.originPort);
    fflush(stdout);
  }

  config.originName = SERVER_NAME;
  fprintf(stderr,"server using certificate for %s on port %d\n", config.originName, config.originPort);

  config.tolerateBadALPN = 1;
  config.handleIO = 0; // todo mvp

  int numTests = sizeof(testList) / sizeof(struct testParam);
  config_tests(testList, numTests, argc, argv, &config);
  mozquic_new_connection(&c, &config);

  setup_tests(testList, numTests, argc, argv, c);
  test_assert (mozquic_start_server(c) == MOZQUIC_OK);

  do {
    usleep (1000); // this is for handleio todo
    if (!(i++ & 0xf)) {
      fprintf(stderr,".");
      fflush(stderr);
    }
    mozquic_IO(c);
  } while (1);
  
}
