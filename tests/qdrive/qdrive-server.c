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

int qdrive_server_crash = 0;

int main(int argc, char **argv)
{
  char *argVal;
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
    sin.sin_port = htons(1776);
    slen = sizeof(sin);
    if (!bind(tfd, (const struct sockaddr *)&sin, sizeof (sin)) &&
        !getsockname(tfd, (struct sockaddr *) &sin,  &slen)) {
      config.originPort = ntohs(sin.sin_port);
    } else {
      sin.sin_port = 0;
      if (!bind(tfd, (const struct sockaddr *)&sin, sizeof (sin)) &&
          !getsockname(tfd, (struct sockaddr *) &sin,  &slen)) {
        config.originPort = ntohs(sin.sin_port);
      } else {
        test_assert(0);
      }
    }
    close(tfd);
  }
  test_assert(config.originPort);

  if (has_arg(argc, argv, "-qdrive", &argVal)) {
    fprintf(stdout,"%d\n", config.originPort);
    fflush(stdout);
  }

  config.originName = SERVER_NAME;

  test_assert(mozquic_unstable_api1(&config, "tolerateBadALPN", 1, 0) == MOZQUIC_OK);
  config.handleIO = 0; // todo mvp

  int numTests = 0;
  while (testList[numTests].name) {
    numTests++;
  }
  do {
    fprintf(stderr,"server using certificate for %s on port %d\n", config.originName, config.originPort);
    config_tests(testList, numTests, argc, argv, &config);
    mozquic_new_connection(&c, &config);

    setup_tests(testList, numTests, argc, argv, c);
    test_assert (mozquic_start_server(c) == MOZQUIC_OK);

    do {
      usleep (1000); // this is for handleio todo
      mozquic_IO(c);
    } while (!qdrive_server_crash);
    qdrive_server_crash = 0;
    mozquic_destroy_connection(c);
  } while (1);
}
