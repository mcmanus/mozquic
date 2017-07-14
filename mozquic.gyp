# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

# See the sample app in makefile for an example outside firefox

# Make sure to set your NSS information in env.gypi if you
# are not using a pkg-config version (which currently does not exist
# as tls 1.3 -20 is required is currently on an unreleased DRAFT-19 branch

{
  'includes': [
     'env.gypi',
  ],

  'targets': [
      {
     'target_name': 'mozquic',
     'type': 'static_library',
     'cflags': [ '-g', '<(nss_include)', ],
     'cflags_mozilla': [ '$(NSPR_CFLAGS)', '$(NSS_CFLAGS)', ],
     'sources': [
         'MozQuic.cpp',
         'MozQuicStream.cpp',
         'NSSHelper.cpp',
        ],
     },
   ],
}

