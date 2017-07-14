# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

# See the sample app in makefile for an example outside firefox

# Choose one of the nss_include versions below, setting
# MOZQUIC_INCLUDE if you have a version of NSS that is not found by
# pkg-config. Currently a special draft-19 branch of NSS is required

{
  'variables' :
    {
     'nss_include' : '-I$(MOZQUIC_INCLUDE)' ' <!@(pkg-config --cflags nspr)',
     'nss_link' : '-L$(MOZQUIC_LINK)' ' <!@(pkg-config --libs nss)',

#      'nss_link' : '>!@(pkg-config --libs nss)',
#      'nss_include' : '>!@(pkg-config --cflags nss)',

   } ,

}

