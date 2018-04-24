/* -*- Mode: C++; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*-
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "Logging.h"
#include "MozQuic.h"
#include "MozQuicInternal.h"
#include "Sender.h"

#include <assert.h>
#include <stdlib.h>
#include <unistd.h>
#include <sechash.h>

namespace mozquic  {

uint32_t
MozQuic::StatelessResetEnsureKey()
{
  // make a reset token if this was not provided as config
  unsigned char empty[128];
  memset(empty, 0, 128);
  assert(sizeof(empty) == sizeof(mStatelessResetKey));
  if (!memcmp(empty, mStatelessResetKey, 128)) {
    assert((sizeof(mStatelessResetKey) % sizeof(uint16_t)) == 0);
    for (unsigned int i=0; i < (sizeof(mStatelessResetKey) / sizeof (uint16_t)); i++) {
      ((uint16_t *)mStatelessResetKey)[i] = random() & 0xffff;
    }
  }
  return MOZQUIC_OK;
}

uint32_t
MozQuic::StatelessResetSend(CID &connID, const struct sockaddr *peer)
{
  if (mIsClient) {
    return MOZQUIC_ERR_GENERAL;
  }
  assert(!mIsChild);
  assert(!mParent);
  ConnectionLog1("Generate Stateless Reset of connection %lx\n", connID);
  unsigned char out[kMaxMTU];
  out[0] = 0x30 | SHORT_1;

  for (int i = 0; i < (18/2); i++) {
    uint16_t tmp16 = random() & 0xffff;
    memcpy(out + 1 + (i * 2), &tmp16, 2);
  }
  out[19] = random() & 0xff; // packet number

  uint32_t pad = mMTU - 36;
  pad = (random() % pad) & ~0x1; // force even
  pad = (pad > 0) ? pad : 1;
  assert((pad + 36) <= kMaxMTU);
  assert((pad + 36) <= mMTU);

  for (unsigned int i=0; i < pad; i++) {
    out[20 + i] = random() & 0xff;
  }

  StatelessResetCalculateToken(mStatelessResetKey, connID, out + 20 + pad); // from key and CID

  return mSendState->Transmit(0, true, false, false, out, 36 + pad, peer);
}

uint32_t
MozQuic::StatelessResetCalculateToken(const unsigned char *key128,
                                      CID &connID, unsigned char *out)
{
  // out needs to be at least 16
  // derive the public resetToken from the resetKey and connectionID
  unsigned char digest[SHA256_LENGTH];
  unsigned int digestLen;
  assert(SHA256_LENGTH >= 16);
  HASHContext *hcontext = HASH_Create(HASH_AlgSHA256);
  HASH_Begin(hcontext);
  HASH_Update(hcontext, key128, 128);
  HASH_Update(hcontext, connID.Data(), connID.Len());
  HASH_End(hcontext, digest, &digestLen, sizeof(digest));
  assert(digestLen == sizeof(digest));
  memcpy(out, digest, 16);
  return MOZQUIC_OK;
}

bool
MozQuic::StatelessResetCheckForReceipt(const unsigned char *pkt, uint32_t pktSize)
{
  if (pktSize < 36) {
    return false;
  }
  if (mConnectionState != CLIENT_STATE_CONNECTED) {
    return false;
  }
  if ((pkt[0] & 0x80) != 0x00) { // only short form packets
    return false;
  }

  if (mValidStatelessResetToken &&
      memcmp(mStatelessResetToken, pkt + pktSize - 16, 16)) {
    return false;
  }

  ConnectionLog1("client recvd verified public reset\n");
  if (mConnEventCB) {
    mConnEventCB(mClosure, MOZQUIC_EVENT_ERROR, this);
  }

  return true;
}


}

