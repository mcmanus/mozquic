/* -*- Mode: C++; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*-
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "Logging.h"
#include "MozQuic.h"
#include "MozQuicInternal.h"
#include "NSSHelper.h"
#include "Streams.h"

#include <assert.h>
#include <stdlib.h>
#include <unistd.h>

namespace mozquic  {

static const uint32_t kFNV64Size = 8;
static const uint32_t kMinClientInitial = 1200;

#define HandshakeLog1(...) Log::sDoLog(Log::HANDSHAKE, 1, this, __VA_ARGS__);
#define HandshakeLog2(...) Log::sDoLog(Log::HANDSHAKE, 2, this, __VA_ARGS__);
#define HandshakeLog3(...) Log::sDoLog(Log::HANDSHAKE, 3, this, __VA_ARGS__);
#define HandshakeLog4(...) Log::sDoLog(Log::HANDSHAKE, 4, this, __VA_ARGS__);
#define HandshakeLog5(...) Log::sDoLog(Log::HANDSHAKE, 5, this, __VA_ARGS__);
#define HandshakeLog6(...) Log::sDoLog(Log::HANDSHAKE, 6, this, __VA_ARGS__);
#define HandshakeLog7(...) Log::sDoLog(Log::HANDSHAKE, 7, this, __VA_ARGS__);
#define HandshakeLog8(...) Log::sDoLog(Log::HANDSHAKE, 8, this, __VA_ARGS__);
#define HandshakeLog9(...) Log::sDoLog(Log::HANDSHAKE, 9, this, __VA_ARGS__);
#define HandshakeLog10(...) Log::sDoLog(Log::HANDSHAKE, 10, this, __VA_ARGS__);

static uint64_t
fnv1a(unsigned char *p, uint32_t len)
{
  const uint64_t prime = 1099511628211UL;
  uint64_t hash = 14695981039346656037UL;
  for (uint32_t i = 0; i < len; ++i) {
    hash ^= p[i];
    hash *= prime;
  }
  return hash;
}

bool
MozQuic::IntegrityCheck(unsigned char *pkt, uint32_t pktSize)
{
  assert (pkt[0] & 0x80);
  assert (((pkt[0] & 0x7f) == PACKET_TYPE_CLIENT_INITIAL) ||
          ((pkt[0] & 0x7f) == PACKET_TYPE_SERVER_STATELESS_RETRY) ||
          ((pkt[0] & 0x7f) == PACKET_TYPE_SERVER_CLEARTEXT) ||
          ((pkt[0] & 0x7f) == PACKET_TYPE_CLIENT_CLEARTEXT));
  if (pktSize < (kFNV64Size + 17)) {
    RaiseError(MOZQUIC_ERR_GENERAL, (char *)"hash err\n");
    return false;
  }
  uint64_t hash = fnv1a(pkt, pktSize - kFNV64Size);
  uint64_t recvdHash;
  memcpy(&recvdHash, pkt + pktSize - kFNV64Size, kFNV64Size);
  recvdHash = PR_ntohll(recvdHash);
  bool rv = recvdHash == hash;
  if (!rv) {
    HandshakeLog1("integrity error\n");
  }
  return rv;
}

uint32_t
MozQuic::FlushStream0(bool forceAck)
{
  mStreamState->FlowControlPromotion();

  if (mStreamState->mConnUnWritten.empty() && !forceAck) {
    return MOZQUIC_OK;
  }

  assert(mMTU <= kMaxMTU);
  unsigned char pkt[kMaxMTU];
  unsigned char *endpkt = pkt + mMTU;
  uint32_t tmp32;

  // section 5.4.1 of transport
  // long form header 17 bytes
  pkt[0] = 0x80;
  if (ServerState()) {
    pkt[0] |= (mConnectionState == SERVER_STATE_SSR) ?
      PACKET_TYPE_SERVER_STATELESS_RETRY : PACKET_TYPE_SERVER_CLEARTEXT;
  } else {
    pkt[0] |= mReceivedServerClearText ? PACKET_TYPE_CLIENT_CLEARTEXT : PACKET_TYPE_CLIENT_INITIAL;
  }

  if ((pkt[0] & 0x7f) == PACKET_TYPE_CLIENT_INITIAL) {
    assert(mStreamState->mStream0->Empty());
    // just in case of server stateless reset pollution
    mStreamState->mStream0->ResetInbound();
  }

  // todo store a network order version of this
  uint64_t connID = PR_htonll(mConnectionID);
  if (mConnectionState == SERVER_STATE_SSR) {
    HandshakeLog4("Generating Server Stateless Retry.\n");
    connID = PR_htonll(mOriginalConnectionID);
    assert(mStreamState->mUnAckedData.empty());
  }
  memcpy(pkt + 1, &connID, 8);

  tmp32 = htonl(mNextTransmitPacketNumber & 0xffffffff);
  if (mConnectionState == SERVER_STATE_SSR) {
    tmp32 = htonl(mClientInitialPacketNumber & 0xffffffff);
  }
  memcpy(pkt + 9, &tmp32, 4);
  tmp32 = htonl(mVersion);
  memcpy(pkt + 13, &tmp32, 4);

  unsigned char *framePtr = pkt + 17;
  mStreamState->CreateStreamFrames(framePtr, endpkt - 8, true); // last 8 are for checksum
  bool sentStream = (framePtr != (pkt + 17));

  // then padding as needed up to mtu on client_initial
  uint32_t finalLen;

  if ((pkt[0] & 0x7f) == PACKET_TYPE_CLIENT_INITIAL) {
    finalLen = (framePtr - pkt) + 8;
    if (finalLen < kMinClientInitial) {
      finalLen = kMinClientInitial;
    }
  } else if (mConnectionState == SERVER_STATE_SSR) {
    finalLen = ((framePtr - pkt) + 8);
    mConnectionState = SERVER_STATE_1RTT;
    mStreamState->mUnAckedData.clear();
    assert(mStreamState->mConnUnWritten.empty());
    if (mConnEventCB) {
      mConnEventCB(mClosure, MOZQUIC_EVENT_ERROR, this);
    }
  } else {
    uint32_t room = endpkt - framePtr - 8; // the last 8 are for checksum
    uint32_t used;
    if (AckPiggyBack(framePtr, mNextTransmitPacketNumber, room, keyPhaseUnprotected, used) == MOZQUIC_OK) {
      if (used) {
        AckLog6("Handy-Ack FlushStream0 packet %lX frame-len=%d\n", mNextTransmitPacketNumber, used);
      }
      framePtr += used;
    }
    finalLen = ((framePtr - pkt) + 8);
  }

  if (framePtr != (pkt + 17)) {
    uint32_t paddingNeeded = finalLen - 8 - (framePtr - pkt);
    memset (framePtr, 0, paddingNeeded);
    framePtr += paddingNeeded;

    // then 8 bytes of checksum on cleartext packets
    assert (kFNV64Size == 8);
    uint64_t hash = fnv1a(pkt, finalLen - kFNV64Size);
    hash = PR_htonll(hash);
    memcpy(framePtr, &hash, kFNV64Size);
    uint32_t code = Transmit(pkt, finalLen, nullptr);
    if (code != MOZQUIC_OK) {
      return code;
    }

    HandshakeLog5("TRANSMIT0[%lX] this=%p len=%d total0=%d\n",
                  mNextTransmitPacketNumber, this, finalLen,
                  mNextTransmitPacketNumber - mOriginalTransmitPacketNumber);
    mNextTransmitPacketNumber++;

    if (sentStream && !mStreamState->mConnUnWritten.empty()) {
      return FlushStream0(false);
    }
  }
  return MOZQUIC_OK;
}
uint32_t
MozQuic::ProcessServerStatelessRetry(unsigned char *pkt, uint32_t pktSize, LongHeaderData &header)
{
  // check packet num and version
  assert(pkt[0] & 0x80);
  assert((pkt[0] & ~0x80) == PACKET_TYPE_SERVER_STATELESS_RETRY);
  assert(pktSize >= 17);

  if (!mIsClient) {
    HandshakeLog1("SSR should only arrive at client. Ignore.\n");
    return MOZQUIC_OK;
  }

  if (mReceivedServerClearText) {
    HandshakeLog1("SSR not allowed after server cleartext.\n");
    return MOZQUIC_OK;
  }

  if ((header.mVersion != mVersion) ||
      (header.mConnectionID != mConnectionID)) {
    // this was supposedly copied from client - so this isn't a match
    HandshakeLog1("version or cid mismatch\n");
    return MOZQUIC_ERR_VERSION;
  }

  // essentially this is an ack of client_initial using the packet #
  // in the header as the ack, so need to find that on the unacked list.
  // then we can reset the unacked list
  bool foundReference = false;
  for (auto i = mStreamState->mUnAckedData.begin(); i != mStreamState->mUnAckedData.end(); i++) {
    if ((*i)->mPacketNumber == header.mPacketNumber) {
      foundReference = true;
      break;
    }
  }
  if (!foundReference) {
    // packet num was supposedly copied from client - so no match
    return MOZQUIC_ERR_VERSION;
  }

  mStreamState->mStream0.reset(new StreamPair(0, this, mStreamState.get(),
                                              kMaxStreamDataDefault,
                                              mStreamState->mLocalMaxStreamData));
  mSetupTransportExtension = false;
  mStreamState->mUnAckedData.clear();
  mStreamState->mConnUnWritten.clear();
  SetInitialPacketNumber();

  bool sendack = false;
  return ProcessGeneralDecoded(pkt + 17, pktSize - 17 - 8, sendack, true);
}

uint32_t
MozQuic::ProcessVersionNegotiation(unsigned char *pkt, uint32_t pktSize, LongHeaderData &header)
{
  // check packet num and version
  assert(pkt[0] & 0x80);
  assert((pkt[0] & ~0x80) == PACKET_TYPE_VERSION_NEGOTIATION);
  assert(pktSize >= 17);
  unsigned char *framePtr = pkt + 17;

  if (!mIsClient) {
    HandshakeLog1("VN should only arrive at client. Ignore.\n");
    return MOZQUIC_OK;
  }

  if (mReceivedServerClearText) {
    HandshakeLog1("VN not allowed after server cleartext.\n");
    return MOZQUIC_OK;
  }

  if (mProcessedVN) {
    HandshakeLog1("only handle one VN per session\n");
    return MOZQUIC_OK;
  }

  if ((header.mVersion != mVersion) ||
      (header.mConnectionID != mConnectionID)) {
    // this was supposedly copied from client - so this isn't a match
    return MOZQUIC_ERR_VERSION;
  }

  // essentially this is an ack of client_initial using the packet #
  // in the header as the ack, so need to find that on the unacked list.
  // then we can reset the unacked list
  bool foundReference = false;
  for (auto i = mStreamState->mUnAckedData.begin(); i != mStreamState->mUnAckedData.end(); i++) {
    if ((*i)->mPacketNumber == header.mPacketNumber) {
      foundReference = true;
      break;
    }
  }
  if (!foundReference) {
    // packet num was supposedly copied from client - so no match
    return MOZQUIC_ERR_VERSION;
  }

  uint16_t numVersions = ((pktSize) - 17) / 4;
  if ((numVersions << 2) != (pktSize - 17)) {
    RaiseError(MOZQUIC_ERR_VERSION, (char *)"negotiate version packet format incorrect\n");
    return MOZQUIC_ERR_VERSION;
  }

  uint32_t newVersion = 0;
  for (uint16_t i = 0; i < numVersions; i++) {
    uint32_t possibleVersion;
    memcpy((unsigned char *)&possibleVersion, framePtr, 4);
    framePtr += 4;
    possibleVersion = ntohl(possibleVersion);
    // todo this does not give client any preference
    if (mVersion == possibleVersion) {
       HandshakeLog1("Ignore version negotiation packet that offers version "
                     "a client selected.\n");
      return MOZQUIC_OK;
    } else if (!newVersion && VersionOK(possibleVersion)) {
      newVersion = possibleVersion;
    }
  }

  if (newVersion) {
    mVersion = newVersion;
    HandshakeLog2("negotiated version %X\n", mVersion);
    mNSSHelper.reset(new NSSHelper(this, mTolerateBadALPN, mOriginName.get(), true));
    mStreamState->mStream0.reset(new StreamPair(0, this, mStreamState.get(),
                                                kMaxStreamDataDefault,
                                                mStreamState->mLocalMaxStreamData));
    mSetupTransportExtension  = false;
    mStreamState->mUnAckedData.clear();
    
    return MOZQUIC_OK;
  }

  RaiseError(MOZQUIC_ERR_VERSION, (char *)"unable to negotiate version\n");
  return MOZQUIC_ERR_VERSION;
}

int
MozQuic::ProcessServerCleartext(unsigned char *pkt, uint32_t pktSize,
                                LongHeaderData &header, bool &sendAck)
{
  // cleartext is always in long form
  assert(pkt[0] & 0x80);
  assert((pkt[0] & 0x7f) == PACKET_TYPE_SERVER_CLEARTEXT);
  assert(pktSize >= 17);

  if (!mIsClient) {
    HandshakeLog1("server cleartext arrived at server. ignored.\n");
    return MOZQUIC_OK;
  }

  if (mConnectionState != CLIENT_STATE_1RTT &&
      mConnectionState != CLIENT_STATE_0RTT) {
    HandshakeLog1("clear text after handshake will be dropped.\n");
    return MOZQUIC_OK;
  }

  if (header.mVersion != mVersion) {
    HandshakeLog1("wrong version\n");
    return MOZQUIC_ERR_GENERAL;
    // this should not abort session as its
    // not authenticated
  }

  if (mConnectionID != header.mConnectionID) {
    if (mReceivedServerClearText) {
      HandshakeLog1("wrong connection id\n");
      return MOZQUIC_ERR_GENERAL;
      // this should not abort session as its
      // not authenticated
    }

    HandshakeLog4("server clear text changed connID to %lx\n",
            header.mConnectionID);
    mConnectionID = header.mConnectionID;
  }
  mReceivedServerClearText = true;

  return ProcessGeneralDecoded(pkt + 17, pktSize - 17 - 8, sendAck, true);
}

int
MozQuic::ProcessClientInitial(unsigned char *pkt, uint32_t pktSize,
                              struct sockaddr_in *clientAddr,
                              LongHeaderData &header,
                              MozQuic **childSession,
                              bool &sendAck)
{
  // this is always in long header form
  assert(pkt[0] & 0x80);
  assert((pkt[0] & 0x7f) == PACKET_TYPE_CLIENT_INITIAL);
  assert(pktSize >= 17);
  assert(!mIsChild);

  *childSession = nullptr;
  if (mConnectionState != SERVER_STATE_LISTEN) {
    return MOZQUIC_ERR_GENERAL ;
  }
  if (mIsClient) {
    return MOZQUIC_ERR_GENERAL;
  }

  if (pktSize < kMinClientInitial) {
    RaiseError(MOZQUIC_ERR_GENERAL, (char *)"client initial packet too small\n");
    return MOZQUIC_ERR_GENERAL;
  }

  mVersion = header.mVersion;

  // Check whether this is an dup.
  auto i = mConnectionHashOriginalNew.find(header.mConnectionID);
  if (i != mConnectionHashOriginalNew.end()) {
    if ((*i).second.mTimestamp < (Timestamp() - kForgetInitialConnectionIDsThresh)) {
      // This connectionId is too old, just remove it.
      mConnectionHashOriginalNew.erase(i);
    } else {
      auto j = mConnectionHash.find((*i).second.mServerConnectionID);
      if (j != mConnectionHash.end()) {
        *childSession = (*j).second;
        // It is a dup and we will ignore it.
        return MOZQUIC_OK;
      } else {
        // TODO maybe do not accept this: we received a dup of connectionId
        // during kForgetInitialConnectionIDsThresh but we do not have a
        // session, i.e. session is terminated.
        mConnectionHashOriginalNew.erase(i);
      }
    }
  }
  MozQuic *child = Accept(clientAddr, header.mConnectionID, header.mPacketNumber);
  assert(!mIsChild);
  assert(!mIsClient);
  mChildren.emplace_back(child->mAlive);
  child->ProcessGeneralDecoded(pkt + 17, pktSize - 17 - 8, sendAck, true);
  child->mConnectionState = SERVER_STATE_1RTT;

  if (mConnEventCB) {
    mConnEventCB(mClosure, MOZQUIC_EVENT_ACCEPT_NEW_CONNECTION, child);
  } else {
    HandshakeLog9("No Event callback\n");
  }
  *childSession = child;
  return MOZQUIC_OK;
}

int
MozQuic::ProcessClientCleartext(unsigned char *pkt, uint32_t pktSize, LongHeaderData &header, bool &sendAck)
{
  // this is always with a long header
  assert(pkt[0] & 0x80);
  assert((pkt[0] & 0x7f) == PACKET_TYPE_CLIENT_CLEARTEXT);
  assert(pktSize >= 17);
  assert(mIsChild);

  assert(!mIsClient);
  assert(mStreamState->mStream0);

  if (header.mVersion != mVersion) {
    RaiseError(MOZQUIC_ERR_GENERAL, (char *)"version mismatch\n");
    return MOZQUIC_ERR_GENERAL;
  }

  return ProcessGeneralDecoded(pkt + 17, pktSize - 17 - 8, sendAck, true);
}

uint32_t
MozQuic::GenerateVersionNegotiation(LongHeaderData &clientHeader, struct sockaddr_in *peer)
{
  assert(!mIsChild);
  assert(!mIsClient);
  assert(mMTU <= kMaxMTU);
  unsigned char pkt[kMaxMTU];
  uint32_t tmp32;
  uint64_t tmp64;

  HandshakeLog5("sending a version negotiation packet\n");
  pkt[0] = 0x80 | PACKET_TYPE_VERSION_NEGOTIATION;
  // client connID echo'd from client
  tmp64 = PR_htonll(clientHeader.mConnectionID);
  memcpy(pkt + 1, &tmp64, 8);

  // 32 packet number echo'd from client
  tmp32 = htonl(clientHeader.mPacketNumber);
  memcpy(pkt + 9, &tmp32, 4);

  // 32 version echo'd from client
  tmp32 = htonl(clientHeader.mVersion);
  memcpy(pkt + 13, &tmp32, 4);

  // list of versions
  unsigned char *framePtr = pkt + 17;
  assert (sizeof(VersionNegotiationList) <= mMTU - 17);
  for (int i = 0; i < sizeof(VersionNegotiationList) / sizeof(uint32_t); i++) {
    tmp32 = htonl(VersionNegotiationList[i]);
    memcpy (framePtr, &tmp32, sizeof(uint32_t));
    framePtr += sizeof(uint32_t);
  }
  if (mSabotageVN) {
    // redo the list of version backwards as a test
    framePtr = pkt + 17;
    HandshakeLog6("Warning generating incorrect version negotation list for testing\n");
    for (int i = (sizeof(VersionNegotiationList) / sizeof(uint32_t)) - 1; i >= 0; i--) {
      tmp32 = htonl(VersionNegotiationList[i]);
      memcpy (framePtr, &tmp32, sizeof(uint32_t));
      framePtr += sizeof(uint32_t);
    }
  }

  return Transmit(pkt, framePtr - pkt, peer);
}

}
