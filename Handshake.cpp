/* -*- Mode: C++; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*-
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "Logging.h"
#include "MozQuic.h"
#include "MozQuicInternal.h"
#include "NSSHelper.h"
#include "Sender.h"
#include "Streams.h"

#include <assert.h>
#include <stdlib.h>
#include <unistd.h>

namespace mozquic  {

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

bool
MozQuic::IntegrityCheck(unsigned char *pkt, uint32_t pktSize,
                        uint64_t pktNum, uint64_t connID,
                        unsigned char *outbuf, uint32_t &outSize)
{
  assert (pkt[0] & 0x80); // long form
  assert (((pkt[0] & 0x7f) == PACKET_TYPE_INITIAL) ||
          ((pkt[0] & 0x7f) == PACKET_TYPE_RETRY) ||
          ((pkt[0] & 0x7f) == PACKET_TYPE_HANDSHAKE));
  assert (pktSize >= 17);

  if (!mNSSHelper) {
    MozQuic *tmpSession = FindSession(connID);
    if (tmpSession) {
      assert (tmpSession->mNSSHelper);
      return tmpSession->IntegrityCheck(pkt, pktSize, pktNum, connID, outbuf, outSize);
    }
  }

  assert(mOriginalConnectionID || ((pkt[0] & 0x7f) == PACKET_TYPE_INITIAL));
  if ((pkt[0] & 0x7f) != PACKET_TYPE_INITIAL) {
    if (!mOriginalConnectionID) {
      ConnectionLog1("Decrypt handshake failed %lX not initial and unknown connid\n", pktNum);
      return false;
    }
    connID = mOriginalConnectionID;
  }

  uint32_t rv;
  if (mNSSHelper) {
    rv = mNSSHelper->DecryptHandshake(pkt, 17, pkt + 17, pktSize - 17, pktNum, connID,
                                      outbuf + 17, kMozQuicMSS - 17, outSize);
  } else {
    assert ((pkt[0] & 0x7f) == PACKET_TYPE_INITIAL || (pkt[0] & 0x7f) == PACKET_TYPE_RETRY);
    rv = NSSHelper::staticDecryptHandshake(pkt, 17, pkt + 17, pktSize - 17, pktNum, connID,
                                           outbuf + 17, kMozQuicMSS - 17, outSize);
  }
    
  if (rv != MOZQUIC_OK) {
    ConnectionLog1("Decrypt handshake failed packet %lX integrity error\n", pktNum);
    return false;
  }
  memcpy(outbuf, pkt, 17);
  outSize += 17;
  ConnectionLog5("Decrypt handshake (pktnum=%lX) ok sz=%d\n", pktNum, outSize);
  return true;
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
    pkt[0] |=
      (mConnectionState == SERVER_STATE_SSR) ? PACKET_TYPE_RETRY : PACKET_TYPE_HANDSHAKE;
  } else {
    pkt[0] |= mReceivedServerClearText ? PACKET_TYPE_HANDSHAKE : PACKET_TYPE_INITIAL;
  }

  if ((pkt[0] & 0x7f) == PACKET_TYPE_INITIAL) {
    assert(mStreamState->mStream0->Empty());
    // just in case of server stateless reset pollution
    mStreamState->mStream0->ResetInbound();
  }

  // todo store a network order version of this
  uint64_t connID = PR_htonll(mConnectionID);
  if (mConnectionState == SERVER_STATE_SSR) {
    HandshakeLog4("Generating Server Stateless Retry.\n");
    assert(mStreamState->mUnAckedPackets.empty());
  }
  memcpy(pkt + 1, &connID, 8);
  connID = PR_ntohll(connID);

  tmp32 = htonl(mVersion);
  memcpy(pkt + 9, &tmp32, 4);
  tmp32 = htonl(mNextTransmitPacketNumber & 0xffffffff);
  if (mConnectionState == SERVER_STATE_SSR) {
    tmp32 = htonl(mClientInitialPacketNumber & 0xffffffff);
  }
  uint32_t usedPacketNumber = ntohl(tmp32);
  memcpy(pkt + 13, &tmp32, 4);

  std::unique_ptr<TransmittedPacket> packet(new TransmittedPacket(mNextTransmitPacketNumber));
  unsigned char *framePtr = pkt + 17;
  mStreamState->CreateFrames(framePtr, endpkt - 16, true, packet.get()); // last 16 are aead tag
  bool sentStream = (framePtr != (pkt + 17));

  // then padding as needed up to mtu on client_initial
  uint32_t paddingNeeded = 0;
  bool bareAck = false;

  if ((pkt[0] & 0x7f) == PACKET_TYPE_INITIAL) {
    if (((framePtr - pkt) + 16) < kMinClientInitial) {
      paddingNeeded = kMinClientInitial - ((framePtr - pkt) + 16);
    }
  } else if (mConnectionState == SERVER_STATE_SSR) {
    mConnectionState = SERVER_STATE_1RTT;
    mStreamState->mUnAckedPackets.clear();
    assert(mStreamState->mConnUnWritten.empty());
    if (mConnEventCB) {
      mConnEventCB(mClosure, MOZQUIC_EVENT_ERROR, this);
    }
  } else {
    uint32_t room = endpkt - framePtr - 16; // the last 16 are for aead tag
    uint32_t used;
    bareAck = framePtr == (pkt + 17);
    if (AckPiggyBack(framePtr, mNextTransmitPacketNumber, room, keyPhaseUnprotected,
                     bareAck, used) == MOZQUIC_OK) {
      if (used) {
        AckLog6("Handy-Ack FlushStream0 packet %lX frame-len=%d\n", mNextTransmitPacketNumber, used);
      }
      framePtr += used;
    }
  }

  if (framePtr != (pkt + 17)) {
    assert(framePtr > (pkt + 17));
    memset (framePtr, 0, paddingNeeded);
    framePtr += paddingNeeded;

    unsigned char cipherPkt[kMozQuicMSS];
    uint32_t cipherLen = 0;
    memcpy(cipherPkt, pkt, 17);

    assert(mOriginalConnectionID);
    uint32_t rv = mNSSHelper->EncryptHandshake(pkt, 17, pkt + 17, framePtr - (pkt + 17),
                                               usedPacketNumber, mOriginalConnectionID,
                                               cipherPkt + 17, kMozQuicMSS - 17, cipherLen);
    if (rv != MOZQUIC_OK) {
      HandshakeLog1("TRANSMIT0[%lX] this=%p Encrypt Fail %x\n",
                    usedPacketNumber, this, rv);
      return rv;
    }
    assert (cipherLen == (framePtr - (pkt + 17)) + 16);
    uint32_t code = mSendState->Transmit(mNextTransmitPacketNumber, bareAck, false,
                                         packet->mQueueOnTransmit,
                                         cipherPkt, cipherLen + 17, nullptr);
    if (code != MOZQUIC_OK) {
      HandshakeLog1("TRANSMIT0[%lX] this=%p Transmit Fail %x\n",
                    usedPacketNumber, this, rv);
      return code;
    }
    packet->mTransmitTime = MozQuic::Timestamp();
    packet->mPacketLen = cipherLen + 17;
    mStreamState->mUnAckedPackets.push_back(std::move(packet));

    if (!bareAck) {
      assert(mHighestTransmittedAckable <= mNextTransmitPacketNumber);
      mHighestTransmittedAckable = mNextTransmitPacketNumber;
    }

    Log::sDoLogCID(Log::HANDSHAKE, 5, this, connID,
                   "TRANSMIT0[%lX] this=%p len=%d total0=%d byte0=%x\n",
                   usedPacketNumber, this, cipherLen + 17,
                   mNextTransmitPacketNumber - mOriginalTransmitPacketNumber,
                   cipherPkt[0]);

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
  assert((pkt[0] & ~0x80) == PACKET_TYPE_RETRY);
  assert(pktSize >= 17);

  if (!mIsClient) {
    HandshakeLog1("SSR should only arrive at client. Ignore.\n");
    return MOZQUIC_OK;
  }

  if (mReceivedServerClearText) {
    HandshakeLog1("SSR not allowed after server cleartext.\n");
    return MOZQUIC_OK;
  }

  if (header.mVersion != mVersion) {
    // this was supposedly copied from client - so this isn't a match
    HandshakeLog1("version mismatch\n");
    return MOZQUIC_ERR_VERSION;
  }

  if (header.mConnectionID != mConnectionID) {
    HandshakeLog4("server RETRY changed connID to %lx\n",
                  header.mConnectionID);
    mConnectionID = header.mConnectionID;
    mOriginalConnectionID = mConnectionID; // because its stateless
  }

  // essentially this is an ack of client_initial using the packet #
  // in the header as the ack, so need to find that on the unacked list.
  // then we can reset the unacked list
  bool foundReference = false;
  for (auto i = mStreamState->mUnAckedPackets.begin(); i != mStreamState->mUnAckedPackets.end(); i++) {
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
                                              mStreamState->mLocalMaxStreamData,
                                              false));
  mSetupTransportExtension = false;
  mConnectionState = CLIENT_STATE_1RTT;
  mStreamState->Reset0RTTData();
  mStreamState->mUnAckedPackets.clear();
  mStreamState->mConnUnWritten.clear();
  SetInitialPacketNumber();

  bool sendack = false;
  return ProcessGeneralDecoded(pkt + 17, pktSize - 17, sendack, true);
}

uint32_t
MozQuic::ProcessVersionNegotiation(unsigned char *pkt, uint32_t pktSize, LongHeaderData &header)
{
  // check packet num and version
  assert(pkt[0] & 0x80);
  assert(header.mVersion == 0);
  assert(pktSize >= 17);
  unsigned char *framePtr = pkt + 13;

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

  if ((header.mVersion != 0) ||
      (header.mConnectionID != mConnectionID)) {
    // this was supposedly copied from client - so this isn't a match
    return MOZQUIC_ERR_VERSION;
  }

  uint32_t numVersions = ((pktSize) - 13) / 4;
  if ((numVersions << 2) != (pktSize - 13)) {
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
                                                mStreamState->mLocalMaxStreamData,
                                                false));
    mSetupTransportExtension  = false;
    mConnectionState = CLIENT_STATE_1RTT;
    mStreamState->Reset0RTTData();
    mStreamState->mUnAckedPackets.clear();

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
  assert((pkt[0] & 0x7f) == PACKET_TYPE_HANDSHAKE);
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
    Shutdown(ERROR_VERSION_NEGOTIATION, "wrong version\n");
    return MOZQUIC_ERR_GENERAL;
  }

  if (mConnectionID != header.mConnectionID) {
    if (mReceivedServerClearText) {
      HandshakeLog1("wrong connection id\n");
      Shutdown(PROTOCOL_VIOLATION, "wrong connection id\n");
      return MOZQUIC_ERR_GENERAL;
    }

    HandshakeLog4("server HANDSHAKE changed connID to %lx\n",
                  header.mConnectionID);
    mConnectionID = header.mConnectionID;
  }
  mReceivedServerClearText = true;

  uint32_t rv = ProcessGeneralDecoded(pkt + 17, pktSize - 17, sendAck, true);
  if (rv != MOZQUIC_OK) {
    Shutdown(PROTOCOL_VIOLATION, "handshake decode issue\n");
  }
  return rv;
}

int
MozQuic::ProcessClientInitial(unsigned char *pkt, uint32_t pktSize,
                              const struct sockaddr *clientAddr,
                              LongHeaderData &header,
                              MozQuic **childSession,
                              bool &sendAck)
{
  // this is always in long header form
  assert(pkt[0] & 0x80);
  assert((pkt[0] & 0x7f) == PACKET_TYPE_INITIAL);
  assert(pktSize >= 17);
  assert(!mIsChild);

  *childSession = nullptr;
  if (mConnectionState != SERVER_STATE_LISTEN) {
    return MOZQUIC_ERR_GENERAL ;
  }
  if (mIsClient) {
    return MOZQUIC_ERR_GENERAL;
  }

  if (pktSize < (kMinClientInitial - 16)) {
    RaiseError(MOZQUIC_ERR_GENERAL, (char *)"client initial packet too small\n");
    // do not send close for this one because of ddos concerns
    return MOZQUIC_ERR_GENERAL;
  }

  mVersion = header.mVersion;

  // Check whether this is an dup.
  auto i = mConnectionHashOriginalNew.find(header.mConnectionID);
  if (i != mConnectionHashOriginalNew.end()) {
    if ((*i).second->mTimestamp <= (Timestamp() - kForgetInitialConnectionIDsThresh)) {
      // This connectionId is too old, just remove it.
      mConnectionHashOriginalNew.erase(i);
    } else {
      auto j = mConnectionHash.find((*i).second->mServerConnectionID);
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
  child->ProcessGeneralDecoded(pkt + 17, pktSize - 17, sendAck, true);
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
  assert((pkt[0] & 0x7f) == PACKET_TYPE_HANDSHAKE);
  assert(pktSize >= 17);
  assert(mIsChild);

  assert(!mIsClient);
  assert(mStreamState->mStream0);

  if (header.mVersion != mVersion) {
    RaiseError(MOZQUIC_ERR_GENERAL, (char *)"version mismatch\n");
    Shutdown(PROTOCOL_VIOLATION, "handshake decode issue\n");
    return MOZQUIC_ERR_GENERAL;
  }

  uint32_t rv = ProcessGeneralDecoded(pkt + 17, pktSize - 17, sendAck, true);
  if (rv != MOZQUIC_OK) {
    Shutdown(PROTOCOL_VIOLATION, "handshake decode issue\n");
  }
  return rv;
}

uint32_t
MozQuic::GenerateVersionNegotiation(LongHeaderData &clientHeader, const struct sockaddr *peer)
{
  assert(!mIsChild);
  assert(!mIsClient);
  assert(mMTU <= kMaxMTU);
  unsigned char pkt[kMaxMTU];
  uint32_t tmp32;
  uint64_t tmp64;

  pkt[0] = 0x80 | (random() & 0xff);
  HandshakeLog5("sending a version negotiation packet type =%X\n", pkt[0]);
  // client connID echo'd from client
  tmp64 = PR_htonll(clientHeader.mConnectionID);
  memcpy(pkt + 1, &tmp64, 8);

  // version is 0 to signal VN
  memset(pkt + 9, 0, 4);

  // list of versions
  unsigned char *framePtr = pkt + 13;
  assert (sizeof(VersionNegotiationList) <= mMTU - 13);
  for (uint32_t i = 0; i < sizeof(VersionNegotiationList) / sizeof(uint32_t); i++) {
    tmp32 = htonl(VersionNegotiationList[i]);
    memcpy (framePtr, &tmp32, sizeof(uint32_t));
    framePtr += sizeof(uint32_t);
  }

  if (mSabotageVN) {
    // redo the list of version backwards as a test
    framePtr = pkt + 13;
    HandshakeLog6("Warning generating incorrect version negotation list for testing\n");
    for (int i = (sizeof(VersionNegotiationList) / sizeof(uint32_t)) - 1; i >= 0; i--) {
      tmp32 = htonl(VersionNegotiationList[i]);
      memcpy (framePtr, &tmp32, sizeof(uint32_t));
      framePtr += sizeof(uint32_t);
    }
  }

  return mSendState->Transmit(clientHeader.mPacketNumber, true, false, false,
                              pkt, framePtr - pkt, peer);
}

}
