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
extern std::unordered_map<std::string, uint32_t> mVNHash;

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
MozQuic::IntegrityCheck(unsigned char *pkt, uint32_t pktSize, uint32_t headerSize,
                        CID handshakeCID, uint64_t packetNumber, unsigned char *outbuf, uint32_t &outSize)
{
  assert (pkt[0] & 0x80); // long form
  assert (((pkt[0] & 0x7f) == PACKET_TYPE_INITIAL) ||
          ((pkt[0] & 0x7f) == PACKET_TYPE_RETRY) ||
          ((pkt[0] & 0x7f) == PACKET_TYPE_HANDSHAKE));

  uint32_t rv;
  if (mNSSHelper) {
    rv = mNSSHelper->DecryptHandshake(pkt, headerSize, pkt + headerSize, pktSize - headerSize,
                                      packetNumber,
                                      handshakeCID, outbuf + headerSize, kMozQuicMSS - headerSize, outSize);
  } else {
    // need longheader.mdestcid
    assert ((pkt[0] & 0x7f) == PACKET_TYPE_INITIAL || (pkt[0] & 0x7f) == PACKET_TYPE_RETRY);
    rv = NSSHelper::staticDecryptHandshake(pkt, headerSize, pkt + headerSize, pktSize - headerSize,
                                           packetNumber,
                                           handshakeCID, outbuf + headerSize, kMozQuicMSS - headerSize, outSize);
  }
    
  if (rv != MOZQUIC_OK) {
    ConnectionLog1("Decrypt handshake failed packet %lX integrity error\n", packetNumber);
    return false;
  }
  memcpy(outbuf, pkt, headerSize);
  outSize += headerSize;
  ConnectionLog5("Decrypt handshake (packetNumber=%lX) ok sz=%d\n", packetNumber, outSize);
  return true;
}

void
MozQuic::EncodePN(uint32_t pn, uint8_t *framePtr, size_t &outPNLen)
{
  if (pn >= 128) {
    uint32_t tmp32 = htonl(pn & 0x3fffffff);
    memcpy(framePtr, &tmp32, 4);
    *framePtr = *framePtr | 0xC0; // 4 byte number
    outPNLen = 4;
  } else {
    // 1 byte PN
    *framePtr = pn;
    assert( (*framePtr & 0x80) == 0);
    outPNLen = 1;
  }
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
  unsigned char *framePtr = pkt;
  uint32_t tmp32;
  uint32_t rv;
  uint32_t used;

  // section 4.1 of transport
  pkt[0] = 0x80;
  framePtr++;
  if (ServerState()) {
    pkt[0] |=
      (mConnectionState == SERVER_STATE_SSR) ? PACKET_TYPE_RETRY : PACKET_TYPE_HANDSHAKE;
  } else {
    pkt[0] |= mReceivedServerClearText ? PACKET_TYPE_HANDSHAKE : PACKET_TYPE_INITIAL;
  }

  if ((pkt[0] & 0x7f) == PACKET_TYPE_INITIAL) {
    // stateless retry and 0rtt can send us down this road
    mStreamState->mStream0->ResetInbound();
  }

  if (mConnectionState == SERVER_STATE_SSR) {
    HandshakeLog4("Generating Server Stateless Retry.\n");
    assert(mStreamState->mUnAckedPackets.empty());
  }

  tmp32 = htonl(mVersion);
  memcpy(framePtr, &tmp32, 4);
  framePtr += 4;

  rv = CID::FormatLongHeader(mPeerCID, mLocalCID, mLocalOmitCID,
                             framePtr, endpkt - framePtr, used);
  if (rv != MOZQUIC_OK) return rv;
  framePtr += used;

  unsigned char *payloadLenPtr = framePtr;
  if ((endpkt - framePtr) < 2) {
    return MOZQUIC_ERR_GENERAL;
  }
  framePtr += 2;
  
  uint32_t usedPacketNumber = (mConnectionState == SERVER_STATE_SSR) ?
    0 : mNextTransmitPacketNumber;

  size_t pnLen;
  const unsigned char *pnPtr = framePtr;
  EncodePN(usedPacketNumber, framePtr, pnLen);
  framePtr += pnLen;

  std::unique_ptr<TransmittedPacket> packet(new TransmittedPacket(mNextTransmitPacketNumber));
  unsigned char *emptyFramePtr = framePtr;
  mStreamState->CreateFrames(framePtr, endpkt - 16, true, packet.get()); // last 16 are aead tag
  bool sentStream = (framePtr != emptyFramePtr);

  // then padding as needed up to mtu on client_initial
  uint32_t paddingNeeded = 0;
  bool bareAck = false;

  if ((pkt[0] & 0x7f) == PACKET_TYPE_INITIAL) {
    if (((framePtr - pkt) + 16) < kMinClientInitial) {
      paddingNeeded = kMinClientInitial - ((framePtr - pkt) + 16);
    }
  } else {
    if (mConnectionState == SERVER_STATE_SSR) {
      mConnectionState = SERVER_STATE_1RTT;
      mStreamState->mUnAckedPackets.clear();
      assert(mStreamState->mConnUnWritten.empty());
      if (mConnEventCB) {
        mConnEventCB(mClosure, MOZQUIC_EVENT_ERROR, this);
      }
    }

    uint32_t room = endpkt - framePtr - 16; // the last 16 are for aead tag
    bareAck = framePtr == emptyFramePtr;
    if (AckPiggyBack(framePtr, mNextTransmitPacketNumber, room, keyPhaseUnprotected,
                     bareAck, used) == MOZQUIC_OK) {
      if (used) {
        AckLog6("Handy-Ack FlushStream0 packet %lX frame-len=%d\n", mNextTransmitPacketNumber, used);
      }
      framePtr += used;
    }
  }

  if (framePtr != emptyFramePtr) {
    assert(framePtr > emptyFramePtr);
    memset (framePtr, 0, paddingNeeded);
    framePtr += paddingNeeded;

    unsigned char cipherPkt[kMozQuicMSS];
    uint32_t cipherLen = 0;
    uint32_t headerLen = emptyFramePtr - pkt;

    // fill in payload length with expected cipherLen
    uint16_t payloadLen = (uint16_t)(framePtr - emptyFramePtr) + 16;;
    payloadLen |= 0x4000;
    payloadLen = htons(payloadLen);
    memcpy(payloadLenPtr, &payloadLen, 2);
    memcpy(cipherPkt, pkt, headerLen);

    assert(mHandshakeCID);
    uint32_t rv = mNSSHelper->EncryptHandshake(pkt, headerLen, pkt + headerLen, framePtr - emptyFramePtr,
                                               usedPacketNumber,
                                               mHandshakeCID, cipherPkt + headerLen, kMozQuicMSS - headerLen, cipherLen);
    if (rv != MOZQUIC_OK) {
      HandshakeLog1("TRANSMIT0[%lX] this=%p Encrypt Fail %x\n",
                    usedPacketNumber, this, rv);
      return rv;
    }
    assert (cipherLen == (framePtr - emptyFramePtr) + 16);
    assert(cipherLen < 16383);
    
    // packet number encryption
    assert(cipherPkt + (pnPtr - pkt) + 4 >= cipherPkt + headerLen); // pn + 4 is in ciphertext
    assert(cipherPkt + (pnPtr - pkt) + 4 <= cipherPkt + headerLen + cipherLen);
    
    EncryptPNInPlace(kEncryptHandshake, cipherPkt + (pnPtr - pkt),
                     cipherPkt + (pnPtr - pkt) + 4,
                     (cipherPkt + headerLen + cipherLen) - (cipherPkt + (pnPtr - pkt) + 4));
    
    uint32_t code = mSendState->Transmit(mNextTransmitPacketNumber, bareAck, false,
                                         packet->mQueueOnTransmit,
                                         cipherPkt, cipherLen + headerLen, nullptr);
    if (code != MOZQUIC_OK) {
      HandshakeLog1("TRANSMIT0[%lX] this=%p Transmit Fail %x\n",
                    usedPacketNumber, this, rv);
      return code;
    }
    packet->mTransmitTime = MozQuic::Timestamp();
    packet->mPacketLen = cipherLen + headerLen;
    mStreamState->mUnAckedPackets.push_back(std::move(packet));

    if (!bareAck) {
      assert(mHighestTransmittedAckable <= mNextTransmitPacketNumber);
      mHighestTransmittedAckable = mNextTransmitPacketNumber;
    }

    Log::sDoLog(Log::HANDSHAKE, 5, this,
                "TRANSMIT0[%lX] this=%p len=%d total0=%d byte0=%x\n",
                usedPacketNumber, this, cipherLen + headerLen,
                mNextTransmitPacketNumber,
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
  assert(mIsClient);

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

  if (header.mSourceCID != ServerCID()) {
    HandshakeLog4("server RETRY sets server connID to %s\n",
                  header.mSourceCID.Text());
    mPeerCID = header.mSourceCID;
    mHandshakeCID = header.mSourceCID; // because its stateless
  }

  if (header.mPacketNumber != 0) {
    HandshakeLog4("RETRY failed because packet number was not 0\n");
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
  return ProcessGeneralDecoded(pkt + header.mHeaderSize, pktSize - header.mHeaderSize, sendack, true);
}

uint32_t
MozQuic::ProcessVersionNegotiation(unsigned char *pkt, uint32_t pktSize, LongHeaderData &header)
{
  // check packet num and version
  assert(pkt[0] & 0x80);
  assert(header.mVersion == 0);

  unsigned char *framePtr = pkt + header.mHeaderSize;

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

  if (header.mVersion != 0) {
    return MOZQUIC_ERR_VERSION;
  }

  if ((header.mDestCID != mLocalCID) &&
      (!mLocalOmitCID || header.mDestCID.Len())) {
    // this was supposedly copied from client - so this isn't a match
    return MOZQUIC_ERR_VERSION;
  }
  
  uint32_t numVersions = ((pktSize) - header.mHeaderSize) / 4;
  if ((numVersions << 2) != (pktSize - header.mHeaderSize)) {
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
    
    std::string key(mOriginName.get());
    auto iter = mVNHash.find(key);
    if (iter != mVNHash.end()) {
      mVNHash.erase(iter);
    }
    mVNHash.insert({key, mVersion});

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

  assert(mLocalCID == ClientCID());

  if ((mLocalCID != header.mDestCID) &&
      (!mLocalOmitCID || header.mDestCID.Len())) {
    HandshakeLog1("wrong connection id\n");
    Shutdown(PROTOCOL_VIOLATION, "wrong connection id\n");
    return MOZQUIC_ERR_GENERAL;
  }

  if (!mReceivedServerClearText) {
    HandshakeLog4("server HANDSHAKE set connID to %s\n", header.mSourceCID.Text());
    mPeerCID = header.mSourceCID;
    mReceivedServerClearText = true;
  }

  uint32_t rv = ProcessGeneralDecoded(pkt + header.mHeaderSize, pktSize - header.mHeaderSize, sendAck, true);
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
  assert(header.mType == PACKET_TYPE_INITIAL);
  assert(!mIsChild && !mIsClient);

  *childSession = nullptr;
  if (mConnectionState != SERVER_STATE_LISTEN) {
    return MOZQUIC_ERR_GENERAL ;
  }
  if (mIsClient) {
    return MOZQUIC_ERR_GENERAL;
  }

  mVersion = header.mVersion;

  // Check whether this is an dup.
  uint64_t key = NSSHelper::SockAddrHasher(clientAddr);
  auto i = mInitialHash.find(key);
  if (i != mInitialHash.end()) {
    if ((*i).second->mTimestamp <= (Timestamp() - kForgetInitialConnectionIDsThresh)) {
      // This connectionId is too old, just remove it.
      mInitialHash.erase(i);
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
        mInitialHash.erase(i);
      }
    }
  }
  MozQuic *child = Accept(clientAddr, header.mSourceCID, header.mDestCID,
                          header.mPacketNumber);
  assert(!mIsChild);
  assert(!mIsClient);
  mChildren.emplace_back(child->mAlive);
  child->ProcessGeneralDecoded(pkt + header.mHeaderSize, pktSize - header.mHeaderSize, sendAck, true);
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
  assert(mIsChild);

  assert(!mIsClient);
  assert(mStreamState->mStream0);

  if (header.mVersion != mVersion) {
    RaiseError(MOZQUIC_ERR_GENERAL, (char *)"version mismatch\n");
    Shutdown(PROTOCOL_VIOLATION, "handshake decode issue\n");
    return MOZQUIC_ERR_GENERAL;
  }

  uint32_t rv = ProcessGeneralDecoded(pkt + header.mHeaderSize,
                                      pktSize - header.mHeaderSize, sendAck, true);
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

  unsigned char *framePtr = pkt;
  framePtr[0] = 0x80 | (random() & 0xff);
  framePtr++;
  HandshakeLog5("sending a version negotiation packet type =%X\n", pkt[0]);
  // version is 0 to signal VN
  memset(framePtr, 0, 4);
  framePtr += 4;

  CID::FormatLongHeader(clientHeader.mSourceCID, clientHeader.mDestCID, false,
                        framePtr, (pkt + mMTU - sizeof(VersionNegotiationList)) - framePtr, tmp32);
  framePtr += tmp32;

  if (mSabotageVN) {
    // redo the list of version backwards as a test
    HandshakeLog6("Warning generating incorrect version negotation list for testing\n");
    for (int i = (sizeof(VersionNegotiationList) / sizeof(uint32_t)) - 1; i >= 0; i--) {
      tmp32 = htonl(VersionNegotiationList[i]);
      memcpy (framePtr, &tmp32, sizeof(uint32_t));
      framePtr += sizeof(uint32_t);
    }
  } else {
    // normal list of versions
    for (uint32_t i = 0; i < sizeof(VersionNegotiationList) / sizeof(uint32_t); i++) {
      tmp32 = htonl(VersionNegotiationList[i]);
      memcpy (framePtr, &tmp32, sizeof(uint32_t));
      framePtr += sizeof(uint32_t);
    }
  }

  return mSendState->Transmit(clientHeader.mPacketNumber, true, false, false,
                              pkt, framePtr - pkt, peer);
}

}
