/* -*- Mode: C++; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*-
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include <array>
#include "Logging.h"
#include "MozQuic.h"
#include "MozQuicInternal.h"
#include "NSSHelper.h"
#include "Streams.h"
#include "TransportExtension.h"

#include "assert.h"
#include "netinet/ip.h"
#include "stdlib.h"
#include "unistd.h"
#include "time.h"
#include "sys/time.h"
#include <string.h>
#include <fcntl.h>
#include "prerror.h"

namespace mozquic  {

const char *MozQuic::kAlpn = MOZQUIC_ALPN;
  
static const uint16_t kIdleTimeoutDefault = 600;

MozQuic::MozQuic(bool handleIO)
  : mFD(MOZQUIC_SOCKET_BAD)
  , mHandleIO(handleIO)
  , mIsClient(true)
  , mIsChild(false)
  , mReceivedServerClearText(false)
  , mSetupTransportExtension(false)
  , mIgnorePKI(false)
  , mTolerateBadALPN(false)
  , mTolerateNoTransportParams(false)
  , mSabotageVN(false)
  , mForceAddressValidation(false)
  , mAppHandlesSendRecv(false)
  , mAppHandlesLogging(false)
  , mIsLoopback(false)
  , mProcessedVN(false)
  , mBackPressure(false)
  , mConnectionState(STATE_UNINITIALIZED)
  , mOriginPort(-1)
  , mVersion(kMozQuicVersion1)
//  , mVersion(kMozQuicIetfID5)
  , mClientOriginalOfferedVersion(0)
  , mMTU(kInitialMTU)
  , mConnectionID(0)
  , mOriginalConnectionID(0)
  , mNextTransmitPacketNumber(0)
  , mOriginalTransmitPacketNumber(0)
  , mNextRecvPacketNumber(0)
  , mClientInitialPacketNumber(0)
  , mClosure(nullptr)
  , mConnEventCB(nullptr)
  , mParent(nullptr)
  , mAlive(this)
  , mTimestampConnBegin(0)
  , mPingDeadline(0)
  , mPMTUD1Deadline(0)
  , mPMTUD1PacketNumber(0)
  , mDecodedOK(false)
  , mPeerIdleTimeout(kIdleTimeoutDefault)
  , mAdvertiseStreamWindow(kMaxStreamDataDefault)
  , mAdvertiseConnectionWindowKB(kMaxDataDefault >> 10)
  , mRemoteTransportExtensionInfoLen(0)
{
  Log::sParseSubscriptions(getenv("MOZQUIC_LOG"));
  
  assert(!handleIO); // todo
  unsigned char seed[4];
  if (SECSuccess != PK11_GenerateRandom(seed, sizeof(seed))) {
    // major badness!
    srandom(Timestamp() & 0xffffffff);
  } else {
    srandom(seed[0] << 24 | seed[1] << 16 | seed[2] << 8 | seed[3]);
  }
  memset(&mPeer, 0, sizeof(mPeer));
  memset(mStatelessResetKey, 0, sizeof(mStatelessResetKey));
  memset(mStatelessResetToken, 0x80, sizeof(mStatelessResetToken));
}

MozQuic::~MozQuic()
{
  if (!mIsChild && (mFD != MOZQUIC_SOCKET_BAD)) {
    close(mFD);
  }
}

void
MozQuic::Destroy(uint32_t code, const char *reason)
{
  Shutdown(code, reason);
  mAlive = nullptr;
}

uint32_t
MozQuic::Transmit(const unsigned char *pkt, uint32_t len, struct sockaddr_in *explicitPeer)
{
  // this would be a reasonable place to insert a queuing layer that
  // thought about cong control, flow control, priority, and pacing

  if (mAppHandlesSendRecv) {
    struct mozquic_eventdata_transmit data;
    data.pkt = pkt;
    data.len = len;
    data.explicitPeer = explicitPeer;
    return mConnEventCB(mClosure, MOZQUIC_EVENT_TRANSMIT, &data);
  }

  int rv;
  if (mIsChild || explicitPeer) {
    struct sockaddr_in *peer = explicitPeer ? explicitPeer : &mPeer;
    rv = sendto(mFD, pkt, len, 0,
                (struct sockaddr *)peer, sizeof(struct sockaddr_in));
  } else {
    rv = send(mFD, pkt, len, 0);
  }

  if (rv == -1) {
    ConnectionLog1("Sending error in transmit\n");
  }

  return MOZQUIC_OK;
}

uint32_t
MozQuic::ProtectedTransmit(unsigned char *header, uint32_t headerLen,
                           unsigned char *data, uint32_t dataLen, uint32_t dataAllocation,
                           bool addAcks, uint32_t MTU)
{
  assert(headerLen >= 11);
  assert(headerLen <= 13);

  if (!MTU) {
    MTU = mMTU;
  }
  if (addAcks) {
    uint32_t room = MTU - kTagLen - headerLen - dataLen;
    if (room > dataAllocation) {
      room = dataAllocation;
    }
    uint32_t usedByAck = 0;
    if (AckPiggyBack(data + dataLen, mNextTransmitPacketNumber, room, keyPhase1Rtt, usedByAck) == MOZQUIC_OK) {
      if (usedByAck) {
        AckLog6("Handy-Ack adds to protected Transmit packet %lX by %d\n", mNextTransmitPacketNumber, usedByAck);
      }
      dataLen += usedByAck;
    }
  }

  if (dataLen == 0) {
    ConnectionLog6("nothing to write\n");
    return MOZQUIC_OK;
  }

  uint32_t written = 0;
  unsigned char cipherPkt[kMaxMTU];
  memcpy(cipherPkt, header, headerLen);
  uint32_t rv = mNSSHelper->EncryptBlock(header, headerLen, data, dataLen,
                                         mNextTransmitPacketNumber, cipherPkt + headerLen,
                                         MTU - headerLen, written);

  ConnectionLog6("encrypt[%lX] rv=%d inputlen=%d (+%d of aead) outputlen=%d\n",
                 mNextTransmitPacketNumber, rv, dataLen, headerLen, written);

  if (rv != MOZQUIC_OK) {
    RaiseError(MOZQUIC_ERR_CRYPTO, (char *) "unexpected encrypt fail");
    return rv;
  }

  rv = Transmit(cipherPkt, written + headerLen, nullptr);
  if (rv != MOZQUIC_OK) {
    return rv;
  }
  
  ConnectionLog5("TRANSMIT[%lX] this=%p len=%d\n",
                 mNextTransmitPacketNumber, this, written + headerLen);
  mNextTransmitPacketNumber++;

  return MOZQUIC_OK;
}

void
MozQuic::Shutdown(uint32_t code, const char *reason)
{
  if (mParent) {
    for (auto iter = mParent->mChildren.begin(); iter != mParent->mChildren.end(); ++iter) {
      if ((*iter).get() == this) {
          mParent->mChildren.erase(iter);
          break;
      }
    }
    assert(mIsChild);
    mParent->RemoveSession(mConnectionID);
  }

  if ((mConnectionState != CLIENT_STATE_CONNECTED) &&
      (mConnectionState != SERVER_STATE_CONNECTED)) {
    mConnectionState = mIsClient ? CLIENT_STATE_CLOSED : SERVER_STATE_CLOSED;
    return;
  }
  if (!mIsChild && !mIsClient) {
    // this is the listener.. it does not send packets
    return;
  }

  ConnectionLog5("sending shutdown as %lX\n", mNextTransmitPacketNumber);

  unsigned char plainPkt[kMaxMTU];
  uint16_t tmp16;
  uint32_t tmp32;
  assert(mMTU <= kMaxMTU);

  // todo before merge - this can't be inlined here
  // what if not kp 0 TODO
  // todo when transport params allow truncate id, the connid might go
  // short header with connid kp = 0, 4 bytes of packetnumber
  uint32_t used, headerLen;
  CreateShortPacketHeader(plainPkt, mMTU - kTagLen, used);
  headerLen = used;

  plainPkt[used] = FRAME_TYPE_CLOSE;
  used++;
  tmp32 = htonl(code);
  memcpy(plainPkt + used, &tmp32, 4);
  used += 4;

  size_t reasonLen = strlen(reason);
  if (reasonLen > (mMTU - kTagLen - used - 2)) {
    reasonLen = mMTU - kTagLen - used - 2;
  }
  tmp16 = htons(reasonLen);
  memcpy(plainPkt + used, &tmp16, 2);
  used += 2;
  if (reasonLen) {
    memcpy(plainPkt + used, reason, reasonLen);
    used += reasonLen;
  }

  ProtectedTransmit(plainPkt, headerLen, plainPkt + headerLen, used - headerLen,
                    mMTU - headerLen - kTagLen, false);
  mConnectionState = mIsClient ? CLIENT_STATE_CLOSED : SERVER_STATE_CLOSED;
}

void
MozQuic::ReleaseBackPressure()
{
  // release id
  mBackPressure = false;
  if (mStreamState) {
    mStreamState->MaybeIssueFlowControlCredit();
  }
}

void
MozQuic::SetInitialPacketNumber()
{
  for (int i=0; i < 2; i++) {
    mNextTransmitPacketNumber = mNextTransmitPacketNumber << 16;
    mNextTransmitPacketNumber = mNextTransmitPacketNumber | (random() & 0xffff);
  }
  mNextTransmitPacketNumber &= 0x7fffffff; // 31 bits
  mOriginalTransmitPacketNumber = mNextTransmitPacketNumber;
}

int
MozQuic::StartClient()
{
  assert(!mHandleIO); // todo
  mIsClient = true;
  mStreamState.reset(new StreamState(this, mAdvertiseStreamWindow, mAdvertiseConnectionWindowKB));
  mStreamState->InitIDs(1,2);
  mNSSHelper.reset(new NSSHelper(this, mTolerateBadALPN, mOriginName.get(), true));
  mStreamState->mStream0.reset(new StreamPair(0, this, mStreamState.get(),
                                              kMaxStreamDataDefault,
                                              mStreamState->mLocalMaxStreamData));

  assert(!mClientOriginalOfferedVersion);
  mClientOriginalOfferedVersion = mVersion;

  mConnectionState = CLIENT_STATE_1RTT;
  for (int i=0; i < 4; i++) {
    mConnectionID = mConnectionID << 16;
    mConnectionID = mConnectionID | (random() & 0xffff);
  }
  SetInitialPacketNumber();

  if (mFD == MOZQUIC_SOCKET_BAD) {
    // the application did not pass in its own fd
    struct addrinfo *outAddr;
    // todo blocking getaddrinfo
    if (getaddrinfo(mOriginName.get(), nullptr, nullptr, &outAddr) != 0) {
      return MOZQUIC_ERR_GENERAL;
    }

    if (outAddr->ai_family == AF_INET) {
      mFD = socket(AF_INET, SOCK_DGRAM, 0);
      ((struct sockaddr_in *) outAddr->ai_addr)->sin_port = htons(mOriginPort);
      if ((ntohl(((struct sockaddr_in *) outAddr->ai_addr)->sin_addr.s_addr) & 0xff000000) == 0x7f000000) {
        mIsLoopback = true;
      }
    } else if (outAddr->ai_family == AF_INET6) {
      mFD = socket(AF_INET6, SOCK_DGRAM, 0);
      ((struct sockaddr_in6 *) outAddr->ai_addr)->sin6_port = htons(mOriginPort);
      const void *ptr1 = &in6addr_loopback.s6_addr;
      const void *ptr2 = &((struct sockaddr_in6 *) outAddr->ai_addr)->sin6_addr.s6_addr;
      if (!memcmp(ptr1, ptr2, 16)) {
        mIsLoopback = true;
      }
    }

    fcntl(mFD, F_SETFL, fcntl(mFD, F_GETFL, 0) | O_NONBLOCK);
#ifdef IP_PMTUDISC_DO
    int val = IP_PMTUDISC_DO;
    setsockopt(mFD, IPPROTO_IP, IP_MTU_DISCOVER, &val, sizeof(val));
#endif
    connect(mFD, outAddr->ai_addr, outAddr->ai_addrlen);
    freeaddrinfo(outAddr);
  }
  mTimestampConnBegin = Timestamp();
  EnsureSetupClientTransportParameters();

  return MOZQUIC_OK;
}

int
MozQuic::StartServer()
{
  assert(!mHandleIO); // todo
  mIsClient = false;
  mStreamState.reset(new StreamState(this, mAdvertiseStreamWindow, mAdvertiseConnectionWindowKB));
  mStreamState->InitIDs(2, 1);

  StatelessResetEnsureKey();

  assert((sizeof(mValidationKey) % sizeof(uint16_t)) == 0);
  for (int i=0; i < (sizeof(mValidationKey) / sizeof (uint16_t)); i++) {
    ((uint16_t *)mValidationKey)[i] = random() & 0xffff;
  }

  mConnectionState = SERVER_STATE_LISTEN;
  return Bind();
}

int
MozQuic::Bind()
{
  if (mFD != MOZQUIC_SOCKET_BAD) {
    return MOZQUIC_OK;
  }
  mFD = socket(AF_INET, SOCK_DGRAM, 0); // todo v6 and non 0 addr
  fcntl(mFD, F_SETFL, fcntl(mFD, F_GETFL, 0) | O_NONBLOCK);
  struct sockaddr_in sin;
  memset (&sin, 0, sizeof (sin));
  sin.sin_family = AF_INET;
  sin.sin_port = htons(mOriginPort);
  int rv = bind(mFD, (const sockaddr *)&sin, sizeof (sin));
  return (rv != -1) ? MOZQUIC_OK : MOZQUIC_ERR_IO;
}

MozQuic *
MozQuic::FindSession(uint64_t cid)
{
  assert (!mIsChild);
  if (mIsClient) {
    return mConnectionID == cid ? this : nullptr;
  }

  auto i = mConnectionHash.find(cid);
  if (i == mConnectionHash.end()) {
    ConnectionLog2("FindSession() could not find id in hash\n");
    return nullptr;
  }
  return (*i).second;
}

void
MozQuic::RemoveSession(uint64_t cid)
{
  assert (!mIsChild);
  if (mIsClient) {
    return;
  }
  mConnectionHash.erase(cid);
}

void
MozQuic::EnsureSetupClientTransportParameters()
{
  if (mSetupTransportExtension) {
    return;
  }
  mSetupTransportExtension = true;
  
  ConnectionLog9("setup transport extension (client)\n");
  unsigned char te[2048];
  uint16_t teLength = 0;
  assert(mVersion && mClientOriginalOfferedVersion);
  TransportExtension::
    EncodeClientTransportParameters(te, teLength, 2048,
                                    mVersion, mClientOriginalOfferedVersion,
                                    mStreamState->mLocalMaxStreamData,
                                    mStreamState->mLocalMaxData,
                                    mStreamState->mLocalMaxStreamID,
                                    kIdleTimeoutDefault);
  if (mAppHandlesSendRecv) {
    struct mozquic_eventdata_tlsinput data;
    data.data = te;
    data.len = teLength;
    mConnEventCB(mClosure, MOZQUIC_EVENT_TLS_CLIENT_TPARAMS, &data);
  } else {
    mNSSHelper->SetLocalTransportExtensionInfo(te, teLength);
  }
}

int
MozQuic::Client1RTT()
{
  EnsureSetupClientTransportParameters();
  if (mAppHandlesSendRecv) {
    if (mStreamState->mStream0->Empty()) {
      return MOZQUIC_OK;
    }
    // Server Reply is available and needs to be passed to app for processing
    unsigned char buf[kMozQuicMSS];
    uint32_t amt = 0;
    bool fin = false;

    uint32_t code = mStreamState->mStream0->Read(buf, kMozQuicMSS, amt, fin);
    if (code != MOZQUIC_OK) {
      return code;
    }
    if (amt > 0) {
      // called to let the app know that the server side TLS data is ready
      struct mozquic_eventdata_tlsinput data;
      data.data = buf;
      data.len = amt;
      mConnEventCB(mClosure, MOZQUIC_EVENT_TLSINPUT, &data);
    }
  } else {

    // handle server reply internally
    uint32_t code = mNSSHelper->DriveHandshake();
    if (code != MOZQUIC_OK) {
      RaiseError(code, (char *) "client 1rtt handshake failed");
      return code;
    }
    if (mNSSHelper->IsHandshakeComplete()) {
      return ClientConnected();
    }
  }

  return MOZQUIC_OK;
}

int
MozQuic::Server1RTT()
{
  assert(!mIsClient && mIsChild && mParent);
  if (mAppHandlesSendRecv) {
    // todo handle app-security on server side
    // todo make sure that includes transport parameters
    assert(false);
    RaiseError(MOZQUIC_ERR_GENERAL, (char *)"need handshaker");
    return MOZQUIC_ERR_GENERAL;
  }

  if (!mSetupTransportExtension) {
    ConnectionLog9("setup transport extension (server)\n");
    unsigned char resetToken[16];
    StatelessResetCalculateToken(mParent->mStatelessResetKey,
                                 mConnectionID, resetToken); // from key and CID
  
    unsigned char te[2048];
    uint16_t teLength = 0;
    TransportExtension::
      EncodeServerTransportParameters(te, teLength, 2048,
                                      VersionNegotiationList, sizeof(VersionNegotiationList) / sizeof (uint32_t),
                                      mStreamState->mLocalMaxStreamData,
                                      mStreamState->mLocalMaxData,
                                      mStreamState->mLocalMaxStreamID,
                                      kIdleTimeoutDefault, resetToken);
    mNSSHelper->SetLocalTransportExtensionInfo(te, teLength);
    mSetupTransportExtension = true;
  }

  if (!mStreamState->mStream0->Empty()) {
    uint32_t code = mNSSHelper->DriveHandshake();
    if (code != MOZQUIC_OK) {
      RaiseError(code, (char *) "server 1rtt handshake failed");
      return code;
    }

    if (mNSSHelper->DoHRR()) {
      mNSSHelper.reset(new NSSHelper(this, mParent->mTolerateBadALPN, mParent->mOriginName.get()));
      mParent->mConnectionHash.erase(mConnectionID);
      mParent->mConnectionHashOriginalNew.erase(mOriginalConnectionID);
      mConnectionState = SERVER_STATE_SSR;
      return MOZQUIC_OK;
    }

    if (mNSSHelper->IsHandshakeComplete()) {
      return ServerConnected();
    }
  }
  return MOZQUIC_OK;
}

uint32_t
MozQuic::Intake(bool *partialResult)
{
  *partialResult = false;
  if (mIsChild) {
    // parent does all fd reading
    return MOZQUIC_OK;
  }
  // check state
  assert (mConnectionState == SERVER_STATE_LISTEN ||
          mConnectionState == SERVER_STATE_1RTT ||
          mConnectionState == SERVER_STATE_CLOSED ||
          mConnectionState == CLIENT_STATE_CONNECTED ||
          mConnectionState == CLIENT_STATE_1RTT ||
          mConnectionState == CLIENT_STATE_CLOSED);
  uint32_t rv = MOZQUIC_OK;

  unsigned char pkt[kMozQuicMSS];
  bool sendAck;
  do {
    uint32_t pktSize = 0;
    sendAck = false;
    struct sockaddr_in peer;
    rv = Recv(pkt, kMozQuicMSS, pktSize, &peer);
    if (rv != MOZQUIC_OK || !pktSize) {
      return rv;
    }

    // dispatch to the right MozQuic class.
    std::shared_ptr<MozQuic> session(mAlive); // default
    MozQuic *tmpSession = nullptr;
      
    if (!(pkt[0] & 0x80)) {
      ShortHeaderData tmpShortHeader(pkt, pktSize, 0, mConnectionID);
      if (pktSize < tmpShortHeader.mHeaderSize) {
        return rv;
      }
      tmpSession = FindSession(tmpShortHeader.mConnectionID);
      if (!tmpSession) {
        ConnectionLogCID1(tmpShortHeader.mConnectionID,
                          "no session found for encoded packet size=%d\n",
                          pktSize);
        StatelessResetSend(tmpShortHeader.mConnectionID, &peer);
        rv = MOZQUIC_ERR_GENERAL;
        continue;
      }
      session = tmpSession->mAlive;
      ShortHeaderData shortHeader(pkt, pktSize, session->mNextRecvPacketNumber, mConnectionID);
      assert(shortHeader.mConnectionID == tmpShortHeader.mConnectionID);
      ConnectionLogCID5(shortHeader.mConnectionID, "SHORTFORM PACKET[%d] pkt# %lX hdrsize=%d\n",
                     pktSize, shortHeader.mPacketNumber, shortHeader.mHeaderSize);
      rv = session->ProcessGeneral(pkt, pktSize,
                                   shortHeader.mHeaderSize, shortHeader.mPacketNumber, sendAck);
      if (rv == MOZQUIC_OK) {
        session->Acknowledge(shortHeader.mPacketNumber, keyPhase1Rtt);
      }

    } else {
      if (pktSize < 17) {
        return rv;
      }
      LongHeaderData longHeader(pkt, pktSize);

      ConnectionLogCID5(longHeader.mConnectionID,
                        "LONGFORM PACKET[%d] pkt# %lX type %d version %X\n",
                        pktSize, longHeader.mPacketNumber, longHeader.mType, longHeader.mVersion);
      if (longHeader.mType < PACKET_TYPE_0RTT_PROTECTED) {
        *partialResult = true;
      }

      if (!VersionOK(longHeader.mVersion)) {
        if (!mIsClient) {
          ConnectionLog1("unacceptable version recvd.\n");
          if (pktSize >= kInitialMTU) {
            session->GenerateVersionNegotiation(longHeader, &peer);
          } else {
            ConnectionLog1("packet too small to be CI, ignoring\n");
          }
          continue;
        } else if (longHeader.mType != PACKET_TYPE_VERSION_NEGOTIATION || longHeader.mVersion != mVersion) {
          ConnectionLog1("unacceptable version recvd.\n");
          ConnectionLog1("Client ignoring as this isn't VN\n");
          continue;
        }
      }

      switch (longHeader.mType) {
      case PACKET_TYPE_VERSION_NEGOTIATION:
        // do not do integrity check (nop)
        break;
      case PACKET_TYPE_CLIENT_INITIAL:
      case PACKET_TYPE_SERVER_CLEARTEXT:
      case PACKET_TYPE_SERVER_STATELESS_RETRY:
        if (!IntegrityCheck(pkt, pktSize)) {
          rv = MOZQUIC_ERR_GENERAL;
        }
        break;
      case PACKET_TYPE_CLIENT_CLEARTEXT:
        if (!IntegrityCheck(pkt, pktSize)) {
          rv = MOZQUIC_ERR_GENERAL;
          break;
        }
        tmpSession = FindSession(longHeader.mConnectionID);
        if (!tmpSession) {
          rv = MOZQUIC_ERR_GENERAL;
        } else {
          session = tmpSession->mAlive;
        }
        break;

      case PACKET_TYPE_1RTT_PROTECTED_KP0:
        tmpSession = FindSession(longHeader.mConnectionID);
        if (!tmpSession) {
          rv = MOZQUIC_ERR_GENERAL;
        } else {
          session = tmpSession->mAlive;
        }
        break;

      default:
        ConnectionLog1("recv unexpected type\n");
        // todo this could actually be out of order protected packet even in handshake
        // and ideally would be queued. for now we rely on retrans
        // todo
        rv = MOZQUIC_ERR_GENERAL;
        break;
      }

      if (!session || rv != MOZQUIC_OK) {
        ConnectionLog1("unable to find connection for packet\n");
        continue;
      }

      switch (longHeader.mType) {
      case PACKET_TYPE_VERSION_NEGOTIATION: // version negotiation
        rv = session->ProcessVersionNegotiation(pkt, pktSize, longHeader);
        // do not ack
        break;
      case PACKET_TYPE_CLIENT_INITIAL:
        rv = session->ProcessClientInitial(pkt, pktSize, &peer, longHeader, &tmpSession, sendAck);
        // ack after processing - find new session
        if (rv == MOZQUIC_OK) {
          session = tmpSession->mAlive;
          session->Acknowledge(longHeader.mPacketNumber, keyPhaseUnprotected);
        }
        break;

      case PACKET_TYPE_SERVER_STATELESS_RETRY:
        rv = session->ProcessServerStatelessRetry(pkt, pktSize, longHeader);
        // do not ack
        break;
      case PACKET_TYPE_SERVER_CLEARTEXT:
        rv = session->ProcessServerCleartext(pkt, pktSize, longHeader, sendAck);
        if (rv == MOZQUIC_OK) {
          session->Acknowledge(longHeader.mPacketNumber, keyPhaseUnprotected);
        }
        break;
      case PACKET_TYPE_CLIENT_CLEARTEXT:
        rv = session->ProcessClientCleartext(pkt, pktSize, longHeader, sendAck);
        if (rv == MOZQUIC_OK) {
          session->Acknowledge(longHeader.mPacketNumber, keyPhaseUnprotected);
        }
        break;
      case PACKET_TYPE_1RTT_PROTECTED_KP0:
        rv = session->ProcessGeneral(pkt, pktSize, 17, longHeader.mPacketNumber, sendAck);
        if (rv == MOZQUIC_OK) {
          session->Acknowledge(longHeader.mPacketNumber, keyPhase1Rtt);
        }
        break;

      default:
        assert(false);
        break;
      }
    }
    if ((rv == MOZQUIC_OK) && sendAck) {
      rv = session->MaybeSendAck();
    }
  } while (rv == MOZQUIC_OK && !(*partialResult));

  return rv;
}

int
MozQuic::IO()
{
  uint32_t code;
  std::shared_ptr<MozQuic> deleteProtector(mAlive);
  ConnectionLog10("MozQuic::IO %p\n", this);

  bool partialResult = false;
  do {
    Intake(&partialResult);
    mStreamState->RetransmitTimer();
    ClearOldInitialConnectIdsTimer();
    mStreamState->Flush(false);

    if (mIsClient) {
      switch (mConnectionState) {
      case CLIENT_STATE_1RTT:
        code = Client1RTT();
        if (code != MOZQUIC_OK) {
          return code;
        }
        break;
      case CLIENT_STATE_CONNECTED:
      case CLIENT_STATE_CLOSED:
      case SERVER_STATE_CLOSED:
        break;
      default:
        assert(false);
        // todo
      }
    } else {
      if (mConnectionState == SERVER_STATE_1RTT) {
        code = Server1RTT();
        if (code != MOZQUIC_OK) {
          return code;
        }
      }
      if (!mIsChild) {
        ssize_t len = mChildren.size();
        for (auto iter = mChildren.begin();
             len == mChildren.size() && iter != mChildren.end(); ++iter) {
          (*iter)->IO();
        }
      }
    }
  } while (partialResult);

  if ((mConnectionState == SERVER_STATE_1RTT) &&
      (mNextTransmitPacketNumber - mOriginalTransmitPacketNumber) > 20) {
    RaiseError(MOZQUIC_ERR_GENERAL, (char *)"TimedOut Client In Handshake");
    return MOZQUIC_ERR_GENERAL;
  }

  if (mPingDeadline && mConnEventCB && mPingDeadline < Timestamp()) {
    ConnectionLog1("ping deadline expired set at %ld now %ld\n", mPingDeadline, Timestamp());
    mPingDeadline = 0;
    mConnEventCB(mClosure, MOZQUIC_EVENT_ERROR, this);
  }
  if (mPMTUD1Deadline && mPMTUD1Deadline < Timestamp()) {
    AbortPMTUD1();
  }
  if (mConnEventCB) {
    mConnEventCB(mClosure, MOZQUIC_EVENT_IO, this);
  }
  return MOZQUIC_OK;
}

uint32_t
MozQuic::Recv(unsigned char *pkt, uint32_t avail, uint32_t &outLen,
              struct sockaddr_in *peer)
{
  uint32_t code = MOZQUIC_OK;

  if (mAppHandlesSendRecv) {
    struct mozquic_eventdata_recv data;
    uint32_t written;

    data.pkt = pkt;
    data.avail = avail;
    data.written = &written;
    code = mConnEventCB(mClosure, MOZQUIC_EVENT_RECV, &data);
    outLen = written;
  } else {
    socklen_t sinlen = sizeof(*peer);
    ssize_t amt =
      recvfrom(mFD, pkt, avail, 0, (struct sockaddr *) peer, &sinlen);
    outLen = amt > 0 ? amt : 0;
    // todo errs
    code = MOZQUIC_OK;
  }
  if (code != MOZQUIC_OK) {
    return code;
  }

  return MOZQUIC_OK;
}

void
MozQuic::RaiseError(uint32_t e, const char *fmt, ...)
{
  ConnectionLog1("RaiseError %u\n", e);

  va_list a;
  va_start(a, fmt);
  Log::sDoLog(Log::CONNECTION, 1, this, mConnectionID, fmt, a);
  va_end(a);
  
  if (mConnEventCB && (mIsClient || mIsChild)) {
    mConnEventCB(mClosure, MOZQUIC_EVENT_ERROR, this);
  }
}

// this is called by the application when the application is handling
// the TLS stream (so that it can do more sophisticated handling
// of certs etc like gecko PSM does). The app is providing the
// client hello
void
MozQuic::HandshakeOutput(const unsigned char *buf, uint32_t datalen)
{
  mStreamState->mStream0->Write(buf, datalen, false);
}

void
MozQuic::HandshakeTParamOutput(const unsigned char *buf, uint32_t datalen)
{
  mRemoteTransportExtensionInfo.reset(new unsigned char[datalen]);
  mRemoteTransportExtensionInfoLen = datalen;
  memcpy(mRemoteTransportExtensionInfo.get(), buf, datalen);
}

// this is called by the application when the application is handling
// the TLS stream (so that it can do more sophisticated handling
// of certs etc like gecko PSM does). The app is providing the
// client hello and interpreting the server hello
uint32_t
MozQuic::HandshakeComplete(uint32_t code,
                           struct mozquic_handshake_info *keyInfo)
{
  if (!mAppHandlesSendRecv) {
    RaiseError(MOZQUIC_ERR_GENERAL, (char *)"not using handshaker api");
    return MOZQUIC_ERR_GENERAL;
  }
  if (mConnectionState != CLIENT_STATE_1RTT) {
    RaiseError(MOZQUIC_ERR_GENERAL, (char *)"Handshake complete in wrong state");
    return MOZQUIC_ERR_GENERAL;
  }
  if (code != MOZQUIC_OK) {
    RaiseError(MOZQUIC_ERR_CRYPTO, (char *)"Handshake complete err");
    return MOZQUIC_ERR_CRYPTO;
  }

  uint32_t sCode = mNSSHelper->HandshakeSecret(keyInfo->ciphersuite,
                                              keyInfo->sendSecret, keyInfo->recvSecret);
  if (sCode != MOZQUIC_OK) {
    return sCode;
  }
  return ClientConnected();
}

uint32_t
MozQuic::ClientConnected()
{
  ConnectionLog4("CLIENT_STATE_CONNECTED\n");
  assert(mConnectionState == CLIENT_STATE_1RTT);
  unsigned char *extensionInfo = nullptr;
  uint16_t extensionInfoLen = 0;
  uint32_t peerVersionList[256];
  uint16_t versionSize = sizeof(peerVersionList) / sizeof (peerVersionList[0]);

  if (!mAppHandlesSendRecv) {
    mNSSHelper->GetRemoteTransportExtensionInfo(extensionInfo, extensionInfoLen);
  } else {
    extensionInfo = mRemoteTransportExtensionInfo.get();
    extensionInfoLen = mRemoteTransportExtensionInfoLen;
  }

  uint32_t decodeResult;
  uint32_t errorCode = ERROR_NO_ERROR;
  if (!extensionInfoLen && mTolerateNoTransportParams) {
    ConnectionLog5("Decoding Server Transport Parameters: tolerated empty by config\n");
    decodeResult = MOZQUIC_OK;
  } else {
    assert(sizeof(mStatelessResetToken) == 16);
    uint32_t peerMaxDataKB;
    decodeResult =
      TransportExtension::
      DecodeServerTransportParameters(extensionInfo, extensionInfoLen,
                                      peerVersionList, versionSize,
                                      mStreamState->mPeerMaxStreamData,
                                      peerMaxDataKB,
                                      mStreamState->mPeerMaxStreamID, mPeerIdleTimeout,
                                      mStatelessResetToken);
    mStreamState->mPeerMaxData = peerMaxDataKB * (__uint128_t) 1024;
    if (decodeResult != MOZQUIC_OK) {
      ConnectionLog1("Decoding Server Transport Parameters: failed\n");
      errorCode = ERROR_TRANSPORT_PARAMETER;
    } else {
      ConnectionLog5("Decoding Server Transport Parameters: passed\n");
    }
    mRemoteTransportExtensionInfo = nullptr;
    mRemoteTransportExtensionInfoLen = 0;
    extensionInfo = nullptr;
    extensionInfoLen = 0;
    mStreamState->mStream0->NewFlowControlLimit(mStreamState->mPeerMaxStreamData);
                                                            
    // need to confirm version negotiation wasn't messed with
    if (decodeResult == MOZQUIC_OK) {
      // is mVersion in the peerVersionList?
      decodeResult = MOZQUIC_ERR_CRYPTO;
      for (int i = 0; i < versionSize; i++) {
        if (peerVersionList[i] == mVersion) {
          decodeResult = MOZQUIC_OK;
          break;
        }
      }
      if (decodeResult != MOZQUIC_OK) {
        errorCode = ERROR_VERSION_NEGOTIATION;
        ConnectionLog1("Verify Server Transport Parameters: version used failed\n");
      } else {
        ConnectionLog5("Verify Server Transport Parameters: version used passed\n");
      }
    }

    // if negotiation happened is the result correct?
    if (decodeResult == MOZQUIC_OK &&
        mVersion != mClientOriginalOfferedVersion) {
      decodeResult = MOZQUIC_ERR_CRYPTO;
      for (int i = 0; i < versionSize; i++) {
        if (VersionOK(peerVersionList[i])) {
          decodeResult = (peerVersionList[i] == mVersion) ? MOZQUIC_OK : MOZQUIC_ERR_CRYPTO;
          break;
        }
      }
      if (decodeResult != MOZQUIC_OK) {
        ConnectionLog1("Verify Server Transport Parameters: negotiation ok failed\n");
        errorCode = ERROR_VERSION_NEGOTIATION;
      } else {
        ConnectionLog5("Verify Server Transport Parameters: negotiation ok passed\n");
      }

    }
  }

  mConnectionState = CLIENT_STATE_CONNECTED;
  if (decodeResult != MOZQUIC_OK) {
    assert (errorCode != ERROR_NO_ERROR);
    MaybeSendAck();
    Shutdown(errorCode, "failed transport parameter verification");
    RaiseError(decodeResult, (char *) "failed to verify server transport parameters\n");
    return MOZQUIC_ERR_CRYPTO;
  }
  if (mConnEventCB) {
    mConnEventCB(mClosure, MOZQUIC_EVENT_CONNECTED, this);
  }
  return MaybeSendAck();
}

uint32_t
MozQuic::ServerConnected()
{
  assert (mIsChild && !mIsClient);
  ConnectionLog4("SERVER_STATE_CONNECTED\n");
  assert(mConnectionState == SERVER_STATE_1RTT);
  unsigned char *extensionInfo = nullptr;
  uint16_t extensionInfoLen = 0;
  uint32_t peerNegotiatedVersion, peerInitialVersion;
  mNSSHelper->GetRemoteTransportExtensionInfo(extensionInfo, extensionInfoLen);
  uint32_t decodeResult;
  uint32_t errorCode = ERROR_NO_ERROR;
  if (!extensionInfoLen && mTolerateNoTransportParams) {
    ConnectionLog6("Decoding Client Transport Parameters: tolerated empty by config\n");
    decodeResult = MOZQUIC_OK;
  } else {
    uint32_t peerMaxDataKB;
    decodeResult =
      TransportExtension::
      DecodeClientTransportParameters(extensionInfo, extensionInfoLen,
                                      peerNegotiatedVersion, peerInitialVersion,
                                      mStreamState->mPeerMaxStreamData,
                                      peerMaxDataKB,
                                      mStreamState->mPeerMaxStreamID, mPeerIdleTimeout,
                                      this);
    ConnectionLog6(
            "decode client parameters: "
            "maxstreamdata %ld "
            "maxdatakb %ld "
            "maxstreamid %ld "
            "idle %ld\n",
            mStreamState->mPeerMaxStreamData,
            peerMaxDataKB,
            mStreamState->mPeerMaxStreamID, mPeerIdleTimeout);
            
    mStreamState->mPeerMaxData = peerMaxDataKB * (__uint128_t) 1024;
    Log::sDoLog(Log::CONNECTION, decodeResult == MOZQUIC_OK ? 5 : 1, this,
                "Decoding Client Transport Parameters: %s\n",
                decodeResult == MOZQUIC_OK ? "passed" : "failed");
    mStreamState->mStream0->NewFlowControlLimit(mStreamState->mPeerMaxStreamData);
    
    if (decodeResult != MOZQUIC_OK) {
      errorCode = ERROR_TRANSPORT_PARAMETER;
    } else {
      // need to confirm version negotiation wasn't messed with
      decodeResult = (mVersion == peerNegotiatedVersion) ? MOZQUIC_OK : MOZQUIC_ERR_CRYPTO;

      Log::sDoLog(Log::CONNECTION, decodeResult == MOZQUIC_OK ? 5 : 1, this,
                  "Verify Client Transport Parameters: version used %s\n",
                  decodeResult == MOZQUIC_OK ? "passed" : "failed");
      if (decodeResult != MOZQUIC_OK) {
        errorCode = ERROR_VERSION_NEGOTIATION;
      } else {
        if ((peerInitialVersion != peerNegotiatedVersion) && VersionOK(peerInitialVersion)) {
          decodeResult = MOZQUIC_ERR_CRYPTO;
        }
        Log::sDoLog(Log::CONNECTION, decodeResult == MOZQUIC_OK ? 5 : 1, this,
                    "Verify Client Transport Parameters: negotiation used %s\n",
                    decodeResult == MOZQUIC_OK ? "passed" : "failed");
        if (decodeResult != MOZQUIC_OK) {
          errorCode = ERROR_VERSION_NEGOTIATION;
        }
      }
    }
  }
  
  mConnectionState = SERVER_STATE_CONNECTED;
  if (decodeResult != MOZQUIC_OK) {
    assert(errorCode != ERROR_NO_ERROR);
    MaybeSendAck();
    Shutdown(errorCode, "failed transport parameter verification");
    RaiseError(decodeResult, (char *) "failed to verify client transport parameters\n");
    return MOZQUIC_ERR_CRYPTO;
  }
  
  if (mConnEventCB) {
    mConnEventCB(mClosure, MOZQUIC_EVENT_CONNECTED, this);
  }
  return MaybeSendAck();
}

uint32_t
MozQuic::ProcessGeneral(const unsigned char *pkt, uint32_t pktSize, uint32_t headerSize,
                        uint64_t packetNum, bool &sendAck)
{
  assert(pktSize >= headerSize);
  assert(pktSize <= kMozQuicMSS);
  unsigned char out[kMozQuicMSS];

  if (mConnectionState == CLIENT_STATE_CLOSED ||
      mConnectionState == SERVER_STATE_CLOSED) {
    ConnectionLog4("processgeneral discarding %lX as closed\n", packetNum);
    return MOZQUIC_ERR_GENERAL;
  }
  uint32_t written;
  uint32_t rv = mNSSHelper->DecryptBlock(pkt, headerSize, pkt + headerSize,
                                         pktSize - headerSize, packetNum, out,
                                         kMozQuicMSS, written);
  ConnectionLog6("decrypt (pktnum=%lX) rv=%d sz=%d\n", packetNum, rv, written);
  if (rv != MOZQUIC_OK) {
    ConnectionLog1("decrypt failed\n");
    if (StatelessResetCheckForReceipt(pkt, pktSize)) {
      return MOZQUIC_OK;
    }
    return rv;
  }
  if (!mDecodedOK) {
    mDecodedOK = true;
    StartPMTUD1();
  }
  if (mPingDeadline && mConnEventCB) {
    mPingDeadline = 0;
    mConnEventCB(mClosure, MOZQUIC_EVENT_PING_OK, nullptr);
  }

  return ProcessGeneralDecoded(out, written, sendAck, false);
}

uint32_t
MozQuic::HandleCloseFrame(FrameHeaderData *result, bool fromCleartext,
                          const unsigned char *pkt, const unsigned char *endpkt,
                          uint32_t &_ptr)
{
  if (fromCleartext) {
    RaiseError(MOZQUIC_ERR_GENERAL, (char *) "close frames not allowed in cleartext\n");
    return MOZQUIC_ERR_GENERAL;
  }
  ConnectionLog5("RECVD CLOSE\n");
  mConnectionState = mIsClient ? CLIENT_STATE_CLOSED : SERVER_STATE_CLOSED;
  if (mConnEventCB) {
    mConnEventCB(mClosure, MOZQUIC_EVENT_CLOSE_CONNECTION, this);
  } else {
    ConnectionLog9("No Event callback\n");
  }
  return MOZQUIC_OK;
}

uint32_t
MozQuic::ProcessGeneralDecoded(const unsigned char *pkt, uint32_t pktSize,
                               bool &sendAck, bool fromCleartext)
{
  // used by both client and server
  const unsigned char *endpkt = pkt + pktSize;
  uint32_t ptr = 0;
  uint32_t rv;
  assert(pktSize <= kMozQuicMSS);
  sendAck = false;

  // fromCleartext frames may only be ack, stream-0, and padding
  // and process_client_initial may not be ack

  while (ptr < pktSize) {
    FrameHeaderData result(pkt + ptr, pktSize - ptr, this, fromCleartext);
    if (result.mValid != MOZQUIC_OK) {
      return result.mValid;
    }
    ptr += result.mFrameLen;
    switch(result.mType) {

    case FRAME_TYPE_STREAM:
      sendAck = true;
      rv = mStreamState->HandleStreamFrame(&result, fromCleartext, pkt, endpkt, ptr);
      if (rv != MOZQUIC_OK) {
        return rv;
      }
      break;

    case FRAME_TYPE_ACK:
      rv = HandleAckFrame(&result, fromCleartext, pkt, endpkt, ptr);
      if (rv != MOZQUIC_OK) {
        return rv;
      }
      break;

    case FRAME_TYPE_PADDING:
      break;

    case FRAME_TYPE_RST_STREAM:
      sendAck = true;
      rv = mStreamState->HandleResetStreamFrame(&result, fromCleartext, pkt, endpkt, ptr);
      if (rv != MOZQUIC_OK) {
        return rv;
      }
      break;

    case FRAME_TYPE_CLOSE:
      sendAck = true;
      rv = HandleCloseFrame(&result, fromCleartext, pkt, endpkt, ptr);
      if (rv != MOZQUIC_OK) {
        return rv;
      }
      break;

    case FRAME_TYPE_MAX_DATA:
      sendAck = true;
      rv = mStreamState->HandleMaxDataFrame(&result, fromCleartext, pkt, endpkt, ptr);
      if (rv != MOZQUIC_OK) {
        return rv;
      }
      break;

    case FRAME_TYPE_MAX_STREAM_DATA:
      sendAck = true;
      rv = mStreamState->HandleMaxStreamDataFrame(&result, fromCleartext, pkt, endpkt, ptr);
      if (rv != MOZQUIC_OK) {
        return rv;
      }
      break;

    case FRAME_TYPE_MAX_STREAM_ID:
      sendAck = true;
      rv = mStreamState->HandleMaxStreamIDFrame(&result, fromCleartext, pkt, endpkt, ptr);
      if (rv != MOZQUIC_OK) {
        return rv;
      }
      break;
      
    case FRAME_TYPE_PING:
      // basically padding with an ack
      if (fromCleartext) {
        ConnectionLog1("ping frames not allowed in cleartext\n");
        return MOZQUIC_ERR_GENERAL;
      }
      ConnectionLog5("recvd ping\n");
      sendAck = true;
      break;

    case FRAME_TYPE_BLOCKED:
      sendAck = true;
      rv = mStreamState->HandleBlockedFrame(&result, fromCleartext, pkt, endpkt, ptr);
      if (rv != MOZQUIC_OK) {
        return rv;
      }
      break;

    case FRAME_TYPE_STREAM_BLOCKED:
      sendAck = true;
      rv = mStreamState->HandleStreamBlockedFrame(&result, fromCleartext, pkt, endpkt, ptr);
      if (rv != MOZQUIC_OK) {
        return rv;
      }
      break;

    case FRAME_TYPE_STREAM_ID_BLOCKED:
      sendAck = true;
      rv = mStreamState->HandleStreamIDBlockedFrame(&result, fromCleartext, pkt, endpkt, ptr);
      if (rv != MOZQUIC_OK) {
        return rv;
      }
      break;

    case FRAME_TYPE_STOP_SENDING:
      sendAck = true;
      rv = mStreamState->HandleStopSendingFrame(&result, fromCleartext, pkt, endpkt, ptr);
      if (rv != MOZQUIC_OK) {
        return rv;
      }
      break;

    default:
      sendAck = true;
      if (fromCleartext) {
        ConnectionLog1("unexpected frame type %d cleartext=%d\n", result.mType, fromCleartext);
        RaiseError(MOZQUIC_ERR_GENERAL, (char *) "unexpected frame type");
        return MOZQUIC_ERR_GENERAL;
      }
      break;
    }
    assert(pkt + ptr <= endpkt);
  }
  return MOZQUIC_OK;
}

void
MozQuic::GetRemotePeerAddressHash(unsigned char *out, uint32_t *outLen)
{
  assert(mIsChild && !mIsClient);
  assert(*outLen >= 14 + sizeof(mParent->mValidationKey));

  *outLen = 0;
  unsigned char *ptr = out;
  assert (mPeer.sin_family == AF_INET); // todo - need v6 support in server
  
  memcpy(ptr, &mPeer.sin_addr.s_addr, sizeof(uint32_t));
  ptr += sizeof(uint32_t);
  memcpy(ptr, &mPeer.sin_port, sizeof(in_port_t));
  ptr += sizeof(in_port_t);
  uint64_t connID = PR_htonll(mOriginalConnectionID);
  memcpy(ptr, &connID, sizeof (uint64_t));
  ptr += sizeof(uint64_t);
  memcpy(ptr, &mParent->mValidationKey, sizeof(mValidationKey));
  ptr += sizeof(mValidationKey);

  *outLen = ptr - out;
  return;
}

MozQuic *
MozQuic::Accept(struct sockaddr_in *clientAddr, uint64_t aConnectionID, uint64_t aCIPacketNumber)
{
  MozQuic *child = new MozQuic(mHandleIO);
  child->mStreamState.reset(new StreamState(child, mAdvertiseStreamWindow, mAdvertiseConnectionWindowKB));
  child->mStreamState->InitIDs(2, 1);
  child->mIsChild = true;
  child->mIsClient = false;
  child->mParent = this;
  child->mConnectionState = SERVER_STATE_LISTEN;
  memcpy(&child->mPeer, clientAddr, sizeof (struct sockaddr_in));
  child->mFD = mFD;
  child->mClientInitialPacketNumber = aCIPacketNumber;

  child->mStreamState->mStream0.reset(new StreamPair(0, child, child->mStreamState.get(),
                                                     kMaxStreamDataDefault,
                                                     child->mStreamState->mLocalMaxStreamData));
  
  do {
    for (int i=0; i < 4; i++) {
      child->mConnectionID = child->mConnectionID << 16;
      child->mConnectionID = child->mConnectionID | (random() & 0xffff);
    }
  } while (mConnectionHash.count(child->mConnectionID) != 0);

  child->SetInitialPacketNumber();

  child->mNSSHelper.reset(new NSSHelper(child, mTolerateBadALPN, mOriginName.get()));
  child->mVersion = mVersion;
  child->mTimestampConnBegin = Timestamp();
  child->mOriginalConnectionID = aConnectionID;
  child->mAppHandlesSendRecv = mAppHandlesSendRecv;
  child->mAppHandlesLogging = mAppHandlesLogging;
  mConnectionHash.insert( { child->mConnectionID, child });
  mConnectionHashOriginalNew.insert( { aConnectionID,
                                       { child->mConnectionID, Timestamp() }
                                     } );

  return child;
}

bool
MozQuic::VersionOK(uint32_t proposed)
{
  if (proposed == kMozQuicVersion1 ||
      proposed == kMozQuicIetfID6 ||
      proposed == kMozQuicIetfID5) {
    return true;
  }
  return false;
}

uint32_t
MozQuic::StartNewStream(StreamPair **outStream, const void *data,
                        uint32_t amount, bool fin)
{
  if (mStreamState) {
    return mStreamState->StartNewStream(outStream, data, amount, fin);
  }
  return MOZQUIC_ERR_GENERAL;
}

void
MozQuic::MaybeDeleteStream(StreamPair *sp)
{
  if (sp) {
    mStreamState->MaybeDeleteStream(sp->mStreamID);
  }
}

uint64_t
MozQuic::Timestamp()
{
  // ms since epoch
  struct timeval tv;
  gettimeofday(&tv, nullptr);
  return (tv.tv_sec * 1000) + (tv.tv_usec / 1000);
}

int32_t
MozQuic::NSSInput(void *buf, int32_t amount)
{
  if (mStreamState->mStream0->Empty()) {
    PR_SetError(PR_WOULD_BLOCK_ERROR, 0);
    return -1;
  }

  // client part of handshake is available in stream 0,
  // feed it to nss via the return code of this fx
  uint32_t amt = 0;
  bool fin = false;

  uint32_t code = mStreamState->mStream0->Read((unsigned char *)buf,
                                 amount, amt, fin);
  if (code != MOZQUIC_OK) {
    PR_SetError(PR_IO_ERROR, 0);
    return -1;
  }
  if (amt > 0) {
    return amt;
  }
  if (fin) {
    return 0;
  }
  PR_SetError(PR_WOULD_BLOCK_ERROR, 0);
  return -1;
}

int32_t
MozQuic::NSSOutput(const void *buf, int32_t amount)
{
  // nss has produced some server output e.g. server hello
  // we need to put it into stream 0 so that it can be
  // written on the network
  return mStreamState->mStream0->Write((const unsigned char *)buf, amount, false);
}

uint32_t
MozQuic::ClearOldInitialConnectIdsTimer()
{
  // todo, really crude

  uint64_t now = Timestamp();
  uint64_t discardEpoch = now - kForgetInitialConnectionIDsThresh;

  for (auto i = mConnectionHashOriginalNew.begin(); i != mConnectionHashOriginalNew.end(); ) {
    if ((*i).second.mTimestamp < discardEpoch) {
      ConnectionLog7("Forget an old client initial connectionID: %lX\n",
                    (*i).first);
      i = mConnectionHashOriginalNew.erase(i);
    } else {
      i++;
    }
  }
  return MOZQUIC_OK;
}

}

