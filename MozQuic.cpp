/* -*- Mode: C++; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*-
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include <array>
#include "MozQuic.h"
#include "MozQuicInternal.h"
#include "MozQuicStream.h"
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

const char *MozQuic::kAlpn = "hq-05";
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
  , mIsLoopback(false)
  , mProcessedVN(false)
  , mConnectionState(STATE_UNINITIALIZED)
  , mOriginPort(-1)
  , mVersion(kMozQuicVersion1)
  , mClientOriginalOfferedVersion(0)
  , mMTU(kInitialMTU)
  , mConnectionID(0)
  , mOriginalConnectionID(0)
  , mNextTransmitPacketNumber(0)
  , mOriginalTransmitPacketNumber(0)
  , mNextRecvPacketNumber(0)
  , mClientInitialPacketNumber(0)
  , mClosure(this)
  , mConnEventCB(nullptr)
  , mParent(nullptr)
  , mAlive(this)
  , mTimestampConnBegin(0)
  , mPingDeadline(0)
  , mPMTUD1Deadline(0)
  , mPMTUD1PacketNumber(0)
  , mDecodedOK(false)
  , mPeerIdleTimeout(kIdleTimeoutDefault)
{
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
  mStreamState.reset(new StreamState(this));
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
    Log((char *)"Sending error in transmit");
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
        fprintf(stderr,"Handy-Ack adds to protected Transmit packet %lX by %d\n", mNextTransmitPacketNumber, usedByAck);
      }
      dataLen += usedByAck;
    }
  }

  if (dataLen == 0) {
    fprintf(stderr,"nothing to write\n");
    return MOZQUIC_OK;
  }

  uint32_t written = 0;
  unsigned char cipherPkt[kMaxMTU];
  memcpy(cipherPkt, header, headerLen);
  uint32_t rv = mNSSHelper->EncryptBlock(header, headerLen, data, dataLen,
                                         mNextTransmitPacketNumber, cipherPkt + headerLen,
                                         MTU - headerLen, written);

  fprintf(stderr,"encrypt[%lX] rv=%d inputlen=%d (+%d of aead) outputlen=%d\n",
          mNextTransmitPacketNumber, rv, dataLen, headerLen, written);

  if (rv != MOZQUIC_OK) {
    RaiseError(MOZQUIC_ERR_CRYPTO, (char *) "unexpected encrypt fail");
    return rv;
  }

  rv = Transmit(cipherPkt, written + headerLen, nullptr);
  if (rv != MOZQUIC_OK) {
    return rv;
  }
  
  fprintf(stderr,"TRANSMIT[%lX] this=%p len=%d cid=%lX\n",
          mNextTransmitPacketNumber, this,
          written + headerLen, mConnectionID);
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

  fprintf(stderr, "sending shutdown as %lx\n", mNextTransmitPacketNumber);

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
  mStreamState->InitIDs(1,2);
  mNSSHelper.reset(new NSSHelper(this, mTolerateBadALPN, mOriginName.get(), true));
  mStreamState->mStream0.reset(new MozQuicStreamPair(0, this, mStreamState.get(),
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
    int r = connect(mFD, outAddr->ai_addr, outAddr->ai_addrlen);
    freeaddrinfo(outAddr);
  }
  mTimestampConnBegin = Timestamp();

  return MOZQUIC_OK;
}

int
MozQuic::StartServer()
{
  assert(!mHandleIO); // todo
  mIsClient = false;
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
    Log((char *)"find session could not find id in hash");
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

int
MozQuic::Client1RTT()
{
  if (mAppHandlesSendRecv) {
    if (mStreamState->mStream0->Empty()) {
      return MOZQUIC_OK;
    }
    // Server Reply is available and needs to be passed to app for processing
    unsigned char buf[kMozQuicMSS];
    uint32_t amt = 0;
    bool fin = false;

    // todo transport extension info needs to be passed to app
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
    if (!mSetupTransportExtension) {
      fprintf(stderr,"setup transport extension (client)\n");
      unsigned char te[2048];
      uint16_t teLength = 0;
      assert(mVersion && mClientOriginalOfferedVersion);
      TransportExtension::
        EncodeClientTransportParameters(te, teLength, 2048,
                                        mVersion, mClientOriginalOfferedVersion,
                                        mStreamState->mLocalMaxStreamData,
                                        kMaxDataDefault,
                                        kMaxStreamIDDefault, kIdleTimeoutDefault);
      mNSSHelper->SetLocalTransportExtensionInfo(te, teLength);
      mSetupTransportExtension = true;
    }

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
    fprintf(stderr,"setup transport extension (server)\n");
    unsigned char resetToken[16];
    StatelessResetCalculateToken(mParent->mStatelessResetKey,
                                 mConnectionID, resetToken); // from key and CID
  
    unsigned char te[2048];
    uint16_t teLength = 0;
    TransportExtension::
      EncodeServerTransportParameters(te, teLength, 2048,
                                      VersionNegotiationList, sizeof(VersionNegotiationList) / sizeof (uint32_t),
                                      mStreamState->mLocalMaxStreamData,
                                      kMaxDataDefault,
                                      kMaxStreamIDDefault, kIdleTimeoutDefault, resetToken);
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
MozQuic::Intake()
{
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
    MozQuic *session = this; // default

    if (!(pkt[0] & 0x80)) {
      ShortHeaderData tmpShortHeader(pkt, pktSize, 0, mConnectionID);
      if (pktSize < tmpShortHeader.mHeaderSize) {
        return rv;
      }
      session = FindSession(tmpShortHeader.mConnectionID);
      if (!session) {
        fprintf(stderr,"no session found for encoded packet id=%lx size=%d\n",
                tmpShortHeader.mConnectionID, pktSize);
        StatelessResetSend(tmpShortHeader.mConnectionID, &peer);
        rv = MOZQUIC_ERR_GENERAL;
        continue;
      }
      ShortHeaderData shortHeader(pkt, pktSize, session->mNextRecvPacketNumber, mConnectionID);
      assert(shortHeader.mConnectionID == tmpShortHeader.mConnectionID);
      fprintf(stderr,"SHORTFORM PACKET[%d] id=%lx pkt# %lx hdrsize=%d\n",
              pktSize, shortHeader.mConnectionID, shortHeader.mPacketNumber,
              shortHeader.mHeaderSize);
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

      fprintf(stderr,"LONGFORM PACKET[%d] id=%lx pkt# %lx type %d version %X\n",
              pktSize, longHeader.mConnectionID, longHeader.mPacketNumber, longHeader.mType, longHeader.mVersion);

      if (!VersionOK(longHeader.mVersion)) {
        fprintf(stderr,"unacceptable version recvd.\n");
        if (!mIsClient) {
          if (pktSize >= kInitialMTU) {
            session->GenerateVersionNegotiation(longHeader, &peer);
          } else {
            fprintf(stderr,"packet too small to be CI, ignoring\n");
          }
          continue;
        } else if (longHeader.mType != PACKET_TYPE_VERSION_NEGOTIATION || longHeader.mVersion != mVersion) {
          fprintf(stderr,"Client ignoring as this isn't VN\n");
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
        session = FindSession(longHeader.mConnectionID);
        if (!session) {
          rv = MOZQUIC_ERR_GENERAL;
        }
        break;

      case PACKET_TYPE_1RTT_PROTECTED_KP0:
        session = FindSession(longHeader.mConnectionID);
        if (!session) {
          rv = MOZQUIC_ERR_GENERAL;
        }
        break;

      default:
        // reject anything that is not a cleartext packet (not right, but later)
        Log((char *)"recv1rtt unexpected type");
        // todo this could actually be out of order protected packet even in handshake
        // and ideally would be queued. for now we rely on retrans
        // todo
        rv = MOZQUIC_ERR_GENERAL;
        break;
      }

      if (!session || rv != MOZQUIC_OK) {
        fprintf(stderr, "unable to find connection for packet\n");
        continue;
      }

      switch (longHeader.mType) {
      case PACKET_TYPE_VERSION_NEGOTIATION: // version negotiation
        rv = session->ProcessVersionNegotiation(pkt, pktSize, longHeader);
        // do not ack
        break;
      case PACKET_TYPE_CLIENT_INITIAL:
        rv = session->ProcessClientInitial(pkt, pktSize, &peer, longHeader, &session, sendAck);
        // ack after processing - find new session
        if (rv == MOZQUIC_OK) {
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
  } while (rv == MOZQUIC_OK);

  return rv;
}

int
MozQuic::IO()
{
  uint32_t code;
  std::shared_ptr<MozQuic> deleteProtector(mAlive);

  Intake();
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

  if ((mConnectionState == SERVER_STATE_1RTT) &&
      (mNextTransmitPacketNumber - mOriginalTransmitPacketNumber) > 20) {
    RaiseError(MOZQUIC_ERR_GENERAL, (char *)"TimedOut Client In Handshake");
    return MOZQUIC_ERR_GENERAL;
  }

  if (mPingDeadline && mConnEventCB && mPingDeadline < Timestamp()) {
    fprintf(stderr,"deadline expired set at %ld now %ld\n", mPingDeadline, Timestamp());
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

void
MozQuic::Log(char *msg)
{
  // todo this should be a structure of some kind
  mConnEventCB(mClosure, MOZQUIC_EVENT_LOG, msg);
  fprintf(stderr,"MozQuic Logger :%s:\n", msg);
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
MozQuic::RaiseError(uint32_t e, char *reason)
{
  Log(reason);
  fprintf(stderr,"MozQuic Logger :%u:\n", e);
  if (mConnEventCB && (mIsClient || mIsChild)) {
    mConnEventCB(mClosure, MOZQUIC_EVENT_ERROR, this);
  }
}

// this is called by the application when the application is handling
// the TLS stream (so that it can do more sophisticated handling
// of certs etc like gecko PSM does). The app is providing the
// client hello
void
MozQuic::HandshakeOutput(unsigned char *buf, uint32_t datalen)
{
  mStreamState->mStream0->Write(buf, datalen, false);
}

// this is called by the application when the application is handling
// the TLS stream (so that it can do more sophisticated handling
// of certs etc like gecko PSM does). The app is providing the
// client hello and interpreting the server hello
void
MozQuic::HandshakeComplete(uint32_t code,
                           struct mozquic_handshake_info *keyInfo)
{
  if (!mAppHandlesSendRecv) {
    RaiseError(MOZQUIC_ERR_GENERAL, (char *)"not using handshaker api");
    return;
  }
  if (mConnectionState != CLIENT_STATE_1RTT) {
    RaiseError(MOZQUIC_ERR_GENERAL, (char *)"Handshake complete in wrong state");
    return;
  }
  if (code != MOZQUIC_OK) {
    RaiseError(MOZQUIC_ERR_CRYPTO, (char *)"Handshake complete err");
    return;
  }

  mNSSHelper->HandshakeSecret(keyInfo->ciphersuite,
                              keyInfo->sendSecret, keyInfo->recvSecret);

  ClientConnected();
}

uint32_t
MozQuic::ClientConnected()
{
  fprintf(stderr,"CLIENT_STATE_CONNECTED\n");
  assert(mConnectionState == CLIENT_STATE_1RTT);
  unsigned char *extensionInfo = nullptr;
  uint16_t extensionInfoLen = 0;
  uint32_t peerVersionList[256];
  uint16_t versionSize = sizeof(peerVersionList) / sizeof (peerVersionList[0]);
  mNSSHelper->GetRemoteTransportExtensionInfo(extensionInfo, extensionInfoLen);
  uint32_t decodeResult;
  uint32_t errorCode = ERROR_NO_ERROR;
  if (!extensionInfoLen && mTolerateNoTransportParams) {
    fprintf(stderr,"Decoding Server Transport Parameters: tolerated empty by config\n");
    decodeResult = MOZQUIC_OK;
  } else {
    assert(sizeof(mStatelessResetToken) == 16);
    decodeResult =
      TransportExtension::
      DecodeServerTransportParameters(extensionInfo, extensionInfoLen,
                                      peerVersionList, versionSize,
                                      mStreamState->mPeerMaxStreamData, mStreamState->mPeerMaxData,
                                      mStreamState->mPeerMaxStreamID, mPeerIdleTimeout,
                                      mStatelessResetToken);
    fprintf(stderr,"Decoding Server Transport Parameters: %s\n",
            decodeResult == MOZQUIC_OK ? "passed" : "failed");
    if (decodeResult != MOZQUIC_OK) {
      errorCode = ERROR_TRANSPORT_PARAMETER;
    }
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
      fprintf(stderr,"Verify Server Transport Parameters: version used %s\n",
              decodeResult == MOZQUIC_OK ? "passed" : "failed");
      if (decodeResult != MOZQUIC_OK) {
        errorCode = ERROR_VERSION_NEGOTIATION;
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
      fprintf(stderr,"Verify Server Transport Parameters: negotiation ok %s\n",
              decodeResult == MOZQUIC_OK ? "passed" : "failed");
      if (decodeResult != MOZQUIC_OK) {
        errorCode = ERROR_VERSION_NEGOTIATION;
      }
    }
  }

  mConnectionState = CLIENT_STATE_CONNECTED;
  if (decodeResult != MOZQUIC_OK) {
    assert (errorCode != ERROR_NO_ERROR);
    MaybeSendAck();
    Shutdown(errorCode, "failed transport parameter verification");
    RaiseError(decodeResult, (char *) "failed to verify server transport parameters");
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
  fprintf(stderr,"SERVER_STATE_CONNECTED\n");
  assert(mConnectionState == SERVER_STATE_1RTT);
  unsigned char *extensionInfo = nullptr;
  uint16_t extensionInfoLen = 0;
  uint32_t peerNegotiatedVersion, peerInitialVersion;
  mNSSHelper->GetRemoteTransportExtensionInfo(extensionInfo, extensionInfoLen);
  uint32_t decodeResult;
  uint32_t errorCode = ERROR_NO_ERROR;
  if (!extensionInfoLen && mTolerateNoTransportParams) {
    fprintf(stderr,"Decoding Client Transport Parameters: tolerated empty by config\n");
    decodeResult = MOZQUIC_OK;
  } else {
    decodeResult =
      TransportExtension::
      DecodeClientTransportParameters(extensionInfo, extensionInfoLen,
                                      peerNegotiatedVersion, peerInitialVersion,
                                      mStreamState->mPeerMaxStreamData, mStreamState->mPeerMaxData,
                                      mStreamState->mPeerMaxStreamID, mPeerIdleTimeout);

    fprintf(stderr,"Decoding Client Transport Parameters: %s\n",
            decodeResult == MOZQUIC_OK ? "passed" : "failed");
    mStreamState->mStream0->NewFlowControlLimit(mStreamState->mPeerMaxStreamData);
    
    if (decodeResult != MOZQUIC_OK) {
      errorCode = ERROR_TRANSPORT_PARAMETER;
    } else {
      // need to confirm version negotiation wasn't messed with
      decodeResult = (mVersion == peerNegotiatedVersion) ? MOZQUIC_OK : MOZQUIC_ERR_CRYPTO;
      fprintf(stderr,"Verify Client Transport Parameters: version used %s\n",
              decodeResult == MOZQUIC_OK ? "passed" : "failed");
      if (decodeResult != MOZQUIC_OK) {
        errorCode = ERROR_VERSION_NEGOTIATION;
      } else {
        if ((peerInitialVersion != peerNegotiatedVersion) && VersionOK(peerInitialVersion)) {
          decodeResult = MOZQUIC_ERR_CRYPTO;
        }
        fprintf(stderr,"Verify Client Transport Parameters: negotiation used %s\n",
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
    RaiseError(decodeResult, (char *) "failed to verify client transport parameters");
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
    fprintf(stderr,"processgeneral discarding %lX as closed\n", packetNum);
    return MOZQUIC_ERR_GENERAL;
  }
  uint32_t written;
  uint32_t rv = mNSSHelper->DecryptBlock(pkt, headerSize, pkt + headerSize,
                                         pktSize - headerSize, packetNum, out,
                                         kMozQuicMSS, written);
  fprintf(stderr,"decrypt (pktnum=%lX) rv=%d sz=%d\n", packetNum, rv, written);
  if (rv != MOZQUIC_OK) {
    fprintf(stderr, "decrypt failed\n");
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
  fprintf(stderr,"RECVD CLOSE\n");
  mConnectionState = mIsClient ? CLIENT_STATE_CLOSED : SERVER_STATE_CLOSED;
  if (mConnEventCB) {
    mConnEventCB(mClosure, MOZQUIC_EVENT_CLOSE_CONNECTION, this);
  } else {
    fprintf(stderr,"No Event callback\n");
  }
  return MOZQUIC_OK;
}

uint32_t
MozQuic::HandleResetFrame(FrameHeaderData *result, bool fromCleartext,
                          const unsigned char *pkt, const unsigned char *endpkt,
                          uint32_t &_ptr)
{
  if (fromCleartext) {
    RaiseError(MOZQUIC_ERR_GENERAL, (char *) "rst_stream frames not allowed in cleartext\n");
    return MOZQUIC_ERR_GENERAL;
  }
  fprintf(stderr,"recvd rst_stream id=%X err=%X, offset=%ld\n",
          result->u.mRstStream.mStreamID, result->u.mRstStream.mErrorCode,
          result->u.mRstStream.mFinalOffset);

  if (!result->u.mRstStream.mStreamID) {
    // todo need to respond with a connection error PROTOCOL_VIOLATION 12.2
    RaiseError(MOZQUIC_ERR_GENERAL, (char *) "rst_stream frames not allowed on stream 0\n");
    return MOZQUIC_ERR_GENERAL;
  }

  std::unique_ptr<MozQuicStreamChunk>
    tmp(new MozQuicStreamChunk(result->u.mRstStream.mStreamID,
                               result->u.mRstStream.mFinalOffset, nullptr,
                               0, 0));
  tmp->MakeStreamRst(result->u.mRstStream.mErrorCode);

  return mStreamState->FindStream(result->u.mStream.mStreamID, tmp);
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
    FrameHeaderData result(pkt + ptr, pktSize - ptr, this);
    if (result.mValid != MOZQUIC_OK) {
      return result.mValid;
    }
    ptr += result.mFrameLen;
    switch(result.mType) {
    case FRAME_TYPE_PADDING:
      break;

    case FRAME_TYPE_PING:
      // basically padding with an ack
      if (fromCleartext) {
        fprintf(stderr, "ping frames not allowed in cleartext\n");
        return MOZQUIC_ERR_GENERAL;
      }
      fprintf(stderr,"recvd ping\n");
      sendAck = true;
      break;

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

    case FRAME_TYPE_CLOSE:
      sendAck = true;
      rv = HandleCloseFrame(&result, fromCleartext, pkt, endpkt, ptr);
      if (rv != MOZQUIC_OK) {
        return rv;
      }
      break;

    case FRAME_TYPE_RST_STREAM:
      sendAck = true;
      rv = HandleResetFrame(&result, fromCleartext, pkt, endpkt, ptr);
      if (rv != MOZQUIC_OK) {
        return rv;
      }
      break;

    default:
      sendAck = true;
      if (fromCleartext) {
        fprintf(stderr,"unexpected frame type %d cleartext=%d\n", result.mType, fromCleartext);
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
  child->mIsChild = true;
  child->mIsClient = false;
  child->mParent = this;
  child->mConnectionState = SERVER_STATE_LISTEN;
  memcpy(&child->mPeer, clientAddr, sizeof (struct sockaddr_in));
  child->mFD = mFD;
  child->mClientInitialPacketNumber = aCIPacketNumber;

  child->mStreamState->mStream0.reset(new MozQuicStreamPair(0, child, child->mStreamState.get(),
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
      proposed == kMozQuicIetfID5) {
    return true;
  }
  return false;
}

uint32_t
MozQuic::StartNewStream(MozQuicStreamPair **outStream, const void *data,
                        uint32_t amount, bool fin)
{
  if (mStreamState) {
    return mStreamState->StartNewStream(outStream, data, amount, fin);
  }
  return MOZQUIC_ERR_GENERAL;
}

void
MozQuic::DeleteStream(uint32_t id)
{
  if (mStreamState) {
    mStreamState->DeleteStream(id);
  }
}

uint32_t
MozQuic::CreateStreamRst(unsigned char *&framePtr, const unsigned char *endpkt,
                         MozQuicStreamChunk *chunk)
{
  fprintf(stderr,"generating stream reset %d\n", chunk->mOffset);
  assert(chunk->mRst);
  assert(chunk->mStreamID);
  assert(!chunk->mLen);
  uint32_t room = endpkt - framePtr;
  if (room < 17) {
    return MOZQUIC_ERR_GENERAL;
  }
  framePtr[0] = FRAME_TYPE_RST_STREAM;
  uint32_t tmp32 = htonl(chunk->mStreamID);
  memcpy(framePtr + 1, &tmp32, 4);
  tmp32 = htonl(chunk->mRstCode);
  memcpy(framePtr + 5, &tmp32, 4);
  uint64_t tmp64 = PR_htonll(chunk->mOffset);
  memcpy(framePtr + 9, &tmp64, 8);
  framePtr += 17;
  return MOZQUIC_OK;
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
      fprintf(stderr,"Forget an old client initial connectionID: %lX\n",
                    (*i).first);
      i = mConnectionHashOriginalNew.erase(i);
    } else {
      i++;
    }
  }
  return MOZQUIC_OK;
}

}

