/* -*- Mode: C++; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*-
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include <array>
#include "MozQuic.h"
#include "MozQuicInternal.h"
#include "MozQuicStream.h"
#include "NSSHelper.h"
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
#include "ufloat16.h"

namespace mozquic  {

// when this set is updated, look at versionOK() and
// GenerateVersionNegotiation()
static const uint32_t kMozQuicVersion1 = 0xf123f0c5; // 0xf123f0c* reserved for mozquic
static const uint32_t kMozQuicIetfID5 = 0xff000005;

static const uint32_t kMozQuicVersionGreaseC = 0xfa1a7a3a;
static const uint32_t kMozQuicVersionGreaseS = 0xea0a6a2a;

// This is the server list
static const uint32_t VersionNegotiationList[] = {
  kMozQuicVersionGreaseS, kMozQuicIetfID5, kMozQuicVersion1,
};

const char *MozQuic::kAlpn = "hq-05";

static const uint32_t kFNV64Size = 8;

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
  , mNextStreamId(1)
  , mNextRecvStreamId(1)
  , mParent(nullptr)
  , mAlive(this)
  , mTimestampConnBegin(0)
  , mPingDeadline(0)
  , mPMTUD1Deadline(0)
  , mPMTUD1PacketNumber(0)
  , mDecodedOK(false)
  , mPeerMaxStreamData(kMaxStreamDataDefault)
  , mPeerMaxData(kMaxDataDefault)
  , mPeerMaxStreamID(kMaxStreamIDDefault)
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
MozQuic::CreateShortPacketHeader(unsigned char *pkt, uint32_t pktSize,
                                 uint32_t &used)
{
  // need to decide if we want 2 or 4 byte packet numbers. 1 is pretty much
  // always too short as it doesn't allow a useful window
  // if (nextNumber - lowestUnacked) > 16000 then use 4.
  uint8_t pnSizeType = 2; // 2 bytes
  if (!mUnAckedData.empty() &&
      ((mNextTransmitPacketNumber - mUnAckedData.front()->mPacketNumber) > 16000)) {
    pnSizeType = 3; // 4 bytes
  }

  // section 5.2 of transport short form header:
  // (0 c=1 k=0) | type [2 or 3]
  pkt[0] = 0x40 | pnSizeType;

  // todo store a network order version of this
  uint64_t tmp64 = PR_htonll(mConnectionID);
  memcpy(pkt + 1, &tmp64, 8);
  used = 9;

  if (pnSizeType == 2) {
    uint16_t tmp16 = htons(mNextTransmitPacketNumber & 0xffff);
    memcpy(pkt + used, &tmp16, 2);
    used += 2;
  } else {
    assert(pnSizeType == 3);
    uint32_t tmp32 = htonl(mNextTransmitPacketNumber & 0xffffffff);
    memcpy(pkt + used, &tmp32, 4);
    used += 4;
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
MozQuic::GreaseVersionNegotiation()
{
  assert(mConnectionState == STATE_UNINITIALIZED);
  fprintf(stderr,"applying version grease\n");
  mVersion = kMozQuicVersionGreaseC;
}

bool
MozQuic::IgnorePKI()
{
  return mIgnorePKI || mIsLoopback;
}

int
MozQuic::StartClient()
{
  assert(!mHandleIO); // todo
  mIsClient = true;
  mNextStreamId = 1;
  mNextRecvStreamId = 2;
  mNSSHelper.reset(new NSSHelper(this, mTolerateBadALPN, mOriginName.get(), true));
  mStream0.reset(new MozQuicStreamPair(0, this, this));

  assert(!mClientOriginalOfferedVersion);
  mClientOriginalOfferedVersion = mVersion;

  mConnectionState = CLIENT_STATE_1RTT;
  for (int i=0; i < 4; i++) {
    mConnectionID = mConnectionID << 16;
    mConnectionID = mConnectionID | (random() & 0xffff);
  }
  for (int i=0; i < 2; i++) {
    mNextTransmitPacketNumber = mNextTransmitPacketNumber << 16;
    mNextTransmitPacketNumber = mNextTransmitPacketNumber | (random() & 0xffff);
  }
  mNextTransmitPacketNumber &= 0x7fffffff; // 31 bits
  mOriginalTransmitPacketNumber = mNextTransmitPacketNumber;

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
  mNextStreamId = 2;
  mNextRecvStreamId = 1;

  StatelessResetEnsureKey();

  assert((sizeof(mValidationKey) % sizeof(uint16_t)) == 0);
  for (int i=0; i < (sizeof(mValidationKey) / sizeof (uint16_t)); i++) {
    ((uint16_t *)mValidationKey)[i] = random() & 0xffff;
  }

  mConnectionState = SERVER_STATE_LISTEN;
  return Bind();
}

int
MozQuic::StartNewStream(MozQuicStreamPair **outStream, const void *data, uint32_t amount, bool fin)
{
  *outStream = new MozQuicStreamPair(mNextStreamId, this, this);
  mStreams.insert( { mNextStreamId, *outStream } );
  mNextStreamId += 2;
  if ( amount || fin) {
    return (*outStream)->Write((const unsigned char *)data, amount, fin);
  }
  return MOZQUIC_OK;
}

void
MozQuic::SetOriginName(const char *name)
{
  mOriginName.reset(new char[strlen(name) + 1]);
  strcpy (mOriginName.get(), name);
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
    RaiseError(MOZQUIC_ERR_GENERAL, (char *)"hash err");
    return false;
  }
  uint64_t hash = fnv1a(pkt, pktSize - kFNV64Size);
  uint64_t recvdHash;
  memcpy(&recvdHash, pkt + pktSize - kFNV64Size, kFNV64Size);
  recvdHash = PR_ntohll(recvdHash);
  bool rv = recvdHash == hash;
  if (!rv) {
    Log((char *)"integrity error");
  }
  return rv;
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
  RetransmitTimer();
  ClearOldInitialConnectIdsTimer();
  Flush();

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

// a request to acknowledge a packetnumber
void
MozQuic::AckScoreboard(uint64_t packetNumber, enum keyPhase kp)
{
  // todo out of order packets should be coalesced
  if (mAckList.empty()) {
    mAckList.emplace_front(packetNumber, Timestamp(), kp);
    return;
  }
  // todo coalesce also in case where two ranges can be combined

  auto iter = mAckList.begin();
  for (; iter != mAckList.end(); ++iter) {
    if ((iter->mPhase == kp) &&
        ((iter->mPacketNumber + 1) == packetNumber)) {
      // the common case is to just adjust this counter
      // in the first element.. but you can't do that if it has
      // already been transmitted. (that needs a new node)
      if (iter->Transmitted()) {
        break;
      }
      iter->mPacketNumber++;
      iter->mExtra++;
      iter->mReceiveTime.push_front(Timestamp());
      return;
    }
    if (iter->mPacketNumber >= packetNumber &&
        packetNumber >= (iter->mPacketNumber - iter->mExtra)) {
      return; // dup
    }
    if (iter->mPacketNumber < packetNumber) {
      break;
    }
  }
  mAckList.emplace(iter, packetNumber, Timestamp(), kp);
}

int
MozQuic::MaybeSendAck()
{
  if (mAckList.empty()) {
    return MOZQUIC_OK;
  }

  // if we aren't in connected we will only piggyback
  if (mConnectionState != CLIENT_STATE_CONNECTED &&
      mConnectionState != SERVER_STATE_CONNECTED) {
    return MOZQUIC_OK;
  }
  // todo for doing some kind of delack

  bool ackedUnprotected = false;
  auto iter = mAckList.begin();
  for (; iter != mAckList.end(); ++iter) {
    if (iter->Transmitted()) {
      continue;
    }
    fprintf(stderr,"Trigger Ack based on %lX (extra %d) kp=%d\n",
            iter->mPacketNumber, iter->mExtra, iter->mPhase);
    FlushStream(true);
    break;
  }
  return MOZQUIC_OK;
}

static uint8_t varSize(uint64_t input)
{
  // returns 0->3 depending on magnitude of input
  return (input < 0x100) ? 0 : (input < 0x10000) ? 1 : (input < 0x100000000UL) ? 2 : 3;
}

// To clarify.. an ack frame for 15,14,13,11,10,8,2,1
// numblocks=3
// largest=15, first ack block length = 2 // 15, 14, 13
// ack block 1 = {1, 2} // 11, 10
// ack block 2 = {1, 1} // 8
// ack block 3 = {5, 2} / 2, 1

uint32_t
MozQuic::AckPiggyBack(unsigned char *pkt, uint64_t pktNumOfAck, uint32_t avail, keyPhase kp, uint32_t &used)
{
  used = 0;

  // build as many ack frames as will fit
  // always 16bit run length
  bool newFrame = true;
  uint8_t *numBlocks = nullptr;
  uint8_t *numTS = nullptr;
  uint64_t largestAcked;
  uint64_t lowAcked;
  for (auto iter = mAckList.begin(); iter != mAckList.end(); ) {
    // list  ordered as 7/2, 2/1.. (with gap @4 @3)
    // i.e. highest num first
    if ((kp <= keyPhaseUnprotected) && iter->mPhase >= keyPhase0Rtt) {
      fprintf(stderr,"skip ack generation of %lX wrong kp need %d\n", iter->mPacketNumber, kp);
      ++iter;
      continue;
    }
    
    largestAcked = iter->mPacketNumber;
    if (newFrame) {
      uint32_t need = 7;
      uint8_t pnSizeType = varSize(largestAcked);
      need += 1 << pnSizeType;
      if (avail < need) {
        fprintf(stderr,"Cannot create new ack frame due to lack of space in packet %d of %d\n",
                avail, need);
        return MOZQUIC_OK; // ok to return as we haven't written any of the frame
      }

      newFrame = false;

      // ack with numblocks, 16/32 bit largest and 16 bit run
      pkt[0] = 0xb0 | (pnSizeType << 2) | 0x01;
      used += 1;
      numBlocks = pkt + used;
      *numBlocks = 0;
      used += 1;
      numTS = pkt + used;
      *numTS = 0;
      used += 1;
      if (pnSizeType == 0) {
        pkt[used] = largestAcked & 0xff;
        used += 1;
      } else if (pnSizeType == 1) {
        uint16_t packet16 = largestAcked & 0xffff;
        packet16 = htons(packet16);
        memcpy(pkt + used, &packet16, 2);
        used += 2;
      } else if (pnSizeType == 2) {
        uint32_t packet32 = largestAcked & 0xffffffff;
        packet32 = htonl(packet32);
        memcpy(pkt + used, &packet32, 4);
        used += 4;
      } else {
        assert (pnSizeType == 3);
        uint32_t packet64 = largestAcked;
        packet64 = PR_htonll(packet64);
        memcpy(pkt + used, &packet64, 8);
        used += 8;
      }

      // timestamp is microseconds (10^-6) as 16 bit fixed point #
      assert(iter->mReceiveTime.size());
      uint64_t delay64 = (Timestamp() - *(iter->mReceiveTime.begin())) * 1000;
      uint16_t delay = htons(ufloat16_encode(delay64));
      memcpy(pkt + used, &delay, 2);
      used += 2;
      uint16_t extra = htons(iter->mExtra);
      memcpy(pkt + used, &extra, 2); // first ack block len
      used += 2;
      lowAcked = iter->mPacketNumber - iter->mExtra;
      pkt += used;
      avail -= used;
    } else {
      assert(lowAcked > iter->mPacketNumber);
      if (avail < 3) {
        fprintf(stderr,"Cannot create new ack frame due to lack of space in packet %d of %d\n",
                avail, 3);
        break; // do not return as we have a partially written frame
      }
      uint64_t gap = lowAcked - iter->mPacketNumber - 1;

      while (gap > 255) {
        if (avail < 3) {
          break;
        }
        *numBlocks = *numBlocks + 1;
        pkt[0] = 255; // empty block
        pkt[1] = 0;
        pkt[2] = 0;
        lowAcked -= 255;
        pkt += 3;
        used += 3;
        avail -= 3;
        gap -= 255;
      }
      assert(gap <= 255);
      if (avail < 3) {
        break;
      }
      *numBlocks = *numBlocks + 1;
      pkt[0] = gap;
      uint16_t ackBlockLen = htons(iter->mExtra + 1);
      memcpy(pkt + 1, &ackBlockLen, 2);
      lowAcked -= (gap + iter->mExtra + 1);
      pkt += 3;
      used += 3;
      avail -= 3;
    }

    fprintf(stderr,"created ack of %lX (%d extra) into pn=%lX [%d prev transmits]\n",
            iter->mPacketNumber, iter->mExtra, pktNumOfAck, iter->mTransmits.size());

    iter->mTransmits.push_back(std::pair<uint64_t, uint64_t>(pktNumOfAck, Timestamp()));
    ++iter;
    if (*numBlocks == 0xff) {
      break;
    }
  }

  newFrame = true;
  uint64_t previousTS;
  uint32_t previousPktID;
  if (kp != keyPhaseUnprotected) {
    for (auto iter = mAckList.begin(); iter != mAckList.end(); iter++) {
      if (iter->mTimestampTransmitted) {
        continue;
      }
      iter->mTimestampTransmitted = true;
      int i = 0;
      for (auto pIter = iter->mReceiveTime.begin();
           pIter != iter->mReceiveTime.end(); pIter++) {
        if (avail < (newFrame ? 5 : 3)) {
          break;
        }

        if (newFrame) {
          newFrame = false;
          uint64_t gap = largestAcked - iter->mPacketNumber;
          if (gap > 255) {
            break;
          }
          pkt[0] = gap;
          uint32_t delta = *pIter - mTimestampConnBegin;
          delta = htonl(delta);
          memcpy(pkt + 1, &delta, 4);
          previousPktID = iter->mPacketNumber;
          previousTS = *pIter;
          pkt += 5;
          used += 5;
          avail -= 5;
        } else {
          uint64_t gap = previousPktID - (iter->mPacketNumber - i);
          if (gap > 255) {
            break;
          }
          pkt[0] = gap;
          uint64_t delay64 = (previousTS - *pIter) * 1000;
          uint16_t delay = htons(ufloat16_encode(delay64));
          memcpy(pkt + 1, &delay, 2);
          pkt += 3;
          used += 3;
          avail -= 3;
        }
        *numTS = *numTS + 1;
        if (*numTS == 0xff) {
          break;
        }
        i++;
      }
    }
  }
  return MOZQUIC_OK;
}

bool
MozQuic::Unprotected(MozQuic::LongHeaderType type)
{
  return type <= PACKET_TYPE_CLIENT_CLEARTEXT;
}

void
MozQuic::Acknowledge(uint64_t packetNum, keyPhase kp)
{
  assert(mIsChild || mIsClient);

  if (packetNum >= mNextRecvPacketNumber) {
    mNextRecvPacketNumber = packetNum + 1;
  }

  fprintf(stderr,"%p REQUEST TO GEN ACK FOR %lX kp=%d\n", this, packetNum, kp);


  AckScoreboard(packetNum, kp);
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
  mStream0->Write(buf, datalen, false);
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
    fprintf(stderr,"Decocding Server Transport Parameters: tolerated empty by config\n");
    decodeResult = MOZQUIC_OK;
  } else {
    assert(sizeof(mStatelessResetToken) == 16);
    decodeResult =
      TransportExtension::
      DecodeServerTransportParameters(extensionInfo, extensionInfoLen,
                                      peerVersionList, versionSize,
                                      mPeerMaxStreamData, mPeerMaxData, mPeerMaxStreamID, mPeerIdleTimeout,
                                      mStatelessResetToken);
    fprintf(stderr,"Decoding Server Transport Parameters: %s\n",
            decodeResult == MOZQUIC_OK ? "passed" : "failed");
    if (decodeResult != MOZQUIC_OK) {
      errorCode = ERROR_TRANSPORT_PARAMETER;
    }

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
  fprintf(stderr,"SERVER_STATE_CONNECTED\n");
  assert(mConnectionState == SERVER_STATE_1RTT);
  unsigned char *extensionInfo = nullptr;
  uint16_t extensionInfoLen = 0;
  uint32_t peerNegotiatedVersion, peerInitialVersion;
  mNSSHelper->GetRemoteTransportExtensionInfo(extensionInfo, extensionInfoLen);
  uint32_t decodeResult;
  uint32_t errorCode = ERROR_NO_ERROR;
  if (!extensionInfoLen && mTolerateNoTransportParams) {
    fprintf(stderr,"Decocding Client Transport Parameters: tolerated empty by config\n");
    decodeResult = MOZQUIC_OK;
  } else {
    decodeResult =
      TransportExtension::
      DecodeClientTransportParameters(extensionInfo, extensionInfoLen,
                                      peerNegotiatedVersion, peerInitialVersion,
                                      mPeerMaxStreamData, mPeerMaxData, mPeerMaxStreamID, mPeerIdleTimeout);

    fprintf(stderr,"Decoding Client Transport Parameters: %s\n",
            decodeResult == MOZQUIC_OK ? "passed" : "failed");

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

int
MozQuic::Client1RTT()
{
  if (mAppHandlesSendRecv) {
    if (mStream0->Empty()) {
      return MOZQUIC_OK;
    }
    // Server Reply is available and needs to be passed to app for processing
    unsigned char buf[kMozQuicMSS];
    uint32_t amt = 0;
    bool fin = false;

    // todo transport extension info needs to be passed to app
    uint32_t code = mStream0->Read(buf, kMozQuicMSS, amt, fin);
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
                                        kMaxStreamDataDefault, kMaxDataDefault,
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
                                      kMaxStreamDataDefault, kMaxDataDefault,
                                      kMaxStreamIDDefault, kIdleTimeoutDefault, resetToken);
    mNSSHelper->SetLocalTransportExtensionInfo(te, teLength);
    mSetupTransportExtension = true;
  }

  if (!mStream0->Empty()) {
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
MozQuic::ProcessServerStatelessRetry(unsigned char *pkt, uint32_t pktSize, LongHeaderData &header)
{
  // check packet num and version
  assert(pkt[0] & 0x80);
  assert((pkt[0] & ~0x80) == PACKET_TYPE_SERVER_STATELESS_RETRY);
  assert(pktSize >= 17);

  if (!mIsClient) {
    fprintf(stderr,"SSR should only arrive at client. Ignore.\n");
    return MOZQUIC_OK;
  }

  if (mReceivedServerClearText) {
    fprintf(stderr,"SSR not allowed after server cleartext.\n");
    return MOZQUIC_OK;
  }

  if ((header.mVersion != mVersion) ||
      (header.mConnectionID != mConnectionID)) {
    // this was supposedly copied from client - so this isn't a match
    fprintf(stderr,"version or cid mismatch\n");
    return MOZQUIC_ERR_VERSION;
  }

  // essentially this is an ack of client_initial using the packet #
  // in the header as the ack, so need to find that on the unacked list.
  // then we can reset the unacked list
  bool foundReference = false;
  for (auto i = mUnAckedData.begin(); i != mUnAckedData.end(); i++) {
    if ((*i)->mPacketNumber == header.mPacketNumber) {
      foundReference = true;
      break;
    }
  }
  if (!foundReference) {
    // packet num was supposedly copied from client - so no match
    return MOZQUIC_ERR_VERSION;
  }

  mStream0.reset(new MozQuicStreamPair(0, this, this));
  mSetupTransportExtension = false;
  mUnAckedData.clear();
  mUnWrittenData.clear();

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
    fprintf(stderr,"VN should only arrive at client. Ignore.\n");
    return MOZQUIC_OK;
  }

  if (mReceivedServerClearText) {
    fprintf(stderr,"VN not allowed after server cleartext.\n");
    return MOZQUIC_OK;
  }

  if (mProcessedVN) {
    fprintf(stderr,"only handle one VN per session\n");
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
  for (auto i = mUnAckedData.begin(); i != mUnAckedData.end(); i++) {
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
    RaiseError(MOZQUIC_ERR_VERSION, (char *)"negotiate version packet format incorrect");
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
       fprintf(stderr, "Ignore version negotiation packet that offers version "
               "a client selected.\n");
      return MOZQUIC_OK;
    } else if (!newVersion && VersionOK(possibleVersion)) {
      newVersion = possibleVersion;
    }
  }

  if (newVersion) {
    mVersion = newVersion;
    fprintf(stderr, "negotiated version %X\n", mVersion);
    mNSSHelper.reset(new NSSHelper(this, mTolerateBadALPN, mOriginName.get(), true));
    mStream0.reset(new MozQuicStreamPair(0, this, this));
    mSetupTransportExtension  = false;
    mUnAckedData.clear();
    
    return MOZQUIC_OK;
  }

  RaiseError(MOZQUIC_ERR_VERSION, (char *)"unable to negotiate version");
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
    fprintf(stderr,"server cleartext arrived at server. ignored.\n");
    return MOZQUIC_OK;
  }

  if (mConnectionState != CLIENT_STATE_1RTT &&
      mConnectionState != CLIENT_STATE_0RTT) {
    fprintf(stderr, "clear text after handshake will be dropped.\n");
    return MOZQUIC_OK;
  }

  if (header.mVersion != mVersion) {
    Log((char *)"wrong version");
    return MOZQUIC_ERR_GENERAL;
    // this should not abort session as its
    // not authenticated
  }

  if (mConnectionID != header.mConnectionID) {
    if (mReceivedServerClearText) {
      Log((char *)"wrong connection id");
      return MOZQUIC_ERR_GENERAL;
      // this should not abort session as its
      // not authenticated
    }

    fprintf(stderr, "server clear text changed connID from %lx to %lx\n",
            mConnectionID, header.mConnectionID);
    mConnectionID = header.mConnectionID;
  }
  mReceivedServerClearText = true;

  return ProcessGeneralDecoded(pkt + 17, pktSize - 17 - 8, sendAck, true);
}

void
MozQuic::ProcessAck(FrameHeaderData *ackMetaInfo, const unsigned char *framePtr, bool fromCleartext)
{
  // frameptr points to the beginning of the ackblock section
  // we have already runtime tested that there is enough data there
  // to read the ackblocks and the tsblocks
  assert (ackMetaInfo->mType == FRAME_TYPE_ACK);
  uint16_t numRanges = 0;

  std::array<std::pair<uint64_t, uint64_t>, 257> ackStack;

  uint64_t largestAcked = ackMetaInfo->u.mAck.mLargestAcked;
  do {
    uint64_t extra = 0;
    const uint8_t blockLengthLen = ackMetaInfo->u.mAck.mAckBlockLengthLen;
    memcpy(((char *)&extra) + (8 - blockLengthLen), framePtr, blockLengthLen);
    extra = PR_ntohll(extra);
    framePtr += blockLengthLen;

    fprintf(stderr,"ACK RECVD (%s) FOR %lX -> %lX\n",
            fromCleartext ? "cleartext" : "protected",
            largestAcked - extra, largestAcked);
    // form a stack here so we can process them starting at the
    // lowest packet number, which is how mUnAckedData is ordered and
    // do it all in one pass
    assert(numRanges < 257);
    ackStack[numRanges] =
      std::pair<uint64_t, uint64_t>(largestAcked - extra, extra + 1);

    largestAcked--;
    largestAcked -= extra;
    if (numRanges++ == ackMetaInfo->u.mAck.mNumBlocks) {
      break;
    }
    uint8_t gap = *framePtr;
    largestAcked -= gap;
    framePtr++;
  } while (1);

  auto dataIter = mUnAckedData.begin();
  for (auto iters = numRanges; iters > 0; --iters) {
    uint64_t haveAckFor = ackStack[iters - 1].first;
    uint64_t haveAckForEnd = haveAckFor + ackStack[iters - 1].second;

    if (mPMTUD1PacketNumber &&
        (mPMTUD1PacketNumber >= haveAckFor) &&
        (mPMTUD1PacketNumber < haveAckForEnd)) {
      CompletePMTUD1();
    }

    for (; haveAckFor < haveAckForEnd; haveAckFor++) {

      // skip over stuff that is too low
      for (; (dataIter != mUnAckedData.end()) && ((*dataIter)->mPacketNumber < haveAckFor); dataIter++);

      if ((dataIter == mUnAckedData.end()) || ((*dataIter)->mPacketNumber > haveAckFor)) {
        fprintf(stderr,"ACK'd data not found for %lX ack\n", haveAckFor);
      } else {
        do {
          assert ((*dataIter)->mPacketNumber == haveAckFor);
          fprintf(stderr,"ACK'd data found for %lX\n", haveAckFor);
          dataIter = mUnAckedData.erase(dataIter);
        } while ((dataIter != mUnAckedData.end()) &&
                 (*dataIter)->mPacketNumber == haveAckFor);
      }
    }
  }

  // todo read the timestamps
  // and obviously todo feed the times into congestion control

  // obv unacked lists should be combined (data, other frames, acks)
  for (auto iters = numRanges; iters > 0; --iters) {
    uint64_t haveAckFor = ackStack[iters - 1].first;
    uint64_t haveAckForEnd = haveAckFor + ackStack[iters - 1].second;
    for (; haveAckFor < haveAckForEnd; haveAckFor++) {
      bool foundHaveAckFor = false;
      for (auto acklistIter = mAckList.begin(); acklistIter != mAckList.end(); ) {
        bool foundAckFor = false;
        for (auto vectorIter = acklistIter->mTransmits.begin();
             vectorIter != acklistIter->mTransmits.end(); vectorIter++ ) {
          if ((*vectorIter).first == haveAckFor) {
            fprintf(stderr,"haveAckFor %lX found unacked ack of %lX (+%d) transmitted %d times\n",
                    haveAckFor, acklistIter->mPacketNumber, acklistIter->mExtra,
                    acklistIter->mTransmits.size());
            foundAckFor = true;
            break; // vector iteration
            // need to keep looking at the rest of mAckList. Todo this is terribly wasteful.
          }
        } // vector iteration
        if (!foundAckFor) {
          acklistIter++;
        } else {
          acklistIter = mAckList.erase(acklistIter);
          foundHaveAckFor = true;
        }
      } // macklist iteration
      if (!foundHaveAckFor) {
        fprintf(stderr,"haveAckFor %lX CANNOT find corresponding unacked ack\n", haveAckFor);
      }
    } // haveackfor iteration
  } //ranges iteration

  uint32_t pktID = ackMetaInfo->u.mAck.mLargestAcked;
  uint64_t timestamp;
  for(int i = 0; i < ackMetaInfo->u.mAck.mNumTS; i++) {
    assert(pktID > framePtr[0]);
    pktID = pktID - framePtr[0];
    if (!i) {
      memcpy(&timestamp, framePtr + 1, 4);
      timestamp = ntohl(timestamp);
      framePtr += 5;
    } else {
      uint16_t tmp16;
      memcpy(&tmp16, framePtr + 1, 2);
      tmp16 = ntohs(tmp16);
      timestamp = timestamp - (ufloat16_decode(tmp16) / 1000);
      framePtr += 3;
    }
    fprintf(stderr, "Timestamp for packet %lX is %lu\n", pktID, timestamp);
  }
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
MozQuic::FindStream(uint32_t streamID, std::unique_ptr<MozQuicStreamChunk> &d)
{
  // Open a new stream and implicitly open all streams with ID smaller than
  // streamID that are not already opened.
  while (streamID >= mNextRecvStreamId) {
    fprintf(stderr, "Add new stream %d\n", mNextRecvStreamId);
    MozQuicStreamPair *stream = new MozQuicStreamPair(mNextRecvStreamId, this, this);
    mStreams.insert( { mNextRecvStreamId, stream } );
    mNextRecvStreamId += 2;
  }

  auto i = mStreams.find(streamID);
  if (i == mStreams.end()) {
    fprintf(stderr, "Stream %d already closed.\n", streamID);
    // this stream is already closed and deleted. Discharge frame.
    d.reset();
    return MOZQUIC_ERR_ALREADY_FINISHED;
  }
  (*i).second->Supply(d);
  if (!(*i).second->Empty() && mConnEventCB) {
    mConnEventCB(mClosure, MOZQUIC_EVENT_NEW_STREAM_DATA, (*i).second);
  }
  return MOZQUIC_OK;
}

void
MozQuic::DeleteStream(uint32_t streamID)
{
  fprintf(stderr, "Delete stream %lu\n", streamID);
  mStreams.erase(streamID);
}

uint32_t
MozQuic::HandleStreamFrame(FrameHeaderData *result, bool fromCleartext,
                           const unsigned char *pkt, const unsigned char *endpkt,
                           uint32_t &_ptr)
{
  fprintf(stderr,"recv stream %d len=%d offset=%d fin=%d\n",
          result->u.mStream.mStreamID,
          result->u.mStream.mDataLen,
          result->u.mStream.mOffset,
          result->u.mStream.mFinBit);

  if (!result->u.mStream.mStreamID && result->u.mStream.mFinBit) {
    // todo need to respond with a connection error PROTOCOL_VIOLATION 12.2
    RaiseError(MOZQUIC_ERR_GENERAL, (char *) "fin not allowed on stream 0\n");
    return MOZQUIC_ERR_GENERAL;
  }

  // todo, ultimately the stream chunk could hold references to
  // the packet buffer and _ptr into it for zero copy

  // parser checked for this, but jic
  assert(pkt + _ptr + result->u.mStream.mDataLen <= endpkt);
  std::unique_ptr<MozQuicStreamChunk>
    tmp(new MozQuicStreamChunk(result->u.mStream.mStreamID,
                               result->u.mStream.mOffset,
                               pkt + _ptr,
                               result->u.mStream.mDataLen,
                               result->u.mStream.mFinBit));
  if (!result->u.mStream.mStreamID) {
    mStream0->Supply(tmp);
  } else {
    if (fromCleartext) {
      RaiseError(MOZQUIC_ERR_GENERAL, (char *) "cleartext non 0 stream id\n");
      return MOZQUIC_ERR_GENERAL;
    }
    uint32_t rv = FindStream(result->u.mStream.mStreamID, tmp);
    if (rv != MOZQUIC_OK) {
      return rv;
    }
  }
  _ptr += result->u.mStream.mDataLen;
  return MOZQUIC_OK;
}

uint32_t
MozQuic::HandleAckFrame(FrameHeaderData *result, bool fromCleartext,
                        const unsigned char *pkt, const unsigned char *endpkt,
                        uint32_t &_ptr)
{
  if (fromCleartext && (mConnectionState == SERVER_STATE_LISTEN)) {
    // acks are not allowed processing client_initial
    RaiseError(MOZQUIC_ERR_GENERAL, (char *) "acks are not allowed in client initial\n");
    return MOZQUIC_ERR_GENERAL;
  }

  // _ptr now points at ack block section
  uint32_t ackBlockSectionLen =
    result->u.mAck.mAckBlockLengthLen +
    (result->u.mAck.mNumBlocks * (result->u.mAck.mAckBlockLengthLen + 1));
  uint32_t timestampSectionLen = result->u.mAck.mNumTS * 3;
  if (timestampSectionLen) {
    timestampSectionLen += 2; // the first one is longer
  }
  assert(pkt + _ptr + ackBlockSectionLen + timestampSectionLen <= endpkt);
  ProcessAck(result, pkt + _ptr, fromCleartext);
  _ptr += ackBlockSectionLen;
  _ptr += timestampSectionLen;
  return MOZQUIC_OK;
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

  return FindStream(result->u.mStream.mStreamID, tmp);
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
      rv = HandleStreamFrame(&result, fromCleartext, pkt, endpkt, ptr);
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

  child->mStream0.reset(new MozQuicStreamPair(0, child, child));
  do {
    for (int i=0; i < 4; i++) {
      child->mConnectionID = child->mConnectionID << 16;
      child->mConnectionID = child->mConnectionID | (random() & 0xffff);
    }
  } while (mConnectionHash.count(child->mConnectionID) != 0);

  for (int i=0; i < 2; i++) {
    child->mNextTransmitPacketNumber = child->mNextTransmitPacketNumber << 16;
    child->mNextTransmitPacketNumber = child->mNextTransmitPacketNumber | (random() & 0xffff);
  }
  child->mNextTransmitPacketNumber &= 0x7fffffff; // 31 bits
  child->mOriginalTransmitPacketNumber = child->mNextTransmitPacketNumber;

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
MozQuic::GenerateVersionNegotiation(LongHeaderData &clientHeader, struct sockaddr_in *peer)
{
  assert(!mIsChild);
  assert(!mIsClient);
  assert(mMTU <= kMaxMTU);
  unsigned char pkt[kMaxMTU];
  uint32_t tmp32;
  uint64_t tmp64;

  fprintf(stderr,"sending a version negotiation packet\n");
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
    fprintf(stderr, "Warning generating incorrect version negotation list for testing\n");
    for (int i = (sizeof(VersionNegotiationList) / sizeof(uint32_t)) - 1; i >= 0; i--) {
      tmp32 = htonl(VersionNegotiationList[i]);
      memcpy (framePtr, &tmp32, sizeof(uint32_t));
      framePtr += sizeof(uint32_t);
    }
  }

  return Transmit(pkt, framePtr - pkt, peer);
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
    RaiseError(MOZQUIC_ERR_GENERAL, (char *)"client initial packet too small");
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
    fprintf(stderr,"No Event callback\n");
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
  assert(mStream0);

  if (header.mVersion != mVersion) {
    RaiseError(MOZQUIC_ERR_GENERAL, (char *)"version mismatch");
    return MOZQUIC_ERR_GENERAL;
  }

  return ProcessGeneralDecoded(pkt + 17, pktSize - 17 - 8, sendAck, true);
}

uint32_t
MozQuic::FlushStream0(bool forceAck)
{
  if (mUnWrittenData.empty() && !forceAck) {
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
    assert(mStream0->Empty());
    // just in case of server stateless reset pollution
    mStream0->ResetInbound();
  }

  // todo store a network order version of this
  uint64_t connID = PR_htonll(mConnectionID);
  if (mConnectionState == SERVER_STATE_SSR) {
    fprintf(stderr,"Generating Server Stateless Retry.\n");
    connID = PR_htonll(mOriginalConnectionID);
    assert(mUnAckedData.empty());
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
  CreateStreamFrames(framePtr, endpkt - 8, true); // last 8 are for checksum
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
    mUnAckedData.clear();
    assert(mUnWrittenData.empty());
    if (mConnEventCB) {
      mConnEventCB(mClosure, MOZQUIC_EVENT_ERROR, this);
    }
  } else {
    uint32_t room = endpkt - framePtr - 8; // the last 8 are for checksum
    uint32_t used;
    if (AckPiggyBack(framePtr, mNextTransmitPacketNumber, room, keyPhaseUnprotected, used) == MOZQUIC_OK) {
      if (used) {
        fprintf(stderr,"Handy-Ack FlushStream0 packet %lX frame-len=%d\n", mNextTransmitPacketNumber, used);
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

    fprintf(stderr,"TRANSMIT0[%lX] this=%p len=%d total0=%d cid=%lX\n",
            mNextTransmitPacketNumber, this, finalLen,
            mNextTransmitPacketNumber - mOriginalTransmitPacketNumber,
            mConnectionID);

    mNextTransmitPacketNumber++;

    if (sentStream && !mUnWrittenData.empty()) {
      return FlushStream0(false);
    }
  }
  return MOZQUIC_OK;
}

static bool CreateStreamRst(unsigned char *&framePtr, const unsigned char *endpkt,
                            MozQuicStreamChunk *chunk)
{
  fprintf(stderr,"generating stream reset %d\n", chunk->mOffset);
  assert(chunk->mRst);
  assert(chunk->mStreamID);
  assert(!chunk->mLen);
  uint32_t room = endpkt - framePtr;
  if (room < 17) {
    return false;
  }
  framePtr[0] = MozQuic::FRAME_TYPE_RST_STREAM;
  uint32_t tmp32 = htonl(chunk->mStreamID);
  memcpy(framePtr + 1, &tmp32, 4);
  tmp32 = htonl(chunk->mRstCode);
  memcpy(framePtr + 5, &tmp32, 4);
  uint64_t tmp64 = PR_htonll(chunk->mOffset);
  memcpy(framePtr + 9, &tmp64, 8);
  framePtr += 17;
  return true;
}

uint32_t
MozQuic::ScrubUnWritten(uint32_t streamID)
{
  auto iter = mUnWrittenData.begin();
  while (iter != mUnWrittenData.end()) {
    auto chunk = (*iter).get();
    if (chunk->mStreamID == streamID && !chunk->mRst) {
      iter = mUnWrittenData.erase(iter);
      fprintf(stderr,"scrubbing chunk %p of unwritten id %d\n",
              chunk, streamID);
    } else {
      iter++;
    }
  }

  auto iter2 = mUnAckedData.begin();
  while (iter2 != mUnAckedData.end()) {
    auto chunk = (*iter2).get();
    if (chunk->mStreamID == streamID && !chunk->mRst) {
      iter2 = mUnAckedData.erase(iter2);
      fprintf(stderr,"scrubbing chunk %p of unacked id %d\n",
              chunk, streamID);
    } else {
      iter2++;
    }
  }
  return MOZQUIC_OK;
}

uint32_t
MozQuic::CreateStreamFrames(unsigned char *&framePtr, const unsigned char *endpkt, bool justZero)
{
  auto iter = mUnWrittenData.begin();
  while (iter != mUnWrittenData.end()) {
    if (justZero && (*iter)->mStreamID) {
      iter++;
      continue;
    }
    if ((*iter)->mRst) {
      if (!CreateStreamRst(framePtr, endpkt, (*iter).get())) {
        break;
      }
    } else {
      uint32_t room = endpkt - framePtr;
      if (room < 1) {
        break; // this is only for type, we will do a second check later.
      }

      // 11fssood -> 11000001 -> 0xC1. Fill in fin, offset-len and id-len below dynamically
      auto typeBytePtr = framePtr;
      framePtr[0] = 0xc1;

      // Determine streamId size without varSize becuase we use 24 bit value
      uint32_t tmp32 = (*iter)->mStreamID;
      tmp32 = htonl(tmp32);
      uint8_t idLen = 4;
      for (int i=0; (i < 3) && (((uint8_t*)(&tmp32))[i] == 0); i++) {
        idLen--;
      }

      // determine offset size
      uint64_t offsetValue = PR_htonll((*iter)->mOffset);
      uint8_t offsetSizeType = varSize((*iter)->mOffset);
      uint8_t offsetLen;
      if (offsetSizeType == 0) {
        // 0, 16, 32, 64 instead of usual 8, 16, 32, 64
        if ((*iter)->mOffset) {
          offsetSizeType = 1;
          offsetLen = 2;
        } else {
          offsetLen = 0;
        }
      } else {
        offsetLen = 1 << offsetSizeType;
      }

      // 1(type) + idLen + offsetLen + 2(len) + 1(data)
      if (room < (4 + idLen + offsetLen)) {
        break;
      }

      // adjust the frame type:
      framePtr[0] |= (idLen - 1) << 3;
      assert(!(offsetSizeType & ~0x3));
      framePtr[0] |= (offsetSizeType << 1);
      framePtr++;

      // Set streamId
      memcpy(framePtr, ((uint8_t*)(&tmp32)) + (4 - idLen), idLen);
      framePtr += idLen;

      // Set offset
      if (offsetLen) {
        memcpy(framePtr, ((uint8_t*)(&offsetValue)) + (8 - offsetLen), offsetLen);
        framePtr += offsetLen;
      }

      room -= (3 + idLen + offsetLen); //  1(type) + idLen + offsetLen + 2(len)
      if (room < (*iter)->mLen) {
        // we need to split this chunk. its too big
        // todo iterate on them all instead of doing this n^2
        // as there is a copy involved
        std::unique_ptr<MozQuicStreamChunk>
          tmp(new MozQuicStreamChunk((*iter)->mStreamID,
                                     (*iter)->mOffset + room,
                                     (*iter)->mData.get() + room,
                                     (*iter)->mLen - room,
                                     (*iter)->mFin));
        (*iter)->mLen = room;
        (*iter)->mFin = false;
        auto iterReg = iter++;
        mUnWrittenData.insert(iter, std::move(tmp));
        iter = iterReg;
      }
      assert(room >= (*iter)->mLen);

      // set the len and fin bits after any potential split
      uint16_t tmp16 = (*iter)->mLen;
      tmp16 = htons(tmp16);
      memcpy(framePtr, &tmp16, 2);
      framePtr += 2;

      if ((*iter)->mFin) {
        *typeBytePtr = *typeBytePtr | STREAM_FIN_BIT;
      }

      memcpy(framePtr, (*iter)->mData.get(), (*iter)->mLen);
      fprintf(stderr,"writing a stream %d frame %d @ offset %d [fin=%d] in packet %lX\n",
              (*iter)->mStreamID, (*iter)->mLen, (*iter)->mOffset, (*iter)->mFin, mNextTransmitPacketNumber);
      framePtr += (*iter)->mLen;
    }

    (*iter)->mPacketNumber = mNextTransmitPacketNumber;
    (*iter)->mTransmitTime = Timestamp();
    if ((mConnectionState == CLIENT_STATE_CONNECTED) ||
        (mConnectionState == SERVER_STATE_CONNECTED) ||
        (mConnectionState == CLIENT_STATE_0RTT)) {
      (*iter)->mTransmitKeyPhase = keyPhase1Rtt;
    } else {
      (*iter)->mTransmitKeyPhase = keyPhaseUnprotected;
    }
    (*iter)->mRetransmitted = false;

    // move it to the unacked list
    std::unique_ptr<MozQuicStreamChunk> x(std::move(*iter));
    mUnAckedData.push_back(std::move(x));
    iter = mUnWrittenData.erase(iter);
  }
  return MOZQUIC_OK;
}



uint32_t
MozQuic::FlushStream(bool forceAck)
{
  if (!mDecodedOK) {
    FlushStream0(forceAck);
  }

  if (mUnWrittenData.empty() && !forceAck) {
    return MOZQUIC_OK;
  }

  assert(mMTU <= kMaxMTU);
  unsigned char plainPkt[kMaxMTU];
  uint32_t headerLen;

  CreateShortPacketHeader(plainPkt, mMTU - kTagLen, headerLen);

  unsigned char *framePtr = plainPkt + headerLen;
  const unsigned char *endpkt = plainPkt + mMTU - kTagLen; // reserve 16 for aead tag
  CreateStreamFrames(framePtr, endpkt, false);
  
  uint32_t rv = ProtectedTransmit(plainPkt, headerLen,
                                  plainPkt + headerLen, framePtr - (plainPkt + headerLen),
                                  mMTU - headerLen - kTagLen, true);
  if (rv != MOZQUIC_OK) {
    return rv;
  }

  if (!mUnWrittenData.empty()) {
    return FlushStream(false);
  }
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

uint32_t
MozQuic::Flush()
{
  return FlushStream(false);
}

uint32_t
MozQuic::DoWriter(std::unique_ptr<MozQuicStreamChunk> &p)
{
  // this data gets queued to unwritten and framed and
  // transmitted after prioritization by flush()
  assert (mConnectionState != STATE_UNINITIALIZED);

  mUnWrittenData.push_back(std::move(p));

  return MOZQUIC_OK;
}

int32_t
MozQuic::NSSInput(void *buf, int32_t amount)
{
  if (mStream0->Empty()) {
    PR_SetError(PR_WOULD_BLOCK_ERROR, 0);
    return -1;
  }

  // client part of handshake is available in stream 0,
  // feed it to nss via the return code of this fx
  uint32_t amt = 0;
  bool fin = false;

  uint32_t code = mStream0->Read((unsigned char *)buf,
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
  return mStream0->Write((const unsigned char *)buf, amount, false);
}

uint32_t
MozQuic::RetransmitTimer()
{
  if (mUnAckedData.empty()) {
    return MOZQUIC_OK;
  }

  // this is a crude stand in for reliability until we get a real loss
  // recovery system built
  uint64_t now = Timestamp();
  uint64_t discardEpoch = now - kForgetUnAckedThresh;

  for (auto i = mUnAckedData.begin(); i != mUnAckedData.end(); ) {
    // just a linear backoff for now
    uint64_t retransEpoch = now - (kRetransmitThresh * (*i)->mTransmitCount);
    if ((*i)->mTransmitTime > retransEpoch) {
      break;
    }
    if (((*i)->mTransmitTime <= discardEpoch) && (*i)->mRetransmitted) {
      // this is only on packets that we are keeping around for timestamp purposes
      fprintf(stderr,"old unacked packet forgotten %lX\n",
              (*i)->mPacketNumber);
      assert(!(*i)->mData);
      i = mUnAckedData.erase(i);
    } else if (!(*i)->mRetransmitted) {
      assert((*i)->mData);
      fprintf(stderr,"data associated with packet %lX retransmitted\n",
              (*i)->mPacketNumber);
      (*i)->mRetransmitted = true;

      // the ctor steals the data pointer
      std::unique_ptr<MozQuicStreamChunk> tmp(new MozQuicStreamChunk(*(*i)));
      assert(!(*i)->mData);
      DoWriter(tmp);
      i++;
    } else {
      i++;
    }
  }

  return MOZQUIC_OK;
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

MozQuic::FrameHeaderData::FrameHeaderData(const unsigned char *pkt,
                                          uint32_t pktSize, MozQuic *session)
{
  memset(&u, 0, sizeof (u));
  mValid = MOZQUIC_ERR_GENERAL;

  unsigned char type = pkt[0];
  const unsigned char *framePtr = pkt + 1;

  if ((type & FRAME_MASK_STREAM) == FRAME_TYPE_STREAM) {
    mType = FRAME_TYPE_STREAM;

    u.mStream.mFinBit = (type & STREAM_FIN_BIT);

    uint8_t ssBit = (type & 0x18) >> 3;
    uint8_t ooBit = (type & 0x06) >> 1;
    uint8_t dBit = (type & 0x01);

    uint32_t lenLen = dBit ? 2 : 0;
    uint32_t offsetLen = 0;
    assert(!(ooBit & 0xFC));
    if (ooBit == 0) {
      offsetLen = 0;
    } else if (ooBit == 1) {
      offsetLen = 2;
    } else if (ooBit == 2) {
      offsetLen = 4;
    } else if (ooBit == 3) {
      offsetLen = 8;
    }

    assert(!(ssBit & 0xFC));
    uint32_t idLen = ssBit + 1;

    uint32_t bytesNeeded = 1 + lenLen + idLen + offsetLen;
    if (bytesNeeded > pktSize) {
      session->RaiseError(MOZQUIC_ERR_GENERAL, (char *) "stream frame header short");
      return;
    }

    memcpy(((char *)&u.mStream.mStreamID) + (4 - idLen), framePtr, idLen);
    framePtr += idLen;
    u.mStream.mStreamID = ntohl(u.mStream.mStreamID);

    memcpy(((char *)&u.mStream.mOffset) + (8 - offsetLen), framePtr, offsetLen);
    framePtr += offsetLen;
    u.mStream.mOffset = PR_ntohll(u.mStream.mOffset);
    if (dBit) {
      memcpy (&u.mStream.mDataLen, framePtr, 2);
      framePtr += 2;
      u.mStream.mDataLen = ntohs(u.mStream.mDataLen);
    } else {
      u.mStream.mDataLen = pktSize - bytesNeeded;
    }

    // todo log frame len
    if (bytesNeeded + u.mStream.mDataLen > pktSize) {
      session->RaiseError(MOZQUIC_ERR_GENERAL, (char *) "stream frame data short");
      return;
    }

    mValid = MOZQUIC_OK;
    mFrameLen = bytesNeeded;
    return;
  } else if ((type & FRAME_MASK_ACK) == FRAME_TYPE_ACK) {
    mType = FRAME_TYPE_ACK;
    uint8_t numBlocks = (type & 0x10) ? 1 : 0; // N bit
    uint32_t ackedLen = (type & 0x0c) >> 2; // LL bits
    ackedLen = 1 << ackedLen;

    // MM bits are type & 0x03
    u.mAck.mAckBlockLengthLen = 1 << (type & 0x03);

    uint16_t bytesNeeded = 1 + numBlocks + 1 + ackedLen + 2;
    if (bytesNeeded > pktSize) {
      session->RaiseError(MOZQUIC_ERR_GENERAL, (char *) "ack frame header short");
      return;
    }

    if (numBlocks) {
      u.mAck.mNumBlocks = framePtr[0];
      framePtr++;
    } else {
      u.mAck.mNumBlocks = 0;
    }
    u.mAck.mNumTS = framePtr[0];
    framePtr++;

    u.mAck.mLargestAcked = 0;
    assert(sizeof(u.mAck.mLargestAcked) == 8);
    assert(ackedLen <= 8);
    memcpy(((char *)&u.mAck.mLargestAcked) + (8 - ackedLen), framePtr, ackedLen);
    u.mAck.mLargestAcked = PR_ntohll(u.mAck.mLargestAcked);
    framePtr += ackedLen;

    memcpy(&u.mAck.mAckDelay, framePtr, 2);
    framePtr += 2;
    u.mAck.mAckDelay = ntohs(u.mAck.mAckDelay);
    bytesNeeded += u.mAck.mAckBlockLengthLen + // required First ACK Block
                   u.mAck.mNumBlocks * (1 + u.mAck.mAckBlockLengthLen); // additional ACK Blocks
    if (u.mAck.mNumTS) {
      bytesNeeded += u.mAck.mNumTS * (1 + 2) + 2;
    }
    if (bytesNeeded > pktSize) {
      session->RaiseError(MOZQUIC_ERR_GENERAL, (char *) "ack frame header short");
      return;
    }
    mValid = MOZQUIC_OK;
    mFrameLen = framePtr - pkt;
    return;
  } else {
    switch(type) {

    case FRAME_TYPE_PADDING:
      mType = FRAME_TYPE_PADDING;
      mValid = MOZQUIC_OK;
      mFrameLen = FRAME_TYPE_PADDING_LENGTH;
      return;

    case FRAME_TYPE_RST_STREAM:
      if (pktSize < FRAME_TYPE_RST_STREAM_LENGTH) {
        session->RaiseError(MOZQUIC_ERR_GENERAL,
                   (char *) "RST_STREAM frame length expected");
        return;
      }

      mType = FRAME_TYPE_RST_STREAM;

      memcpy(&u.mRstStream.mStreamID, framePtr, 4);
      u.mRstStream.mStreamID = ntohl(u.mRstStream.mStreamID);
      framePtr += 4;
      memcpy(&u.mRstStream.mErrorCode, framePtr, 4);
      u.mRstStream.mErrorCode = ntohl(u.mRstStream.mErrorCode);
      framePtr += 4;
      memcpy(&u.mRstStream.mFinalOffset, framePtr, 8);
      u.mRstStream.mFinalOffset = PR_ntohll(u.mRstStream.mFinalOffset);
      mValid = MOZQUIC_OK;
      mFrameLen = FRAME_TYPE_RST_STREAM_LENGTH;
      return;

    case FRAME_TYPE_CLOSE:
      if (pktSize < FRAME_TYPE_CLOSE_LENGTH) {
        session->RaiseError(MOZQUIC_ERR_GENERAL,
                   (char *) "CONNECTION_CLOSE frame length expected");
        return;
      }

      mType = FRAME_TYPE_CLOSE;

      memcpy(&u.mClose.mErrorCode, framePtr, 4);
      u.mClose.mErrorCode = ntohl(u.mClose.mErrorCode);
      framePtr += 4;
      uint16_t len;
      memcpy(&len, framePtr, 2);
      len = ntohs(len);
      framePtr += 2;
      if (len) {
        if (pktSize < ((uint32_t)FRAME_TYPE_CLOSE_LENGTH + len)) {
          session->RaiseError(MOZQUIC_ERR_GENERAL,
                     (char *) "CONNECTION_CLOSE frame length expected");
          return;
        }
        // Log error!
        char reason[kMozQuicMSS];
        if (len + 64 < kMozQuicMSS) {
          snprintf(reason, 64, "Close code %X reason: ", u.mClose.mErrorCode);
          ssize_t slen = strlen(reason);
          memcpy(reason + slen, framePtr, len);
          reason[len + slen] = '\0';
          session->Log((char *)reason);
        }
      }
      mValid = MOZQUIC_OK;
      mFrameLen = FRAME_TYPE_CLOSE_LENGTH + len;
      return;

    case FRAME_TYPE_GOAWAY:
      if (pktSize < FRAME_TYPE_GOAWAY_LENGTH) {
        session->RaiseError(MOZQUIC_ERR_GENERAL,
                   (char *) "GOAWAY frame length expected");
        return;
      }

      mType = FRAME_TYPE_GOAWAY;

      memcpy(&u.mGoaway.mClientStreamID, framePtr, 4);
      u.mGoaway.mClientStreamID = ntohl(u.mGoaway.mClientStreamID);
      framePtr += 4;
      memcpy(&u.mGoaway.mServerStreamID, framePtr, 4);
      u.mGoaway.mServerStreamID = ntohl(u.mGoaway.mServerStreamID);
      framePtr += 4;
      mValid = MOZQUIC_OK;
      mFrameLen = FRAME_TYPE_GOAWAY_LENGTH;
      return;

    case FRAME_TYPE_MAX_DATA:
      if (pktSize < FRAME_TYPE_MAX_DATA_LENGTH) {
        session->RaiseError(MOZQUIC_ERR_GENERAL,
                   (char *) "MAX_DATA frame length expected");
        return;
      }

      mType = FRAME_TYPE_MAX_DATA;

      memcpy(&u.mMaxData.mMaximumData, framePtr, 8);
      u.mMaxData.mMaximumData = PR_ntohll(u.mMaxData.mMaximumData);
      mValid = MOZQUIC_OK;
      mFrameLen =  FRAME_TYPE_MAX_DATA_LENGTH;
      return;

    case FRAME_TYPE_MAX_STREAM_DATA:
      if (pktSize < FRAME_TYPE_MAX_STREAM_DATA_LENGTH) {
        session->RaiseError(MOZQUIC_ERR_GENERAL,
                   (char *) "MAX_STREAM_DATA frame length expected");
        return;
      }

      mType = FRAME_TYPE_MAX_STREAM_DATA;

      memcpy(&u.mMaxStreamData.mStreamID, framePtr, 4);
      u.mMaxStreamData.mStreamID = ntohl(u.mMaxStreamData.mStreamID);
      framePtr += 4;
      memcpy(&u.mMaxStreamData.mMaximumStreamData, framePtr, 8);
      u.mMaxStreamData.mMaximumStreamData =
        PR_ntohll(u.mMaxStreamData.mMaximumStreamData);
      mValid = MOZQUIC_OK;
      mFrameLen = FRAME_TYPE_MAX_STREAM_DATA_LENGTH;
      return;

    case FRAME_TYPE_MAX_STREAM_ID:
      if (pktSize < FRAME_TYPE_MAX_STREAM_ID_LENGTH) {
        session->RaiseError(MOZQUIC_ERR_GENERAL,
                   (char *) "MAX_STREAM_ID frame length expected");
        return;
      }

      mType = FRAME_TYPE_MAX_STREAM_ID;

      memcpy(&u.mMaxStreamID.mMaximumStreamID, framePtr, 4);
      u.mMaxStreamID.mMaximumStreamID =
        ntohl(u.mMaxStreamID.mMaximumStreamID);
      mValid = MOZQUIC_OK;
      mFrameLen = FRAME_TYPE_MAX_STREAM_ID_LENGTH;
      return;

    case FRAME_TYPE_PING:
      mType = FRAME_TYPE_PING;
      mValid = MOZQUIC_OK;
      mFrameLen = FRAME_TYPE_PING_LENGTH;
      return;

    case FRAME_TYPE_BLOCKED:
      mType = FRAME_TYPE_BLOCKED;
      mValid = MOZQUIC_OK;
      mFrameLen = FRAME_TYPE_BLOCKED_LENGTH;
      return;

    case FRAME_TYPE_STREAM_BLOCKED:
      if (pktSize < FRAME_TYPE_STREAM_BLOCKED_LENGTH) {
        session->RaiseError(MOZQUIC_ERR_GENERAL,
                   (char *) "STREAM_BLOCKED frame length expected");
        return;
      }

      mType = FRAME_TYPE_STREAM_BLOCKED;

      memcpy(&u.mStreamBlocked.mStreamID, framePtr, 4);
      u.mStreamBlocked.mStreamID = ntohl(u.mStreamBlocked.mStreamID);
      mValid = MOZQUIC_OK;
      mFrameLen = FRAME_TYPE_STREAM_BLOCKED_LENGTH;
      return;

    case FRAME_TYPE_STREAM_ID_NEEDED:
      mType = FRAME_TYPE_STREAM_ID_NEEDED;
      mValid = MOZQUIC_OK;
      mFrameLen = FRAME_TYPE_STREAM_ID_NEEDED_LENGTH;
      return;

    case FRAME_TYPE_NEW_CONNECTION_ID:
      if (pktSize < FRAME_TYPE_NEW_CONNECTION_ID_LENGTH) {
        session->RaiseError(MOZQUIC_ERR_GENERAL,
                   (char *) "NEW_CONNECTION_ID frame length expected");
        return;
      }

      mType = FRAME_TYPE_NEW_CONNECTION_ID;

      memcpy(&u.mNewConnectionID.mSequence, framePtr, 2);
      u.mNewConnectionID.mSequence = ntohs(u.mNewConnectionID.mSequence);
      framePtr += 2;
      memcpy(&u.mNewConnectionID.mConnectionID, framePtr, 8);
      u.mNewConnectionID.mConnectionID =
        PR_ntohll(u.mNewConnectionID.mConnectionID);
      mValid = MOZQUIC_OK;
      mFrameLen = FRAME_TYPE_NEW_CONNECTION_ID_LENGTH;
      return;

    default:
      assert(false);
    }
  }
  mValid = MOZQUIC_OK;
}

MozQuic::LongHeaderData::LongHeaderData(unsigned char *pkt, uint32_t pktSize)
{
  // these fields are all version independent - though the interpretation
  // of type is not.
  assert(pktSize >= 17);
  assert(pkt[0] & 0x80);
  mType = static_cast<enum LongHeaderType>(pkt[0] & ~0x80);
  memcpy(&mConnectionID, pkt + 1, 8);
  mConnectionID = PR_ntohll(mConnectionID);
  memcpy(&mPacketNumber, pkt + 9, 4);
  mPacketNumber = ntohl(mPacketNumber);
  memcpy(&mVersion, pkt + 13, 4);
  mVersion = ntohl(mVersion);
}

uint64_t
MozQuic::DecodePacketNumber(unsigned char *pkt, int pnSize, uint64_t next)
{
  // pkt should point to a variable (as defined by pnSize) amount of data
  // in network byte order
  uint64_t candidate1, candidate2;
  if (pnSize == 1) {
    candidate1 = (next & ~0xFFUL) | pkt[0];
    candidate2 = candidate1 + 0x100UL;
  } else if (pnSize == 2) {
    uint16_t tmp16;
    memcpy(&tmp16, pkt, 2);
    tmp16 = ntohs(tmp16);
    candidate1 = (next & ~0xFFFFUL) | tmp16;
    candidate2 = candidate1 + 0x10000UL;
  } else {
    assert (pnSize == 4);
    uint32_t tmp32;
    memcpy(&tmp32, pkt, 4);
    tmp32 = ntohl(tmp32);
    candidate1 = (next & ~0xFFFFFFFFUL) | tmp32;
    candidate2 = candidate1 + 0x100000000UL;
  }

  uint64_t distance1 = (next >= candidate1) ? (next - candidate1) : (candidate1 - next);
  uint64_t distance2 = (next >= candidate2) ? (next - candidate2) : (candidate2 - next);
  uint64_t rv = (distance1 < distance2) ? candidate1 : candidate2;
  return rv;
}

MozQuic::ShortHeaderData::ShortHeaderData(unsigned char *pkt, uint32_t pktSize,
                                          uint64_t nextPN, uint64_t defaultCID)
{
  mHeaderSize = 0xffffffff;
  mConnectionID = 0;
  mPacketNumber = 0;
  assert(pktSize >= 1);
  assert(!(pkt[0] & 0x80));
  uint32_t pnSize = pkt[0] & 0x1f;
  if (pnSize == 1) {
    pnSize = 1;
  } else if (pnSize == 2) {
    pnSize = 2;
  } else if (pnSize == 3) {
    pnSize = 4;
  } else {
    return;
  }

  uint32_t used;
  if ((!(pkt[0] & 0x40)) || (pktSize < (9 + pnSize))) {
    // missing connection id. without the truncate transport option this cannot happen
    used = 1;
    mConnectionID = defaultCID;
  } else {
    memcpy(&mConnectionID, pkt + 1, 8);
    mConnectionID = PR_ntohll(mConnectionID);
    used = 9;
  }

  mHeaderSize = used + pnSize;
  mPacketNumber = DecodePacketNumber(pkt + used, pnSize, nextPN);
}

}

