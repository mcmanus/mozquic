/* -*- Mode: C++; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*-
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#pragma once

#include <netinet/ip.h>
#include <string>
#include <list>
#include <stdint.h>
#include <unistd.h>
#include <forward_list>
#include <unordered_map>
#include <memory>
#include <vector>
#include <string.h>
#include "prnetdb.h"
#include "MozQuic.h"
#include "Packetization.h"
#include "Timer.h"

namespace mozquic {

/* socket typedef */
#ifdef WIN32
#define MOZQUIC_SOCKET_BAD INVALID_SOCKET
#else
#define MOZQUIC_SOCKET_BAD -1
#endif

// The version negotiation List
//
// sync with versionOK() and GenerateVersionNegotiation()
static const uint32_t kMozQuicVersion1 = 0xf123f0c5; // 0xf123f0c* reserved for mozquic
static const uint32_t kMozQuicIetfID11 = 0xff00000b;
static const uint32_t kMozQuicVersionGreaseS = 0xea0a6a2a;
static const uint32_t VersionNegotiationList[] = {
  kMozQuicVersionGreaseS, kMozQuicIetfID11, kMozQuicVersion1,
};

enum connectionState
{
  STATE_UNINITIALIZED,
  CLIENT_STATE_0RTT,
  CLIENT_STATE_1RTT,
  CLIENT_STATE_CONNECTED,
  CLIENT_STATE_CLOSED,  // todo more shutdown states

  SERVER_STATE_BREAK,

  SERVER_STATE_LISTEN,
  SERVER_STATE_0RTT,
  SERVER_STATE_1RTT,
  SERVER_STATE_SSR,
  SERVER_STATE_CONNECTED,
  SERVER_STATE_CLOSED,
};

enum transportErrorType {
  ERROR_NO_ERROR            = 0x0000,
  ERROR_INTERNAL            = 0x0001,
  SERVER_BUSY_ERROR         = 0x0002,
  FLOW_CONTROL_ERROR        = 0x0003,
  STREAM_ID_ERROR           = 0x0004,
  STREAM_STATE_ERROR        = 0x0005,
  FINAL_OFFSET_ERROR        = 0x0006,
  FRAME_FORMAT_ERROR        = 0x0007,
  ERROR_TRANSPORT_PARAMETER = 0x0008,
  ERROR_VERSION_NEGOTIATION = 0x0009,
  PROTOCOL_VIOLATION        = 0x000A,
  UNSOLICITED_PATH_RESPONSE = 0x000B,
  // FRAME_ERROR 0x01XX
  FRAME_ERROR_MASK          = 0x0100
};

enum httpErrorType {
  STOPPING = 0x00,
  HTTP_NO_ERROR = 0x01,
  HTTP_PUSH_REFUSED = 0x02,
  HTTP_INTERNAL_ERROR = 0x03,
  HTTP_PUSH_ALREADY_IN_CACHE = 0x04,
  HTTP_REQUEST_CANCELLED = 0x05,
  HTTP_HPACK_DECOMPRESSION_FAILED = 0x06,
  HTTP_CONNECT_ERROR = 0x07,
  HTTP_EXCESSIVE_LOAD = 0x08,
  HTTP_VERSION_FALLBACK = 0x09,
  HTTP_MALFORMED_HEADERS = 0x0A,
  HTTP_MALFORMED_PRIORITY = 0x0B,
  HTTP_MALFORMED_SETTINGS = 0x0C,
  HTTP_MALFORMED_PUSH_PROMISE = 0x0D,
  HTTP_MALFORMED_DATA = 0x0E,
  HTTP_INTERRUPTED_HEADERS = 0x0F,
  HTTP_WRONG_STREAM = 0x10,
  HTTP_MULTIPLE_SETTINGS = 0x11,
  HTTP_MALFORMED_PUSH = 0x12,
  HTTP_MALFORMED_MAX_PUSH_ID = 0x13,
};

enum keyPhase {
  keyPhaseUnknown,
  keyPhaseUnprotected,
  keyPhase0Rtt,
  keyPhase1Rtt
};

enum earlyDataState {
  EARLY_DATA_NOT_NEGOTIATED,
  EARLY_DATA_SENT,
  EARLY_DATA_IGNORED,
  EARLY_DATA_ACCEPTED
};

class StreamPair;
class StreamAck;
class NSSHelper;
class Sender;
class StreamState;
class ReliableData;
class BufferedPacket;

class ConnIDTimeout
  : public TimerNotification
{
public:
  ConnIDTimeout(MozQuic *session)
    : mSession(session)    {}
  virtual ~ConnIDTimeout() {}
  void Alarm(Timer *) override;
private:
  MozQuic *mSession;
};

// used by mInitialHash
class InitialClientPacketInfo {
public:
  InitialClientPacketInfo() {}
  virtual ~InitialClientPacketInfo() {}
  CID mServerConnectionID; // source cid in server handshake resp
  uint64_t mHashKey; // source cid from client initial
  uint64_t mTimestamp;
  std::unique_ptr<Timer> mTimer;

  bool operator ==(const InitialClientPacketInfo &b) const {
    return b.mHashKey == mHashKey;
  }

};

struct CIDHasher {
  size_t operator()(const CID&x)const{
    return x.Hash();
  }
};

class MozQuic
  : public TimerNotification
{
  friend class StreamPair;
  friend class Log;
  friend class FrameHeaderData;
  friend class StreamState;
  friend class ConnIDTimeout;

public:
  static const char *kAlpn;
  static const uint32_t kForgetInitialConnectionIDsThresh = 15000; // ms

  MozQuic(bool handleIO);
  virtual ~MozQuic();

  void Alarm(Timer *) override;

  int StartClient();
  int StartServer();
  void SetInitialPacketNumber();
  uint32_t StartNewStream(StreamPair **outStream, bool uni, bool no_replay, const void *data, uint32_t amount, bool fin);
  void MaybeDeleteStream(StreamPair *sp);
  int IO();
  void HandshakeOutput(const unsigned char *, uint32_t amt);
  void HandshakeTParamOutput(const unsigned char *, uint32_t amt);
  uint32_t HandshakeComplete(uint32_t errCode, struct mozquic_handshake_info *keyInfo);

  CID HandshakeCID() const { return mHandshakeCID;}
  CID ServerCID() { return mIsClient ? mPeerCID : mLocalCID; }
  CID ClientCID() { return (!mIsClient) ? mPeerCID : mLocalCID; }
  
  void SetOriginPort(int port) { mOriginPort = port; }
  void SetOriginName(const char *name);
  void SetStatelessResetKey(const unsigned char *key) { memcpy(mStatelessResetKey, key, 128); }
  void SetClosure(void *closure) { mClosure = closure; }
  void SetConnEventCB(int (*fx)(mozquic_connection_t *,
                      uint32_t event, void * param)) { mConnEventCB = fx; }
  void SetFD(mozquic_socket_t fd) { mFD = fd; }
  int  GetFD() { return mFD; }
  void GreaseVersionNegotiation();
  void SetIgnorePKI() { mIgnorePKI = true; }
  void SetTolerateBadALPN() { mTolerateBadALPN = true; }
  void SetTolerateNoTransportParams() { mTolerateNoTransportParams = true; }
  void SetSabotageVN() { mSabotageVN = true; }
  void SetForceAddressValidation() { mForceAddressValidation = true; }
  bool GetForceAddressValidation() {
    return mParent ? mParent->mForceAddressValidation : mForceAddressValidation;
  }
  void SetEnable0RTT() {
    mEnabled0RTT = true;
  }
  bool Enabled0RTT() {
    return mParent ? mParent->mEnabled0RTT : mEnabled0RTT;
  }
  void SetReject0RTTData() {
    mReject0RTTData = true;
  }
  bool Reject0RTTData() {
    return mParent ? mParent->mReject0RTTData : mReject0RTTData;
  }
  void SetStreamWindow(uint64_t w) { mAdvertiseStreamWindow = w; }
  void SetConnWindowBytes(uint64_t bytes) { mAdvertiseConnectionWindow = bytes; }
  void SetDropRate(uint64_t dr) { mDropRate = dr; }

  void SetMaxSizeAllowed(uint16_t ms) { mLocalMaxSizeAllowed = ms; }
  void SetClientPort(int clientPort) { mClientPort = clientPort; }

  void SetAppHandlesSendRecv() { mAppHandlesSendRecv = true; }
  void SetAppHandlesLogging() { mAppHandlesLogging = true; }
  void SetV6() { mIPV6 = true; }
  bool IgnorePKI();
  void Destroy(uint32_t, const char *);
  uint32_t CheckPeer(uint32_t);
  bool IsAllAcked();
  enum connectionState GetConnectionState() { return mConnectionState; }
  
  bool IsOpen() {
    return (mConnectionState == CLIENT_STATE_0RTT || mConnectionState == CLIENT_STATE_1RTT ||
            mConnectionState == CLIENT_STATE_CONNECTED || mConnectionState == SERVER_STATE_0RTT ||
            mConnectionState == SERVER_STATE_1RTT || mConnectionState == SERVER_STATE_CONNECTED);
  }

  bool DecodedOK() { return mDecodedOK; }
  void GetPeerAddressHash(CID cid, unsigned char *out, uint32_t *outLen);
  static uint64_t Timestamp();
  void Shutdown(uint16_t code, const char *);

  void StartBackPressure() { mBackPressure = true; }
  void ReleaseBackPressure();
  uint32_t RealTransmit(const unsigned char *, uint32_t len,
                        const struct sockaddr *peer, bool updateTimers);
  uint32_t RetransmitOldestUnackedData(bool fromRTO);
  uint32_t FlushOnce(bool forceack, bool forceframe);
  bool     AnyUnackedPackets();
  bool     IsV6() { return mIPV6; }
  unsigned char Processed0RTT() { return !!mProcessed0RTT; }

private:
  void RaiseError(uint32_t err, const char *fmt, ...);

  void AckScoreboard(uint64_t num, enum keyPhase kp);
  int MaybeSendAck(bool delackOK = false);

  void Acknowledge(uint64_t packetNumber, keyPhase kp);
  uint32_t AckPiggyBack(unsigned char *pkt, uint64_t packetNumber, uint32_t avail, keyPhase kp,
                        bool bareAck, uint32_t &used);
  uint32_t Recv(unsigned char *, uint32_t len, uint32_t &outLen, const struct sockaddr *peer);
  int ProcessServerCleartext(unsigned char *, uint32_t size, LongHeaderData &, bool &);
  int ProcessClientInitial(unsigned char *, uint32_t size, const struct sockaddr *peer,
                           LongHeaderData &, MozQuic **outSession, bool &);
  int ProcessClientCleartext(unsigned char *pkt, uint32_t pktSize, LongHeaderData &, bool&);
  uint32_t ProcessGeneralDecoded(const unsigned char *, uint32_t size, bool &, bool fromClearText);
  uint32_t ProcessGeneral(const unsigned char *, uint32_t size, uint32_t headerSize, uint64_t packetNumber, bool &);
  uint32_t Process0RTTProtectedPacket(const unsigned char *, uint32_t size, uint32_t headerSize, uint64_t packetNumber, bool &);
  uint32_t BufferForLater(const unsigned char *pkt, uint32_t pktSize, uint32_t headerSize,
                          uint64_t packetNumber);
  uint32_t ReleaseProtectedPackets();
  bool IntegrityCheck(unsigned char *, uint32_t pktsize, uint32_t headersize, CID handhakeCID, uint64_t packetNumber,
                      unsigned char *outbuf, uint32_t &outSize);
  void ProcessAck(FrameHeaderData *ackMetaInfo, const unsigned char *framePtr,
                  const unsigned char *endOfPacket, bool fromCleartext,
                  uint32_t &used);

  uint32_t HandlePathChallengeFrame(FrameHeaderData *meta);
  uint32_t HandleAckFrame(FrameHeaderData *result, bool fromCleartext,
                          const unsigned char *pkt, const unsigned char *endpkt,
                          uint32_t &_ptr);
  uint32_t HandleConnCloseFrame(FrameHeaderData *result, bool fromCleartext,
                                const unsigned char *pkt, const unsigned char *endpkt,
                                uint32_t &_ptr);
  uint32_t HandleApplicationCloseFrame(FrameHeaderData *result, bool fromCleartext,
                                       const unsigned char *pkt, const unsigned char *endpkt,
                                       uint32_t &_ptr);
  
  bool ServerState() { return mConnectionState > SERVER_STATE_BREAK; }
  MozQuic *FindSession(const sockaddr *peer);
  MozQuic *FindSession(CID &cid);
  void RemoveSession(CID &cid);
  uint32_t ClientConnected();
  uint32_t ServerConnected();

  uint32_t Intake(bool *partialResult);
  uint32_t FlushStream0(bool forceAck);

  int Client1RTT();
  int ClientReadPostHandshakeTLSMessages();
  int Server1RTT();
  int Bind(int portno);
  void AdjustBuffering();
  bool VersionOK(uint32_t proposed);
  uint32_t GenerateVersionNegotiation(LongHeaderData &clientHeader, const struct sockaddr *peer);
  uint32_t ProcessVersionNegotiation(unsigned char *pkt, uint32_t pktSize, LongHeaderData &header);
  uint32_t ProcessServerStatelessRetry(unsigned char *pkt, uint32_t pktSize, LongHeaderData &header);

  MozQuic *Accept(const struct sockaddr *clientAddr,
                  CID clientCID, CID handshakeCID, uint64_t aCIPacketNumber);

  void StartPMTUD1();
  void CompletePMTUD1();
  void AbortPMTUD1();

public:
  static uint32_t EncodeVarint(uint64_t input, unsigned char *dest, uint32_t avail, uint32_t &used);
  static uint32_t DecodeVarint(const unsigned char *ptr, uint32_t avail, uint64_t &result, uint32_t &used);
  static uint32_t DecodeVarintMax32(const unsigned char *ptr, uint32_t avail, uint32_t &result, uint32_t &used);

  static void EncodeVarintAs1(uint64_t input, unsigned char *dest);
  static void EncodeVarintAs2(uint64_t input, unsigned char *dest);
  static void EncodeVarintAs4(uint64_t input, unsigned char *dest);
  static void EncodeVarintAs8(uint64_t input, unsigned char *dest);

private:
  uint32_t CreateShortPacketHeader(unsigned char *pkt, uint32_t pktSize, uint32_t &used);
  uint32_t Create0RTTLongPacketHeader(unsigned char *pkt, uint32_t pktSize, uint32_t &used,
                                      unsigned char **payloadLenPtr);
  uint32_t ProtectedTransmit(unsigned char *header, uint32_t headerLen,
                             unsigned char *data, uint32_t dataLen, uint32_t dataAllocation,
                             bool addAcks, bool ackable, bool queueOnly = false,
                             uint32_t mtuOverride = 0, uint32_t *bytesOut = nullptr);

  // Stateless Reset
  bool     StatelessResetCheckForReceipt(const unsigned char *pkt, uint32_t pktSize);
  uint32_t StatelessResetSend(CID &connID, const struct sockaddr *peer);
  static uint32_t StatelessResetCalculateToken(const unsigned char *key128,
                                               CID &connID, unsigned char *out);
  uint32_t StatelessResetEnsureKey();
  void EnsureSetupClientTransportParameters();
  mozquic_socket_t mFD;

  bool mHandleIO;
  bool mIsClient;
  bool mIsChild;
  bool mReceivedServerClearText;
  bool mSetupTransportExtension;
  bool mIgnorePKI;
  bool mTolerateBadALPN;
  bool mTolerateNoTransportParams;
  bool mSabotageVN;
  bool mForceAddressValidation;
  bool mAppHandlesSendRecv;
  bool mAppHandlesLogging;
  bool mIsLoopback;
  bool mProcessedVN;
  bool mBackPressure;
  bool mEnabled0RTT;
  bool mReject0RTTData;
  bool mIPV6;
  bool mProcessed0RTT;

  enum connectionState mConnectionState;
  int mOriginPort;
  int mClientPort;
  std::unique_ptr<char []> mOriginName;

  struct sockaddr_in6 mPeer; // cast into v4

  // both only set in server parent
  unsigned char mStatelessResetKey[128];
  unsigned char mValidationKey[32];

  // only set in client after exchange of transport params
  bool          mValidStatelessResetToken;
  unsigned char mStatelessResetToken[16];

  uint32_t mVersion;
  uint32_t mClientOriginalOfferedVersion;

  std::unordered_map<CID, MozQuic *, CIDHasher> mConnectionHash;
    
  // This maps connectionId sent by a client and connectionId chosen by the
  // server. This is used to detect dup client initial packets.
  // The elemets are going to be removed using a timer.
  std::unordered_map<uint64_t,
    std::unique_ptr<InitialClientPacketInfo>> mInitialHash;

  CID mLocalCID;
  CID mPeerCID;
  CID mHandshakeCID;

  uint16_t mMaxPacketConfig;
  uint16_t mMTU;
  uint16_t mDropRate;
  uint64_t mNextTransmitPacketNumber;
  uint64_t mOriginalTransmitPacketNumber;
  uint64_t mNextRecvPacketNumber; // expected
  uint64_t mClientInitialPacketNumber; // only set on child in server

  uint64_t mGenAckFor;
  uint64_t mGenAckForTime;
  std::unique_ptr<Timer> mDelAckTimer;

  void *mClosure;
  int  (*mConnEventCB)(void *, uint32_t, void *);

  std::unique_ptr<NSSHelper>   mNSSHelper;
  std::unique_ptr<StreamState> mStreamState;
  std::unique_ptr<Sender>      mSendState;

  // parent and children are only defined on the server
  MozQuic *mParent; // only in child
  std::shared_ptr<MozQuic> mAlive;
  std::list<std::shared_ptr<MozQuic>> mChildren; // only in parent

  std::list<BufferedPacket> mBufferedProtectedPackets;

  // The beginning of a connection.
  uint64_t mTimestampConnBegin;

  // Related to PING and PMTUD
  std::unique_ptr<Timer> mPingDeadline;
  std::unique_ptr<Timer> mPMTUD1Deadline;
  uint64_t mPMTUD1PacketNumber;
  uint16_t mPMTUDTarget;

  std::unique_ptr<Timer> mIdleDeadline;

  bool     mDecodedOK;
  bool     mLocalOmitCID;

  uint16_t mPeerIdleTimeout;

  uint8_t  mPeerAckDelayExponent;
  uint8_t  mLocalAckDelayExponent;

  uint64_t mAdvertiseStreamWindow;
  uint64_t mAdvertiseConnectionWindow;
  uint16_t mLocalMaxSizeAllowed;

  std::unique_ptr<unsigned char []> mRemoteTransportExtensionInfo;
  uint32_t mRemoteTransportExtensionInfoLen;

  bool mCheck0RTTPossible;
  earlyDataState mEarlyDataState;
  uint64_t mEarlyDataLastPacketNumber;

  ConnIDTimeout mConnIDTimeout;

public:
  uint64_t HighestTransmittedAckable() { return mHighestTransmittedAckable; }
private:
  uint64_t mHighestTransmittedAckable;
  
public: // callbacks from nsshelper
  int32_t NSSInput(void *buf, int32_t amount);
  int32_t NSSOutput(const void *buf, int32_t amount);
   
};

} //namespace
