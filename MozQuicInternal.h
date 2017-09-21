/* -*- Mode: C++; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*-
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#pragma once

#include <netinet/ip.h>
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
static const uint32_t kMozQuicIetfID5 = 0xff000005;
static const uint32_t kMozQuicVersionGreaseS = 0xea0a6a2a;
static const uint32_t VersionNegotiationList[] = {
  kMozQuicVersionGreaseS, kMozQuicIetfID5, kMozQuicVersion1,
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

enum errorType {
  ERROR_NO_ERROR            = 0x80000000,
  ERROR_INTERNAL            = 0x80000001,
  ERROR_CANCELLED           = 0x80000002,
  FLOW_CONTROL_ERROR        = 0x80000003,
  STREAM_ID_ERROR           = 0x80000004,
  STREAM_STATE_ERROR        = 0x80000005,
  FINAL_OFFSET_ERROR        = 0x80000006,
  FRAME_FORMAT_ERROR        = 0x80000007,
  ERROR_TRANSPORT_PARAMETER = 0x80000008,
  ERROR_VERSION_NEGOTIATION = 0x80000009,
  PROTOCOL_VIOLATION        = 0x8000000A,
  QUIC_RECEIVED_RST         = 0x80000035,
  
  // FRAME_ERROR 0x8000001XX
};

enum keyPhase {
  keyPhaseUnknown,
  keyPhaseUnprotected,
  keyPhase0Rtt,
  keyPhase1Rtt
};

class StreamPair;
class StreamAck;
class NSSHelper;
class StreamState;
class ReliableData;

class MozQuic final
{
friend class StreamPair;
friend class Log;
friend class FrameHeaderData;
friend class StreamState;
public:
  static const char *kAlpn;
  static const uint32_t kForgetInitialConnectionIDsThresh = 4000; // ms

  MozQuic(bool handleIO);
  MozQuic();
  ~MozQuic();

  int StartClient();
  int StartServer();
  void SetInitialPacketNumber();
  uint32_t StartNewStream(StreamPair **outStream, const void *data, uint32_t amount, bool fin);
  void MaybeDeleteStream(StreamPair *sp);
  int IO();
  void HandshakeOutput(unsigned char *, uint32_t amt);
  void HandshakeComplete(uint32_t errCode, struct mozquic_handshake_info *keyInfo);

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
  void SetStreamWindow(uint64_t w) { mAdvertiseStreamWindow = w; }
  void SetConnWindowKB(uint64_t kb) { mAdvertiseConnectionWindowKB = kb; }

  void SetAppHandlesSendRecv() { mAppHandlesSendRecv = true; }
  void SetAppHandlesLogging() { mAppHandlesLogging = true; }
  bool IgnorePKI();
  void Destroy(uint32_t, const char *);
  uint32_t CheckPeer(uint32_t);
  enum connectionState GetConnectionState() { return mConnectionState; }

  bool IsOpen() {
    return (mConnectionState == CLIENT_STATE_0RTT || mConnectionState == CLIENT_STATE_1RTT ||
            mConnectionState == CLIENT_STATE_CONNECTED || mConnectionState == SERVER_STATE_0RTT ||
            mConnectionState == SERVER_STATE_1RTT || mConnectionState == SERVER_STATE_CONNECTED);
  }

  bool DecodedOK() { return mDecodedOK; }
  void GetRemotePeerAddressHash(unsigned char *out, uint32_t *outLen);
  static uint64_t Timestamp();
  void Shutdown(uint32_t, const char *);

  void StartBackPressure() { mBackPressure = true; }
  void ReleaseBackPressure();
  
private:
  void RaiseError(uint32_t err, const char *fmt, ...);

  void AckScoreboard(uint64_t num, enum keyPhase kp);
  int MaybeSendAck();

  uint32_t ClearOldInitialConnectIdsTimer();
  void Acknowledge(uint64_t packetNum, keyPhase kp);
  uint32_t AckPiggyBack(unsigned char *pkt, uint64_t pktNumber, uint32_t avail, keyPhase kp, uint32_t &used);
  uint32_t Recv(unsigned char *, uint32_t len, uint32_t &outLen, struct sockaddr_in *peer);
  int ProcessServerCleartext(unsigned char *, uint32_t size, LongHeaderData &, bool &);
  int ProcessClientInitial(unsigned char *, uint32_t size, struct sockaddr_in *peer,
                           LongHeaderData &, MozQuic **outSession, bool &);
  int ProcessClientCleartext(unsigned char *pkt, uint32_t pktSize, LongHeaderData &, bool&);
  uint32_t ProcessGeneralDecoded(const unsigned char *, uint32_t size, bool &, bool fromClearText);
  uint32_t ProcessGeneral(const unsigned char *, uint32_t size, uint32_t headerSize, uint64_t packetNumber, bool &);
  bool IntegrityCheck(unsigned char *, uint32_t size);
  void ProcessAck(class FrameHeaderData *ackMetaInfo, const unsigned char *framePtr, bool fromCleartext);

  uint32_t HandleAckFrame(FrameHeaderData *result, bool fromCleartext,
                          const unsigned char *pkt, const unsigned char *endpkt,
                          uint32_t &_ptr);
  uint32_t HandleCloseFrame(FrameHeaderData *result, bool fromCleartext,
                            const unsigned char *pkt, const unsigned char *endpkt,
                            uint32_t &_ptr);
  
  bool ServerState() { return mConnectionState > SERVER_STATE_BREAK; }
  MozQuic *FindSession(uint64_t cid);
  void RemoveSession(uint64_t cid);
  uint32_t ClientConnected();
  uint32_t ServerConnected();

  uint32_t Intake(bool *partialResult);
  uint32_t FlushStream0(bool forceAck);

  int Client1RTT();
  int Server1RTT();
  int Bind();
  bool VersionOK(uint32_t proposed);
  uint32_t GenerateVersionNegotiation(LongHeaderData &clientHeader, struct sockaddr_in *peer);
  uint32_t ProcessVersionNegotiation(unsigned char *pkt, uint32_t pktSize, LongHeaderData &header);
  uint32_t ProcessServerStatelessRetry(unsigned char *pkt, uint32_t pktSize, LongHeaderData &header);

  MozQuic *Accept(struct sockaddr_in *peer, uint64_t aConnectionID, uint64_t ciNumber);

  void StartPMTUD1();
  void CompletePMTUD1();
  void AbortPMTUD1();

  uint32_t Transmit(const unsigned char *, uint32_t len, struct sockaddr_in *peer);
  uint32_t CreateShortPacketHeader(unsigned char *pkt, uint32_t pktSize, uint32_t &used);
  uint32_t ProtectedTransmit(unsigned char *header, uint32_t headerLen,
                             unsigned char *data, uint32_t dataLen, uint32_t dataAllocation,
                             bool addAcks, uint32_t mtuOverride = 0);

  // Stateless Reset
  bool     StatelessResetCheckForReceipt(const unsigned char *pkt, uint32_t pktSize);
  uint32_t StatelessResetSend(uint64_t connID, struct sockaddr_in *peer);
  static uint32_t StatelessResetCalculateToken(const unsigned char *key128,
                                               uint64_t connID, unsigned char *out);
  uint32_t StatelessResetEnsureKey();
    
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

  enum connectionState mConnectionState;
  int mOriginPort;
  std::unique_ptr<char []> mOriginName;
  struct sockaddr_in mPeer; // todo not a v4 world

  // both only set in server parent
  unsigned char mStatelessResetKey[128];
  unsigned char mValidationKey[32];

  // only set in client after exchange of transport params
  unsigned char mStatelessResetToken[16];

  uint32_t mVersion;
  uint32_t mClientOriginalOfferedVersion;

  // todo mvp lifecycle.. stuff never comes out of here
  std::unordered_map<uint64_t, MozQuic *> mConnectionHash;
  // This maps connectionId sent by a client and connectionId chosen by the
  // server. This is used to detect dup client initial packets.
  // The elemets are going to be removed using a timer.
  struct InitialClientPacketInfo {
    uint64_t mServerConnectionID;
    uint64_t mTimestamp;
  };
  std::unordered_map<uint64_t, struct InitialClientPacketInfo> mConnectionHashOriginalNew;

  uint32_t mMTU;
  uint64_t mConnectionID;
  uint64_t mOriginalConnectionID;
  uint64_t mNextTransmitPacketNumber;
  uint64_t mOriginalTransmitPacketNumber;
  uint64_t mNextRecvPacketNumber; // expected
  uint64_t mClientInitialPacketNumber; // only set on child in server

  void *mClosure;
  int  (*mConnEventCB)(void *, uint32_t, void *);

  std::unique_ptr<NSSHelper>   mNSSHelper;
  std::unique_ptr<StreamState> mStreamState;

  // parent and children are only defined on the server
  MozQuic *mParent; // only in child
  std::shared_ptr<MozQuic> mAlive;
  std::list<std::shared_ptr<MozQuic>> mChildren; // only in parent

  // The beginning of a connection.
  uint64_t mTimestampConnBegin;

  // Related to PING and PMTUD
  uint64_t mPingDeadline;
  uint64_t mPMTUD1Deadline;
  uint64_t mPMTUD1PacketNumber;

  bool     mDecodedOK;

  uint16_t mPeerIdleTimeout;

  uint64_t mAdvertiseStreamWindow;
  uint64_t mAdvertiseConnectionWindowKB;
      
public: // callbacks from nsshelper
  int32_t NSSInput(void *buf, int32_t amount);
  int32_t NSSOutput(const void *buf, int32_t amount);
   
};

} //namespace
