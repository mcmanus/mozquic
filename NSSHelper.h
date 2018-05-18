/* -*- Mode: C++; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*-
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#pragma once

#include "prio.h"
#include "ssl.h"
#include "pk11pub.h"
#include "sslexp.h"

namespace mozquic {

class MozQuic;

enum operationType {
  kEncrypt0,
  kDecrypt0,
//  kEncrypt1,
//  kDecrypt1,
  kEncryptHandshake,
  kDecryptHandshake,
  kEncrypt0RTT,
  kDecrypt0RTT,
};

// if you Read() from the helper, it pulls through the tls layer from the mozquic::stream0 buffer where
// peer data lke the client hello is stored.. if you Write() to the helper something
// like "", the tls layer adds the server hello on the way out into mozquic::stream0

class NSSHelper final
{
public:
  static int Init(char *dir);
  NSSHelper(MozQuic *quicSession, bool tolerateBadALPN, const char *originKey);
  NSSHelper(MozQuic *quicSession, bool tolerateBadALPN, const char *originKey, bool clientindicator);
  ~NSSHelper();
  uint32_t ReadTLSData();
  uint32_t DriveHandshake();
  bool IsHandshakeComplete() { return mHandshakeComplete; }
  uint32_t HandshakeSecret(unsigned int ciphersuite, unsigned char *sendSecret, unsigned char *recvSecret);

  uint32_t EncryptBlock(const unsigned char *aeadData, uint32_t aeadLen,
                        const unsigned char *plaintext, uint32_t plaintextLen,
                        uint64_t packetNumber, unsigned char *out, uint32_t outAvail,
                        uint32_t &written);

  uint32_t DecryptBlock(const unsigned char *aeadData, uint32_t aeadLen,
                        const unsigned char *ciphertext, uint32_t ciphertextLen,
                        uint64_t packetNumber, unsigned char *out, uint32_t outAvail,
                        uint32_t &written);


  uint32_t EncryptHandshake(const unsigned char *aeadData, uint32_t aeadLen,
                            const unsigned char *plaintext, uint32_t plaintextLen,
                            uint64_t packetNumber, CID cid,
                            unsigned char *out, uint32_t outAvail,
                            uint32_t &written);

  uint32_t DecryptHandshake(const unsigned char *aeadData, uint32_t aeadLen,
                            const unsigned char *ciphertext, uint32_t ciphertextLen,
                            uint64_t packetNumber, CID cid,
                            unsigned char *out, uint32_t outAvail,
                            uint32_t &written);

  uint32_t EncryptBlock0RTT(const unsigned char *aeadData, uint32_t aeadLen,
                            const unsigned char *plaintext, uint32_t plaintextLen,
                            uint64_t packetNumber, unsigned char *out, uint32_t outAvail,
                            uint32_t &written);

  uint32_t DecryptBlock0RTT(const unsigned char *aeadData, uint32_t aeadLen,
                            const unsigned char *ciphertext, uint32_t ciphertextLen,
                            uint64_t packetNumber, unsigned char *out, uint32_t outAvail,
                            uint32_t &written);

  bool SetLocalTransportExtensionInfo(const unsigned char *data, uint16_t datalen); // local data to send
  bool SetRemoteTransportExtensionInfo(const unsigned char *data, uint16_t datalen); // remote data recvd
  void GetRemoteTransportExtensionInfo(unsigned char * &_output, uint16_t &actual) {
    _output = mRemoteTransportExtensionInfo;
    actual = mRemoteTransportExtensionLen;
  }

  static const uint32_t kTransportParametersID = 26;

  bool DoHRR() {return mDoHRR;}

  bool IsEarlyDataPossible();
  bool IsEarlyDataAcceptedServer();
  bool IsEarlyDataAcceptedClient();

private:
  void SharedInit();
  static PRStatus NSPRGetPeerName(PRFileDesc *aFD, PRNetAddr*addr);
  static PRStatus NSPRGetSocketOption(PRFileDesc *aFD, PRSocketOptionData *aOpt);
  static PRStatus nssHelperConnect(PRFileDesc *fd, const PRNetAddr *addr, PRIntervalTime to);
  static int nssHelperWrite(PRFileDesc *aFD, const void *aBuf, int32_t aAmount);
  static int nssHelperSend(PRFileDesc *aFD, const void *aBuf, int32_t aAmount,
                           int , PRIntervalTime);
  static int32_t nssHelperRead(PRFileDesc *fd, void *buf, int32_t amount);
  static int32_t nssHelperRecv(PRFileDesc *fd, void *buf, int32_t amount, int flags,
                               PRIntervalTime timeout);

  static SSLHelloRetryRequestAction HRRCallback(PRBool firstHello, const unsigned char *clientToken,
                                                unsigned int clientTokenLen, unsigned char *retryToken,
                                                unsigned int *retryTokenLen, unsigned int retryTokMax,
                                                void *arg);
  static void HandshakeCallback(PRFileDesc *fd, void *);
  static SECStatus BadCertificate(void *client_data, PRFileDesc *fd);

  static PRBool TransportExtensionWriter(PRFileDesc *fd, SSLHandshakeType m, PRUint8 *data,
                                         unsigned int *len, unsigned int maxlen, void *arg);
  static SECStatus TransportExtensionHandler(PRFileDesc *fd, SSLHandshakeType m, const PRUint8 *data,
                                             unsigned int len, SSLAlertDescription *alert, void *arg);
  
  uint32_t BlockOperation(enum operationType mode, const unsigned char *aeadData, uint32_t aeadLen,
                          const unsigned char *plaintext, uint32_t plaintextLen,
                          uint64_t packetNumber, unsigned char *out, uint32_t outAvail,
                          uint32_t &written);
  uint32_t MakeKeyFromNSS(PRFileDesc *fd, bool earlyKey, const char *label,
                          unsigned int secretSize, unsigned int keySize, SSLHashType hashType,
                          CK_MECHANISM_TYPE importMechanism1, CK_MECHANISM_TYPE importMechanism2,
                          unsigned char *outIV, PK11SymKey **outKey);
public:
  static uint32_t MakeKeyFromRaw(unsigned char *initialSecret,
                          unsigned int secretSize, unsigned int keySize, SSLHashType hashType,
                          CK_MECHANISM_TYPE importMechanism1, CK_MECHANISM_TYPE importMechanism2,
                          unsigned char *outIV, PK11SymKey **outKey);
  static uint32_t staticDecryptHandshake(const unsigned char *aadData, uint32_t aadLen,
                                         const unsigned char *data, uint32_t dataLen,
                                         uint64_t packetNumber, CID connectionID,
                                         unsigned char *out, uint32_t outAvail, uint32_t &written);

  static uint64_t SockAddrHasher(const struct sockaddr *);

private:
  static void GetKeyParamsFromCipherSuite(uint16_t cipherSuite,
                                          unsigned int &secretSize,
                                          unsigned int &keySize,
                                          SSLHashType &hashType,
                                          CK_MECHANISM_TYPE &packetMechanism,
                                          CK_MECHANISM_TYPE &importMechanism1,
                                          CK_MECHANISM_TYPE &importMechanism2);
  void MakeHandshakeKeys(CID cid);
  
  MozQuic             *mMozQuic;
  PRFileDesc          *mFD;
  bool                 mNSSReady;
  bool                 mHandshakeComplete;
  bool                 mHandshakeFailed; // complete but bad above nss
  bool                 mIsClient;
  bool                 mTolerateBadALPN;

  bool                mDoHRR;

  unsigned char       mExternalSendSecret[48];
  unsigned char       mExternalRecvSecret[48];
  unsigned int        mExternalCipherSuite;

  unsigned char       mLocalTransportExtensionInfo[2048];
  uint16_t            mLocalTransportExtensionLen;
  unsigned char       mRemoteTransportExtensionInfo[2048];
  uint16_t            mRemoteTransportExtensionLen;

  CK_MECHANISM_TYPE   mPacketProtectionMech;
  PK11SymKey         *mPacketProtectionSenderKey0;
  unsigned char       mPacketProtectionSenderIV0[12];
  PK11SymKey         *mPacketProtectionReceiverKey0;
  unsigned char       mPacketProtectionReceiverIV0[12];

  CK_MECHANISM_TYPE   mPacketProtectionMech0RTT;
  PK11SymKey         *mPacketProtectionKey0RTT;
  unsigned char       mPacketProtectionIV0RTT[12];

  CID                 mPacketProtectionHandshakeCID;
  PK11SymKey         *mPacketProtectionHandshakeSenderKey;
  unsigned char       mPacketProtectionHandshakeSenderIV[12];
  PK11SymKey         *mPacketProtectionHandshakeReceiverKey;
  unsigned char       mPacketProtectionHandshakeReceiverIV[12];
};

} //namespace
