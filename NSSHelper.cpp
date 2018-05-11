/* -*- Mode: C++; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*-
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "Logging.h"
#include "MozQuic.h"
#include "MozQuicInternal.h"
#include "NSSHelper.h"
#include "nss.h"
#include "ssl.h"
#include "sslexp.h"
#include "sslproto.h"
#include "cert.h"
#include "certdb.h"
#include "pk11pub.h"
#include "secmod.h"
#include "assert.h"
#include "sechash.h"

#if NSS_VMAJOR < 3 || (NSS_VMINOR < 36 && NSS_VMAJOR == 3)
fail compile due to nss version;
#endif

// relies on tls1.3 draft 23 NSS_3_36_BRANCH

#define sTlsLog1(...) Log::sDoLog(Log::TLS, 1, self->mMozQuic, __VA_ARGS__);
#define sTlsLog2(...) Log::sDoLog(Log::TLS, 2, self->mMozQuic, __VA_ARGS__);
#define sTlsLog3(...) Log::sDoLog(Log::TLS, 3, self->mMozQuic, __VA_ARGS__);
#define sTlsLog4(...) Log::sDoLog(Log::TLS, 4, self->mMozQuic, __VA_ARGS__);
#define sTlsLog5(...) Log::sDoLog(Log::TLS, 5, self->mMozQuic, __VA_ARGS__);
#define sTlsLog6(...) Log::sDoLog(Log::TLS, 6, self->mMozQuic, __VA_ARGS__);
#define sTlsLog7(...) Log::sDoLog(Log::TLS, 7, self->mMozQuic, __VA_ARGS__);
#define sTlsLog8(...) Log::sDoLog(Log::TLS, 8, self->mMozQuic, __VA_ARGS__);
#define sTlsLog9(...) Log::sDoLog(Log::TLS, 9, self->mMozQuic, __VA_ARGS__);
#define sTlsLog10(...) Log::sDoLog(Log::TLS, 10, self->mMozQuic, __VA_ARGS__);

#define sTlsLog6q(...) Log::sDoLog(Log::TLS, 16, self->mMozQuic, __VA_ARGS__);

#define TlsLog1(...) Log::sDoLog(Log::TLS, 1, mMozQuic, __VA_ARGS__);
#define TlsLog2(...) Log::sDoLog(Log::TLS, 2, mMozQuic, __VA_ARGS__);
#define TlsLog3(...) Log::sDoLog(Log::TLS, 3, mMozQuic, __VA_ARGS__);
#define TlsLog4(...) Log::sDoLog(Log::TLS, 4, mMozQuic, __VA_ARGS__);
#define TlsLog5(...) Log::sDoLog(Log::TLS, 5, mMozQuic, __VA_ARGS__);
#define TlsLog6(...) Log::sDoLog(Log::TLS, 6, mMozQuic, __VA_ARGS__);
#define TlsLog7(...) Log::sDoLog(Log::TLS, 7, mMozQuic, __VA_ARGS__);
#define TlsLog8(...) Log::sDoLog(Log::TLS, 8, mMozQuic, __VA_ARGS__);
#define TlsLog9(...) Log::sDoLog(Log::TLS, 9, mMozQuic, __VA_ARGS__);
#define TlsLog10(...) Log::sDoLog(Log::TLS, 10, mMozQuic, __VA_ARGS__);

namespace mozquic {

#define MAX_ALPN_LENGTH 256

static bool mozQuicInit = false;
static PRDescIdentity nssHelperIdentity;
static PRIOMethods nssHelperMethods;

int
NSSHelper::Init(char *dir)
{
  if (mozQuicInit) {
    return MOZQUIC_ERR_GENERAL;
  }
  mozQuicInit = true;
  nssHelperIdentity = PR_GetUniqueIdentity("nssHelper");
  nssHelperMethods = *PR_GetDefaultIOMethods();

  nssHelperMethods.getpeername = NSPRGetPeerName;
  nssHelperMethods.getsocketoption = NSPRGetSocketOption;
  nssHelperMethods.connect = nssHelperConnect;
  nssHelperMethods.write = nssHelperWrite;
  nssHelperMethods.send = nssHelperSend;
  nssHelperMethods.recv = nssHelperRecv;
  nssHelperMethods.read = nssHelperRead;

  if (NSS_Init(dir) != SECSuccess) {
    return MOZQUIC_ERR_GENERAL;
  }
  return MOZQUIC_OK;
}

SSLHelloRetryRequestAction
NSSHelper::HRRCallback(PRBool firstHello, const unsigned char *clientToken,
                       unsigned int clientTokenLen, unsigned char *retryToken,
                       unsigned int *retryTokenLen, unsigned int retryTokMax,
                       void *arg)
{
  unsigned char digest[SHA256_LENGTH];
  assert(retryTokMax >= sizeof(digest));
  if (retryTokMax < sizeof(digest)) {
    return ssl_hello_retry_accept;
  }

  NSSHelper *self = reinterpret_cast<NSSHelper *>(arg);

  unsigned char sourceAddressInfo[128];
  uint32_t sourceAddressLen = sizeof(sourceAddressInfo);
  // on the token generation (first pass) we want to place the server specified retry cid
  // on the token validation (second pass) we want to confirm the initial had that retry cid
  self->mMozQuic->GetPeerAddressHash(
    firstHello? self->mMozQuic->ConnectionID() : self->mMozQuic->OriginalConnectionID(),
    sourceAddressInfo, &sourceAddressLen);

  HASHContext *hcontext = HASH_Create(HASH_AlgSHA256);
  HASH_Begin(hcontext);
  HASH_Update(hcontext, sourceAddressInfo, sourceAddressLen);
  unsigned int digestLen;
  HASH_End(hcontext, digest, &digestLen, sizeof(digest));
  assert(digestLen == sizeof(digest));

  sTlsLog5("HRRCallback first=%d tokenlen=%d max=%d\n", firstHello, clientTokenLen, retryTokMax);
  sTlsLog6("Input : ");
  for (unsigned int i = 0 ; i < sourceAddressLen; i++) {
    sTlsLog6q("%02X ", sourceAddressInfo[i]);
  }
  sTlsLog6("\nDigest: ");
  for (unsigned int i = 0 ; i < digestLen; i++) {
    sTlsLog6q("%02X ", digest[i]);
  }
  if (!firstHello) {
    sTlsLog6("\nCookie: ");
    for (unsigned int i = 0 ; i < clientTokenLen; i++) {
      sTlsLog6q("%02X ", clientToken[i]);
    }
  }
  sTlsLog6q("\n");
  sTlsLog5("HRRCallback %d bytes of SourceAddress into %d bytes of hash\n",
           sourceAddressLen, digestLen);

  if (!firstHello) { // verify!
    if (clientTokenLen != sizeof(digest)) {
      sTlsLog1("HRRCallback clientToken wrong size\n");
      return ssl_hello_retry_fail;
    }
    if (memcmp(clientToken, digest, sizeof(digest))) {
      sTlsLog1("HRRCallback clientToken wrong\n");
      return ssl_hello_retry_fail;
    }
    sTlsLog1("HRRCallback clientToken verified!\n");
    return ssl_hello_retry_accept;
  }

  assert(!self->mDoHRR);
  self->mDoHRR = true;
  memcpy(retryToken, digest, digestLen);
  *retryTokenLen = digestLen;
  return ssl_hello_retry_request;
}

void
NSSHelper::HandshakeCallback(PRFileDesc *fd, void *client_data)
{
  unsigned int bufLen = 0;
  unsigned char buf[MAX_ALPN_LENGTH];
  SSLNextProtoState state;
  bool didHandshakeFail = false;

  PRFileDesc *tmpFD = fd;
  while (tmpFD && (tmpFD->identity != nssHelperIdentity)) {
    tmpFD = tmpFD->lower;
  }
  assert(tmpFD);
  NSSHelper *self = reinterpret_cast<NSSHelper *>(tmpFD->secret);
  sTlsLog5("handshakecallback\n");

  if (!self->mTolerateBadALPN &&
      (SSL_GetNextProto(fd, &state, buf, &bufLen, MAX_ALPN_LENGTH) != SECSuccess ||
       bufLen != strlen(MozQuic::kAlpn) ||
       memcmp(MozQuic::kAlpn, buf, bufLen))) {
    sTlsLog1("alpn fail\n");
    goto failure;
  } else {
    SSLChannelInfo info;

    if (SSL_GetChannelInfo(fd, &info, sizeof(info)) != SECSuccess) {
      goto failure;
    } 
  }

  self->mHandshakeComplete = true;
  if (didHandshakeFail) {
    self->mHandshakeFailed = true;
  }
  return;

failure:
  self->mHandshakeComplete = true;
  self->mHandshakeFailed = true;
}

uint32_t
NSSHelper::BlockOperation(enum operationType mode,
                          const unsigned char *aadData, uint32_t aadLen,
                          const unsigned char *data, uint32_t dataLen,
                          uint64_t packetNumber,
                          unsigned char *out, uint32_t outAvail, uint32_t &written)
// for encrypt outAvail should be at least dataLen + 16 (for tag), for decrypt out should be at
// least dataLen - 16 (for tag removal)
{
  assert(outAvail >= (dataLen + 16));
  if (!mNSSReady) {
    return MOZQUIC_ERR_GENERAL;
  }

  assert(mode == kEncrypt0 || mode == kEncrypt0RTT ||
         mode == kDecrypt0 || mode == kDecrypt0RTT);

  if (!mHandshakeComplete || mHandshakeFailed) {
    return MOZQUIC_ERR_GENERAL;
  }

  assert(!mBlockBuffer);
  if (mode == kEncrypt0 || mode == kEncrypt0RTT) {
    // the answer shows up in out via nssHelperWrite
    mBlockBufferLen = outAvail;
    mBlockBuffer = out;
    PR_Write(mFD, data, dataLen);
    mBlockBuffer = nullptr;
    written = mBlockBufferLen;
    return MOZQUIC_OK;
  }

  // nsshelperread gets the data from the pr_read stack
  mBlockBufferLen = dataLen;
  mBlockBuffer = (unsigned char *)data;
  int rv = PR_Read(mFD, out, outAvail);
  mBlockBuffer = nullptr;
  if (rv >= 0) {
    written = rv;
    return MOZQUIC_OK;
  }

  return MOZQUIC_ERR_CRYPTO;
}


uint32_t
NSSHelper::EncryptBlock(const unsigned char *aadData, uint32_t aadLen,
                        const unsigned char *plaintext, uint32_t plaintextLen,
                        uint64_t packetNumber, unsigned char *out,
                        uint32_t outAvail, uint32_t &written)
{
  return BlockOperation(kEncrypt0, aadData, aadLen, plaintext, plaintextLen,
                        packetNumber, out, outAvail, written);
}

uint32_t
NSSHelper::DecryptBlock(const unsigned char *aadData, uint32_t aadLen,
                        const unsigned char *ciphertext, uint32_t ciphertextLen,
                        uint64_t packetNumber, unsigned char *out, uint32_t outAvail,
                        uint32_t &written)
{
  return BlockOperation(kDecrypt0, aadData, aadLen, ciphertext, ciphertextLen,
                        packetNumber, out, outAvail, written);
}

uint32_t
NSSHelper::EncryptBlock0RTT(const unsigned char *aadData, uint32_t aadLen,
                            const unsigned char *plaintext, uint32_t plaintextLen,
                            uint64_t packetNumber, unsigned char *out,
                            uint32_t outAvail, uint32_t &written)
{
  return BlockOperation(kEncrypt0RTT, aadData, aadLen, plaintext, plaintextLen,
                        packetNumber, out, outAvail, written);
}

uint32_t
NSSHelper::DecryptBlock0RTT(const unsigned char *aadData, uint32_t aadLen,
                            const unsigned char *ciphertext, uint32_t ciphertextLen,
                            uint64_t packetNumber, unsigned char *out, uint32_t outAvail,
                            uint32_t &written)
{
  return BlockOperation(kDecrypt0RTT, aadData, aadLen, ciphertext, ciphertextLen,
                        packetNumber, out, outAvail, written);
}

SECStatus
NSSHelper::BadCertificate(void *client_data, PRFileDesc *fd)
{
  while (fd && (fd->identity != nssHelperIdentity)) {
    fd = fd->lower;
  }
  assert(fd);
  NSSHelper *self = reinterpret_cast<NSSHelper *>(fd->secret);
  sTlsLog2("badcertificate override=%d\n",
           self->mMozQuic->IgnorePKI());
  return self->mMozQuic->IgnorePKI() ? SECSuccess : SECFailure;
}

void 
NSSHelper::SharedInit()
{
  mFD = PR_CreateIOLayerStub(nssHelperIdentity, &nssHelperMethods);
  mFD->secret = (struct PRFilePrivate *)this;
  mFD = DTLS_ImportFD(nullptr, mFD);

  // To disable any of the usual cipher suites..
  // SSL_CipherPrefSet(mFD, TLS_AES_128_GCM_SHA256, 0);
  // SSL_CipherPrefSet(mFD, TLS_AES_256_GCM_SHA384, 0);
  // SSL_CipherPrefSet(mFD, TLS_CHACHA20_POLY1305_SHA256, 0);

  SSL_OptionSet(mFD, SSL_SECURITY, true);
  SSL_OptionSet(mFD, SSL_HANDSHAKE_AS_CLIENT, mIsClient);
  SSL_OptionSet(mFD, SSL_HANDSHAKE_AS_SERVER, !mIsClient);
  SSL_OptionSet(mFD, SSL_ENABLE_RENEGOTIATION, SSL_RENEGOTIATE_NEVER);

  SSL_OptionSet(mFD, SSL_NO_CACHE, true);

  SSL_OptionSet(mFD, SSL_ENABLE_SESSION_TICKETS, true);
  if (mMozQuic->Enabled0RTT()) {
    SSL_OptionSet(mFD, SSL_ENABLE_0RTT_DATA, true);
    if (!mIsClient && !mMozQuic->Reject0RTTData()) {
      // If this option is not set 0rtt data will be rejected.
      // We will use this to test the case when the server rejects 0rtt data.
      SSL_SetupAntiReplay(10000, 1, 3);
    }
  }
  SSL_OptionSet(mFD, SSL_REQUEST_CERTIFICATE, false);
  SSL_OptionSet(mFD, SSL_REQUIRE_CERTIFICATE, SSL_REQUIRE_NEVER);

  SSL_OptionSet(mFD, SSL_ENABLE_NPN, false);
  SSL_OptionSet(mFD, SSL_ENABLE_ALPN, true);

  SSLVersionRange range = {SSL_LIBRARY_VERSION_TLS_1_2, // just for dtls
                           SSL_LIBRARY_VERSION_TLS_1_3};
  SSL_VersionRangeSet(mFD, &range);
  SSL_HandshakeCallback(mFD, HandshakeCallback, nullptr);

  unsigned char buffer[256];
  assert(strlen(MozQuic::kAlpn) < 256);
  buffer[0] = strlen(MozQuic::kAlpn);
  memcpy(buffer + 1, MozQuic::kAlpn, strlen(MozQuic::kAlpn));
#if 0
// dtls
  if (SSL_SetNextProtoNego(mFD,
                           buffer, strlen(MozQuic::kAlpn) + 1) != SECSuccess) {
    mNSSReady = false;
  }
#endif
  
  SSLExtensionSupport supportTransportParameters;
  if (SSL_GetExtensionSupport(kTransportParametersID, &supportTransportParameters) == SECSuccess &&
      supportTransportParameters != ssl_ext_native_only &&
      SSL_InstallExtensionHooks(mFD, kTransportParametersID,
                                TransportExtensionWriter, this,
                                TransportExtensionHandler, this) == SECSuccess) {
    PRNetAddr addr;
    memset(&addr,0,sizeof(addr));
    addr.raw.family = PR_AF_INET;
    PR_Connect(mFD, &addr, 0);
  } else {
    TlsLog1("Transport ExtensionSupport not possible. not connecting\n");
    mNSSReady = false;
  }

}

// server version
NSSHelper::NSSHelper(MozQuic *quicSession, bool tolerateBadALPN, const char *originKey)
  : mMozQuic(quicSession)
  , mNSSReady(true)
  , mHandshakeComplete(false)
  , mHandshakeFailed(false)
  , mIsClient(false)
  , mTolerateBadALPN(tolerateBadALPN)
  , mDoHRR(false)
  , mBlockBuffer(nullptr)
  , mLocalTransportExtensionLen(0)
  , mRemoteTransportExtensionLen(0)
{
  SharedInit();

  SSL_SetMaxEarlyDataSize(mFD, 0xffffffff); // 0rtt nst requires
  if (mMozQuic->GetForceAddressValidation()) {
    SSL_HelloRetryRequestCallback(mFD, HRRCallback, this);
  }

  CERTCertificate *cert =
    CERT_FindCertByNickname(CERT_GetDefaultCertDB(), originKey);
  if (cert) {
    SECKEYPrivateKey *key = PK11_FindKeyByAnyCert(cert, nullptr);
    if (key) {
      SECStatus rv = SSL_ConfigServerCert(mFD, cert, key, nullptr, 0);
      if (rv == SECFailure) {
        mNSSReady = false;
      }
    }
  }
}

// client version
NSSHelper::NSSHelper(MozQuic *quicSession, bool tolerateBadALPN, const char *originKey, bool unused)
  : mMozQuic(quicSession)
  , mNSSReady(true)
  , mHandshakeComplete(false)
  , mHandshakeFailed(false)
  , mIsClient(true)
  , mTolerateBadALPN(tolerateBadALPN)
  , mDoHRR(false)
  , mBlockBuffer(nullptr)
  , mLocalTransportExtensionLen(0)
  , mRemoteTransportExtensionLen(0)
{
  SharedInit();
  SSL_SendAdditionalKeyShares(mFD, 2);
  SSLNamedGroup groups[] = {  ssl_grp_ec_secp256r1,
                              ssl_grp_ec_curve25519,
                              ssl_grp_ec_secp384r1
  };
  SSL_NamedGroupConfig(mFD, groups, PR_ARRAY_SIZE(groups));
  SSL_BadCertHook(mFD, BadCertificate, nullptr);

  char module_name[] = "library=libnssckbi.so name=\"Root Certs\"";
  SECMOD_LoadUserModule(module_name, NULL, PR_FALSE);

  SSL_SetURL(mFD, originKey);
}

int
NSSHelper::nssHelperWrite(PRFileDesc *fd, const void *aBuf, int32_t aAmount)
{
  // this is output from nss

  // data (e.g. server hello) has come from nss and needs to be written into MozQuic
  // to be written out to the network in stream 0
  NSSHelper *self = reinterpret_cast<NSSHelper *>(fd->secret);
  if (!self->mBlockBuffer) {
    self->mMozQuic->NSSOutput(aBuf, aAmount);
  } else {
    if (aAmount > (int)self->mBlockBufferLen) {
      self->mBlockBufferLen = 0;
      return aAmount;
    }
    memcpy(self->mBlockBuffer, aBuf, aAmount);
    self->mBlockBufferLen = aAmount;
  }
  return aAmount;
}

int
NSSHelper::nssHelperSend(PRFileDesc *aFD, const void *aBuf, int32_t aAmount,
                           int , PRIntervalTime)
{
  return nssHelperWrite(aFD, aBuf, aAmount);
}

int32_t
NSSHelper::nssHelperRead(PRFileDesc *fd, void *buf, int32_t amount)
{
  // nss is asking for input, i.e. a client hello from stream 0 after
  // stream reassembly
  NSSHelper *self = reinterpret_cast<NSSHelper *>(fd->secret);
  if (!self->mBlockBuffer) {
    return self->mMozQuic->NSSInput(buf, amount);
  }
  if (!self->mBlockBufferLen || (amount < (int)self->mBlockBufferLen)) {
    PR_SetError(PR_WOULD_BLOCK_ERROR, 0);
    return -1;
  }
  memcpy(buf, self->mBlockBuffer, self->mBlockBufferLen);
  int32_t rv = self->mBlockBufferLen;
  self->mBlockBufferLen = 0;
  return rv;
}

int32_t
NSSHelper::nssHelperRecv(PRFileDesc *fd, void *buf, int32_t amount, int flags,
                           PRIntervalTime timeout)
{
  return nssHelperRead(fd, buf, amount);
}

PRStatus
NSSHelper::NSPRGetPeerName(PRFileDesc *aFD, PRNetAddr *addr)
{
  memset(addr,0,sizeof(*addr));
  addr->raw.family = PR_AF_INET;
  return PR_SUCCESS;
}

PRStatus
NSSHelper::NSPRGetSocketOption(PRFileDesc *aFD, PRSocketOptionData *aOpt)
{
  if (aOpt->option == PR_SockOpt_Nonblocking) {
    aOpt->value.non_blocking = PR_TRUE;
    return PR_SUCCESS;
  }
  return PR_FAILURE;
}

PRStatus
NSSHelper::nssHelperConnect(PRFileDesc *fd, const PRNetAddr *addr, PRIntervalTime to)
{
  return PR_SUCCESS;
}


uint32_t
NSSHelper::DriveHandshake()
{
  if (mHandshakeFailed) {
    return MOZQUIC_ERR_CRYPTO;
  }
  if (mHandshakeComplete) {
    return MOZQUIC_OK;
  }

  if (!mNSSReady) {
    return MOZQUIC_ERR_GENERAL;
  }

  if (SSL_ForceHandshake(mFD) == SECSuccess) {
    char data[256];
    int32_t rd = PR_Read(mFD, data, 256);
    if (mHandshakeComplete || (rd > 0)) {
      return MOZQUIC_OK;
    }
    if (rd == 0) {
      TlsLog1("eof on pipe?\n");
      return MOZQUIC_ERR_IO;
    }
  }
  if (PR_GetError() == PR_WOULD_BLOCK_ERROR) {
    return MOZQUIC_OK;
  }
  TlsLog1("handshake err: %s\n", PR_ErrorToName(PR_GetError()));
  return MOZQUIC_ERR_GENERAL;
}

PRBool
NSSHelper::TransportExtensionWriter(PRFileDesc *fd, SSLHandshakeType m,
                                    PRUint8 *data, unsigned int *len, unsigned int maxlen, void *arg)
{
  NSSHelper *self = reinterpret_cast<NSSHelper *>(arg);
  if (m != ssl_hs_client_hello && m != ssl_hs_encrypted_extensions) {
    return PR_FALSE;
  }
  if (maxlen < self->mLocalTransportExtensionLen) {
    return PR_FALSE;
  }

  sTlsLog6("transport extension sent %d bytes long.\n", self->mLocalTransportExtensionLen);
  memcpy(data, self->mLocalTransportExtensionInfo, self->mLocalTransportExtensionLen);
  *len = self->mLocalTransportExtensionLen;
  return PR_TRUE;
}

SECStatus
NSSHelper::TransportExtensionHandler(PRFileDesc *fd, SSLHandshakeType m, const PRUint8 *data,
                                     unsigned int len, SSLAlertDescription *alert, void *arg)
{
  NSSHelper *self = reinterpret_cast<NSSHelper *>(arg);
  if (!self->mIsClient && m != ssl_hs_client_hello) {
    return SECSuccess;
  }
  if (self->mIsClient && m != ssl_hs_encrypted_extensions) {
    return SECSuccess;
  }
  
  sTlsLog6("transport extension read %d bytes long.\n", len);
  self->SetRemoteTransportExtensionInfo(data, len);
  return SECSuccess;
}

bool
NSSHelper::SetLocalTransportExtensionInfo(const unsigned char *data, uint16_t datalen)
{
  if (datalen > sizeof(mLocalTransportExtensionInfo)) {
    return false;
  }

  memcpy(mLocalTransportExtensionInfo, data, datalen);
  mLocalTransportExtensionLen = datalen;
  return true;
}

bool
NSSHelper::SetRemoteTransportExtensionInfo(const unsigned char *data, uint16_t datalen)
{
  if (datalen > sizeof(mRemoteTransportExtensionInfo)) {
    return false;
  }

  memcpy(mRemoteTransportExtensionInfo, data, datalen);
  mRemoteTransportExtensionLen = datalen;
  return true;
}

bool
NSSHelper::IsEarlyDataPossible()
{
  assert (mIsClient);
  SSLPreliminaryChannelInfo info;

  if (SSL_GetPreliminaryChannelInfo(mFD, &info, sizeof(info)) != SECSuccess) {
    return false;
  }

  if (!info.canSendEarlyData) {
    return false;
  }

  unsigned int bufLen = 0;
  unsigned char buf[MAX_ALPN_LENGTH];
  SSLNextProtoState state;

  if (SSL_GetNextProto(mFD, &state, buf, &bufLen, MAX_ALPN_LENGTH) != SECSuccess) {
    return false;
  }

  if (!mTolerateBadALPN &&
      (bufLen != strlen(MozQuic::kAlpn) ||
       memcmp(MozQuic::kAlpn, buf, bufLen))) {
    NSSHelper *self = this;
    sTlsLog1("Early data alpn fail\n");
    return false;
  }

  return true;
}

bool
NSSHelper::IsEarlyDataAcceptedServer()
{
  assert (!mIsClient);
  assert(0); // dtls hack broken

  SSLPreliminaryChannelInfo info;
  if (SSL_GetPreliminaryChannelInfo(mFD, &info, sizeof(info)) != SECSuccess) {
    TlsLog6("IsEarlyDataAccepted fail 1\n");
    return false;
  }

  TlsLog6("IsEarlyDataAccepted pass\n");
  return true;
}

bool
NSSHelper::IsEarlyDataAcceptedClient()
{
  assert (mIsClient);

  SSLChannelInfo info;

  if (SSL_GetChannelInfo(mFD, &info, sizeof(info)) != SECSuccess) {
    return false;
  }

  return info.earlyDataAccepted;
}

NSSHelper::~NSSHelper()
{
}

}
