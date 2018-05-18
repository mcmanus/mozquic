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

#if NSS_VMAJOR < 3 || (NSS_VMINOR < 38 && NSS_VMAJOR == 3)
fail compile due to nss version;
#endif

// relies on tls1.3 draft 28

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

extern "C"
{
// All of this hkdf code is copied from NSS and modified for quic

static const struct {
  SSLHashType hash;
  CK_MECHANISM_TYPE pkcs11Mech;
  unsigned int hashSize;
} kTlsHkdfInfo[] = {
  { ssl_hash_none, 0, 0 },
  { ssl_hash_md5, 0, 0 },
  { ssl_hash_sha1, 0, 0 },
  { ssl_hash_sha224, 0, 0 },
  { ssl_hash_sha256, CKM_NSS_HKDF_SHA256, 32 },
  { ssl_hash_sha384, CKM_NSS_HKDF_SHA384, 48 },
  { ssl_hash_sha512, CKM_NSS_HKDF_SHA512, 64 }
};

/* Helper function to encode an unsigned integer into a buffer. */
static PRUint8 *
ssl_EncodeUintX(PRUint64 value, unsigned int bytes, PRUint8 *to)
{
  PRUint64 encoded;

  PORT_Assert(bytes > 0 && bytes <= sizeof(encoded));

  encoded = PR_htonll(value);
  memcpy(to, ((unsigned char *)(&encoded)) + (sizeof(encoded) - bytes), bytes);
  return to + bytes;
}

static PRUint8 kVersion1ID10Salt[] = 
{ 0x9c, 0x10, 0x8f, 0x98, 0x52, 0x0a, 0x5c, 0x5c, 0x32, 0x96,
  0x8e, 0x95, 0x0e, 0x8a, 0x2c, 0x5f, 0xe0, 0x6d, 0x6c, 0x38 };
  
static SECItem saltItem = { siBuffer, kVersion1ID10Salt, 20 };

static SECStatus
QHkdfExtract(PK11SymKey *ikm1, PK11SymKey *ikm2, SSLHashType baseHash,
             PK11SymKey **prkp)
{
  CK_NSS_HKDFParams params;
  SECItem paramsi;
  SECStatus rv;
  SECItem *salt;
  PK11SymKey *prk;

  params.bExtract = CK_TRUE;
  params.bExpand = CK_FALSE;
  params.pInfo = NULL;
  params.ulInfoLen = 0UL;
  if (!ikm1 || !ikm2) {
    return SECFailure;
  }

  /* TODO(ekr@rtfm.com): This violates the PKCS#11 key boundary
   * but is imposed on us by the present HKDF interface. */
  rv = PK11_ExtractKeyValue(ikm1);
  if (rv != SECSuccess)
    return rv;

  salt = PK11_GetKeyData(ikm1);
  if (!salt)
    return SECFailure;

  params.pSalt = salt->data;
  params.ulSaltLen = salt->len;
  PORT_Assert(salt->len > 0);

  paramsi.data = (unsigned char *)&params;
  paramsi.len = sizeof(params);

  PORT_Assert(kTlsHkdfInfo[baseHash].pkcs11Mech);
  PORT_Assert(kTlsHkdfInfo[baseHash].hashSize);
  PORT_Assert(kTlsHkdfInfo[baseHash].hash == baseHash);

  prk = PK11_Derive(ikm2, kTlsHkdfInfo[baseHash].pkcs11Mech,
                    &paramsi, kTlsHkdfInfo[baseHash].pkcs11Mech,
                    CKA_DERIVE, kTlsHkdfInfo[baseHash].hashSize);
  if (!prk)
    return SECFailure;

  *prkp = prk;

  return SECSuccess;
}

static SECStatus
QHkdfExpandLabel(PK11SymKey *prk, SSLHashType baseHash,
                 const char *label, unsigned int labelLen,
                 CK_MECHANISM_TYPE algorithm, unsigned int keySize,
                 PK11SymKey **keyp)
{
  CK_NSS_HKDFParams params;
  SECItem paramsi = { siBuffer, NULL, 0 };
  /* Size of info array needs to be big enough to hold the maximum Prefix,
   * Label, plus HandshakeHash. If it's ever to small, the code will abort.
   */
  PRUint8 info[256];
  PRUint8 *ptr = info;
  unsigned int infoLen;
  PK11SymKey *derived;
  const char *kLabelPrefix = "QUIC ";
  const unsigned int kLabelPrefixLen = strlen(kLabelPrefix);

  /*
   *  QHKDF-Expand-Label(Secret, Label, Length) =
   *       HKDF-Expand(Secret, QuicHkdfLabel, Length)
   *
   *  Where QuicHkdfLabel is specified as:
   *
   *  struct QuicHkdfLabel {
   *    uint16 length; = Length
   *    opaque label<6..255>; = "QUIC " + label
   *    uint8 hashLength = 0; // TODO
   *  };
   *
   */
  infoLen = 2 + 1 + kLabelPrefixLen + labelLen;
  if (infoLen > sizeof(info)) {
    PORT_Assert(0);
    goto abort;
  }

  ptr = ssl_EncodeUintX(keySize, 2, ptr);
  ptr = ssl_EncodeUintX(labelLen + kLabelPrefixLen, 1, ptr);
  PORT_Memcpy(ptr, kLabelPrefix, kLabelPrefixLen);
  ptr += kLabelPrefixLen;
  PORT_Memcpy(ptr, label, labelLen);
  ptr += labelLen;
  PORT_Assert((ptr - info) == infoLen);

  params.bExtract = CK_FALSE;
  params.bExpand = CK_TRUE;
  params.pInfo = info;
  params.ulInfoLen = infoLen;
  paramsi.data = (unsigned char *)&params;
  paramsi.len = sizeof(params);

  derived = PK11_DeriveWithFlags(prk, kTlsHkdfInfo[baseHash].pkcs11Mech,
                                 &paramsi, algorithm,
                                 CKA_DERIVE, keySize,
                                 CKF_SIGN | CKF_VERIFY);
  if (!derived)
    return SECFailure;

  *keyp = derived;
  return SECSuccess;

abort:
    return SECFailure;
}

static SECStatus
QHkdfExpandLabelRaw(PK11SymKey *prk, SSLHashType baseHash,
                    const char *label, unsigned int labelLen,
                    unsigned char *output, unsigned int outputLen)
{
  PK11SymKey *derived = NULL;
  SECItem *rawkey;
  SECStatus rv;
  
  rv = QHkdfExpandLabel(prk, baseHash, label, labelLen,
                        kTlsHkdfInfo[baseHash].pkcs11Mech, outputLen,
                        &derived);
  if (rv != SECSuccess || !derived) {
    goto abort;
  }

  rv = PK11_ExtractKeyValue(derived);
  if (rv != SECSuccess) {
    goto abort;
  }

  rawkey = PK11_GetKeyData(derived);
  if (!rawkey) {
    goto abort;
  }

  PORT_Assert(rawkey->len == outputLen);
  memcpy(output, rawkey->data, outputLen);
  PK11_FreeSymKey(derived);

  return SECSuccess;

abort:
  if (derived) {
    PK11_FreeSymKey(derived);
  }
  return SECFailure;
}
} // extern c - nss include

namespace mozquic {

#define MAX_ALPN_LENGTH 256

static bool mozQuicInit = false;
static PRDescIdentity nssHelperIdentity;
static PRIOMethods nssHelperMethods;
static const char *k0RTTLabel =   "EXPORTER-QUIC 0rtt";
static const char *kHandshakeServerLabel = "server hs";
static const char *kHandshakeClientLabel = "client hs";
static const char *k1RTTClientLabel = "EXPORTER-QUIC client 1rtt";
static const char *k1RTTServerLabel = "EXPORTER-QUIC server 1rtt";
// static const char *kPacketNumberLabel = "EXPORTER-QUIC packet number;

static class keyWrapper 
{
public:
  keyWrapper()
    : key(nullptr) { }

  ~keyWrapper() {
    if (key) {
      PK11_FreeSymKey(key);
    }
  }
  PK11SymKey *key;
} gCleartextSaltKey;

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
  
  if (!gCleartextSaltKey.key) {
    PK11SlotInfo *slot = PK11_GetInternalSlot();
    if (slot) {
      gCleartextSaltKey.key = PK11_ImportSymKey(slot,
                                                CKM_NSS_HKDF_SHA256,
                                                PK11_OriginUnwrap,
                                                CKA_DERIVE, &saltItem, NULL);
      PK11_FreeSlot(slot);
    }
  }
  return MOZQUIC_OK;
}

uint32_t
NSSHelper::MakeKeyFromRaw(unsigned char *initialSecret,
                          unsigned int secretSize, unsigned int keySize, SSLHashType hashType,
                          CK_MECHANISM_TYPE importMechanism1, CK_MECHANISM_TYPE importMechanism2,
                          unsigned char *outIV, PK11SymKey **outKey)
{
  PK11SymKey *finalKey = nullptr;
  PK11SymKey *secretSKey = nullptr;
  unsigned char ppKey[32];
  assert (secretSize <= 48);
  assert (keySize <= sizeof(ppKey));

  PK11SlotInfo *slot = PK11_GetInternalSlot();
  {
    SECItem secret_item = {siBuffer, initialSecret, secretSize};
    secretSKey = PK11_ImportSymKey(slot, importMechanism1, PK11_OriginUnwrap,
                                   CKA_DERIVE, &secret_item, NULL);
  }
  PK11_FreeSlot(slot);
  slot = nullptr;
  if (!secretSKey) {
    goto failure;
  }

  if (QHkdfExpandLabelRaw(secretSKey, hashType,
                          "key", 3, ppKey, keySize) != SECSuccess) {
    goto failure;
  }

  // iv length is max(8, n_min) - n_min is aead specific, but is 12 for everything currently known
  if (QHkdfExpandLabelRaw(secretSKey, hashType,
                          "iv", 2, outIV, 12) != SECSuccess) {
    goto failure;
  }

  if (!(slot = PK11_GetInternalSlot())){
    goto failure;
  }

  {
    SECItem ppKey_item = {siBuffer, ppKey, keySize};
    finalKey = PK11_ImportSymKey(slot, importMechanism2, PK11_OriginUnwrap,
                                 CKA_DERIVE, &ppKey_item, NULL);
  }
  PK11_FreeSlot(slot);
  if (secretSKey) {
    PK11_FreeSymKey(secretSKey);
  }
  *outKey = finalKey;
  return finalKey ? MOZQUIC_OK : MOZQUIC_ERR_CRYPTO;

failure:
  if (slot) {
    PK11_FreeSlot(slot);
  }
  if (secretSKey) {
    PK11_FreeSymKey(secretSKey);
  }
  if (finalKey) {
    PK11_FreeSymKey(finalKey);
  }
  return MOZQUIC_ERR_CRYPTO;
}

uint32_t
NSSHelper::MakeKeyFromNSS(PRFileDesc *fd, bool earlyKey, const char *label,
                          unsigned int secretSize, unsigned int keySize, SSLHashType hashType,
                          CK_MECHANISM_TYPE importMechanism1, CK_MECHANISM_TYPE importMechanism2,
                          unsigned char *outIV, PK11SymKey **outKey)
{
  unsigned char initialSecret[48];
  assert (secretSize <= 48);

  if (earlyKey) {
    if (SSL_ExportEarlyKeyingMaterial(fd, label, strlen (label),
                                      (const unsigned char *)"", 0, initialSecret, secretSize) != SECSuccess) {
      return MOZQUIC_ERR_CRYPTO;
    }
  } else {
    if (SSL_ExportKeyingMaterial(fd, label, strlen (label),
                                 false, (const unsigned char *)"", 0, initialSecret, secretSize) != SECSuccess) {
      return MOZQUIC_ERR_CRYPTO;
    }
  }

  return MakeKeyFromRaw(initialSecret, secretSize, keySize, hashType, importMechanism1,
                        importMechanism2, outIV, outKey);
}

uint32_t
NSSHelper::HandshakeSecret(unsigned int ciphersuite,
                           unsigned char *sendSecret, unsigned char *recvSecret)
{
  mExternalCipherSuite = ciphersuite;
  memcpy (mExternalSendSecret, sendSecret, 48);
  memcpy (mExternalRecvSecret, recvSecret, 48);
  mHandshakeComplete = true;

  uint16_t nssSuite;
  if (ciphersuite == MOZQUIC_AES_128_GCM_SHA256) {
    nssSuite = TLS_AES_128_GCM_SHA256;
  } else if (ciphersuite == MOZQUIC_AES_256_GCM_SHA384) {
    nssSuite = TLS_AES_256_GCM_SHA384;
  } else if (ciphersuite == MOZQUIC_CHACHA20_POLY1305_SHA256) {
    nssSuite = TLS_CHACHA20_POLY1305_SHA256;
  } else {
    return MOZQUIC_ERR_CRYPTO;
  }

  unsigned int secretSize;
  unsigned int keySize;
  SSLHashType hashType;
  CK_MECHANISM_TYPE importMechanism1, importMechanism2;

  GetKeyParamsFromCipherSuite(nssSuite, secretSize, keySize, hashType, mPacketProtectionMech,
                              importMechanism1, importMechanism2);

  bool didHandshakeFail =
    MakeKeyFromRaw(mExternalSendSecret, secretSize, keySize, hashType, importMechanism1,
                   importMechanism2, mPacketProtectionSenderIV0, &mPacketProtectionSenderKey0) != MOZQUIC_OK;
  memset(mExternalSendSecret, 0, sizeof(mExternalSendSecret));

  didHandshakeFail = didHandshakeFail ||
    MakeKeyFromRaw(mExternalRecvSecret, secretSize, keySize, hashType, importMechanism1,
                   importMechanism2, mPacketProtectionReceiverIV0, &mPacketProtectionReceiverKey0) != MOZQUIC_OK;
  memset(mExternalRecvSecret, 0, sizeof(mExternalRecvSecret));

  mHandshakeComplete = true;
  if (didHandshakeFail) {
    mHandshakeFailed = true;
  }
  return didHandshakeFail ? MOZQUIC_ERR_CRYPTO : MOZQUIC_OK;
}

void
NSSHelper::GetKeyParamsFromCipherSuite(uint16_t cipherSuite,
                                       unsigned int &secretSize,
                                       unsigned int &keySize,
                                       SSLHashType &hashType,
                                       CK_MECHANISM_TYPE &packetProtectionMech,
                                       CK_MECHANISM_TYPE &importMechanism1,
                                       CK_MECHANISM_TYPE &importMechanism2)
{
  hashType = (cipherSuite == TLS_AES_256_GCM_SHA384) ? ssl_hash_sha384 : ssl_hash_sha256;
  if (cipherSuite == TLS_AES_128_GCM_SHA256) {
    secretSize = 32;
    keySize = 16;
    packetProtectionMech = CKM_AES_GCM;
    importMechanism1 = CKM_NSS_HKDF_SHA256;
    importMechanism2 = CKM_AES_KEY_GEN;
  } else if (cipherSuite == TLS_AES_256_GCM_SHA384) {
    secretSize = 48;
    keySize = 32;
    packetProtectionMech = CKM_AES_GCM;
    importMechanism1 = CKM_NSS_HKDF_SHA384;
    importMechanism2 = CKM_AES_KEY_GEN;
  } else if (cipherSuite == TLS_CHACHA20_POLY1305_SHA256) {
    secretSize = 32;
    keySize = 32;
    packetProtectionMech = CKM_NSS_CHACHA20_POLY1305;
    importMechanism1 = CKM_NSS_HKDF_SHA256;
    importMechanism2 = CKM_NSS_CHACHA20_KEY_GEN;
  } else {
    assert(false);
  }
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

  unsigned char sourceAddressInfo[1024];
  uint32_t sourceAddressLen = sizeof(sourceAddressInfo);
  // on the token generation (first pass) we want to place the server specified retry cid
  // on the token validation (second pass) we want to confirm the initial had that retry cid
  self->mMozQuic->GetPeerAddressHash(
    firstHello ? self->mMozQuic->ServerCID() : self->mMozQuic->HandshakeCID(),
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

class ServerHandshakeReceiverKeys
{
public:
  ~ServerHandshakeReceiverKeys() {
    if (mPacketProtectionHandshakeReceiverKey) {
      PK11_FreeSymKey(mPacketProtectionHandshakeReceiverKey);
    }
  }

  PK11SymKey *Take()
  {
    PK11SymKey *rv = mPacketProtectionHandshakeReceiverKey;
    mPacketProtectionHandshakeReceiverKey = nullptr;
    return rv;
  }

  ServerHandshakeReceiverKeys(CID cid)
  {
    PK11SlotInfo *slot = nullptr;
    PK11SymKey *cidKey = nullptr;
    PK11SymKey *handshakeSecret = nullptr;
    unsigned char expandOut[32];
    
    SECItem cidItem = { siBuffer, (unsigned char *)cid.Data(), cid.Len() };

    if (!(slot = PK11_GetInternalSlot())) {
      goto cleanup;
    }

    cidKey =  PK11_ImportSymKey(slot, CKM_NSS_HKDF_SHA256,
                                PK11_OriginUnwrap,
                                CKA_DERIVE, &cidItem, NULL);
    if (!cidKey) {
      goto cleanup;
    }

    if ((QHkdfExtract(gCleartextSaltKey.key, cidKey, ssl_hash_sha256, &handshakeSecret) != SECSuccess) ||
        !handshakeSecret) {
      goto cleanup;
    }
    assert (PK11_ExtractKeyValue(handshakeSecret) == SECSuccess);
    assert (PK11_GetKeyData(handshakeSecret)->len == 32);

    if (QHkdfExpandLabelRaw(handshakeSecret, ssl_hash_sha256,
                            kHandshakeClientLabel, strlen(kHandshakeClientLabel),
                            expandOut, 32) != SECSuccess) {
      goto cleanup;
    }

    NSSHelper::MakeKeyFromRaw(expandOut, 32, 16, ssl_hash_sha256,
                              CKM_NSS_HKDF_SHA256, CKM_AES_KEY_GEN,
                              mPacketProtectionHandshakeReceiverIV, &mPacketProtectionHandshakeReceiverKey);

  cleanup:
    if (slot) {
      PK11_FreeSlot(slot);
    }
    if (cidKey) {
      PK11_FreeSymKey(cidKey);
    }
    if (handshakeSecret) {
      PK11_FreeSymKey(handshakeSecret);
    }
  }

  PK11SymKey    *mPacketProtectionHandshakeReceiverKey;
  unsigned char  mPacketProtectionHandshakeReceiverIV[12];
};

void
NSSHelper::MakeHandshakeKeys(CID cid)
{
  PK11SlotInfo *slot = nullptr;
  PK11SymKey *cidKey = nullptr;
  PK11SymKey *handshakeSecret = nullptr;
  unsigned char expandOut[32];
    
  mPacketProtectionHandshakeCID = cid;

  TlsLog5("MakeHandshakeKeys for ConnID %s\n", mPacketProtectionHandshakeCID.Text());
  SECItem cidItem = { siBuffer, (unsigned char *)mPacketProtectionHandshakeCID.Data(),
                      mPacketProtectionHandshakeCID.Len() };
      
  if (!(slot = PK11_GetInternalSlot())) {
    goto cleanup;
  }

  cidKey =  PK11_ImportSymKey(slot,
                              CKM_NSS_HKDF_SHA256,
                              PK11_OriginUnwrap,
                              CKA_DERIVE, &cidItem, NULL);
  if (!cidKey) {
    goto cleanup;
  }

  if ((QHkdfExtract(gCleartextSaltKey.key, cidKey, ssl_hash_sha256, &handshakeSecret) != SECSuccess) ||
      !handshakeSecret) {
    goto cleanup;
  }
  assert (PK11_ExtractKeyValue(handshakeSecret) == SECSuccess);
  assert (PK11_GetKeyData(handshakeSecret)->len == 32);

  if (mIsClient) {
    if (QHkdfExpandLabelRaw(handshakeSecret, ssl_hash_sha256,
                            kHandshakeClientLabel, strlen(kHandshakeClientLabel),
                            expandOut, 32) != SECSuccess) {
      goto cleanup;
    }

    MakeKeyFromRaw(expandOut, 32, 16, ssl_hash_sha256,
                   CKM_NSS_HKDF_SHA256, CKM_AES_KEY_GEN,
                   mPacketProtectionHandshakeSenderIV, &mPacketProtectionHandshakeSenderKey);
  } else {
    ServerHandshakeReceiverKeys skey(mPacketProtectionHandshakeCID);
    mPacketProtectionHandshakeReceiverKey = skey.Take();
    memcpy(mPacketProtectionHandshakeReceiverIV,
           skey.mPacketProtectionHandshakeReceiverIV,
           sizeof(mPacketProtectionHandshakeReceiverIV));
  }

  if (QHkdfExpandLabelRaw(handshakeSecret, ssl_hash_sha256,
                          kHandshakeServerLabel, strlen(kHandshakeServerLabel),
                          expandOut, 32) != SECSuccess) {
    goto cleanup;
  }

  if (mIsClient) {
    MakeKeyFromRaw(expandOut, 32, 16, ssl_hash_sha256,
                   CKM_NSS_HKDF_SHA256, CKM_AES_KEY_GEN,
                   mPacketProtectionHandshakeReceiverIV, &mPacketProtectionHandshakeReceiverKey);
  } else {
    MakeKeyFromRaw(expandOut, 32, 16, ssl_hash_sha256,
                   CKM_NSS_HKDF_SHA256, CKM_AES_KEY_GEN,
                   mPacketProtectionHandshakeSenderIV, &mPacketProtectionHandshakeSenderKey);
  }

cleanup:
  if (slot) {
    PK11_FreeSlot(slot);
  }
  if (cidKey) {
    PK11_FreeSymKey(cidKey);
  }
  if (handshakeSecret) {
    PK11_FreeSymKey(handshakeSecret);
  }
}

void
NSSHelper::HandshakeCallback(PRFileDesc *fd, void *)
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
  SSLHashType hashType;
  unsigned int secretSize;
  unsigned int keySize;
  CK_MECHANISM_TYPE importMechanism1, importMechanism2;

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
    } else {
      GetKeyParamsFromCipherSuite(info.cipherSuite,
                                  secretSize, keySize, hashType, self->mPacketProtectionMech,
                                  importMechanism1, importMechanism2);
    }
  }

  if (self->mIsClient) {
    if (self->MakeKeyFromNSS(fd, false, k1RTTClientLabel,
                             secretSize, keySize, hashType, importMechanism1, importMechanism2,
                             self->mPacketProtectionSenderIV0, &self->mPacketProtectionSenderKey0) != MOZQUIC_OK) {
      didHandshakeFail = true;
    }
    if (self->MakeKeyFromNSS(fd, false, k1RTTServerLabel,
                             secretSize, keySize, hashType, importMechanism1, importMechanism2,
                             self->mPacketProtectionReceiverIV0, &self->mPacketProtectionReceiverKey0) != MOZQUIC_OK) {
      didHandshakeFail = true;
    }
  } else {
    if (self->MakeKeyFromNSS(fd, false, k1RTTServerLabel,
                             secretSize, keySize, hashType, importMechanism1, importMechanism2,
                             self->mPacketProtectionSenderIV0, &self->mPacketProtectionSenderKey0) != MOZQUIC_OK) {
      didHandshakeFail = true;
    }
    if (self->MakeKeyFromNSS(fd, false, k1RTTClientLabel,
                             secretSize, keySize, hashType, importMechanism1, importMechanism2,
                             self->mPacketProtectionReceiverIV0, &self->mPacketProtectionReceiverKey0) != MOZQUIC_OK) {
      didHandshakeFail = true;
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
  
  if ((mode != kEncryptHandshake) && (mode != kDecryptHandshake) &&
      (mode != kEncrypt0RTT) && (mode != kDecrypt0RTT)) {
    if (mHandshakeFailed) {
      return MOZQUIC_ERR_GENERAL;
    }
    if (mode == kEncrypt0 && !mPacketProtectionSenderKey0) {
      return MOZQUIC_ERR_GENERAL;
    }
    if (mode == kDecrypt0 && !mPacketProtectionReceiverKey0) {
      return MOZQUIC_ERR_GENERAL;
    }
  }

  CK_GCM_PARAMS gcmParams;
  CK_NSS_AEAD_PARAMS polyParams;
  unsigned char *params;
  unsigned int paramsLength;
  unsigned char nonce[12];
  PK11SymKey *key;
  CK_MECHANISM_TYPE mech;

  assert(sizeof(nonce) == 12);
  if (mode == kEncrypt0) {
    key = mPacketProtectionSenderKey0;
    memcpy(nonce, mPacketProtectionSenderIV0, sizeof(nonce));
    mech = mPacketProtectionMech;
  } else if (mode == kDecrypt0) {
    key = mPacketProtectionReceiverKey0;
    memcpy(nonce, mPacketProtectionReceiverIV0, sizeof(nonce));
    mech = mPacketProtectionMech;
  } else if (mode == kEncryptHandshake) {
    TlsLog5("BlockOperation encrypt handshake with cidkey %lX\n",
            mPacketProtectionHandshakeCID);
    key = mPacketProtectionHandshakeSenderKey;
    memcpy(nonce, mPacketProtectionHandshakeSenderIV, sizeof(nonce));
    mech = CKM_AES_GCM;
  } else if (mode == kDecryptHandshake) {
    TlsLog5("BlockOperation decrypt handshake with cidkey %lX\n",
            mPacketProtectionHandshakeCID);
    key = mPacketProtectionHandshakeReceiverKey;
    mech = CKM_AES_GCM;
    memcpy(nonce, mPacketProtectionHandshakeReceiverIV, sizeof(nonce));
  } else if (mode == kEncrypt0RTT) {
    TlsLog5("BlockOperation encrypt with the 0RTT key\n");
    key = mPacketProtectionKey0RTT;
    memcpy(nonce, mPacketProtectionIV0RTT, sizeof(nonce));
    mech = mPacketProtectionMech0RTT;
  } else {
    assert (mode == kDecrypt0RTT);
    TlsLog5("BlockOperation decrypt with the 0RTT key\n");
    key = mPacketProtectionKey0RTT;
    memcpy(nonce, mPacketProtectionIV0RTT, sizeof(nonce));
    mech = mPacketProtectionMech0RTT;
  }

  packetNumber = PR_htonll(packetNumber);
  unsigned char *tmp = (unsigned char *)&packetNumber;
  for(int i = 0; i < 8; ++i) {
    nonce[i + 4] ^= tmp[i];
  }

  if (mech == CKM_AES_GCM) {
    params = (unsigned char *) &gcmParams;
    paramsLength = sizeof(gcmParams);
    memset(&gcmParams, 0, sizeof(gcmParams));
    gcmParams.pIv = nonce;
    gcmParams.ulIvLen = sizeof(nonce);
    gcmParams.pAAD = (unsigned char *)aadData;
    gcmParams.ulAADLen = aadLen;
    gcmParams.ulTagBits = 128;
  } else {
    assert (mech == CKM_NSS_CHACHA20_POLY1305);
    params = (unsigned char *) &polyParams;
    paramsLength = sizeof(polyParams);
    memset(&polyParams, 0, sizeof(polyParams));
    polyParams.pNonce = nonce;
    polyParams.ulNonceLen = sizeof(nonce);
    polyParams.pAAD = (unsigned char *)aadData;
    polyParams.ulAADLen = aadLen;
    polyParams.ulTagLen = 16;
  }

  unsigned int enlen = 0;
  SECItem param = {siBuffer, params, paramsLength};
  uint32_t rv = MOZQUIC_OK;

  if (mode == kEncrypt0 || mode == kEncryptHandshake || mode == kEncrypt0RTT) {
    rv = PK11_Encrypt(key, mech, &param, out, &enlen, outAvail,
                      data, dataLen) == SECSuccess ? MOZQUIC_OK : MOZQUIC_ERR_GENERAL;
  } else {
    assert (mode == kDecrypt0 || mode == kDecryptHandshake ||
            mode == kDecrypt0RTT);
    rv = PK11_Decrypt(key, mech, &param, out, &enlen, outAvail,
                      data, dataLen) == SECSuccess ? MOZQUIC_OK : MOZQUIC_ERR_GENERAL;
  }
  written = enlen;
  return rv;
}

uint32_t
NSSHelper::staticDecryptHandshake(const unsigned char *aadData, uint32_t aadLen,
                                  const unsigned char *data, uint32_t dataLen,
                                  uint64_t packetNumber, CID connectionID,
                                  unsigned char *out, uint32_t outAvail, uint32_t &written)
// out should be at least dataLen - 16 (for tag removal)
{
  assert(outAvail >= (dataLen + 16));

  CK_GCM_PARAMS gcmParams;
  unsigned char *params;
  unsigned int paramsLength;
  unsigned char nonce[12];

  assert(sizeof(nonce) == 12);
  ServerHandshakeReceiverKeys keys(connectionID);
  memcpy(nonce, keys.mPacketProtectionHandshakeReceiverIV, sizeof(nonce));
  packetNumber = PR_htonll(packetNumber);
  unsigned char *tmp = (unsigned char *)&packetNumber;
  for(int i = 0; i < 8; ++i) {
    nonce[i + 4] ^= tmp[i];
  }

  params = (unsigned char *) &gcmParams;
  paramsLength = sizeof(gcmParams);
  memset(&gcmParams, 0, sizeof(gcmParams));
  gcmParams.pIv = nonce;
  gcmParams.ulIvLen = sizeof(nonce);
  gcmParams.pAAD = (unsigned char *)aadData;
  gcmParams.ulAADLen = aadLen;
  gcmParams.ulTagBits = 128;

  unsigned int enlen = 0;
  SECItem param = {siBuffer, params, paramsLength};
  uint32_t rv = MOZQUIC_OK;

  rv = PK11_Decrypt(keys.mPacketProtectionHandshakeReceiverKey,
                    CKM_AES_GCM, &param, out, &enlen, outAvail,
                    data, dataLen) == SECSuccess ? MOZQUIC_OK : MOZQUIC_ERR_GENERAL;
  written = enlen;
  return rv;
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
NSSHelper::EncryptHandshake(const unsigned char *aadData, uint32_t aadLen,
                            const unsigned char *plaintext, uint32_t plaintextLen,
                            uint64_t packetNumber, CID cid, unsigned char *out,
                            uint32_t outAvail, uint32_t &written)
{
  if (cid != mPacketProtectionHandshakeCID) {
    MakeHandshakeKeys(cid);
  }
  assert (cid == mPacketProtectionHandshakeCID);
  return BlockOperation(kEncryptHandshake, aadData, aadLen, plaintext, plaintextLen,
                        packetNumber, out, outAvail, written);
}

uint32_t
NSSHelper::DecryptHandshake(const unsigned char *aadData, uint32_t aadLen,
                            const unsigned char *ciphertext, uint32_t ciphertextLen,
                            uint64_t packetNumber, CID cid, unsigned char *out, uint32_t outAvail,
                            uint32_t &written)
{ 
  if (cid != mPacketProtectionHandshakeCID) {
    MakeHandshakeKeys(cid);
  }
  assert (cid == mPacketProtectionHandshakeCID);
  return BlockOperation(kDecryptHandshake, aadData, aadLen, ciphertext, ciphertextLen,
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
  memset(mExternalSendSecret, 0, sizeof(mExternalSendSecret));
  memset(mExternalRecvSecret, 0, sizeof(mExternalRecvSecret));

  mFD = PR_CreateIOLayerStub(nssHelperIdentity, &nssHelperMethods);
  mFD->secret = (struct PRFilePrivate *)this;
  mFD = SSL_ImportFD(nullptr, mFD);

  // To disable any of the usual cipher suites..
  // SSL_CipherPrefSet(mFD, TLS_AES_128_GCM_SHA256, 0);
  // SSL_CipherPrefSet(mFD, TLS_AES_256_GCM_SHA384, 0);
  // SSL_CipherPrefSet(mFD, TLS_CHACHA20_POLY1305_SHA256, 0);

  SSL_OptionSet(mFD, SSL_SECURITY, true);
  SSL_OptionSet(mFD, SSL_HANDSHAKE_AS_CLIENT, mIsClient);
  SSL_OptionSet(mFD, SSL_HANDSHAKE_AS_SERVER, !mIsClient);
  SSL_OptionSet(mFD, SSL_ENABLE_RENEGOTIATION, SSL_RENEGOTIATE_NEVER);

  SSL_OptionSet(mFD, SSL_NO_CACHE, false);

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

  SSLVersionRange range = {SSL_LIBRARY_VERSION_TLS_1_3,
                           SSL_LIBRARY_VERSION_TLS_1_3};
  SSL_VersionRangeSet(mFD, &range);
  SSL_HandshakeCallback(mFD, HandshakeCallback, nullptr);

  unsigned char buffer[256];
  assert(strlen(MozQuic::kAlpn) < 256);
  buffer[0] = strlen(MozQuic::kAlpn);
  memcpy(buffer + 1, MozQuic::kAlpn, strlen(MozQuic::kAlpn));
  if (SSL_SetNextProtoNego(mFD,
                           buffer, strlen(MozQuic::kAlpn) + 1) != SECSuccess) {
    mNSSReady = false;
  }

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

  MakeHandshakeKeys(mMozQuic->HandshakeCID());
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
  , mExternalCipherSuite(0)
  , mLocalTransportExtensionLen(0)
  , mRemoteTransportExtensionLen(0)
  , mPacketProtectionSenderKey0(nullptr)
  , mPacketProtectionReceiverKey0(nullptr)
  , mPacketProtectionHandshakeSenderKey(nullptr)
  , mPacketProtectionHandshakeReceiverKey(nullptr)
{
  SharedInit();

  SSL_ConfigServerSessionIDCache(25000, 60, 43200, NULL);
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
  , mExternalCipherSuite(0)
  , mLocalTransportExtensionLen(0)
  , mRemoteTransportExtensionLen(0)
  , mPacketProtectionSenderKey0(nullptr)
  , mPacketProtectionReceiverKey0(nullptr)
  , mPacketProtectionHandshakeSenderKey(nullptr)
  , mPacketProtectionHandshakeReceiverKey(nullptr)
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
  // data (e.g. server hello) has come from nss and needs to be written into MozQuic
  // to be written out to the network in stream 0
  NSSHelper *self = reinterpret_cast<NSSHelper *>(fd->secret);
  self->mMozQuic->NSSOutput(aBuf, aAmount);
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
  return self->mMozQuic->NSSInput(buf, amount);
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
NSSHelper::ReadTLSData()
{
  if (mHandshakeFailed) {
    return MOZQUIC_ERR_CRYPTO;
  }

  if (!mNSSReady) {
    return MOZQUIC_ERR_GENERAL;
  }
  char data[256];
  if (PR_Read(mFD, data, 256) == SECSuccess) {
    return MOZQUIC_OK;
  }

  if (PR_GetError() == PR_WOULD_BLOCK_ERROR) {
    return MOZQUIC_OK;
  }
  TlsLog1("Post handshake TLS messages err: %s\n", PR_ErrorToName(PR_GetError()));
  return MOZQUIC_ERR_GENERAL;
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

  SSLHashType hashType;
  unsigned int secretSize;
  unsigned int keySize;
  CK_MECHANISM_TYPE importMechanism1, importMechanism2;
  GetKeyParamsFromCipherSuite(info.cipherSuite,
                              secretSize, keySize, hashType, mPacketProtectionMech0RTT,
                              importMechanism1, importMechanism2);

  if (MakeKeyFromNSS(mFD, true, k0RTTLabel,
                     secretSize, keySize, hashType, importMechanism1, importMechanism2,
                     mPacketProtectionIV0RTT, &mPacketProtectionKey0RTT) != MOZQUIC_OK) {
    return false;
  }

  return true;
}

bool
NSSHelper::IsEarlyDataAcceptedServer()
{
  assert (!mIsClient);

  SSLPreliminaryChannelInfo info;
  if (SSL_GetPreliminaryChannelInfo(mFD, &info, sizeof(info)) != SECSuccess) {
    TlsLog6("IsEarlyDataAccepted fail 1\n");
    return false;
  }

  SSLHashType hashType;
  unsigned int secretSize;
  unsigned int keySize;
  CK_MECHANISM_TYPE importMechanism1, importMechanism2;
  GetKeyParamsFromCipherSuite(info.cipherSuite,
                              secretSize, keySize, hashType, mPacketProtectionMech0RTT,
                              importMechanism1, importMechanism2);

  if (MakeKeyFromNSS(mFD, true, k0RTTLabel,
                     secretSize, keySize, hashType, importMechanism1, importMechanism2,
                     mPacketProtectionIV0RTT, &mPacketProtectionKey0RTT) != MOZQUIC_OK) {
    TlsLog6("IsEarlyDataAccepted fail 2\n");
    return false;
  }

  if (MakeKeyFromNSS(mFD, false, k1RTTServerLabel,
                     secretSize, keySize, hashType, importMechanism1, importMechanism2,
                     mPacketProtectionSenderIV0, &mPacketProtectionSenderKey0) != MOZQUIC_OK) {
    TlsLog6("IsEarlyDataAccepted fail 3\n");
    return false;
  }
  mPacketProtectionMech = mPacketProtectionMech0RTT; // this seems redundant
  
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

uint64_t
NSSHelper::SockAddrHasher(const struct sockaddr *sock)
{
  bool ipv4;

  {
    const struct sockaddr_in *s = (const struct sockaddr_in *) sock;
    ipv4 = (s->sin_family == AF_INET);
  }

  if (ipv4) {
    const struct sockaddr_in *s = (const struct sockaddr_in *) sock;
    assert(s->sin_family == AF_INET);
    uint64_t rv = 0;
    memcpy(&rv,(unsigned char *)&s->sin_port, 2);
    memcpy((&rv) + 2, (unsigned char *)&s->sin_addr, 4);
    return rv;
  }
  
  unsigned char digest[SHA1_LENGTH];
  HASHContext *hcontext = HASH_Create(HASH_AlgSHA1);
  HASH_Begin(hcontext);
  const struct sockaddr_in6 *s = (const struct sockaddr_in6 *) sock;
  assert(s->sin6_family == AF_INET6);
  HASH_Update(hcontext, (unsigned char *)&s->sin6_port, sizeof(uint16_t));
  HASH_Update(hcontext, (unsigned char *)&s->sin6_addr, sizeof(struct in6_addr));

  unsigned int digestLen;
  HASH_End(hcontext, digest, &digestLen, sizeof(digest));
  assert(digestLen == sizeof(digest));
  
  uint64_t rv = 0;
  memcpy(&rv, digest, sizeof(digest) < sizeof(rv) ? sizeof(digest) : sizeof(rv));
  return rv;
}

NSSHelper::~NSSHelper()
{
  if (mPacketProtectionSenderKey0) {
    PK11_FreeSymKey(mPacketProtectionSenderKey0);
  }
  if (mPacketProtectionReceiverKey0) {
    PK11_FreeSymKey(mPacketProtectionReceiverKey0);
  }
  if (mPacketProtectionHandshakeSenderKey) {
    PK11_FreeSymKey(mPacketProtectionHandshakeSenderKey);
  }
  if (mPacketProtectionHandshakeReceiverKey) {
    PK11_FreeSymKey(mPacketProtectionHandshakeReceiverKey);
  }
}

}
