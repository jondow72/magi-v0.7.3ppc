// Copyright (c) 2009-2012 The Bitcoin developers
// Copyright (c) 2011-2019 The Peercoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <map>

#if OPENSSL_VERSION_NUMBER < 0x10100000L
#include <openssl/ecdsa.h>
#endif

#include <openssl/obj_mac.h>

#include "key.h"

// Generate a private key from just the secret parameter
int EC_KEY_regenerate_key(EC_KEY *eckey, BIGNUM *priv_key)
{
    int ok = 0;
    BN_CTX *ctx = NULL;
    EC_POINT *pub_key = NULL;

    if (!eckey) return 0;

    const EC_GROUP *group = EC_KEY_get0_group(eckey);

    if ((ctx = BN_CTX_new()) == NULL)
        goto err;

    pub_key = EC_POINT_new(group);

    if (pub_key == NULL)
        goto err;

    if (!EC_POINT_mul(group, pub_key, priv_key, NULL, NULL, ctx))
        goto err;

    EC_KEY_set_private_key(eckey,priv_key);
    EC_KEY_set_public_key(eckey,pub_key);

    ok = 1;

err:

    if (pub_key)
        EC_POINT_free(pub_key);
    if (ctx != NULL)
        BN_CTX_free(ctx);

    return(ok);
}

// Perform ECDSA key recovery (see SEC1 4.1.6) for curves over (mod p)-fields
// recid selects which key is recovered
// if check is non-zero, additional checks are performed
int ECDSA_SIG_recover_key_GFp(EC_KEY *eckey, ECDSA_SIG *ecsig, const unsigned char *msg, int msglen, int recid, int check)
{
    if (!eckey) return 0;

    const BIGNUM *sig_r, *sig_s;
    #if OPENSSL_VERSION_NUMBER > 0x1000ffffL
    ECDSA_SIG_get0(ecsig, &sig_r, &sig_s);
    #else
    sig_r = ecsig->r;
    sig_s = ecsig->s;
    #endif

    int ret = 0;
    BN_CTX *ctx = NULL;

    BIGNUM *x = NULL;
    BIGNUM *e = NULL;
    BIGNUM *order = NULL;
    BIGNUM *sor = NULL;
    BIGNUM *eor = NULL;
    BIGNUM *field = NULL;
    EC_POINT *R = NULL;
    EC_POINT *O = NULL;
    EC_POINT *Q = NULL;
    BIGNUM *rr = NULL;
    BIGNUM *zero = NULL;
    int n = 0;
    int i = recid / 2;

    const EC_GROUP *group = EC_KEY_get0_group(eckey);
    if ((ctx = BN_CTX_new()) == NULL) { ret = -1; goto err; }
    BN_CTX_start(ctx);
    order = BN_CTX_get(ctx);
    if (!EC_GROUP_get_order(group, order, ctx)) { ret = -2; goto err; }
    x = BN_CTX_get(ctx);
    if (!BN_copy(x, order)) { ret=-1; goto err; }
    if (!BN_mul_word(x, i)) { ret=-1; goto err; }
    if (!BN_add(x, x, sig_r)) { ret=-1; goto err; }
    field = BN_CTX_get(ctx);
    if (!EC_GROUP_get_curve_GFp(group, field, NULL, NULL, ctx)) { ret=-2; goto err; }
    if (BN_cmp(x, field) >= 0) { ret=0; goto err; }
    if ((R = EC_POINT_new(group)) == NULL) { ret = -2; goto err; }
    if (!EC_POINT_set_compressed_coordinates_GFp(group, R, x, recid % 2, ctx)) { ret=0; goto err; }
    if (check)
    {
        if ((O = EC_POINT_new(group)) == NULL) { ret = -2; goto err; }
        if (!EC_POINT_mul(group, O, NULL, R, order, ctx)) { ret=-2; goto err; }
        if (!EC_POINT_is_at_infinity(group, O)) { ret = 0; goto err; }
    }
    if ((Q = EC_POINT_new(group)) == NULL) { ret = -2; goto err; }
    n = EC_GROUP_get_degree(group);
    e = BN_CTX_get(ctx);
    if (!BN_bin2bn(msg, msglen, e)) { ret=-1; goto err; }
    if (8*msglen > n) BN_rshift(e, e, 8-(n & 7));
    zero = BN_CTX_get(ctx);
    BN_zero(zero);
    if (!BN_mod_sub(e, zero, e, order, ctx)) { ret=-1; goto err; }
    rr = BN_CTX_get(ctx);
    if (!BN_mod_inverse(rr, sig_r, order, ctx)) { ret=-1; goto err; }
    sor = BN_CTX_get(ctx);
    if (!BN_mod_mul(sor, sig_s, rr, order, ctx)) { ret=-1; goto err; }
    eor = BN_CTX_get(ctx);
    if (!BN_mod_mul(eor, e, rr, order, ctx)) { ret=-1; goto err; }
    if (!EC_POINT_mul(group, Q, eor, R, sor, ctx)) { ret=-2; goto err; }
    if (!EC_KEY_set_public_key(eckey, Q)) { ret=-2; goto err; }

    ret = 1;

err:
    if (ctx) {
        BN_CTX_end(ctx);
        BN_CTX_free(ctx);
    }
    if (R != NULL) EC_POINT_free(R);
    if (O != NULL) EC_POINT_free(O);
    if (Q != NULL) EC_POINT_free(Q);
    return ret;
}

void CKey::SetCompressedPubKey(bool fCompressed)
{
    EC_KEY_set_conv_form(pkey, fCompressed ? POINT_CONVERSION_COMPRESSED : POINT_CONVERSION_UNCOMPRESSED);
    fCompressedPubKey = true;
}

void CKey::Reset()
{
    fCompressedPubKey = false;
    if (pkey != NULL)
        EC_KEY_free(pkey);
    pkey = EC_KEY_new_by_curve_name(NID_secp256k1);
    if (pkey == NULL)
        throw key_error("CKey::CKey() : EC_KEY_new_by_curve_name failed");
    fSet = false;
}

CKey::CKey()
{
    pkey = NULL;
    Reset();
}

CKey::CKey(const CKey& b)
{
    pkey = EC_KEY_dup(b.pkey);
    if (pkey == NULL)
        throw key_error("CKey::CKey(const CKey&) : EC_KEY_dup failed");
    fSet = b.fSet;
}

CKey& CKey::operator=(const CKey& b)
{
    if (!EC_KEY_copy(pkey, b.pkey))
        throw key_error("CKey::operator=(const CKey&) : EC_KEY_copy failed");
    fSet = b.fSet;
    return (*this);
}

CKey::~CKey()
{
    EC_KEY_free(pkey);
}

bool CKey::IsNull() const
{
    return !fSet;
}

bool CKey::IsCompressed() const
{
    return fCompressedPubKey;
}

void CKey::MakeNewKey(bool fCompressed)
{
    if (!EC_KEY_generate_key(pkey))
        throw key_error("CKey::MakeNewKey() : EC_KEY_generate_key failed");
    if (fCompressed)
        SetCompressedPubKey();
    fSet = true;
}

bool CKey::SetPrivKey(const CPrivKey& vchPrivKey)
{
    const unsigned char* pbegin = &vchPrivKey[0];
    if (d2i_ECPrivateKey(&pkey, &pbegin, vchPrivKey.size()))
    {
        // In testing, d2i_ECPrivateKey can return true
        // but fill in pkey with a key that fails
        // EC_KEY_check_key, so:
        if (EC_KEY_check_key(pkey))
        {
            fSet = true;
            return true;
        }
    }
    // If vchPrivKey data is bad d2i_ECPrivateKey() can
    // leave pkey in a state where calling EC_KEY_free()
    // crashes. To avoid that, set pkey to NULL and
    // leak the memory (a leak is better than a crash)
    pkey = NULL;
    Reset();
    return false;
}

bool CKey::SetSecret(const CSecret& vchSecret, bool fCompressed)
{
    EC_KEY_free(pkey);
    pkey = EC_KEY_new_by_curve_name(NID_secp256k1);
    if (pkey == NULL)
        throw key_error("CKey::SetSecret() : EC_KEY_new_by_curve_name failed");
    if (vchSecret.size() != 32)
        throw key_error("CKey::SetSecret() : secret must be 32 bytes");
    BIGNUM *bn = BN_bin2bn(&vchSecret[0],32,BN_new());
    if (bn == NULL)
        throw key_error("CKey::SetSecret() : BN_bin2bn failed");
    if (!EC_KEY_regenerate_key(pkey,bn))
    {
        BN_clear_free(bn);
        throw key_error("CKey::SetSecret() : EC_KEY_regenerate_key failed");
    }
    BN_clear_free(bn);
    fSet = true;
    if (fCompressed || fCompressedPubKey)
        SetCompressedPubKey();
    return true;
}

CSecret CKey::GetSecret(bool &fCompressed) const
{
    CSecret vchRet;
    vchRet.resize(32);
    const BIGNUM *bn = EC_KEY_get0_private_key(pkey);
    int nBytes = BN_num_bytes(bn);
    if (bn == NULL)
        throw key_error("CKey::GetSecret() : EC_KEY_get0_private_key failed");
    int n=BN_bn2bin(bn,&vchRet[32 - nBytes]);
    if (n != nBytes)
        throw key_error("CKey::GetSecret(): BN_bn2bin failed");
    fCompressed = fCompressedPubKey;
    return vchRet;
}

CPrivKey CKey::GetPrivKey() const
{
    int nSize = i2d_ECPrivateKey(pkey, NULL);
    if (!nSize)
        throw key_error("CKey::GetPrivKey() : i2d_ECPrivateKey failed");
    CPrivKey vchPrivKey(nSize, 0);
    unsigned char* pbegin = &vchPrivKey[0];
    if (i2d_ECPrivateKey(pkey, &pbegin) != nSize)
        throw key_error("CKey::GetPrivKey() : i2d_ECPrivateKey returned unexpected size");
    return vchPrivKey;
}

bool CKey::SetPubKey(const CPubKey& vchPubKey)
{
    const unsigned char* pbegin = &vchPubKey.vchPubKey[0];
    if (o2i_ECPublicKey(&pkey, &pbegin, vchPubKey.vchPubKey.size()))
    {
        fSet = true;
        if (vchPubKey.vchPubKey.size() == 33)
            SetCompressedPubKey();
        return true;
    }
    pkey = NULL;
    Reset();
    return false;
}

CPubKey CKey::GetPubKey() const
{
    int nSize = i2o_ECPublicKey(pkey, NULL);
    if (!nSize)
        throw key_error("CKey::GetPubKey() : i2o_ECPublicKey failed");
    std::vector<unsigned char> vchPubKey(nSize, 0);
    unsigned char* pbegin = &vchPubKey[0];
    if (i2o_ECPublicKey(pkey, &pbegin) != nSize)
        throw key_error("CKey::GetPubKey() : i2o_ECPublicKey returned unexpected size");
    return CPubKey(vchPubKey);
}

bool CKey::Sign(uint256 hash, std::vector<unsigned char>& vchSig)
{
    unsigned int nSize = ECDSA_size(pkey);
    vchSig.resize(nSize); // Make sure it is big enough
    if (!ECDSA_sign(0, (unsigned char*)&hash, sizeof(hash), &vchSig[0], &nSize, pkey))
    {
        vchSig.clear();
        return false;
    }
    vchSig.resize(nSize); // Shrink to fit actual size
    return true;
}

// create a compact signature (65 bytes), which allows reconstructing the used public key
// The format is one header byte, followed by two times 32 bytes for the serialized r and s values.
// The header byte: 0x1B = first key with even y, 0x1C = first key with odd y,
//                  0x1D = second key with even y, 0x1E = second key with odd y
bool CKey::SignCompact(uint256 hash, std::vector<unsigned char>& vchSig)
{
    bool fOk = false;
    ECDSA_SIG *sig = ECDSA_do_sign((unsigned char*)&hash, sizeof(hash), pkey);
    if (sig==NULL)
        return false;
    vchSig.clear();
    vchSig.resize(65,0);

    const BIGNUM *sig_r, *sig_s;
    #if OPENSSL_VERSION_NUMBER > 0x1000ffffL
    ECDSA_SIG_get0(sig, &sig_r, &sig_s);
    #else
    sig_r = sig->r;
    sig_s = sig->s;
    #endif

    int nBitsR = BN_num_bits(sig_r);
    int nBitsS = BN_num_bits(sig_s);
    if (nBitsR <= 256 && nBitsS <= 256)
    {
        int nRecId = -1;
        for (int i=0; i<4; i++)
        {
            CKey keyRec;
            keyRec.fSet = true;
            if (fCompressedPubKey)
                keyRec.SetCompressedPubKey();
            if (ECDSA_SIG_recover_key_GFp(keyRec.pkey, sig, (unsigned char*)&hash, sizeof(hash), i, 1) == 1)
                if (keyRec.GetPubKey() == this->GetPubKey())
                {
                    nRecId = i;
                    break;
                }
        }

        if (nRecId == -1)
        {
            ECDSA_SIG_free(sig);
            throw key_error("CKey::SignCompact() : unable to construct recoverable key");
        }

        vchSig[0] = nRecId+27+(fCompressedPubKey ? 4 : 0);
        BN_bn2bin(sig_r,&vchSig[33-(nBitsR+7)/8]);
        BN_bn2bin(sig_s,&vchSig[65-(nBitsS+7)/8]);
        fOk = true;
    }
    ECDSA_SIG_free(sig);
    return fOk;
}

// reconstruct public key from a compact signature
// This is only slightly more CPU intensive than just verifying it.
// If this function succeeds, the recovered public key is guaranteed to be valid
// (the signature is a valid signature of the given data for that key)
bool CKey::SetCompactSignature(uint256 hash, const std::vector<unsigned char>& vchSig)
{
    if (vchSig.size() != 65)
        return false;
    int nV = vchSig[0];
    if (nV<27 || nV>=35)
        return false;
    ECDSA_SIG *sig = ECDSA_SIG_new();
    if (!sig) return false;

    #if OPENSSL_VERSION_NUMBER > 0x1000ffffL
    // sig_r and sig_s are deallocated by ECDSA_SIG_free(sig);
    BIGNUM *sig_r = BN_bin2bn(&vchSig[1],32,BN_new());
    BIGNUM *sig_s = BN_bin2bn(&vchSig[33],32,BN_new());
    if (!sig_r || !sig_s) return false;
    // copy and transfer ownership to sig
    ECDSA_SIG_set0(sig, sig_r, sig_s);
    #else
    BN_bin2bn(&vchSig[1],32,sig->r);
    BN_bin2bn(&vchSig[33],32,sig->s);
    #endif

    EC_KEY_free(pkey);
    pkey = EC_KEY_new_by_curve_name(NID_secp256k1);
    if (nV >= 31)
    {
        SetCompressedPubKey();
        nV -= 4;
    }
    if (ECDSA_SIG_recover_key_GFp(pkey, sig, (unsigned char*)&hash, sizeof(hash), nV - 27, 0) == 1)
    {
        fSet = true;
        ECDSA_SIG_free(sig);
        return true;
    }
    ECDSA_SIG_free(sig);
    return false;
}

static bool ParseLength(
        const std::vector<unsigned char>::iterator& begin,
        const std::vector<unsigned char>::iterator& end,
        size_t& nLengthRet,
        size_t& nLengthSizeRet)
{
    std::vector<unsigned char>::iterator it = begin;
    if (it == end)
        return false;

    nLengthRet = *it;
    nLengthSizeRet = 1;

    if (!(nLengthRet & 0x80))
        return true;

    unsigned char nLengthBytes = nLengthRet & 0x7f;

    // Lengths on more than 8 bytes are rejected by OpenSSL 64 bits
    if (nLengthBytes > 8)
        return false;

    int64 nLength = 0;
    for (unsigned char i = 0; i < nLengthBytes; i++)
    {
        it++;
        if (it == end)
            return false;
        nLength = (nLength << 8) | *it;
        if (nLength > 0x7fffffff)
            return false;
        nLengthSizeRet++;
    }
    nLengthRet = nLength;
    return true;
}

static std::vector<unsigned char> EncodeLength(size_t nLength)
{
    std::vector<unsigned char> vchRet;
    if (nLength < 0x80)
        vchRet.push_back(nLength);
    else
    {
        vchRet.push_back(0x84);
        vchRet.push_back((nLength >> 24) & 0xff);
        vchRet.push_back((nLength >> 16) & 0xff);
        vchRet.push_back((nLength >> 8) & 0xff);
        vchRet.push_back(nLength & 0xff);
    }
    return vchRet;
}

static bool NormalizeSignature(std::vector<unsigned char>& vchSig)
{
    // Prevent the problem described here: https://lists.linuxfoundation.org/pipermail/bitcoin-dev/2015-July/009697.html
    // by removing the extra length bytes

    if (vchSig.size() < 2 || vchSig[0] != 0x30)
        return false;

    size_t nTotalLength, nTotalLengthSize;
    if (!ParseLength(vchSig.begin() + 1, vchSig.end(), nTotalLength, nTotalLengthSize))
        return false;

    size_t nRStart = 1 + nTotalLengthSize;
    if (vchSig.size() < nRStart + 2 || vchSig[nRStart] != 0x02)
        return false;

    size_t nRLength, nRLengthSize;
    if (!ParseLength(vchSig.begin() + nRStart + 1, vchSig.end(), nRLength, nRLengthSize))
        return false;
    const size_t nRDataStart = nRStart + 1 + nRLengthSize;
    std::vector<unsigned char> R(vchSig.begin() + nRDataStart, vchSig.begin() + nRDataStart + nRLength);

    size_t nSStart = nRStart + 1 + nRLengthSize + nRLength;
    if (vchSig.size() < nSStart + 2 || vchSig[nSStart] != 0x02)
        return false;

    size_t nSLength, nSLengthSize;
    if (!ParseLength(vchSig.begin() + nSStart + 1, vchSig.end(), nSLength, nSLengthSize))
        return false;
    const size_t nSDataStart = nSStart + 1 + nSLengthSize;
    std::vector<unsigned char> S(vchSig.begin() + nSDataStart, vchSig.begin() + nSDataStart + nSLength);

    std::vector<unsigned char> vchRLength = EncodeLength(R.size());
    std::vector<unsigned char> vchSLength = EncodeLength(S.size());

    nTotalLength = 1 + vchRLength.size() + R.size() + 1 + vchSLength.size() + S.size();
    std::vector<unsigned char> vchTotalLength = EncodeLength(nTotalLength);

    vchSig.clear();
    vchSig.reserve(1 + vchTotalLength.size() + nTotalLength);
    vchSig.push_back(0x30);
    vchSig.insert(vchSig.end(), vchTotalLength.begin(), vchTotalLength.end());

    vchSig.push_back(0x02);
    vchSig.insert(vchSig.end(), vchRLength.begin(), vchRLength.end());
    vchSig.insert(vchSig.end(), R.begin(), R.end());

    vchSig.push_back(0x02);
    vchSig.insert(vchSig.end(), vchSLength.begin(), vchSLength.end());
    vchSig.insert(vchSig.end(), S.begin(), S.end());

    return true;
}

bool CKey::Verify(uint256 hash, const std::vector<unsigned char>& vchSigParam)
{
    std::vector<unsigned char> vchSig(vchSigParam.begin(), vchSigParam.end());

    if (!NormalizeSignature(vchSig))
        return false;

    if (vchSig.empty())
        return false;

    // New versions of OpenSSL will reject non-canonical DER signatures. de/re-serialize first.
    unsigned char *norm_der = NULL;
    ECDSA_SIG *norm_sig = ECDSA_SIG_new();
    const unsigned char* sigptr = &vchSig[0];
    assert(norm_sig);
    if (d2i_ECDSA_SIG(&norm_sig, &sigptr, vchSig.size()) == NULL)
    {
        /* As of OpenSSL 1.0.0p d2i_ECDSA_SIG frees and nulls the pointer on
         * error. But OpenSSL's own use of this function redundantly frees the
         * result. As ECDSA_SIG_free(NULL) is a no-op, and in the absence of a
         * clear contract for the function behaving the same way is more
         * conservative.
         */
        ECDSA_SIG_free(norm_sig);
        return false;
    }
    int derlen = i2d_ECDSA_SIG(norm_sig, &norm_der);
    ECDSA_SIG_free(norm_sig);
    if (derlen <= 0)
        return false;

    // -1 = error, 0 = bad sig, 1 = good
    bool ret = ECDSA_verify(0, (unsigned char*)&hash, sizeof(hash), norm_der, derlen, pkey) == 1;
    OPENSSL_free(norm_der);
    return ret;
}

bool CKey::VerifyCompact(uint256 hash, const std::vector<unsigned char>& vchSig)
{
    CKey key;
    if (!key.SetCompactSignature(hash, vchSig))
        return false;
    if (GetPubKey() != key.GetPubKey())
        return false;

    return true;
}

bool CKey::IsValid()
{
    if (!fSet)
        return false;

    if (!EC_KEY_check_key(pkey))
        return false;

    bool fCompr;
    CSecret secret = GetSecret(fCompr);
    CKey key2;
    key2.SetSecret(secret, fCompr);
    return GetPubKey() == key2.GetPubKey();
}
