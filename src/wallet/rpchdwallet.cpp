// Copyright (c) 2017-2021 The Particl Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <amount.h>
#include <base58.h>
#include <chain.h>
#include <consensus/validation.h>
#include <consensus/tx_verify.h>
#include <consensus/merkle.h>
#include <core_io.h>
#include <validation.h>
#include <net.h>
#include <policy/policy.h>
#include <rpc/server.h>
#include <rpc/util.h>
#include <rpc/blockchain.h>
#include <node/context.h>
#include <node/blockstorage.h>
#include <rpc/rawtransaction_util.h>
#include <script/sign.h>
#include <script/descriptor.h>
#include <timedata.h>
#include <util/string.h>
#include <txdb.h>
#include <blind.h>
#include <anon.h>
#include <util/strencodings.h>
#include <util/moneystr.h>
#include <util/translation.h>
#include <util/fees.h>
#include <util/rbf.h>
#include <wallet/hdwallet.h>
#include <wallet/hdwalletdb.h>
#include <wallet/coincontrol.h>
#include <wallet/rpcwallet.h>
#include <chainparams.h>
#include <key/mnemonic.h>
#include <pos/miner.h>
#include <pos/kernel.h>
#include <crypto/sha256.h>
#include <warnings.h>
#include <shutdown.h>
#include <txmempool.h>

#include <univalue.h>

void EnsureWalletIsUnlocked(CHDWallet *pwallet)
{
    if (pwallet->IsLocked()) {
        throw JSONRPCError(RPC_WALLET_UNLOCK_NEEDED, "Error: Wallet locked, please enter the wallet passphrase with walletpassphrase first.");
    }
    if (pwallet->fUnlockForStakingOnly) {
        throw JSONRPCError(RPC_WALLET_UNLOCK_NEEDED, "Error: Wallet is unlocked for staking only.");
    }
};

static const std::string WALLET_ENDPOINT_BASE = "/wallet/";
static const std::string HELP_REQUIRING_PASSPHRASE{"\nRequires wallet passphrase to be set with walletpassphrase call if wallet is encrypted.\n"};

static inline uint32_t reversePlace(const uint8_t *p)
{
    uint32_t rv = 0;
    for (int i = 0; i < 4; ++i) {
        rv |= (uint32_t) *(p+i) << (8 * (3-i));
    }
    return rv;
};

static int ExtractBip32InfoV(const std::vector<uint8_t> &vchKey, UniValue &keyInfo, std::string &sError)
{
    CExtKey58 ek58;
    CExtKeyPair vk;
    vk.DecodeV(&vchKey[4]);

    CChainParams::Base58Type typePk = CChainParams::EXT_PUBLIC_KEY;
    if (memcmp(&vchKey[0], &Params().Base58Prefix(CChainParams::EXT_SECRET_KEY)[0], 4) == 0) {
        keyInfo.pushKV("type", "Particl extended secret key");
    } else
    if (memcmp(&vchKey[0], &Params().Base58Prefix(CChainParams::EXT_SECRET_KEY_BTC)[0], 4) == 0) {
        keyInfo.pushKV("type", "Bitcoin extended secret key");
        typePk = CChainParams::EXT_PUBLIC_KEY_BTC;
    } else {
        keyInfo.pushKV("type", "Unknown extended secret key");
    }

    keyInfo.pushKV("version", strprintf("%02X", reversePlace(&vchKey[0])));
    keyInfo.pushKV("depth", strprintf("%u", vchKey[4]));
    keyInfo.pushKV("parent_fingerprint", strprintf("%08X", reversePlace(&vchKey[5])));
    keyInfo.pushKV("child_index", strprintf("%u", reversePlace(&vchKey[9])));
    keyInfo.pushKV("chain_code", HexStr(Span<const unsigned char>(&vchKey[13], 32)));
    keyInfo.pushKV("key", HexStr(Span<const unsigned char>(&vchKey[46], 32)));

    // don't display raw secret ??
    // TODO: add option

    CKey key;
    key.Set(&vchKey[46], true);
    keyInfo.pushKV("privkey", CBitcoinSecret(key).ToString());
    CPubKey pk = key.GetPubKey();
    keyInfo.pushKV("pubkey", HexStr(pk));
    CKeyID id = pk.GetID();
    CBitcoinAddress addr;
    addr.Set(id, CChainParams::EXT_KEY_HASH);
    keyInfo.pushKV("id", addr.ToString());
    addr.Set(id);
    keyInfo.pushKV("address", addr.ToString());
    keyInfo.pushKV("checksum", strprintf("%02X", reversePlace(&vchKey[78])));

    ek58.SetKey(vk, typePk);
    keyInfo.pushKV("ext_public_key", ek58.ToString());

    return 0;
};

static int ExtractBip32InfoP(const std::vector<uint8_t> &vchKey, UniValue &keyInfo, std::string &sError)
{
    CExtPubKey pk;

    if (memcmp(&vchKey[0], &Params().Base58Prefix(CChainParams::EXT_PUBLIC_KEY)[0], 4) == 0) {
        keyInfo.pushKV("type", "Particl extended public key");
    } else
    if (memcmp(&vchKey[0], &Params().Base58Prefix(CChainParams::EXT_PUBLIC_KEY_BTC)[0], 4) == 0)  {
        keyInfo.pushKV("type", "Bitcoin extended public key");
    } else {
        keyInfo.pushKV("type", "Unknown extended public key");
    }

    keyInfo.pushKV("version", strprintf("%02X", reversePlace(&vchKey[0])));
    keyInfo.pushKV("depth", strprintf("%u", vchKey[4]));
    keyInfo.pushKV("parent_fingerprint", strprintf("%08X", reversePlace(&vchKey[5])));
    keyInfo.pushKV("child_index", strprintf("%u", reversePlace(&vchKey[9])));
    keyInfo.pushKV("chain_code", HexStr(Span<const unsigned char>(&vchKey[13], 32)));
    keyInfo.pushKV("key", HexStr(Span<const unsigned char>(&vchKey[45], 33)));

    CPubKey key;
    key.Set(&vchKey[45], &vchKey[78]);
    CKeyID id = key.GetID();
    CBitcoinAddress addr;
    addr.Set(id, CChainParams::EXT_KEY_HASH);

    keyInfo.pushKV("id", addr.ToString());
    addr.Set(id);
    keyInfo.pushKV("address", addr.ToString());
    keyInfo.pushKV("checksum", strprintf("%02X", reversePlace(&vchKey[78])));

    return 0;
};

static int ExtKeyPathV(const std::string &sPath, const std::vector<uint8_t> &vchKey, UniValue &keyInfo, std::string &sError)
{
    if (sPath.compare("info") == 0) {
        return ExtractBip32InfoV(vchKey, keyInfo, sError);
    }

    CExtKey vk;
    vk.Decode(&vchKey[4]);
    CExtKey vkOut, vkWork = vk;

    std::vector<uint32_t> vPath;
    int rv;
    if ((rv = ExtractExtKeyPath(sPath, vPath)) != 0) {
        return errorN(1, sError, __func__, "ExtractExtKeyPath failed %s", ExtKeyGetString(rv));
    }

    for (std::vector<uint32_t>::iterator it = vPath.begin(); it != vPath.end(); ++it) {
        if (!vkWork.Derive(vkOut, *it)) {
            return errorN(1, sError, __func__, "CExtKey Derive failed");
        }
        vkWork = vkOut;
    }

    CBitcoinExtKey ekOut;
    ekOut.SetKey(vkOut);
    keyInfo.pushKV("result", ekOut.ToString());

    // Display path, the quotes can go missing through the debug console. eg: m/44'/1', m/44\'/1\' works
    std::string sPathOut;
    if (0 != PathToString(vPath, sPathOut)) {
        return errorN(1, sError, __func__, "PathToString failed");
    }
    keyInfo.pushKV("path", sPathOut);

    return 0;
};

static int ExtKeyPathP(const std::string &sPath, const std::vector<uint8_t> &vchKey, UniValue &keyInfo, std::string &sError)
{
    if (sPath.compare("info") == 0) {
        return ExtractBip32InfoP(vchKey, keyInfo, sError);
    }

    CExtPubKey pk;
    pk.Decode(&vchKey[4]);

    CExtPubKey pkOut, pkWork = pk;

    std::vector<uint32_t> vPath;
    int rv;
    if ((rv = ExtractExtKeyPath(sPath, vPath)) != 0) {
        return errorN(1, sError, __func__, "ExtractExtKeyPath failed %s", ExtKeyGetString(rv));
    }

    for (std::vector<uint32_t>::iterator it = vPath.begin(); it != vPath.end(); ++it) {
        if ((*it >> 31) == 1) {
            return errorN(1, sError, __func__, "Can't derive hardened keys from public ext key");
        }
        if (!pkWork.Derive(pkOut, *it)) {
            return errorN(1, sError, __func__, "CExtKey Derive failed");
        }
        pkWork = pkOut;
    }

    CBitcoinExtPubKey ekOut;
    ekOut.SetKey(pkOut);
    keyInfo.pushKV("result", ekOut.ToString());

    // Display path, the quotes can go missing through the debug console. eg: m/44'/1', m/44\'/1\' works
    std::string sPathOut;
    if (0 != PathToString(vPath, sPathOut)) {
        return errorN(1, sError, __func__, "PathToString failed");
    }
    keyInfo.pushKV("path", sPathOut);

    return 0;
};

static int AccountInfo(CHDWallet *pwallet, CExtKeyAccount *pa, int nShowKeys, bool fAllChains, UniValue &obj, std::string &sError) EXCLUSIVE_LOCKS_REQUIRED(pwallet->cs_wallet)
{
    CExtKey58 eKey58;

    obj.pushKV("type", "Account");
    obj.pushKV("active", (pa->nFlags & EAF_ACTIVE) ? "true" : "false");
    obj.pushKV("label", pa->sLabel);

    if (pwallet->idDefaultAccount == pa->GetID()) {
        obj.pushKV("default_account", "true");
    }

    mapEKValue_t::iterator mvi = pa->mapValue.find(EKVT_CREATED_AT);
    if (mvi != pa->mapValue.end()) {
        int64_t nCreatedAt;
        GetCompressedInt64(mvi->second, (uint64_t&)nCreatedAt);
        obj.pushKV("created_at", nCreatedAt);
    }

    mvi = pa->mapValue.find(EKVT_HARDWARE_DEVICE);
    if (mvi != pa->mapValue.end()) {
        if (mvi->second.size() >= 8) {
            int nVendorId = *((int*)mvi->second.data());
            int nProductId = *((int*)(mvi->second.data() + 4));
            obj.pushKV("hardware_device", strprintf("0x%04x 0x%04x", nVendorId, nProductId));
        }
    }

    obj.pushKV("id", pa->GetIDString58());
    obj.pushKV("has_secret", (pa->nFlags & EAF_HAVE_SECRET) ? "true" : "false");

    CStoredExtKey *sekAccount = pa->ChainAccount();
    if (!sekAccount) {
        obj.pushKV("error", "chain account not set.");
        return 0;
    }

    if (pa->nFlags & EAF_HAVE_SECRET) {
        obj.pushKV("encrypted", (sekAccount->nFlags & EAF_IS_CRYPTED) ? "true" : "false");
    }

    CBitcoinAddress addr;
    addr.Set(pa->idMaster, CChainParams::EXT_KEY_HASH);
    obj.pushKV("root_key_id", addr.ToString());

    mvi = sekAccount->mapValue.find(EKVT_PATH);
    if (mvi != sekAccount->mapValue.end()) {
        std::string sPath;
        if (0 == PathToString(mvi->second, sPath, 'h')) {
            obj.pushKV("path", sPath);
        }
    }
    // TODO: separate passwords for accounts
    if (pa->nFlags & EAF_HAVE_SECRET
        && nShowKeys > 1
        && pwallet->ExtKeyUnlock(sekAccount) == 0) {
        eKey58.SetKeyV(sekAccount->kp);
        obj.pushKV("evkey", eKey58.ToString());
    }

    if (nShowKeys > 0) {
        eKey58.SetKeyP(sekAccount->kp);
        obj.pushKV("epkey", eKey58.ToString());
    }

    if (nShowKeys > 2) { // dumpwallet
        obj.pushKV("stealth_address_pack", (int)pa->nPackStealth);
        obj.pushKV("stealth_keys_received_pack", (int)pa->nPackStealthKeys);
    }


    if (fAllChains) {
        UniValue arChains(UniValue::VARR);
        for (size_t i = 1; i < pa->vExtKeys.size(); ++i) { // vExtKeys[0] stores the account key
            UniValue objC(UniValue::VOBJ);
            CStoredExtKey *sek = pa->vExtKeys[i];
            eKey58.SetKeyP(sek->kp);

            if (pa->nActiveExternal == i) {
                objC.pushKV("function", "active_external");
            }
            if (pa->nActiveInternal == i) {
                objC.pushKV("function", "active_internal");
            }
            if (pa->nActiveStealth == i) {
                objC.pushKV("function", "active_stealth");
            }

            objC.pushKV("id", sek->GetIDString58());
            objC.pushKV("chain", eKey58.ToString());
            objC.pushKV("label", sek->sLabel);
            objC.pushKV("active", (sek->nFlags & EAF_ACTIVE) ? "true" : "false");
            objC.pushKV("receive_on", (sek->nFlags & EAF_RECEIVE_ON) ? "true" : "false");

            mapEKValue_t::const_iterator it = sek->mapValue.find(EKVT_KEY_TYPE);
            if (it != sek->mapValue.end() && it->second.size() > 0) {
                std::string sUseType;
                switch (it->second[0]) {
                    case EKT_EXTERNAL:      sUseType = "external";      break;
                    case EKT_INTERNAL:      sUseType = "internal";      break;
                    case EKT_STEALTH:       sUseType = "stealth";       break;
                    case EKT_CONFIDENTIAL:  sUseType = "confidential";  break;
                    case EKT_STEALTH_SCAN:  sUseType = "stealth_scan";  break;
                    case EKT_STEALTH_SPEND: sUseType = "stealth_spend"; break;
                    default:                sUseType = "unknown";       break;
                }
                objC.pushKV("use_type", sUseType);
            }

            objC.pushKV("num_derives", strprintf("%u", sek->nGenerated));
            objC.pushKV("num_derives_h", strprintf("%u", sek->nHGenerated));

            if (nShowKeys > 2 // dumpwallet
                && pa->nFlags & EAF_HAVE_SECRET) {
                if (pwallet->ExtKeyUnlock(sek) == 0) {
                    eKey58.SetKeyV(sek->kp);
                    objC.pushKV("evkey", eKey58.ToString());
                } else {
                    objC.pushKV("evkey", "Decryption failed");
                }

                mvi = sek->mapValue.find(EKVT_CREATED_AT);
                if (mvi != sek->mapValue.end()) {
                    int64_t nCreatedAt;
                    GetCompressedInt64(mvi->second, (uint64_t&)nCreatedAt);
                    objC.pushKV("created_at", nCreatedAt);
                }
            }

            mvi = sek->mapValue.find(EKVT_PATH);
            if (mvi != sek->mapValue.end()) {
                std::string sPath;
                if (0 == PathToString(mvi->second, sPath, 'h')) {
                    objC.pushKV("path", sPath);
                }
            }

            arChains.push_back(objC);
        }
        obj.pushKV("chains", arChains);
    } else {
        if (pa->nActiveExternal < pa->vExtKeys.size()) {
            CStoredExtKey *sekE = pa->vExtKeys[pa->nActiveExternal];
            if (nShowKeys > 0) {
                eKey58.SetKeyP(sekE->kp);
                obj.pushKV("external_chain", eKey58.ToString());
            }
            obj.pushKV("num_derives_external", strprintf("%u", sekE->nGenerated));
            obj.pushKV("num_derives_external_h", strprintf("%u", sekE->nHGenerated));
        }

        if (pa->nActiveInternal < pa->vExtKeys.size()) {
            CStoredExtKey *sekI = pa->vExtKeys[pa->nActiveInternal];
            if (nShowKeys > 0) {
                eKey58.SetKeyP(sekI->kp);
                obj.pushKV("internal_chain", eKey58.ToString());
            }
            obj.pushKV("num_derives_internal", strprintf("%u", sekI->nGenerated));
            obj.pushKV("num_derives_internal_h", strprintf("%u", sekI->nHGenerated));
        }

        if (pa->nActiveStealth < pa->vExtKeys.size()) {
            CStoredExtKey *sekS = pa->vExtKeys[pa->nActiveStealth];
            obj.pushKV("num_derives_stealth", strprintf("%u", sekS->nGenerated));
            obj.pushKV("num_derives_stealth_h", strprintf("%u", sekS->nHGenerated));
        }
    }

    return 0;
};

static int AccountInfo(CHDWallet *pwallet, CKeyID &keyId, int nShowKeys, bool fAllChains, UniValue &obj, std::string &sError)
{
    LOCK(pwallet->cs_wallet);
    // TODO: inactive keys can be in db and not in memory - search db for keyId
    ExtKeyAccountMap::const_iterator mi = pwallet->mapExtAccounts.find(keyId);
    if (mi == pwallet->mapExtAccounts.end()) {
        sError = "Unknown account.";
        return 1;
    }

    CExtKeyAccount *pa = mi->second;
    return AccountInfo(pwallet, pa, nShowKeys, fAllChains, obj, sError);
};

static int KeyInfo(CHDWallet *pwallet, CKeyID &idMaster, CKeyID &idKey, CStoredExtKey &sek, int nShowKeys, UniValue &obj, std::string &sError) EXCLUSIVE_LOCKS_REQUIRED(pwallet->cs_wallet)
{
    CExtKey58 eKey58;

    bool fBip44Root = false;
    obj.pushKV("type", "Loose");
    obj.pushKV("active", sek.IsActive() ? "true" : "false");
    obj.pushKV("receive_on", sek.IsReceiveEnabled() ? "true" : "false");
    obj.pushKV("encrypted", sek.IsEncrypted() ? "true" : "false");
    obj.pushKV("hardware_device", sek.IsHardwareLinked() ? "true" : "false");
    obj.pushKV("label", sek.sLabel);

    if (reversePlace(&sek.kp.vchFingerprint[0]) == 0) {
        obj.pushKV("path", "Root");
    } else {
        mapEKValue_t::iterator mvi = sek.mapValue.find(EKVT_PATH);
        if (mvi != sek.mapValue.end()) {
            std::string sPath;
            if (0 == PathToString(mvi->second, sPath, 'h')) {
                obj.pushKV("path", sPath);
            }
        }
    }

    mapEKValue_t::iterator mvi = sek.mapValue.find(EKVT_KEY_TYPE);
    if (mvi != sek.mapValue.end()) {
        uint8_t type = EKT_MAX_TYPES;
        if (mvi->second.size() == 1) {
            type = mvi->second[0];
        }

        std::string sType;
        switch (type) {
            case EKT_MASTER      : sType = "Master"; break;
            case EKT_BIP44_MASTER:
                sType = "BIP44 Root Key";
                fBip44Root = true;
                break;
            default              : sType = "Unknown"; break;
        }
        obj.pushKV("key_type", sType);
    }

    if (idMaster == idKey) {
        obj.pushKV("current_master", "true");
    }

    CBitcoinAddress addr;
    mvi = sek.mapValue.find(EKVT_ROOT_ID);
    if (mvi != sek.mapValue.end()) {
        CKeyID idRoot;

        if (GetCKeyID(mvi->second, idRoot)) {
            addr.Set(idRoot, CChainParams::EXT_KEY_HASH);
            obj.pushKV("root_key_id", addr.ToString());
        } else {
            obj.pushKV("root_key_id", "malformed");
        }
    }

    mvi = sek.mapValue.find(EKVT_CREATED_AT);
    if (mvi != sek.mapValue.end()) {
        int64_t nCreatedAt;
        GetCompressedInt64(mvi->second, (uint64_t&)nCreatedAt);
        obj.pushKV("created_at", nCreatedAt);
    }

    addr.Set(idKey, CChainParams::EXT_KEY_HASH);
    obj.pushKV("id", addr.ToString());

    if (nShowKeys > 1
        && pwallet->ExtKeyUnlock(&sek) == 0) {
        std::string sKey;
        if (sek.kp.IsValidV()) {
            if (fBip44Root) {
                eKey58.SetKey(sek.kp, CChainParams::EXT_SECRET_KEY_BTC);
            } else {
                eKey58.SetKeyV(sek.kp);
            }
            sKey = eKey58.ToString();
        } else {
            sKey = "Unknown";
        }

        obj.pushKV("evkey", sKey);
    }

    if (nShowKeys > 0) {
        if (fBip44Root) {
            eKey58.SetKey(sek.kp, CChainParams::EXT_PUBLIC_KEY_BTC);
        } else {
            eKey58.SetKeyP(sek.kp);
        }

        obj.pushKV("epkey", eKey58.ToString());
    }

    obj.pushKV("num_derives", strprintf("%u", sek.nGenerated));
    obj.pushKV("num_derives_hardened", strprintf("%u", sek.nHGenerated));

    return 0;
};

static int KeyInfo(CHDWallet *pwallet, CKeyID &idMaster, CKeyID &idKey, int nShowKeys, UniValue &obj, std::string &sError)
{
    CStoredExtKey sek;
    LOCK(pwallet->cs_wallet);
    CHDWalletDB wdb(pwallet->GetDatabase());

    if (!wdb.ReadExtKey(idKey, sek)) {
        sError = "Key not found in wallet.";
        return 1;
    }

    return KeyInfo(pwallet, idMaster, idKey, sek, nShowKeys, obj, sError);
};

class ListExtCallback : public LoopExtKeyCallback
{
public:
    ListExtCallback(CHDWallet *pwalletIn, UniValue *arr, int _nShowKeys)
    {
        pwallet = pwalletIn;
        nItems = 0;
        rvArray = arr;
        nShowKeys = _nShowKeys;

        if (pwallet && pwallet->pEKMaster) {
            idMaster = pwallet->pEKMaster->GetID();
        }
    };

    int ProcessKey(CKeyID &id, CStoredExtKey &sek) override
    {
        nItems++;
        UniValue obj(UniValue::VOBJ);
        LOCK(pwallet->cs_wallet);
        if (0 != KeyInfo(pwallet, idMaster, id, sek, nShowKeys, obj, sError)) {
            obj.pushKV("id", sek.GetIDString58());
            obj.pushKV("error", sError);
        }

        rvArray->push_back(obj);
        return 0;
    };

    int ProcessAccount(CKeyID &id, CExtKeyAccount &sea) override
    {
        nItems++;
        UniValue obj(UniValue::VOBJ);

        bool fAllChains = nShowKeys > 2 ? true : false;
        LOCK(pwallet->cs_wallet);
        if (0 != AccountInfo(pwallet, &sea, nShowKeys, fAllChains, obj, sError)) {
            obj.pushKV("id", sea.GetIDString58());
            obj.pushKV("error", sError);
        }

        rvArray->push_back(obj);
        return 0;
    };

    std::string sError;
    int nItems;
    int nShowKeys;
    CKeyID idMaster;
    UniValue *rvArray;
};

int ListLooseExtKeys(CHDWallet *pwallet, int nShowKeys, UniValue &ret, size_t &nKeys) EXCLUSIVE_LOCKS_REQUIRED(pwallet->cs_wallet)
{
    ListExtCallback cbc(pwallet, &ret, nShowKeys);

    if (0 != LoopExtKeysInDB(pwallet, true, false, cbc)) {
        return errorN(1, "LoopExtKeys failed.");
    }

    nKeys = cbc.nItems;

    return 0;
};

int ListAccountExtKeys(CHDWallet *pwallet, int nShowKeys, UniValue &ret, size_t &nKeys) EXCLUSIVE_LOCKS_REQUIRED(pwallet->cs_wallet)
{
    ListExtCallback cbc(pwallet, &ret, nShowKeys);

    if (0 != LoopExtAccountsInDB(pwallet, true, cbc)) {
        return errorN(1, "LoopExtKeys failed.");
    }

    nKeys = cbc.nItems;

    return 0;
};

static int ManageExtKey(CStoredExtKey &sek, std::string &sOptName, std::string &sOptValue, UniValue &result, std::string &sError)
{
    if (sOptName == "label") {
        if (sOptValue.length() == 0) {
            sek.sLabel = sOptValue;
        }

        result.pushKV("set_label", sek.sLabel);
    } else
    if (sOptName == "active") {
        if (sOptValue.length() > 0) {
            if (part::IsStringBoolPositive(sOptValue)) {
                sek.nFlags |= EAF_ACTIVE;
            } else {
                sek.nFlags &= ~EAF_ACTIVE;
            }
        }

        result.pushKV("set_active", sek.IsActive() ? "true" : "false");
    } else
    if (sOptName == "receive_on") {
        if (sOptValue.length() > 0) {
            if (part::IsStringBoolPositive(sOptValue)) {
                sek.nFlags |= EAF_RECEIVE_ON;
            } else {
                sek.nFlags &= ~EAF_RECEIVE_ON;
            }
        }
        result.pushKV("receive_on", sek.IsReceiveEnabled() ? "true" : "false");
    } else
    if (sOptName == "track_only") {
        if (sOptValue.length() > 0) {
            if (part::IsStringBoolPositive(sOptValue)) {
                sek.nFlags |= EAF_TRACK_ONLY;
            } else {
                sek.nFlags &= ~EAF_TRACK_ONLY;
            }
        }
        result.pushKV("track_only", sek.IsTrackOnly() ? "true" : "false");
    } else
    if (sOptName == "look_ahead") {
        uint64_t nLookAhead = gArgs.GetArg("-defaultlookaheadsize", DEFAULT_LOOKAHEAD_SIZE);

        if (sOptValue.length() > 0) {
            if (!ParseUInt64(sOptValue, &nLookAhead)) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Failed: look_ahead invalid number.");
            }

            if (nLookAhead < 1 || nLookAhead > 1000) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Failed: look_ahead number out of range.");
            }

            std::vector<uint8_t> v;
            sek.mapValue[EKVT_N_LOOKAHEAD] = SetCompressedInt64(v, nLookAhead);
            result.pushKV("note", "Wallet must be restarted to reload lookahead pool.");
        }

        mapEKValue_t::iterator itV = sek.mapValue.find(EKVT_N_LOOKAHEAD);
        if (itV != sek.mapValue.end()) {
            nLookAhead = GetCompressedInt64(itV->second, nLookAhead);
            result.pushKV("look_ahead", (int)nLookAhead);
        } else {
            result.pushKV("look_ahead", "default");
        }
    } else
    if (sOptName == "num_derives") {
        uint32_t v;
        if (!ParseUInt32(sOptValue, &v)) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Failed: invalid number.");
        }
        sek.nGenerated = v;
        result.pushKV("num_derives", (int)sek.nGenerated);
    } else
    if (sOptName == "num_derives_hardened") {
        uint32_t v;
        if (!ParseUInt32(sOptValue, &v)) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Failed: invalid number.");
        }
        sek.nHGenerated = v;
        result.pushKV("num_derives_hardened", (int)sek.nHGenerated);
    } else {
        // List all possible
        result.pushKV("label", sek.sLabel);
        result.pushKV("active", sek.IsActive() ? "true" : "false");
        result.pushKV("receive_on", sek.IsReceiveEnabled() ? "true" : "false");
        result.pushKV("track_only", sek.IsTrackOnly() ? "true" : "false");
        result.pushKV("num_derives", (int)sek.nGenerated);
        result.pushKV("num_derives_hardened", (int)sek.nHGenerated);

        mapEKValue_t::iterator itV = sek.mapValue.find(EKVT_N_LOOKAHEAD);
        if (itV != sek.mapValue.end()) {
            uint64_t nLookAhead = GetCompressedInt64(itV->second, nLookAhead);
            result.pushKV("look_ahead", (int)nLookAhead);
        } else {
            result.pushKV("look_ahead", "default");
        }
    }

    return 0;
};

static int ManageExtAccount(CExtKeyAccount &sea, std::string &sOptName, std::string &sOptValue, UniValue &result, std::string &sError)
{
    if (sOptName == "label") {
        if (sOptValue.length() > 0) {
            sea.sLabel = sOptValue;
        }

        result.pushKV("set_label", sea.sLabel);
    } else
    if (sOptName == "active") {
        if (sOptValue.length() > 0) {
            if (part::IsStringBoolPositive(sOptValue)) {
                sea.nFlags |= EAF_ACTIVE;
            } else {
                sea.nFlags &= ~EAF_ACTIVE;
            }
        }

        result.pushKV("set_active", (sea.nFlags & EAF_ACTIVE) ? "true" : "false");
    } else {
        // List all possible
        result.pushKV("label", sea.sLabel);
        result.pushKV("active", (sea.nFlags & EAF_ACTIVE) ? "true" : "false");
    }

    return 0;
};

static int ExtractExtKeyId(const std::string &sInKey, CKeyID &keyId, CChainParams::Base58Type prefix)
{
    CExtKey58 eKey58;
    CExtKeyPair ekp;
    CBitcoinAddress addr;

    if (addr.SetString(sInKey)
        && addr.IsValid(prefix)
        && addr.GetKeyID(keyId, prefix)) {
        // keyId is set
    } else
    if (eKey58.Set58(sInKey.c_str()) == 0) {
        ekp = eKey58.GetKey();
        keyId = ekp.GetID();
    } else {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid key.");
    }

    return 0;
};

static OutputTypes WordToType(const std::string &s, bool allow_data=false)
{
    const std::string ls = ToLower(s);
    if (ls == "part" || ls == "plain" || ls == "standard") {
        return OUTPUT_STANDARD;
    }
    if (ls == "blind") {
        return OUTPUT_CT;
    }
    if (ls == "anon") {
        return OUTPUT_RINGCT;
    }
    if (allow_data && ls == "data") {
        return OUTPUT_DATA;
    }
    return OUTPUT_NULL;
};

static void ParseSecretKey(const std::string &s, CKey &key)
{
    if (IsHex(s) && (s.size() == 64)) {
        // LE
        uint256 tmp;
        tmp.SetHex(s);
        key.Set(tmp.begin(), true);
    } else {
        key = DecodeSecret(s);
    }
}

void ParseCoinControlOptions(const UniValue &obj, CHDWallet *pwallet, CCoinControl &coin_control)
{
    std::string sChangeAddress;
    if (obj.exists("changeaddress")) {
        sChangeAddress = obj["changeaddress"].get_str();
    } else
    if (obj.exists("changeAddress")) {
        sChangeAddress = obj["changeAddress"].get_str();
    } else
    if (obj.exists("change_address")) {
        sChangeAddress = obj["change_address"].get_str();
    }

    if (sChangeAddress.size() > 0) {
        if (obj.exists("changepubkey")) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Can't set changepubkey and changeaddress");
        }
        // Check for script
        bool fHaveScript = false;
        if (IsHex(sChangeAddress)) {
            std::vector<uint8_t> vScript = ParseHex(sChangeAddress);
            CScript script(vScript.begin(), vScript.end());

            TxoutType whichType;
            if (IsStandard(script, whichType)) {
                coin_control.scriptChange = script;
                fHaveScript = true;
            }
        }

        if (!fHaveScript) {
            CTxDestination dest = DecodeDestination(sChangeAddress);
            if (!IsValidDestination(dest)) {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "changeAddress must be a valid particl address");
            }
            coin_control.destChange = dest;
        }
    } else
    if (obj.exists("changepubkey")) {
        std::string s = obj["changepubkey"].get_str();
        if (!IsHex(s) || !(s.size() == 66)) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Public key must be 33 bytes and hex encoded.");
        }
        std::vector<uint8_t> v = ParseHex(s);
        coin_control.m_changepubkey = CPubKey(v.begin(), v.end());
    }

    const UniValue &uvInputs = obj["inputs"];
    if (uvInputs.isArray()) {
        for (size_t i = 0; i < uvInputs.size(); ++i) {
            const UniValue &uvi = uvInputs[i];
            RPCTypeCheckObj(uvi,
            {
                {"tx", UniValueType(UniValue::VSTR)},
                {"n", UniValueType(UniValue::VNUM)},
            });

            COutPoint op(ParseHashO(uvi, "tx"), uvi["n"].get_int());
            coin_control.setSelected.insert(op);

            bool have_attribute = false;
            CInputData im;
            if (uvi["blind"].isStr()) {
                std::string s = uvi["blind"].get_str();
                if (!IsHex(s) || !(s.size() == 64)) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "Blinding factor must be 32 bytes and hex encoded.");
                }
                im.blind.SetHex(s);
                have_attribute = true;
            }
            if (!uvi["value"].isNull()) {
                im.nValue = AmountFromValue(uvi["value"]);
                have_attribute = true;
            }
            if (uvi["type"].isStr()) {
                std::string s = uvi["type"].get_str();
                im.nType = WordToType(s);
                if (im.nType == OUTPUT_NULL) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "Unknown input type.");
                }
                have_attribute = true;
            }
            if (uvi["commitment"].isStr()) {
                std::string s = uvi["commitment"].get_str();
                if (!IsHex(s) || !(s.size() == 66)) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "Commitment must be 33 bytes and hex encoded.");
                }
                std::vector<uint8_t> v = ParseHex(s);
                memcpy(im.commitment.data, v.data(), 33);
                have_attribute = true;
            }
            if (uvi["pubkey"].isStr()) {
                std::string s = uvi["pubkey"].get_str();
                if (!IsHex(s) || !(s.size() == 66)) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "Public key must be 33 bytes and hex encoded.");
                }
                std::vector<uint8_t> v = ParseHex(s);
                im.pubkey = CCmpPubKey(v.begin(), v.end());
                have_attribute = true;
            }
            if (uvi["privkey"].isStr()) {
                std::string s = uvi["privkey"].get_str();
                ParseSecretKey(s, im.privkey);
                if (!im.privkey.IsValid()) {
                    throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid secret key");
                }
                have_attribute = true;
            }

            if (have_attribute) {
                coin_control.m_inputData[op] = im;
            }
        }
    } else
    if (!uvInputs.isNull()) {
        throw JSONRPCError(RPC_TYPE_ERROR, "coin_control inputs must be an array");
    }

    if (obj.exists("feeRate") && obj.exists("estimate_mode")) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Cannot specify both estimate_mode and feeRate");
    }
    if (obj.exists("feeRate") && obj.exists("conf_target")) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Cannot specify both conf_target and feeRate");
    }

    if (obj.exists("replaceable")) {
        if (!obj["replaceable"].isBool())
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Replaceable parameter must be boolean.");
        coin_control.m_signal_bip125_rbf = obj["replaceable"].get_bool();
    }

    if (obj.exists("conf_target")) {
        if (!obj["conf_target"].isNum())
            throw JSONRPCError(RPC_INVALID_PARAMETER, "conf_target parameter must be numeric.");
        coin_control.m_confirm_target = ParseConfirmTarget(obj["conf_target"], pwallet->chain().estimateMaxBlocks());
    }

    if (obj.exists("estimate_mode")) {
        if (!obj["estimate_mode"].isStr())
            throw JSONRPCError(RPC_INVALID_PARAMETER, "estimate_mode parameter must be a string.");
        if (!FeeModeFromString(obj["estimate_mode"].get_str(), coin_control.m_fee_mode))
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid estimate_mode parameter");
    }

    if (obj.exists("feeRate")) {
        coin_control.m_feerate = CFeeRate(AmountFromValue(obj["feeRate"]));
        coin_control.fOverrideFeeRate = true;
    }

    if (obj.exists("includeWatching")) {
        coin_control.fAllowWatchOnly = obj["includeWatching"].get_bool();
    }
    if (obj.exists("minimumAmount")) {
        coin_control.m_minimum_output_amount = AmountFromValue(obj["minimumAmount"]);
    }
    if (obj.exists("maximumAmount")) {
        coin_control.m_maximum_output_amount = AmountFromValue(obj["maximumAmount"]);
    }

    coin_control.m_avoid_address_reuse = GetAvoidReuseFlag(*pwallet, obj["avoid_reuse"]);
};

static RPCHelpMan extkey()
{
    return RPCHelpMan{"extkey",
            "\nManage extended keys.\n"
            "extkey info \"key\" ( \"path\" )\n"
        "    Return info for provided \"key\" or key at \"path\" from \"key\".\n"
        "extkey list ( show_secrets )\n"
        "    List loose and account ext keys.\n"
        "extkey account ( \"key/id\" show_secrets )\n"
        "    Display details of account.\n"
        "    Show default account when called without parameters or \"key/id\" = \"default\".\n"
        "extkey key \"key/id\" ( show_secrets )\n"
        "    Display details of loose extkey in wallet.\n"
        "extkey import \"key\" ( \"label\" bip44 save_bip44_key )\n"
        "    Add loose key to wallet.\n"
        "    If bip44 is set import will add the key derived from <key> on the bip44 path.\n"
        "    If save_bip44_key is set import will save the bip44 key to the wallet.\n"
        "extkey importAccount \"key\" ( time_scan_from \"label\" ) \n"
        "    Add account key to wallet.\n"
        "        time_scan_from: N no check, Y-m-d date to start scanning the blockchain for owned txns.\n"
        "extkey setMaster \"key/id\"\n"
        "    Set a private ext key as current master key.\n"
        "    key can be a extkeyid or full key, but must be in the wallet.\n"
        "extkey setDefaultAccount \"id\"\n"
        "    Set an account as the default.\n"
        "extkey deriveAccount ( \"label\" \"path\" )\n"
        "    Make a new account from the current master key, save to wallet.\n"
        "extkey options \"key\" ( \"optionName\" \"newValue\" )\n"
        "    Manage keys and accounts.\n"
        "    Provide key argument only to list available options.\n" +
    HELP_REQUIRING_PASSPHRASE,
    {
        {"mode", RPCArg::Type::STR, RPCArg::Default{"list"}, "One of: info, list, account, import, importAccount, setMaster, setDefaultAccount, deriveAccount, options"},
        {"arg0", RPCArg::Type::STR, RPCArg::Optional::OMITTED_NAMED_ARG, ""},
        {"arg1", RPCArg::Type::STR, RPCArg::Optional::OMITTED_NAMED_ARG, ""},
        {"arg2", RPCArg::Type::STR, RPCArg::Optional::OMITTED_NAMED_ARG, ""},
        {"arg3", RPCArg::Type::STR, RPCArg::Optional::OMITTED_NAMED_ARG, ""},
    },
    RPCResult{RPCResult::Type::ANY, "", ""},
    RPCExamples{""},
    [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    // default mode is list unless 1st parameter is a key - then mode is set to info

    // path:
    // master keys are hashed with an integer (child_index) to form child keys
    // each child key can spawn more keys
    // payments etc are not send to keys derived from the master keys
    //  m - master key
    //  m/0 - key0 (1st) key derived from m
    //  m/1/2 key2 (3rd) key derived from key1 derived from m

    // hardened keys are keys with (child_index) > 2^31
    // it's not possible to compute the next extended public key in the sequence from a hardened public key (still possible with a hardened private key)

    // this maintains privacy, you can give hardened public keys to customers
    // and they will not be able to compute/guess the key you give out to other customers
    // but will still be able to send payments to you on the 2^32 keys derived from the public key you provided


    // accounts to receive must be non-hardened
    //   - locked wallets must be able to derive new keys as they receive
    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
    if (!wallet) return NullUniValue;
    CHDWallet *const pwallet = GetParticlWallet(wallet.get());

    EnsureWalletIsUnlocked(pwallet);

    std::string mode = "list";
    std::string sInKey = "";

    uint32_t nParamOffset = 0;
    if (request.params.size() > 0) {
        std::string s = request.params[0].get_str();
        std::string st = " " + s + " "; // Requires the spaces
        st = ToLower(st);
        static const char *pmodes = " info list account key import importaccount setmaster setdefaultaccount deriveaccount options ";
        if (strstr(pmodes, st.c_str()) != nullptr) {
            st.erase(std::remove(st.begin(), st.end(), ' '), st.end());
            mode = st;
            nParamOffset = 1;
        } else {
            sInKey = s;
            mode = "info";
            nParamOffset = 1;
        }
    }

    CBitcoinExtKey bvk;
    CBitcoinExtPubKey bpk;
    std::vector<uint8_t> vchVersionIn(4);

    UniValue result(UniValue::VOBJ);

    if (mode == "info") {
        std::string sMode = "info"; // info lists details of bip32 key, m displays internal key

        if (sInKey.length() == 0) {
            if (request.params.size() > nParamOffset) {
                sInKey = request.params[nParamOffset].get_str();
                nParamOffset++;
            }
        }

        if (request.params.size() > nParamOffset) {
            sMode = request.params[nParamOffset].get_str();
        }

        UniValue keyInfo(UniValue::VOBJ);
        std::vector<uint8_t> vchOut;

        if (!DecodeBase58(sInKey.c_str(), vchOut, BIP32_KEY_LEN)) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "DecodeBase58 failed.");
        }
        if (!VerifyChecksum(vchOut)) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "VerifyChecksum failed.");
        }

        size_t keyLen = vchOut.size();
        std::string sError;

        if (keyLen != BIP32_KEY_LEN) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, strprintf("Unknown ext key length '%d'", keyLen));
        }

        if (memcmp(&vchOut[0], &Params().Base58Prefix(CChainParams::EXT_SECRET_KEY)[0], 4) == 0
            || memcmp(&vchOut[0], &Params().Base58Prefix(CChainParams::EXT_SECRET_KEY_BTC)[0], 4) == 0) {
            if (ExtKeyPathV(sMode, vchOut, keyInfo, sError) != 0) {
                throw JSONRPCError(RPC_MISC_ERROR, strprintf("ExtKeyPathV failed %s.", sError.c_str()));
            }
        } else
        if (memcmp(&vchOut[0], &Params().Base58Prefix(CChainParams::EXT_PUBLIC_KEY)[0], 4) == 0
            || memcmp(&vchOut[0], &Params().Base58Prefix(CChainParams::EXT_PUBLIC_KEY_BTC)[0], 4) == 0) {
            if (ExtKeyPathP(sMode, vchOut, keyInfo, sError) != 0) {
                throw JSONRPCError(RPC_MISC_ERROR, strprintf("ExtKeyPathP failed %s.", sError.c_str()));
            }
        } else {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, strprintf("Unknown prefix '%s'", sInKey.substr(0, 4)));
        }

        result.pushKV("key_info", keyInfo);
    } else
    if (mode == "list") {
        UniValue ret(UniValue::VARR);

        int nListFull = 0; // 0 id only, 1 id+pubkey, 2 id+pubkey+secret
        if (request.params.size() > nParamOffset) {
            if (GetBool(request.params[nParamOffset])) {
                nListFull = 2;
            }
            nParamOffset++;
        }

        size_t nKeys = 0, nAcc = 0;

        {
            LOCK(pwallet->cs_wallet);
            ListLooseExtKeys(pwallet, nListFull, ret, nKeys);
            ListAccountExtKeys(pwallet, nListFull, ret, nAcc);
        } // cs_wallet

        if (nKeys + nAcc > 0) {
            return ret;
        }

        result.pushKV("result", "No keys to list.");
    } else
    if (mode == "account"
        || mode == "key") {
        CKeyID keyId;
        if (request.params.size() > nParamOffset) {
            sInKey = request.params[nParamOffset].get_str();
            nParamOffset++;

            if (mode == "account" && sInKey == "default") {
                keyId = pwallet->idDefaultAccount;
            } else {
                ExtractExtKeyId(sInKey, keyId, mode == "account" ? CChainParams::EXT_ACC_HASH : CChainParams::EXT_KEY_HASH);
            }
        } else {
            if (mode == "account") {
                // Display default account
                keyId = pwallet->idDefaultAccount;
            }
        }

        if (keyId.IsNull()) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("Must specify ext key or id %s.", mode == "account" ? "or 'default'" : ""));
        }

        int nListFull = 0; // 0 id only, 1 id+pubkey, 2 id+pubkey+secret
        if (request.params.size() > nParamOffset) {
            if (GetBool(request.params[nParamOffset])) {
                nListFull = 2;
            }
            nParamOffset++;
        }

        std::string sError;
        if (mode == "account") {
            if (0 != AccountInfo(pwallet, keyId, nListFull, true, result, sError)) {
                throw JSONRPCError(RPC_MISC_ERROR, "AccountInfo failed: " + sError);
            }
        } else {
            CKeyID idMaster;
            if (pwallet->pEKMaster) {
                idMaster = pwallet->pEKMaster->GetID();
            } else {
                LogPrintf("%s: Warning: Master key isn't set!\n", __func__);
            }
            if (0 != KeyInfo(pwallet, idMaster, keyId, nListFull, result, sError)) {
                throw JSONRPCError(RPC_MISC_ERROR, "KeyInfo failed: " + sError);
            }
        }
    } else
    if (mode == "import") {
        if (sInKey.length() == 0) {
            if (request.params.size() > nParamOffset) {
                sInKey = request.params[nParamOffset].get_str();
                nParamOffset++;
            }
        }

        CStoredExtKey sek;
        if (request.params.size() > nParamOffset) {
            sek.sLabel = request.params[nParamOffset].get_str();
            nParamOffset++;
        }

        bool fBip44 = false;
        if (request.params.size() > nParamOffset) {
            fBip44 = GetBool(request.params[nParamOffset]);
            nParamOffset++;
        }

        bool fSaveBip44 = false;
        if (request.params.size() > nParamOffset) {
            fSaveBip44 = GetBool(request.params[nParamOffset]);
            nParamOffset++;
        }

        std::vector<uint8_t> v;
        sek.mapValue[EKVT_CREATED_AT] = SetCompressedInt64(v, GetTime());

        CExtKey58 eKey58;
        if (eKey58.Set58(sInKey.c_str()) != 0) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Import failed - Invalid key.");
        }

        if (pwallet->IsWalletFlagSet(WALLET_FLAG_DISABLE_PRIVATE_KEYS)
            && (eKey58.IsValid(CChainParams::EXT_SECRET_KEY_BTC) || eKey58.IsValid(CChainParams::EXT_SECRET_KEY))) {
            throw JSONRPCError(RPC_WALLET_ERROR, "Error: Private keys are disabled for this wallet");
        }

        if (fBip44) {
            if (!eKey58.IsValid(CChainParams::EXT_SECRET_KEY_BTC)) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Import failed - BIP44 key must begin with a bitcoin secret key prefix.");
            }
        } else {
            if (!eKey58.IsValid(CChainParams::EXT_SECRET_KEY)
                && !eKey58.IsValid(CChainParams::EXT_PUBLIC_KEY_BTC)
                && !eKey58.IsValid(CChainParams::EXT_PUBLIC_KEY)) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Import failed - Key must begin with a particl prefix.");
            }
        }

        sek.kp = eKey58.GetKey();

        {
            LOCK(pwallet->cs_wallet);
            CHDWalletDB wdb(pwallet->GetDatabase());
            if (!wdb.TxnBegin()) {
                throw JSONRPCError(RPC_MISC_ERROR, "TxnBegin failed.");
            }

            int rv;
            CKeyID idDerived;
            if (0 != (rv = pwallet->ExtKeyImportLoose(&wdb, sek, idDerived, fBip44, fSaveBip44))) {
                wdb.TxnAbort();
                throw JSONRPCError(RPC_MISC_ERROR, strprintf("ExtKeyImportLoose failed, %s", ExtKeyGetString(rv)));
            }

            if (!wdb.TxnCommit()) {
                throw JSONRPCError(RPC_MISC_ERROR, "TxnCommit failed.");
            }

            CBitcoinAddress addr;
            addr.Set(fBip44 ? idDerived : sek.GetID(), CChainParams::EXT_KEY_HASH);
            result.pushKV("result", "Success.");
            result.pushKV("id", addr.ToString());
            result.pushKV("key_label", sek.sLabel);
            result.pushKV("note", "Please backup your wallet."); // TODO: check for child of existing key?
        } // cs_wallet
    } else
    if (mode == "importaccount") {
        if (sInKey.length() == 0) {
            if (request.params.size() > nParamOffset) {
                sInKey = request.params[nParamOffset].get_str();
                nParamOffset++;
            }
        }

        int64_t nTimeStartScan = 1; // Scan from start, 0 means no scan
        if (request.params.size() > nParamOffset) {
            std::string sVar = request.params[nParamOffset].get_str();
            nParamOffset++;

            if (sVar == "N") {
                nTimeStartScan = 0;
            } else
            if (part::IsStrOnlyDigits(sVar)) {
                // Setting timestamp directly
                if (sVar.length() && !ParseInt64(sVar, &nTimeStartScan)) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "Import Account failed - Parse time error.");
                }
            } else {
                int year, month, day;

                if (sscanf(sVar.c_str(), "%d-%d-%d", &year, &month, &day) != 3) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "Import Account failed - Parse time error.");
                }

                struct tm tmdate;
                memset(&tmdate, 0, sizeof(tmdate));
                tmdate.tm_year = year - 1900;
                tmdate.tm_mon = month - 1;
                tmdate.tm_mday = day;
                time_t t = mktime(&tmdate);

                nTimeStartScan = t;
            }
        }

        int64_t nCreatedAt = nTimeStartScan ? nTimeStartScan : GetTime();

        std::string sLabel;
        if (request.params.size() > nParamOffset) {
            sLabel = request.params[nParamOffset].get_str();
            nParamOffset++;
        }

        CStoredExtKey sek;
        CExtKey58 eKey58;
        if (eKey58.Set58(sInKey.c_str()) == 0)  {
            sek.kp = eKey58.GetKey();
        } else {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Import Account failed - Invalid key.");
        }

        if (pwallet->IsWalletFlagSet(WALLET_FLAG_DISABLE_PRIVATE_KEYS)
            && (eKey58.IsValid(CChainParams::EXT_SECRET_KEY_BTC) || eKey58.IsValid(CChainParams::EXT_SECRET_KEY))) {
            throw JSONRPCError(RPC_WALLET_ERROR, "Error: Private keys are disabled for this wallet");
        }

        {
            WalletRescanReserver reserver(*pwallet);
            if (!reserver.reserve()) {
                throw JSONRPCError(RPC_WALLET_ERROR, "Wallet is currently rescanning. Abort existing rescan or wait.");
            }

            LOCK(pwallet->cs_wallet);
            CHDWalletDB wdb(pwallet->GetDatabase());
            if (!wdb.TxnBegin()) {
                throw JSONRPCError(RPC_MISC_ERROR, "TxnBegin failed.");
            }

            int rv = pwallet->ExtKeyImportAccount(&wdb, sek, nCreatedAt, sLabel);
            if (rv == 1) {
                wdb.TxnAbort();
                throw JSONRPCError(RPC_WALLET_ERROR, "Import failed - ExtKeyImportAccount failed.");
            } else
            if (rv == 2) {
                wdb.TxnAbort();
                throw JSONRPCError(RPC_WALLET_ERROR, "Import failed - account exists.");
            } else {
                if (!wdb.TxnCommit()) {
                    throw JSONRPCError(RPC_MISC_ERROR, "TxnCommit failed.");
                }
                result.pushKV("result", "Success.");

                if (rv == 3) {
                    result.pushKV("result", "secret added to existing account.");
                }

                result.pushKV("account_id", HDAccIDToString(sek.GetID()));
                result.pushKV("has_secret", sek.kp.IsValidV() ? "true" : "false");
                result.pushKV("account_label", sLabel);
                result.pushKV("account_label", sLabel);
                result.pushKV("scanned_from", nTimeStartScan);
                result.pushKV("note", "Please backup your wallet."); // TODO: check for child of existing key?
            }

            pwallet->RescanFromTime(nTimeStartScan, reserver, true /* update */);
            pwallet->MarkDirty();
            pwallet->ReacceptWalletTransactions();

        } // cs_wallet
    } else
    if (mode == "setmaster") {
        if (sInKey.length() == 0) {
            if (request.params.size() > nParamOffset) {
                sInKey = request.params[nParamOffset].get_str();
                nParamOffset++;
            } else {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Must specify ext key or id.");
            }
        }

        CKeyID idNewMaster;
        ExtractExtKeyId(sInKey, idNewMaster, CChainParams::EXT_KEY_HASH);

        {
            LOCK(pwallet->cs_wallet);
            CHDWalletDB wdb(pwallet->GetDatabase());
            if (!wdb.TxnBegin()) {
                throw JSONRPCError(RPC_MISC_ERROR, "TxnBegin failed.");
            }

            int rv;
            if (0 != (rv = pwallet->ExtKeySetMaster(&wdb, idNewMaster))) {
                wdb.TxnAbort();
                throw JSONRPCError(RPC_WALLET_ERROR, strprintf("ExtKeySetMaster failed, %s.", ExtKeyGetString(rv)));
            }
            if (!wdb.TxnCommit()) {
                throw JSONRPCError(RPC_MISC_ERROR, "TxnCommit failed.");
            }
            result.pushKV("result", "Success.");
        } // cs_wallet

    } else
    if (mode == "setdefaultaccount") {
        if (sInKey.length() == 0) {
            if (request.params.size() > nParamOffset) {
                sInKey = request.params[nParamOffset].get_str();
                nParamOffset++;
            } else {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Must specify ext key or id.");
            }
        }

        CKeyID idNewDefault;
        CKeyID idOldDefault = pwallet->idDefaultAccount;
        CBitcoinAddress addr;

        if (addr.SetString(sInKey)
            && addr.IsValid(CChainParams::EXT_ACC_HASH)
            && addr.GetKeyID(idNewDefault, CChainParams::EXT_ACC_HASH)) {
            // idNewDefault is set
        }

        int rv;
        {
            LOCK(pwallet->cs_wallet);
            CHDWalletDB wdb(pwallet->GetDatabase());

            if (!wdb.TxnBegin()) {
                throw JSONRPCError(RPC_MISC_ERROR, "TxnBegin failed.");
            }

            if (0 != (rv = pwallet->ExtKeySetDefaultAccount(&wdb, idNewDefault))) {
                wdb.TxnAbort();
                throw JSONRPCError(RPC_WALLET_ERROR, strprintf("ExtKeySetDefaultAccount failed, %s.", ExtKeyGetString(rv)));
            }

            if (!wdb.TxnCommit()) {
                pwallet->idDefaultAccount = idOldDefault;
                throw JSONRPCError(RPC_MISC_ERROR, "TxnCommit failed.");
            }

            result.pushKV("result", "Success.");
        } // cs_wallet

    } else
    if (mode == "deriveaccount") {
        std::string sLabel, sPath;
        if (request.params.size() > nParamOffset) {
            sLabel = request.params[nParamOffset].get_str();
            nParamOffset++;
        }

        if (request.params.size() > nParamOffset) {
            sPath = request.params[nParamOffset].get_str();
            nParamOffset++;
        }

        if (nParamOffset < request.params.size()) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("Unknown parameter '%s'", request.params[nParamOffset].get_str().c_str()));
        }

        CExtKeyAccount *sea = new CExtKeyAccount();

        {
            LOCK(pwallet->cs_wallet);
            CHDWalletDB wdb(pwallet->GetDatabase());
            if (!wdb.TxnBegin()) {
                delete sea;
                throw JSONRPCError(RPC_MISC_ERROR, "TxnBegin failed.");
            }

            int rv;
            if ((rv = pwallet->ExtKeyDeriveNewAccount(&wdb, sea, sLabel, sPath)) != 0) {
                delete sea;
                wdb.TxnAbort();
                result.pushKV("result", "Failed.");
                result.pushKV("reason", ExtKeyGetString(rv));
            } else {
                if (!wdb.TxnCommit()) {
                    delete sea;
                    throw JSONRPCError(RPC_MISC_ERROR, "TxnCommit failed.");
                }

                result.pushKV("result", "Success.");
                result.pushKV("account", sea->GetIDString58());
                CStoredExtKey *sekAccount = sea->ChainAccount();
                if (sekAccount) {
                    CExtKey58 eKey58;
                    eKey58.SetKeyP(sekAccount->kp);
                    result.pushKV("public key", eKey58.ToString());
                }

                if (sLabel != "") {
                    result.pushKV("label", sLabel);
                }
            }
        } // cs_wallet
    } else
    if (mode == "options") {
        std::string sOptName, sOptValue, sError;
        if (sInKey.length() == 0) {
            if (request.params.size() > nParamOffset) {
                sInKey = request.params[nParamOffset].get_str();
                nParamOffset++;
            } else {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Must specify ext key or id.");
            }
        }

        if (request.params.size() > nParamOffset) {
            sOptName = request.params[nParamOffset].get_str();
            nParamOffset++;
        }

        if (request.params.size() > nParamOffset) {
            sOptValue = request.params[nParamOffset].get_str();
            nParamOffset++;
        }

        CBitcoinAddress addr;

        CKeyID id;
        if (!addr.SetString(sInKey)) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid key or account id.");
        }

        bool fAccount = false;
        bool fKey = false;
        if (addr.IsValid(CChainParams::EXT_KEY_HASH)
            && addr.GetKeyID(id, CChainParams::EXT_KEY_HASH)) {
            // id is set
            fKey = true;
        } else
        if (addr.IsValid(CChainParams::EXT_ACC_HASH)
            && addr.GetKeyID(id, CChainParams::EXT_ACC_HASH)) {
            // id is set
            fAccount = true;
        } else
        if (addr.IsValid(CChainParams::EXT_PUBLIC_KEY)) {
            CExtPubKey ek = std::get<CExtPubKey>(addr.Get());

            id = ek.GetID();

            ExtKeyAccountMap::iterator it = pwallet->mapExtAccounts.find(id);
            if (it != pwallet->mapExtAccounts.end()) {
                fAccount = true;
            } else {
                fKey = true;
            }
        } else {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid key or account id.");
        }

        CStoredExtKey sek;
        CExtKeyAccount sea;
        {
            LOCK(pwallet->cs_wallet);
            CHDWalletDB wdb(pwallet->GetDatabase());
            if (!wdb.TxnBegin()) {
                throw JSONRPCError(RPC_MISC_ERROR, "TxnBegin failed.");
            }

            if (fKey) {
                // Try key in memory first
                CStoredExtKey *pSek;
                ExtKeyMap::iterator it = pwallet->mapExtKeys.find(id);
                if (it != pwallet->mapExtKeys.end()) {
                    pSek = it->second;
                } else
                if (wdb.ReadExtKey(id, sek)) {
                    pSek = &sek;
                } else {
                    wdb.TxnAbort();
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "Key not in wallet.");
                }

                if (0 != ManageExtKey(*pSek, sOptName, sOptValue, result, sError)) {
                    wdb.TxnAbort();
                    throw std::runtime_error("Error: " + sError);
                }

                if (sOptValue.length() > 0
                    && !wdb.WriteExtKey(id, *pSek)) {
                    wdb.TxnAbort();
                    throw JSONRPCError(RPC_MISC_ERROR, "WriteExtKey failed.");
                }
                pwallet->ExtKeyReload(pSek);
            }

            if (fAccount) {
                CExtKeyAccount *pSea;
                ExtKeyAccountMap::iterator it = pwallet->mapExtAccounts.find(id);
                if (it != pwallet->mapExtAccounts.end()) {
                    pSea = it->second;
                } else
                if (wdb.ReadExtAccount(id, sea)) {
                    pSea = &sea;
                } else {
                    wdb.TxnAbort();
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "Account not in wallet.");
                }

                if (0 != ManageExtAccount(*pSea, sOptName, sOptValue, result, sError)) {
                    wdb.TxnAbort();
                    throw std::runtime_error("Error: " + sError);
                }

                if (sOptValue.length() > 0
                    && !wdb.WriteExtAccount(id, *pSea)) {
                    wdb.TxnAbort();
                    throw JSONRPCError(RPC_WALLET_ERROR,"WriteExtAccount failed.");
                }
            }

            if (sOptValue.length() == 0) {
                wdb.TxnAbort();
            } else {
                if (!wdb.TxnCommit()) {
                    throw JSONRPCError(RPC_MISC_ERROR, "TxnCommit failed.");
                }
                result.pushKV("result", "Success.");
            }
        } // cs_wallet

    } else {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Unknown mode.");
    }

    return result;
},
    };
};

static UniValue extkeyimportinternal(const JSONRPCRequest &request, bool fGenesisChain)
{
    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
    if (!wallet) return NullUniValue;
    CHDWallet *const pwallet = GetParticlWallet(wallet.get());

    EnsureWalletIsUnlocked(pwallet);

    if (pwallet->IsWalletFlagSet(WALLET_FLAG_DISABLE_PRIVATE_KEYS)) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Error: Private keys are disabled for this wallet");
    }

    if (request.params.size() < 1) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Please specify a private extkey or mnemonic phrase.");
    }

    std::string sMnemonic = request.params[0].get_str();

    std::string sLblMaster = "Master Key";
    std::string sLblAccount = "Default Account";
    std::string sPassphrase = "";
    std::string sError;
    int64_t nScanFrom = 1;
    int create_extkeys = 0;

    if (request.params.size() > 1) {
        sPassphrase = request.params[1].get_str();
    }
    bool fSaveBip44Root = request.params.size() > 2 ? GetBool(request.params[2]) : false;
    if (request.params.size() > 3) {
        sLblMaster = request.params[3].get_str();
    }
    if (request.params.size() > 4) {
        sLblAccount = request.params[4].get_str();
    }

    if (request.params[5].isStr()) {
        std::string s = request.params[5].get_str();
        if (s.length() && !ParseInt64(s, &nScanFrom)) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("Unknown argument for scan_chain_from: %s.", s.c_str()));
        }
    } else
    if (request.params[5].isNum()) {
        nScanFrom = request.params[5].get_int64();
    }
    if (!request.params[6].isNull()) {
        LOCK(pwallet->cs_wallet);
        const UniValue &options = request.params[6].get_obj();

        RPCTypeCheckObj(options,
            {
                {"createextkeys", UniValueType(UniValue::VNUM)},
                {"lookaheadsize", UniValueType(UniValue::VNUM)},
                {"stealthv1lookaheadsize", UniValueType(UniValue::VNUM)},
                {"stealthv2lookaheadsize", UniValueType(UniValue::VNUM)},
            },
            true, true);

        if (options.exists("createextkeys")) {
            create_extkeys = options["createextkeys"].get_int();
            if (create_extkeys < 0) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "createextkeys must be positive.");
            }
        }
        if (options.exists("lookaheadsize")) {
            int override_lookaheadsize = options["lookaheadsize"].get_int();
            if (override_lookaheadsize < 0) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "lookaheadsize must be positive.");
            }
            pwallet->m_default_lookahead = override_lookaheadsize;
            pwallet->PrepareLookahead();
        }
        if (options.exists("stealthv1lookaheadsize")) {
            int override_stealthv1lookaheadsize = options["stealthv1lookaheadsize"].get_int();
            if (override_stealthv1lookaheadsize < 0) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "stealthv1lookaheadsize must be positive.");
            }
            pwallet->m_rescan_stealth_v1_lookahead = override_stealthv1lookaheadsize;
        }
        if (options.exists("stealthv2lookaheadsize")) {
            int override_stealthv2lookaheadsize = options["stealthv2lookaheadsize"].get_int();
            if (override_stealthv2lookaheadsize < 0) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "stealthv2lookaheadsize must be positive.");
            }
            pwallet->m_rescan_stealth_v2_lookahead = override_stealthv2lookaheadsize;
        }
    }
    if (request.params.size() > 7) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("Unknown parameter '%s'", request.params[6].get_str()));
    }

    LogPrintf("%s Importing master key and account with labels '%s', '%s'.\n", pwallet->GetDisplayName(), sLblMaster.c_str(), sLblAccount.c_str());

    WalletRescanReserver reserver(*pwallet);
    if (!reserver.reserve()) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Wallet is currently rescanning. Abort existing rescan or wait.");
    }

    CExtKey58 eKey58;
    CExtKeyPair ekp;
    if (eKey58.Set58(sMnemonic.c_str()) == 0) {
        if (!eKey58.IsValid(CChainParams::EXT_SECRET_KEY)
            && !eKey58.IsValid(CChainParams::EXT_SECRET_KEY_BTC)) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Please specify a private extkey or mnemonic phrase.");
        }

        // Key was provided directly
        ekp = eKey58.GetKey();
    } else {
        std::vector<uint8_t> vSeed, vEntropy;

        // First check the mnemonic is valid
        int nLanguage = -1;
        if (0 != mnemonic::Decode(nLanguage, sMnemonic, vEntropy, sError)) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("MnemonicDecode failed: %s", sError.c_str()));
        }
        if (0 != mnemonic::ToSeed(sMnemonic, sPassphrase, vSeed)) {
            throw JSONRPCError(RPC_MISC_ERROR, "MnemonicToSeed failed.");
        }

        ekp.SetSeed(&vSeed[0], vSeed.size());
    }

    CStoredExtKey sek;
    sek.sLabel = sLblMaster;

    std::vector<uint8_t> v;
    sek.mapValue[EKVT_CREATED_AT] = SetCompressedInt64(v, GetTime());
    sek.kp = ekp;

    UniValue result(UniValue::VOBJ);

    int rv;
    bool fBip44 = true;
    CKeyID idDerived;
    CExtKeyAccount *sea;

    {
        LOCK(pwallet->cs_wallet);
        CHDWalletDB wdb(pwallet->GetDatabase());
        if (!wdb.TxnBegin()) {
            throw JSONRPCError(RPC_MISC_ERROR, "TxnBegin failed.");
        }

        if (0 != (rv = pwallet->ExtKeyImportLoose(&wdb, sek, idDerived, fBip44, fSaveBip44Root))) {
            wdb.TxnAbort();
            throw JSONRPCError(RPC_WALLET_ERROR, strprintf("ExtKeyImportLoose failed, %s", ExtKeyGetString(rv)));
        }

        if (0 != (rv = pwallet->ExtKeySetMaster(&wdb, idDerived))) {
            wdb.TxnAbort();
            throw JSONRPCError(RPC_WALLET_ERROR, strprintf("ExtKeySetMaster failed, %s.", ExtKeyGetString(rv)));
        }

        sea = new CExtKeyAccount();
        if (0 != (rv = pwallet->ExtKeyDeriveNewAccount(&wdb, sea, sLblAccount))) {
            pwallet->ExtKeyRemoveAccountFromMapsAndFree(sea);
            wdb.TxnAbort();
            throw JSONRPCError(RPC_WALLET_ERROR, strprintf("ExtKeyDeriveNewAccount failed, %s.", ExtKeyGetString(rv)));
        }

        CKeyID idNewDefaultAccount = sea->GetID();
        CKeyID idOldDefault = pwallet->idDefaultAccount;

        if (0 != (rv = pwallet->ExtKeySetDefaultAccount(&wdb, idNewDefaultAccount))) {
            pwallet->ExtKeyRemoveAccountFromMapsAndFree(sea);
            wdb.TxnAbort();
            throw JSONRPCError(RPC_WALLET_ERROR, strprintf("ExtKeySetDefaultAccount failed, %s.", ExtKeyGetString(rv)));
        }

        if (fGenesisChain) {
            std::string genesisChainLabel = "Genesis Import";
            CStoredExtKey *sekGenesisChain = new CStoredExtKey();

            if (0 != (rv = pwallet->NewExtKeyFromAccount(&wdb, idNewDefaultAccount,
                genesisChainLabel, sekGenesisChain, nullptr, &CHAIN_NO_GENESIS))) {
                delete sekGenesisChain;
                pwallet->ExtKeyRemoveAccountFromMapsAndFree(sea);
                wdb.TxnAbort();
                throw JSONRPCError(RPC_WALLET_ERROR, strprintf("NewExtKeyFromAccount failed, %s.", ExtKeyGetString(rv)));
            }
        }

        if (!wdb.TxnCommit()) {
            pwallet->idDefaultAccount = idOldDefault;
            pwallet->ExtKeyRemoveAccountFromMapsAndFree(sea);
            throw JSONRPCError(RPC_MISC_ERROR, "TxnCommit failed.");
        }
    } // cs_wallet

    for (int k = 0; k < create_extkeys; ++k) {
        CStoredExtKey *sek = new CStoredExtKey();
        std::string str_label = "Imported";
        const char *plabel = str_label.c_str();
        if (0 != pwallet->NewExtKeyFromAccount(str_label, sek, plabel)) {
            delete sek;
            throw JSONRPCError(RPC_WALLET_ERROR, "NewExtKeyFromAccount failed.");
        }
    }

    if (nScanFrom >= 0) {
        pwallet->RescanFromTime(nScanFrom, reserver, true);
        pwallet->MarkDirty();
        LOCK(pwallet->cs_wallet);
        pwallet->ReacceptWalletTransactions();
    }

    // Reset to defaults
    {
        LOCK(pwallet->cs_wallet);
        pwallet->m_rescan_stealth_v1_lookahead = gArgs.GetArg("-stealthv1lookaheadsize", DEFAULT_STEALTH_LOOKAHEAD_SIZE);
        pwallet->m_rescan_stealth_v2_lookahead = gArgs.GetArg("-stealthv2lookaheadsize", DEFAULT_STEALTH_LOOKAHEAD_SIZE);

        pwallet->m_default_lookahead = gArgs.GetArg("-defaultlookaheadsize", DEFAULT_LOOKAHEAD_SIZE);
        pwallet->PrepareLookahead();
    }

    UniValue warnings(UniValue::VARR);
    // Check for coldstaking outputs without coldstakingaddress set
    if (pwallet->CountColdstakeOutputs() > 0) {
        UniValue jsonSettings;
        if (!pwallet->GetSetting("changeaddress", jsonSettings)
            || !jsonSettings["coldstakingaddress"].isStr()) {
            warnings.push_back("Wallet has coldstaking outputs. Please remember to set a coldstakingaddress.");
        }
    }

    CBitcoinAddress addr;
    addr.Set(idDerived, CChainParams::EXT_KEY_HASH);
    result.pushKV("result", "Success.");
    result.pushKV("master_id", addr.ToString());
    result.pushKV("master_label", sek.sLabel);

    result.pushKV("account_id", sea->GetIDString58());
    result.pushKV("account_label", sea->sLabel);

    result.pushKV("note", "Please backup your wallet.");

    if (warnings.size() > 0) {
        result.pushKV("warnings", warnings);
    }

    return result;
}

static RPCHelpMan extkeyimportmaster()
{
    // Doesn't generate key, require users to run mnemonic new, more likely they'll save the phrase
    return RPCHelpMan{"extkeyimportmaster",
                "\nImport master key from bip44 mnemonic root key and derive default account." +
                HELP_REQUIRING_PASSPHRASE,
                {
                    {"source", RPCArg::Type::STR, RPCArg::Optional::NO, "The mnemonic or root extended key.\n"
        "       Use '-stdin' to be prompted to enter a passphrase.\n"
        "       if mnemonic is blank, defaults to '-stdin'."},
                    {"passphrase", RPCArg::Type::STR, RPCArg::Default{""}, "Passphrase when importing mnemonic.\n"
        "       Use '-stdin' to be prompted to enter a passphrase."},
                    {"save_bip44_root", RPCArg::Type::BOOL, RPCArg::Default{false}, "Save bip44 root key to wallet."},
                    {"master_label", RPCArg::Type::STR, RPCArg::Default{"Master Key"}, "Label for master key."},
                    {"account_label", RPCArg::Type::STR, RPCArg::Default{"Default Account"}, "Label for account."},
                    {"scan_chain_from", RPCArg::Type::NUM, RPCArg::Default{0}, "Scan for transactions in blocks after timestamp, negative number to skip."},
                    {"options", RPCArg::Type::OBJ, RPCArg::Default{UniValue::VOBJ}, "",
                        {
                            {"createextkeys", RPCArg::Type::NUM, RPCArg::Default{0}, "Run getnewextaddress \"createextkeys\" times before rescanning the wallet."},
                            {"lookaheadsize", RPCArg::Type::NUM, RPCArg::Default{(int)DEFAULT_LOOKAHEAD_SIZE}, "Override the defaultlookaheadsize parameter."},
                            {"stealthv1lookaheadsize", RPCArg::Type::NUM, RPCArg::Default{(int)DEFAULT_STEALTH_LOOKAHEAD_SIZE}, "Override the stealthv1lookaheadsize parameter."},
                            {"stealthv2lookaheadsize", RPCArg::Type::NUM, RPCArg::Default{(int)DEFAULT_STEALTH_LOOKAHEAD_SIZE}, "Override the stealthv2lookaheadsize parameter."},
                        },
                        "options"},
                },
            RPCResult{
                RPCResult::Type::ANY, "", ""
            },
            RPCExamples{
        HelpExampleCli("extkeyimportmaster", "-stdin -stdin false \"label_master\" \"label_account\"")
        + HelpExampleCli("extkeyimportmaster", "\"word1 ... word24\" \"passphrase\" false \"label_master\" \"label_account\"") +
        "\nAs a JSON-RPC call\n"
        + HelpExampleRpc("extkeyimportmaster", "\"word1 ... word24\", \"passphrase\", false, \"label_master\", \"label_account\"")
            },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
    if (!wallet) return NullUniValue;

    return extkeyimportinternal(request, false);
},
    };
};

static RPCHelpMan extkeygenesisimport()
{
    return RPCHelpMan{"extkeygenesisimport",
                "\nImport master key from bip44 mnemonic root key and derive default account.\n"
                "Derives an extra chain from path 444444 to receive imported coin." +
                HELP_REQUIRING_PASSPHRASE,
                {
                    {"source", RPCArg::Type::STR, RPCArg::Optional::NO, "The mnemonic or root extended key.\n"
        "       Use '-stdin' to be prompted to enter a passphrase.\n"
        "       if mnemonic is blank, defaults to '-stdin'."},
                    {"passphrase", RPCArg::Type::STR, RPCArg::Default{""}, "Passphrase when importing mnemonic.\n"
        "       Use '-stdin' to be prompted to enter a passphrase."},
                    {"save_bip44_root", RPCArg::Type::BOOL, RPCArg::Default{false}, "Save bip44 root key to wallet."},
                    {"master_label", RPCArg::Type::STR, RPCArg::Default{"Master Key"}, "Label for master key."},
                    {"account_label", RPCArg::Type::STR, RPCArg::Default{"Default Account"}, "Label for account."},
                    {"scan_chain_from", RPCArg::Type::NUM, RPCArg::Default{0}, "Scan for transactions in blocks after timestamp, negative number to skip."},
                    {"options", RPCArg::Type::OBJ, RPCArg::Default{UniValue::VOBJ}, "",
                        {
                            {"createextkeys", RPCArg::Type::NUM, RPCArg::Default{0}, "Run getnewextaddress \"createextkeys\" times before rescanning the wallet."},
                            {"lookaheadsize", RPCArg::Type::NUM, RPCArg::Default{(int)DEFAULT_LOOKAHEAD_SIZE}, "Override the defaultlookaheadsize parameter."},
                            {"stealthv1lookaheadsize", RPCArg::Type::NUM, RPCArg::Default{(int)DEFAULT_STEALTH_LOOKAHEAD_SIZE}, "Override the stealthv1lookaheadsize parameter."},
                            {"stealthv2lookaheadsize", RPCArg::Type::NUM, RPCArg::Default{(int)DEFAULT_STEALTH_LOOKAHEAD_SIZE}, "Override the stealthv2lookaheadsize parameter."},
                        },
                        "options"},
                },
            RPCResult{
                RPCResult::Type::ANY, "", ""
            },
            RPCExamples{
        HelpExampleCli("extkeygenesisimport", "-stdin -stdin false \"label_master\" \"label_account\"")
        + HelpExampleCli("extkeygenesisimport", "\"word1 ... word24\" \"passphrase\" false \"label_master\" \"label_account\"") +
        "\nAs a JSON-RPC call\n"
        + HelpExampleRpc("extkeygenesisimport", "\"word1 ... word24\", \"passphrase\", false, \"label_master\", \"label_account\"")
            },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
    if (!wallet) return NullUniValue;

    return extkeyimportinternal(request, true);
},
    };
}

static RPCHelpMan extkeyaltversion()
{
    return RPCHelpMan{"extkeyaltversion",
                "\nReturns the provided ext_key encoded with alternate version bytes.\n"
                "If the provided ext_key has a Bitcoin prefix the output will be encoded with a Particl prefix.\n"
                "If the provided ext_key has a Particl prefix the output will be encoded with a Bitcoin prefix.\n",
                {
                    {"ext_key", RPCArg::Type::STR, RPCArg::Optional::NO, ""},
                },
                RPCResult{
                    RPCResult::Type::ANY, "", ""
                },
                RPCExamples{""},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::string sKeyIn = request.params[0].get_str();
    std::string sKeyOut;

    CExtKey58 eKey58;
    CExtKeyPair ekp;
    if (eKey58.Set58(sKeyIn.c_str()) != 0) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid input key.");
    }

    // TODO: handle testnet keys on main etc
    if (eKey58.IsValid(CChainParams::EXT_SECRET_KEY_BTC)) {
        return eKey58.ToStringVersion(CChainParams::EXT_SECRET_KEY);
    }
    if (eKey58.IsValid(CChainParams::EXT_SECRET_KEY)) {
        return eKey58.ToStringVersion(CChainParams::EXT_SECRET_KEY_BTC);
    }

    if (eKey58.IsValid(CChainParams::EXT_PUBLIC_KEY_BTC)) {
        return eKey58.ToStringVersion(CChainParams::EXT_PUBLIC_KEY);
    }
    if (eKey58.IsValid(CChainParams::EXT_PUBLIC_KEY)) {
        return eKey58.ToStringVersion(CChainParams::EXT_PUBLIC_KEY_BTC);
    }

    throw JSONRPCError(RPC_INVALID_PARAMETER, "Unknown input key version.");
},
    };
}


static RPCHelpMan getnewextaddress()
{
        return RPCHelpMan{"getnewextaddress",
                "\nReturns a new Particl ext address for receiving payments." +
                HELP_REQUIRING_PASSPHRASE,
                {
                    {"label", RPCArg::Type::STR, RPCArg::Default{""}, "If specified the key is added to the address book."},
                    {"childnum", RPCArg::Type::STR, RPCArg::Default{""}, "If specified the account derive counter is not updated."},
                    {"bech32", RPCArg::Type::BOOL, RPCArg::Default{false}, "Use Bech32 encoding."},
                    {"hardened", RPCArg::Type::BOOL, RPCArg::Default{false}, "Derive a hardened key."},
                },
                RPCResult{
                    RPCResult::Type::STR, "address", "The new extended address"
                },
                RPCExamples{
            HelpExampleCli("getnewextaddress", "") +
            "\nAs a JSON-RPC call\n"
            + HelpExampleRpc("getnewextaddress", "")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
    if (!wallet) return NullUniValue;
    CHDWallet *const pwallet = GetParticlWallet(wallet.get());

    EnsureWalletIsUnlocked(pwallet);

    uint32_t nChild = 0;
    uint32_t *pChild = nullptr;
    std::string strLabel;
    const char *pLabel = nullptr;
    if (request.params[0].isStr()) {
        strLabel = request.params[0].get_str();
        if (strLabel.size() > 0) {
            pLabel = strLabel.c_str();
        }
    }

    if (request.params[1].isStr()) {
        std::string s = request.params[1].get_str();
        if (!s.empty()) {
            // TODO, make full path work
            std::vector<uint32_t> vPath;
            if (0 != ExtractExtKeyPath(s, vPath) || vPath.size() != 1) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "bad childNo.");
            }
            nChild = vPath[0];
            pChild = &nChild;
        }
    }

    bool fBech32 = !request.params[2].isNull() ? request.params[2].get_bool() : false;
    bool fHardened = !request.params[3].isNull() ? request.params[3].get_bool() : false;

    CStoredExtKey *sek = new CStoredExtKey();
    if (0 != pwallet->NewExtKeyFromAccount(strLabel, sek, pLabel, pChild, fHardened, fBech32)) {
        delete sek;
        throw JSONRPCError(RPC_WALLET_ERROR, "NewExtKeyFromAccount failed.");
    }

    // CBitcoinAddress displays public key only
    return CBitcoinAddress(MakeExtPubKey(sek->kp), fBech32).ToString();
},
    };
}

static RPCHelpMan getnewstealthaddress()
{
        return RPCHelpMan{"getnewstealthaddress",
                "\nReturns a new Particl stealth address for receiving payments." +
                HELP_REQUIRING_PASSPHRASE,
                {
                    {"label", RPCArg::Type::STR, RPCArg::Default{""}, "If specified the key is added to the address book."},
                    {"num_prefix_bits", RPCArg::Type::NUM, RPCArg::Default{0}, ""},
                    {"prefix_num", RPCArg::Type::STR, RPCArg::Default{""}, "If prefix_num is not specified the prefix will be selected deterministically.\n"
            "           prefix_num can be specified in base2, 10 or 16, for base 2 prefix_num must begin with 0b, 0x for base16.\n"
            "           A 32bit integer will be created from prefix_num and the least significant num_prefix_bits will become the prefix.\n"
            "           A stealth address created without a prefix will scan all incoming stealth transactions, irrespective of transaction prefixes.\n"
            "           Stealth addresses with prefixes will scan only incoming stealth transactions with a matching prefix."},
                    {"bech32", RPCArg::Type::BOOL, RPCArg::Default{false}, "Use Bech32 encoding."},
                    {"makeV2", RPCArg::Type::BOOL, RPCArg::Default{false}, "Generate an address from the same scheme used for hardware wallets."},
                },
                RPCResult{
                    RPCResult::Type::STR, "address", "The new stealth address"
                },
                RPCExamples{
            HelpExampleCli("getnewstealthaddress", "\"lblTestSxAddrPrefix\" 3 \"0b101\"") +
            HelpExampleRpc("getnewstealthaddress", "\"lblTestSxAddrPrefix\", 3, \"0b101\"")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
    if (!wallet) return NullUniValue;
    CHDWallet *const pwallet = GetParticlWallet(wallet.get());

    EnsureWalletIsUnlocked(pwallet);

    std::string sLabel;
    if (request.params.size() > 0) {
        sLabel = request.params[0].get_str();
    }

    uint32_t num_prefix_bits = request.params.size() > 1 ? GetUInt32(request.params[1]) : 0;
    if (num_prefix_bits > 32) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "num_prefix_bits must be <= 32.");
    }

    std::string sPrefix_num;
    if (request.params.size() > 2) {
        sPrefix_num = request.params[2].get_str();
    }

    bool fBech32 = request.params.size() > 3 ? request.params[3].get_bool() : false;
    bool fMakeV2 = request.params.size() > 4 ? request.params[4].get_bool() : false;

    if (fMakeV2 && !fBech32) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "bech32 must be true when using makeV2.");
    }

    CEKAStealthKey akStealth;
    std::string sError;
    if (fMakeV2) {
        if (0 != pwallet->NewStealthKeyV2FromAccount(sLabel, akStealth, num_prefix_bits, sPrefix_num.empty() ? nullptr : sPrefix_num.c_str(), fBech32)) {
            throw JSONRPCError(RPC_WALLET_ERROR, "NewStealthKeyV2FromAccount failed.");
        }
    } else {
        if (0 != pwallet->NewStealthKeyFromAccount(sLabel, akStealth, num_prefix_bits, sPrefix_num.empty() ? nullptr : sPrefix_num.c_str(), fBech32)) {
            throw JSONRPCError(RPC_WALLET_ERROR, "NewStealthKeyFromAccount failed.");
        }
    }

    CStealthAddress sxAddr;
    akStealth.SetSxAddr(sxAddr);

    return sxAddr.ToString(fBech32);
},
    };
}

static RPCHelpMan importstealthaddress()
{
    return RPCHelpMan{"importstealthaddress",
                "\nImport a stealth addresses." +
                HELP_REQUIRING_PASSPHRASE,
                {
                    {"scan_secret", RPCArg::Type::STR, RPCArg::Optional::NO, "The hex or WIF encoded scan secret."},
                    {"spend_secret", RPCArg::Type::STR, RPCArg::Optional::NO, "The hex or WIF encoded spend secret or hex public key."},
                    {"label", RPCArg::Type::STR, RPCArg::Default{""}, "If specified the key is added to the address book."},
                    {"num_prefix_bits", RPCArg::Type::NUM, RPCArg::Default{0}, ""},
                    {"prefix_num", RPCArg::Type::STR, RPCArg::Default{""}, "If prefix_num is not specified the prefix will be selected deterministically.\n"
            "           prefix_num can be specified in base2, 10 or 16, for base 2 prefix_num must begin with 0b, 0x for base16.\n"
            "           A 32bit integer will be created from prefix_num and the least significant num_prefix_bits will become the prefix.\n"
            "           A stealth address created without a prefix will scan all incoming stealth transactions, irrespective of transaction prefixes.\n"
            "           Stealth addresses with prefixes will scan only incoming stealth transactions with a matching prefix."},
                    {"bech32", RPCArg::Type::BOOL, RPCArg::Default{false}, "Use Bech32 encoding."},
                },
                RPCResult{
                    RPCResult::Type::OBJ, "", "", {
                        {RPCResult::Type::STR, "result", "Result."},
                        {RPCResult::Type::STR, "stealth_address", "The imported stealth address"},
                        {RPCResult::Type::BOOL, "watchonly", "Watchonly."},
                }},
                RPCExamples{
            HelpExampleCli("importstealthaddress", "scan_secret spend_secret \"label\" 3 \"0b101\"") +
            HelpExampleRpc("importstealthaddress", "scan_secret, spend_secret, \"label\", 3, \"0b101\"")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
    if (!wallet) return NullUniValue;
    CHDWallet *const pwallet = GetParticlWallet(wallet.get());

    if (pwallet->IsWalletFlagSet(WALLET_FLAG_DISABLE_PRIVATE_KEYS)) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Error: Private keys are disabled for this wallet");
    }

    EnsureWalletIsUnlocked(pwallet);

    std::string sScanSecret  = request.params[0].get_str();
    std::string sLabel, sSpendSecret;

    if (request.params.size() > 1) {
        sSpendSecret = request.params[1].get_str();
    }
    if (request.params.size() > 2) {
        sLabel = request.params[2].get_str();
    }

    uint32_t num_prefix_bits = request.params.size() > 3 ? GetUInt32(request.params[3]) : 0;
    if (num_prefix_bits > 32) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "num_prefix_bits must be <= 32.");
    }

    uint32_t nPrefix = 0;
    std::string sPrefix_num;
    if (request.params.size() > 4) {
        sPrefix_num = request.params[4].get_str();
        if (!ExtractStealthPrefix(sPrefix_num.c_str(), nPrefix)) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Could not convert prefix to number.");
        }
    }

    bool fBech32 = request.params.size() > 5 ? request.params[5].get_bool() : false;

    std::vector<uint8_t> vchScanSecret, vchSpendSecret;
    CBitcoinSecret wifScanSecret, wifSpendSecret;
    CKey skScan, skSpend;
    CPubKey pkSpend;
    if (IsHex(sScanSecret)) {
        vchScanSecret = ParseHex(sScanSecret);
    } else
    if (wifScanSecret.SetString(sScanSecret)) {
        skScan = wifScanSecret.GetKey();
    } else {
        if (!DecodeBase58(sScanSecret, vchScanSecret, MAX_STEALTH_RAW_SIZE)) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Could not decode scan secret as WIF, hex or base58.");
        }
    }
    if (vchScanSecret.size() > 0) {
        if (vchScanSecret.size() != 32) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Scan secret is not 32 bytes.");
        }
        skScan.Set(&vchScanSecret[0], true);
    }

    if (IsHex(sSpendSecret)) {
        vchSpendSecret = ParseHex(sSpendSecret);
    } else
    if (wifSpendSecret.SetString(sSpendSecret)) {
        skSpend = wifSpendSecret.GetKey();
    } else {
        if (!DecodeBase58(sSpendSecret, vchSpendSecret, MAX_STEALTH_RAW_SIZE)) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Could not decode spend secret as hex or base58.");
        }
    }
    if (vchSpendSecret.size() > 0) {
        if (vchSpendSecret.size() == 32) {
            skSpend.Set(&vchSpendSecret[0], true);
        } else
        if (vchSpendSecret.size() == 33) {
            // watchonly
            pkSpend = CPubKey(vchSpendSecret.begin(), vchSpendSecret.end());
        } else {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Spend secret is not 32 or 33 bytes.");
        }
    }

    if (!pkSpend.IsValid() && !skSpend.IsValid()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Must provide the spend key or pubkey.");
    }

    if (skSpend == skScan) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Spend secret must be different to scan secret.");
    }

    CStealthAddress sxAddr;
    sxAddr.label = sLabel;
    sxAddr.scan_secret = skScan;
    if (skSpend.IsValid()) {
        pkSpend = skSpend.GetPubKey();
        sxAddr.spend_secret_id = pkSpend.GetID();
    } else {
        sxAddr.spend_secret_id = pkSpend.GetID();
    }

    sxAddr.prefix.number_bits = num_prefix_bits;
    if (sxAddr.prefix.number_bits > 0) {
        if (sPrefix_num.empty()) {
            // if pPrefix is null, set nPrefix from the hash of kSpend
            uint8_t tmp32[32];
            CSHA256().Write(skSpend.begin(), 32).Finalize(tmp32);
            memcpy(&nPrefix, tmp32, 4);
            nPrefix = le32toh(nPrefix);
        }

        uint32_t nMask = SetStealthMask(num_prefix_bits);
        nPrefix = nPrefix & nMask;
        sxAddr.prefix.bitfield = nPrefix;
    }

    if (0 != SecretToPublicKey(sxAddr.scan_secret, sxAddr.scan_pubkey)) {
        throw JSONRPCError(RPC_INTERNAL_ERROR, "Could not get scan public key.");
    }
    if (skSpend.IsValid() && 0 != SecretToPublicKey(skSpend, sxAddr.spend_pubkey)) {
        throw JSONRPCError(RPC_INTERNAL_ERROR, "Could not get spend public key.");
    } else {
        SetPublicKey(pkSpend, sxAddr.spend_pubkey);
    }

    UniValue result(UniValue::VOBJ);
    bool fFound = false;
    // Find if address already exists, can update
    for (auto it = pwallet->stealthAddresses.begin(); it != pwallet->stealthAddresses.end(); ++it) {
        CStealthAddress &sxAddrIt = const_cast<CStealthAddress&>(*it);
        if (sxAddrIt.scan_pubkey == sxAddr.scan_pubkey
            && sxAddrIt.spend_pubkey == sxAddr.spend_pubkey) {
            CKeyID sid = sxAddrIt.GetSpendKeyID();

            if (!pwallet->HaveKey(sid) && skSpend.IsValid()) {
                LOCK(pwallet->cs_wallet);
                CPubKey pk = skSpend.GetPubKey();
                auto spk_man = pwallet->GetLegacyScriptPubKeyMan();
                if (spk_man) {
                    LOCK(spk_man->cs_KeyStore);
                    if (!spk_man->AddKeyPubKey(skSpend, pk)) {
                        throw JSONRPCError(RPC_WALLET_ERROR, "Import failed - AddKeyPubKey failed.");
                    }
                } else {
                    throw JSONRPCError(RPC_WALLET_ERROR, "Import failed - GetLegacyScriptPubKeyMan failed.");
                }
                fFound = true; // update stealth address with secret
                break;
            }

            throw JSONRPCError(RPC_WALLET_ERROR, "Import failed - stealth address exists.");
        }
    }

    if (!fFound) {
        LOCK(pwallet->cs_wallet);
        if (pwallet->HaveStealthAddress(sxAddr)) { // check for extkeys, no update possible
            throw JSONRPCError(RPC_WALLET_ERROR, "Import failed - stealth address exists.");
        }
    }

    pwallet->SetAddressBook(sxAddr, sLabel, "", fBech32);

    if (fFound) {
        result.pushKV("result", "Success, updated " + sxAddr.Encoded(fBech32));
    } else {
        if (!pwallet->ImportStealthAddress(sxAddr, skSpend)) {
            throw JSONRPCError(RPC_WALLET_ERROR, "Could not save to wallet.");
        }
        result.pushKV("result", "Success");
        result.pushKV("stealth_address", sxAddr.Encoded(fBech32));

        if (!skSpend.IsValid()) {
            result.pushKV("watchonly", true);
        }
    }

    return result;
},
    };
}

int ListLooseStealthAddresses(UniValue &arr, const CHDWallet *pwallet, bool fShowSecrets, bool fAddressBookInfo, bool show_pubkeys=false, bool bech32=false) EXCLUSIVE_LOCKS_REQUIRED(pwallet->cs_wallet)
{
    for (auto it = pwallet->stealthAddresses.begin(); it != pwallet->stealthAddresses.end(); ++it) {
        UniValue obj(UniValue::VOBJ);
        obj.pushKV("Label", it->label);
        obj.pushKV("Address", it->ToString(bech32));

        if (fShowSecrets) {
            obj.pushKV("Scan Secret", CBitcoinSecret(it->scan_secret).ToString());

            CKeyID sid = it->GetSpendKeyID();
            CKey skSpend;
            if (pwallet->GetKey(sid, skSpend)) {
                obj.pushKV("Spend Secret", CBitcoinSecret(skSpend).ToString());
            }
        }

        if (show_pubkeys) {
            obj.pushKV("scan_public_key", HexStr(it->scan_pubkey));
            obj.pushKV("spend_public_key", HexStr(it->spend_pubkey));
        }

        if (fAddressBookInfo) {
            std::map<CTxDestination, CAddressBookData>::const_iterator mi = pwallet->m_address_book.find(*it);
            if (mi != pwallet->m_address_book.end()) {
                // TODO: confirm vPath?

                if (mi->second.GetLabel() != it->label) {
                    obj.pushKV("addr_book_label", mi->second.GetLabel());
                }
                if (!mi->second.purpose.empty()) {
                    obj.pushKV("purpose", mi->second.purpose);
                }

                UniValue objDestData(UniValue::VOBJ);
                for (const auto &pair : mi->second.destdata) {
                    obj.pushKV(pair.first, pair.second);
                }
                if (objDestData.size() > 0) {
                    obj.pushKV("destdata", objDestData);
                }
            }
        }

        arr.push_back(obj);
    }

    return 0;
};

static RPCHelpMan liststealthaddresses()
{
    return RPCHelpMan{"liststealthaddresses",
                "\nList stealth addresses in this wallet.\n",
                {
                    {"show_secrets", RPCArg::Type::BOOL, RPCArg::Default{false}, "Display secret keys to stealth addresses.\n"
                "                  Wallet must be unlocked if true."},
                    {"options", RPCArg::Type::OBJ, RPCArg::Default{UniValue::VOBJ}, "JSON with options",
                        {
                            {"bech32", RPCArg::Type::BOOL, RPCArg::Default{false}, "Display addresses in bech32 format"},
                            {"verbose", RPCArg::Type::BOOL, RPCArg::Default{false}, "Display extra details"},
                        },
                        "options"},
                },
                RPCResult{
                    RPCResult::Type::ARR, "", "",
                    {
                        {RPCResult::Type::OBJ, "", "", {
                            {RPCResult::Type::STR, "Account", "Account name"},
                            {RPCResult::Type::ARR, "Stealth Addresses", "", {
                                {RPCResult::Type::STR, "Label", "Stealth address label"},
                                {RPCResult::Type::STR, "Address", "Stealth address"},
                                {RPCResult::Type::STR, "Scan Secret", "Scan secret, if show_secrets=1"},
                                {RPCResult::Type::STR, "Spend Secret", "Spend secret, if show_secrets=1"},
                                {RPCResult::Type::STR_HEX, "scan_public_key", "Scan public key, if show_secrets=1"},
                                {RPCResult::Type::STR_HEX, "spend_public_key", "Spend public key, if show_secrets=1"},
                            }
                        }}},
                    }
                },
                RPCExamples{
            HelpExampleCli("liststealthaddresses", "") +
            HelpExampleRpc("liststealthaddresses", "")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
    if (!wallet) return NullUniValue;
    CHDWallet *const pwallet = GetParticlWallet(wallet.get());

    bool fShowSecrets = request.params.size() > 0 ? GetBool(request.params[0]) : false;

    bool show_in_bech32 = false;
    bool verbose = false;
    if (!request.params[1].isNull()) {
        const UniValue &options = request.params[1].get_obj();
        RPCTypeCheckObj(options,
            {
                {"bech32",               UniValueType(UniValue::VBOOL)},
                {"verbose",              UniValueType(UniValue::VBOOL)},
            }, true, false);
        if (options.exists("bech32")) {
            show_in_bech32 = options["bech32"].get_bool();
        }
        if (options.exists("verbose")) {
            verbose = options["verbose"].get_bool();
        }
    }

    if (fShowSecrets) {
        EnsureWalletIsUnlocked(pwallet);
    }

    LOCK(pwallet->cs_wallet);

    UniValue result(UniValue::VARR);

    for (auto mi = pwallet->mapExtAccounts.cbegin(); mi != pwallet->mapExtAccounts.cend(); ++mi) {
        CExtKeyAccount *ea = mi->second;

        if (ea->mapStealthKeys.size() < 1) {
            continue;
        }

        UniValue rAcc(UniValue::VOBJ);
        UniValue arrayKeys(UniValue::VARR);

        rAcc.pushKV("Account", ea->sLabel);

        for (auto it = ea->mapStealthKeys.cbegin(); it != ea->mapStealthKeys.cend(); ++it) {
            const CEKAStealthKey &aks = it->second;

            UniValue objA(UniValue::VOBJ);
            objA.pushKV("Label", aks.sLabel);

            CStealthAddress sxAddr;
            aks.SetSxAddr(sxAddr);

            bool is_v2_address = false;
            if (verbose) {
                const CExtKeyAccount *pa = nullptr;
                const CEKAStealthKey *pask = nullptr;
                bool mine = pwallet->IsMine(sxAddr, pa, pask);
                if (mine && pa && pask) {
                    CStoredExtKey *sek = pa->GetChain(pask->nScanParent);
                    std::string sPath;
                    if (sek) {
                        std::vector<uint32_t> vPath;
                        AppendChainPath(sek, vPath);
                        vPath.push_back(pask->nScanKey);
                        PathToString(vPath, sPath);
                        objA.pushKV("scan_path", sPath);
                    }
                    sek = pa->GetChain(pask->akSpend.nParent);
                    if (sek) {
                        std::vector<uint32_t> vPath;
                        AppendChainPath(sek, vPath);
                        vPath.push_back(pask->akSpend.nKey);
                        PathToString(vPath, sPath);
                        objA.pushKV("spend_path", sPath);
                    }

                    mapEKValue_t::const_iterator it = sek->mapValue.find(EKVT_KEY_TYPE);
                    if (it != sek->mapValue.end() && it->second.size() > 0 && it->second[0] == EKT_STEALTH_SPEND) {
                        is_v2_address = true;
                    }
                }

                int num_received = 0;
                CKeyID idStealthKey = aks.GetID();
                for (const auto &entry : pa->mapStealthChildKeys) {
                    if (entry.second.idStealthKey == idStealthKey) {
                        num_received++;
                    }
                }
                objA.pushKV("received_addresses", num_received);
            }
            objA.pushKV("Address", sxAddr.ToString(show_in_bech32 || is_v2_address));

            if (fShowSecrets) {
                objA.pushKV("Scan Secret", CBitcoinSecret(aks.skScan).ToString());
                objA.pushKV("scan_public_key", HexStr(aks.pkScan));
                std::string sSpend;
                CStoredExtKey *sekAccount = ea->ChainAccount();
                if (sekAccount && !sekAccount->fLocked) {
                    CKey skSpend;
                    if (ea->GetKey(aks.akSpend, skSpend)) {
                        sSpend = CBitcoinSecret(skSpend).ToString();
                    } else {
                        sSpend = "Extract failed.";
                    }
                } else {
                    sSpend = "Account Locked.";
                }
                objA.pushKV("Spend Secret", sSpend);
                objA.pushKV("spend_public_key", HexStr(aks.pkSpend));
            }

            arrayKeys.push_back(objA);
        }

        if (arrayKeys.size() > 0) {
            rAcc.pushKV("Stealth Addresses", arrayKeys);
            result.push_back(rAcc);
        }
    }


    if (pwallet->stealthAddresses.size() > 0) {
        UniValue rAcc(UniValue::VOBJ);
        UniValue arrayKeys(UniValue::VARR);

        rAcc.pushKV("Account", "Loose Keys");

        ListLooseStealthAddresses(arrayKeys, pwallet, fShowSecrets, false, fShowSecrets, show_in_bech32);

        if (arrayKeys.size() > 0) {
            rAcc.pushKV("Stealth Addresses", arrayKeys);
            result.push_back(rAcc);
        }
    }

    return result;
},
    };
}

static RPCHelpMan reservebalance()
{
    // Reserve balance from being staked for network protection
    return RPCHelpMan{"reservebalance",
                "\nSet reserve amount not participating in network protection.\n"
                "If no parameters provided current setting is printed.\n"
                "Wallet must be unlocked to modify." +
                HELP_REQUIRING_PASSPHRASE,
                {
                    {"enabled", RPCArg::Type::BOOL, RPCArg::Default{false}, "Turn balance reserve on or off, leave out to display current reserve."},
                    {"amount", RPCArg::Type::AMOUNT, RPCArg::Default{""}, "Amount of coin to reserve."},
                },
                RPCResult{
                    RPCResult::Type::ANY, "", ""
                },
                RPCExamples{
            HelpExampleCli("reservebalance", "true 1000") +
            "\nAs a JSON-RPC call\n"
            + HelpExampleRpc("reservebalance", "true, 1000")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
    if (!wallet) return NullUniValue;
    CHDWallet *const pwallet = GetParticlWallet(wallet.get());

    if (request.params.size() > 0) {
        EnsureWalletIsUnlocked(pwallet);
        {
            LOCK(pwallet->cs_wallet);
            bool fReserve = request.params[0].get_bool();
            if (fReserve) {
                if (request.params.size() == 1)
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "must provide amount to reserve balance.");
                int64_t nAmount = AmountFromValue(request.params[1]);
                nAmount = (nAmount / CENT) * CENT;  // round to cent
                if (nAmount < 0)
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "amount cannot be negative.");
                pwallet->SetReserveBalance(nAmount);
            } else {
                if (request.params.size() > 1)
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "cannot specify amount to turn off reserve.");
                pwallet->SetReserveBalance(0);
            }
        }
        WakeThreadStakeMiner(pwallet);
    }

    UniValue result(UniValue::VOBJ);
    result.pushKV("reserve", (pwallet->nReserveBalance > 0));
    result.pushKV("amount", ValueFromAmount(pwallet->nReserveBalance));
    return result;
},
    };
}

static RPCHelpMan deriverangekeys()
{
    return RPCHelpMan{"deriverangekeys",
                "\nDerive keys from the specified chain.\n"
                "Wallet must be unlocked if save or hardened options are set.\n",
                {
                    {"start", RPCArg::Type::NUM, RPCArg::Optional::NO, "Start from key index."},
                    {"end", RPCArg::Type::NUM, RPCArg::DefaultHint{"start+1"}, "Stop deriving after key index."},
                    {"key/id", RPCArg::Type::STR, RPCArg::Default{""}, "Account to derive from or \"external\",\"internal\",\"stealthv1\",\"stealthv2\". Defaults to external chain of current account. Set to empty (\"\") for default."},
                    {"hardened", RPCArg::Type::BOOL, RPCArg::Default{false}, "Derive hardened keys."},
                    {"save", RPCArg::Type::BOOL, RPCArg::Default{false}, "Save derived keys to the wallet."},
                    {"add_to_addressbook", RPCArg::Type::BOOL, RPCArg::Default{false}, "Add derived keys to address book, only applies when saving keys."},
                    {"256bithash", RPCArg::Type::BOOL, RPCArg::Default{false}, "Display addresses from sha256 hash of public keys."},
                },
                RPCResult{
                    RPCResult::Type::ARR, "addresses", "Array of derived addresses",
                    {
                        {RPCResult::Type::STR, "", "address"}
                    }
                },
                RPCExamples{
            HelpExampleCli("deriverangekeys", "0 1") +
            "\nAs a JSON-RPC call\n"
            + HelpExampleRpc("deriverangekeys", "0, 1")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
    if (!wallet) return NullUniValue;
    CHDWallet *const pwallet = GetParticlWallet(wallet.get());

    // TODO: manage nGenerated, nHGenerated properly

    int nStart = request.params[0].get_int();
    int nEnd = nStart;
    std::string sInKey;

    if (request.params.size() > 1) {
        nEnd = request.params[1].get_int();
    }
    if (nEnd < nStart) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "\"end\" can not be before start.");
    }
    if (nStart < 0) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "\"start\" can not be negative.");
    }
    if (request.params.size() > 2) {
        sInKey = request.params[2].get_str();
    }

    bool fHardened = request.params.size() > 3 ? GetBool(request.params[3]) : false;
    bool fSave = request.params.size() > 4 ? GetBool(request.params[4]) : false;
    bool fAddToAddressBook = request.params.size() > 5 ? GetBool(request.params[5]) : false;
    bool f256bit = request.params.size() > 6 ? GetBool(request.params[6]) : false;

    if (!fSave && fAddToAddressBook) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "\"add_to_addressbook\" can't be set without save");
    }
    if (fSave || fHardened) {
        EnsureWalletIsUnlocked(pwallet);
    }

    UniValue result(UniValue::VARR);

    {
        LOCK(pwallet->cs_wallet);

        CStoredExtKey *sek = nullptr;
        CExtKeyAccount *sea = nullptr;
        uint32_t nChain = 0;
        if (sInKey.length() == 0 || sInKey == "external") {
            if (pwallet->idDefaultAccount.IsNull()) {
                throw JSONRPCError(RPC_WALLET_ERROR, "No default account set.");
            }
            ExtKeyAccountMap::iterator mi = pwallet->mapExtAccounts.find(pwallet->idDefaultAccount);
            if (mi == pwallet->mapExtAccounts.end()) {
                throw JSONRPCError(RPC_WALLET_ERROR, "Unknown account.");
            }
            sea = mi->second;
            nChain = sea->nActiveExternal;
            if (nChain < sea->vExtKeys.size()) {
                sek = sea->vExtKeys[nChain];
            }
        } else
        if (sInKey == "internal") {
            if (pwallet->idDefaultAccount.IsNull()) {
                throw JSONRPCError(RPC_WALLET_ERROR, "No default account set.");
            }
            ExtKeyAccountMap::iterator mi = pwallet->mapExtAccounts.find(pwallet->idDefaultAccount);
            if (mi == pwallet->mapExtAccounts.end()) {
                throw JSONRPCError(RPC_WALLET_ERROR, "Unknown account.");
            }
            sea = mi->second;
            nChain = sea->nActiveInternal;
            if (nChain < sea->vExtKeys.size()) {
                sek = sea->vExtKeys[nChain];
            }
        } else
        if (sInKey == "stealthv1" || sInKey == "stealthv2") {
            EnsureWalletIsUnlocked(pwallet);
            bool stealth_v2 = sInKey == "stealthv2";
            if (fHardened) {
                throw JSONRPCError(RPC_WALLET_ERROR, "Hardened option is invalid when deriving stealth addresses.");
            }
            if (f256bit) {
                throw JSONRPCError(RPC_WALLET_ERROR, "256bit option is invalid when deriving stealth addresses.");
            }

            if (pwallet->idDefaultAccount.IsNull()) {
                throw JSONRPCError(RPC_WALLET_ERROR, "No default account set.");
            }
            ExtKeyAccountMap::iterator mi = pwallet->mapExtAccounts.find(pwallet->idDefaultAccount);
            if (mi == pwallet->mapExtAccounts.end()) {
                throw JSONRPCError(RPC_WALLET_ERROR, "Unknown account.");
            }
            sea = mi->second;

            CHDWalletDB wdb(pwallet->GetDatabase());  // May need to save keys or initialise the stealth v2 chains
            if (!wdb.TxnBegin()) {
                throw JSONRPCError(RPC_WALLET_ERROR, "TxnBegin failed.");
            }
            size_t num_keys = (nEnd - nStart) + 1;
            CStealthAddress sxAddr;
            CEKAStealthKey akStealth;
            if (!stealth_v2) {
                uint32_t nChain = sea->nActiveStealth;
                CStoredExtKey *sek = sea->GetChain(nChain);
                if (!sek) {
                    throw JSONRPCError(RPC_WALLET_ERROR, "No active stealth chain found.");
                }
                uint32_t nKey = nStart * 2;
                for (size_t k = 0; k < num_keys; ++k) {
                    pwallet->NewStealthKeyFromAccount(nullptr, pwallet->idDefaultAccount, "", akStealth, 0, nullptr, false, &nKey, false /* add_to_lookahead */);
                    nKey += 1;  // NewStealthKeyFromAccount advances nKey
                    akStealth.SetSxAddr(sxAddr);
                    result.push_back(sxAddr.ToString());

                    if (fSave
                        && !pwallet->HaveStealthAddress(sxAddr)
                        && 0 != pwallet->SaveStealthAddress(&wdb, sea, akStealth, false)) {
                        throw JSONRPCError(RPC_WALLET_ERROR, "SaveStealthAddress failed.");
                    }
                }
            } else {
                uint32_t nScanKey = nStart, nSpendKey = nStart;
                for (size_t k = 0; k < num_keys; ++k) {
                    pwallet->NewStealthKeyV2FromAccount(&wdb, pwallet->idDefaultAccount, "", akStealth, 0, nullptr, true, &nScanKey, &nSpendKey, false /* add_to_lookahead */);
                    nScanKey += 1;
                    nSpendKey += 1;
                    akStealth.SetSxAddr(sxAddr);
                    result.push_back(sxAddr.ToString(true));  // V2 stealth addresses are always formatted in bech32

                    if (fSave
                        && !pwallet->HaveStealthAddress(sxAddr)
                        && 0 != pwallet->SaveStealthAddress(&wdb, sea, akStealth, true)) {
                        throw JSONRPCError(RPC_WALLET_ERROR, "SaveStealthAddress failed");
                    }
                }
            }
            if (!wdb.TxnCommit()) {
                throw JSONRPCError(RPC_WALLET_ERROR, "TxnCommit failed.");
            }

            return result;
        } else {
            CKeyID keyId;
            ExtractExtKeyId(sInKey, keyId, CChainParams::EXT_KEY_HASH);

            ExtKeyAccountMap::iterator mi = pwallet->mapExtAccounts.begin();
            for (; mi != pwallet->mapExtAccounts.end(); ++mi) {
                sea = mi->second;
                for (uint32_t i = 0; i < sea->vExtKeyIDs.size(); ++i) {
                    if (sea->vExtKeyIDs[i] != keyId)
                        continue;
                    nChain = i;
                    sek = sea->vExtKeys[i];
                }
                if (sek)
                    break;
            }
        }

        CHDWalletDB wdb(pwallet->GetDatabase());
        CStoredExtKey sekLoose, sekDB;
        if (!sek) {
            CExtKey58 eKey58;
            CBitcoinAddress addr;
            CKeyID idk;

            if (addr.SetString(sInKey)
                && addr.IsValid(CChainParams::EXT_KEY_HASH)
                && addr.GetKeyID(idk, CChainParams::EXT_KEY_HASH)) {
                // idk is set
            } else
            if (eKey58.Set58(sInKey.c_str()) == 0) {
                sek = &sekLoose;
                sek->kp = eKey58.GetKey();
                idk = sek->kp.GetID();
            } else {
                throw JSONRPCError(RPC_WALLET_ERROR, "Invalid key.");
            }

            if (!idk.IsNull()) {
                if (wdb.ReadExtKey(idk, sekDB)) {
                    sek = &sekDB;
                    if (fHardened && (sek->nFlags & EAF_IS_CRYPTED)) {
                        throw std::runtime_error("TODO: decrypt key.");
                    }
                }
            }
        }

        if (!sek) {
            throw JSONRPCError(RPC_WALLET_ERROR, "Unknown chain.");
        }
        if (fHardened && !sek->kp.IsValidV()) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "extkey must have private key to derive hardened keys.");
        }
        if (fSave && !sea) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Must have account to save keys.");
        }

        uint32_t idIndex;
        if (fAddToAddressBook) {
            if (0 != pwallet->ExtKeyGetIndex(sea, idIndex)) {
                throw JSONRPCError(RPC_WALLET_ERROR, "ExtKeyGetIndex failed.");
            }
        }

        uint32_t nChildIn = (uint32_t)nStart;
        CPubKey newKey;
        for (int i = nStart; i <= nEnd; ++i) {
            nChildIn = (uint32_t)i;
            uint32_t nChildOut = 0;
            if (0 != sek->DeriveKey(newKey, nChildIn, nChildOut, fHardened)) {
                throw JSONRPCError(RPC_WALLET_ERROR, "DeriveKey failed.");
            }
            if (nChildIn != nChildOut) {
                LogPrintf("Warning: %s - DeriveKey skipped key %d.\n", __func__, nChildIn);
            }
            if (fHardened) {
                SetHardenedBit(nChildOut);
            }

            CKeyID idk = newKey.GetID();
            CKeyID256 idk256;
            if (f256bit) {
                idk256 = newKey.GetID256();
                result.push_back(CBitcoinAddress(idk256).ToString());
            } else {
                result.push_back(CBitcoinAddress(PKHash(idk)).ToString());
            }

            if (fSave) {
                if (HK_YES != sea->HaveSavedKey(idk)) {
                    CEKAKey ak(nChain, nChildOut);
                    if (0 != pwallet->ExtKeySaveKey(sea, idk, ak)) {
                        throw JSONRPCError(RPC_WALLET_ERROR, "ExtKeySaveKey failed.");
                    }
                }

                if (fAddToAddressBook) {
                    std::vector<uint32_t> vPath;
                    vPath.push_back(idIndex); // first entry is the index to the account / master key

                    if (0 == AppendChainPath(sek, vPath)) {
                        vPath.push_back(nChildOut);
                    } else {
                        vPath.clear();
                    }

                    std::string strAccount = "";
                    if (f256bit) {
                        pwallet->SetAddressBook(&wdb, idk256, strAccount, "receive", vPath, false);
                    } else {
                        pwallet->SetAddressBook(&wdb, PKHash(idk), strAccount, "receive", vPath, false);
                    }
                }
            }
        }
    }

    return result;
},
    };
}

static RPCHelpMan clearwallettransactions()
{
    return RPCHelpMan{"clearwallettransactions",
                "\nDelete transactions from the wallet.\n"
                "By default removes only failed stakes.\n"
                "Warning: Backup your wallet before using!" +
                HELP_REQUIRING_PASSPHRASE,
                {
                    {"remove_all", RPCArg::Type::BOOL, RPCArg::Default{false}, "Remove all transactions."},
                },
                RPCResult{
                    RPCResult::Type::ANY, "", ""
                },
                RPCExamples{
            HelpExampleCli("clearwallettransactions", "") +
            "\nAs a JSON-RPC call\n"
            + HelpExampleRpc("clearwallettransactions", "true")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
    if (!wallet) return NullUniValue;
    CHDWallet *const pwallet = GetParticlWallet(wallet.get());

    EnsureWalletIsUnlocked(pwallet);

    bool fRemoveAll = request.params.size() > 0 ? GetBool(request.params[0]) : false;

    int rv;
    size_t nRemoved = 0;
    size_t nRecordsRemoved = 0;

    {
        LOCK(pwallet->cs_wallet);

        pwallet->ClearCachedBalances(); // Clear stakeable coins cache

        CHDWalletDB wdb(pwallet->GetDatabase());
        if (!wdb.TxnBegin()) {
            throw JSONRPCError(RPC_MISC_ERROR, "TxnBegin failed.");
        }

        Dbc *pcursor = wdb.GetTxnCursor();
        if (!pcursor) {
            throw JSONRPCError(RPC_MISC_ERROR, "GetTxnCursor failed.");
        }

        CDataStream ssKey(SER_DISK, CLIENT_VERSION);

        std::map<uint256, CWalletTx>::const_iterator itw;
        std::string strType;
        uint256 hash;
        uint32_t fFlags = DB_SET_RANGE;
        ssKey << std::string("tx");
        while (wdb.ReadKeyAtCursor(pcursor, ssKey, fFlags) == 0) {
            fFlags = DB_NEXT;

            ssKey >> strType;
            if (strType != "tx") {
                break;
            }
            ssKey >> hash;

            if (!fRemoveAll) {
                if ((itw = pwallet->mapWallet.find(hash)) == pwallet->mapWallet.end()) {
                    LogPrintf("Warning: %s - tx not found in mapwallet! %s.\n", __func__, hash.ToString());
                    continue; // err on the side of caution
                }

                const CWalletTx *pcoin = &itw->second;
                if (!pcoin->IsCoinStake() || !pcoin->isAbandoned()) {
                    continue;
                }
            }

            //if (0 != pwallet->UnloadTransaction(hash))
            //    throw std::runtime_error("UnloadTransaction failed.");
            pwallet->UnloadTransaction(hash); // ignore failure

            if ((rv = pcursor->del(0)) != 0) {
                throw JSONRPCError(RPC_MISC_ERROR, "pcursor->del failed.");
            }

            nRemoved++;
        }

        if (fRemoveAll) {
            fFlags = DB_SET_RANGE;
            ssKey.clear();
            ssKey << std::string("rtx");
            while (wdb.ReadKeyAtCursor(pcursor, ssKey, fFlags) == 0) {
                fFlags = DB_NEXT;

                ssKey >> strType;
                if (strType != "rtx")
                    break;
                ssKey >> hash;

                pwallet->UnloadTransaction(hash); // ignore failure

                if ((rv = pcursor->del(0)) != 0) {
                    throw JSONRPCError(RPC_MISC_ERROR, "pcursor->del failed.");
                }

                // TODO: Remove CStoredTransaction

                nRecordsRemoved++;
            }
        }

        pcursor->close();
        if (!wdb.TxnCommit()) {
            throw JSONRPCError(RPC_MISC_ERROR, "TxnCommit failed.");
        }
    }

    UniValue result(UniValue::VOBJ);

    result.pushKV("transactions_removed", (int)nRemoved);
    result.pushKV("records_removed", (int)nRecordsRemoved);

    return result;
},
    };
}

static bool ParseOutput(
    UniValue                  &output,
    const COutputEntry        &o,
    const CHDWallet           *pwallet,
    const CWalletTx           &wtx,
    const isminefilter        &watchonly,
    std::vector<std::string>  &addresses,
    std::vector<std::string>  &amounts,
    bool                      &watch_only_out
) EXCLUSIVE_LOCKS_REQUIRED(pwallet->cs_wallet)
{
    CBitcoinAddress addr;
    watch_only_out = false;

    std::string sKey = strprintf("n%d", o.vout);
    mapValue_t::const_iterator mvi = wtx.mapValue.find(sKey);
    if (mvi != wtx.mapValue.end()) {
        output.pushKV("narration", mvi->second);
    }
    if (addr.Set(o.destination)) {
        output.pushKV("address", addr.ToString());
        addresses.push_back(addr.ToString());
    }
    if (o.ismine & ISMINE_WATCH_ONLY) {
        if (watchonly & ISMINE_WATCH_ONLY) {
            output.pushKV("involvesWatchonly", true);
            watch_only_out = true;
        } else {
            return false;
        }
    }
    if (!std::get_if<CNoDestination>(&o.destStake)) {
        output.pushKV("coldstake_address", EncodeDestination(o.destStake));
    }
    auto mi = pwallet->m_address_book.find(o.destination);
    if (mi != pwallet->m_address_book.end()) {
        output.pushKV("label", mi->second.GetLabel());
    }
    output.pushKV("vout", o.vout);
    amounts.push_back(ToString(o.amount));
    return true;
}

extern void WalletTxToJSON(interfaces::Chain& chain, const CWalletTx& wtx, UniValue& entry, bool fFilterMode=false);

static void ParseOutputs(
    UniValue            &entries,
    CWalletTx           &wtx,
    const CHDWallet     *pwallet,
    const isminefilter  &watchonly,
    const std::string   &search,
    const std::string   &category_filter,
    bool                 fWithReward,
    bool                 fBech32,
    bool                 hide_zero_coinstakes,
    std::vector<CScript> &vTreasuryFundScripts,
    bool                 show_change,
    bool                 show_smsg_fees
) EXCLUSIVE_LOCKS_REQUIRED(pwallet->cs_wallet)
{
    UniValue entry(UniValue::VOBJ);

    // GetAmounts variables
    std::list<COutputEntry> listReceived, listSent, listStaked;
    CAmount nFee, amount = 0;

    wtx.GetAmounts(
        listReceived,
        listSent,
        listStaked,
        nFee,
        ISMINE_ALL,
        true);

    if (hide_zero_coinstakes && !listStaked.empty() && nFee == 0) {
        return;
    }

    std::vector<std::string> addresses, amounts;

    UniValue outputs(UniValue::VARR);
    WalletTxToJSON(pwallet->chain(), wtx, entry, true);

    if (!listStaked.empty() || !listSent.empty()) {
        entry.pushKV("abandoned", wtx.isAbandoned());
    }

    // Staked
    size_t num_watchonly = 0;
    if (!listStaked.empty()) {
        if (wtx.GetDepthInMainChain() < 1) {
            entry.pushKV("category", "orphaned_stake");
        } else {
            entry.pushKV("category", "stake");
        }
        for (const auto &s : listStaked) {
            UniValue output(UniValue::VOBJ);
            bool is_watchonly = false;
            if (!ParseOutput(
                output,
                s,
                pwallet,
                wtx,
                watchonly,
                addresses,
                amounts,
                is_watchonly)) {
                return ;
            }
            output.pushKV("amount", ValueFromAmount(s.amount));
            outputs.push_back(output);
            num_watchonly += is_watchonly ? 1 : 0;
        }
        amount += -nFee;
    } else {
        // Sent
        if (!listSent.empty()) {
            for (const auto &s : listSent) {
                UniValue output(UniValue::VOBJ);
                bool is_watchonly = false;
                if (!ParseOutput(output,
                    s,
                    pwallet,
                    wtx,
                    watchonly,
                    addresses,
                    amounts,
                    is_watchonly)) {
                    return ;
                }
                output.pushKV("amount", ValueFromAmount(-s.amount));
                amount -= s.amount;
                outputs.push_back(output);
                num_watchonly += is_watchonly ? 1 : 0;
            }
        }

        // Received
        if (!listReceived.empty()) {
            for (const auto &r : listReceived) {
                UniValue output(UniValue::VOBJ);
                bool is_watchonly = false;
                if (!ParseOutput(
                    output,
                    r,
                    pwallet,
                    wtx,
                    watchonly,
                    addresses,
                    amounts,
                    is_watchonly)) {
                    return ;
                }
                if (r.destination.index() == DI::_PKHash) {
                    CStealthAddress sx;
                    CKeyID idK = ToKeyID(std::get<PKHash>(r.destination));
                    if (pwallet->GetStealthLinked(idK, sx)) {
                        output.pushKV("stealth_address", sx.Encoded(fBech32));
                    }
                }
                output.pushKV("amount", ValueFromAmount(r.amount));
                amount += r.amount;

                bool fExists = false;
                for (size_t i = 0; i < outputs.size(); ++i) {
                    auto &o = outputs.get(i);
                    if (o["vout"].get_int() == r.vout) {
                        o.get("amount").setStr(FormatMoney(r.amount));
                        fExists = true;
                    }
                }
                if (!fExists) {
                    outputs.push_back(output);
                    num_watchonly += is_watchonly ? 1 : 0;
                }
            }
        }

        CAmount debit_watchonly = wtx.GetDebit(ISMINE_WATCH_ONLY);
        CAmount debit_spendable = wtx.GetDebit(ISMINE_SPENDABLE);
        if (num_watchonly >= outputs.size()) { // Only has watchonly outputs or none
            bool from_watchonly_only = debit_watchonly && !debit_spendable;
            if (from_watchonly_only && !(watchonly & ISMINE_WATCH_ONLY)) {
                return;
            }
        }
        if (debit_watchonly) {
            entry.__pushKV("involvesWatchonlyInput", "true");
        }

        if (wtx.IsCoinBase()) {
            if (wtx.GetDepthInMainChain() < 1) {
                entry.pushKV("category", "orphan");
            } else if (wtx.GetBlocksToMaturity() > 0) {
                entry.pushKV("category", "immature");
            } else {
                entry.pushKV("category", "coinbase");
            }
        } else if (!nFee) {
            entry.pushKV("category", "receive");
        } else if (amount == 0) {
            entry.pushKV("fee", ValueFromAmount(-nFee));
            entry.pushKV("category", "internal_transfer");
        } else {
            entry.pushKV("category", "send");

            // Handle txns partially funded by wallet
            if (nFee < 0) {
                amount = wtx.GetCredit(ISMINE_ALL) - wtx.GetDebit(ISMINE_ALL);
            } else {
                entry.pushKV("fee", ValueFromAmount(-nFee));
            }
        }
    }

    entry.pushKV("outputs", outputs);
    entry.pushKV("amount", ValueFromAmount(amount));

    if (category_filter != "all" && category_filter != entry["category"].get_str()) {
        return;
    }
    if (search != "") {
        bool drop = true;
        // search in addresses
        if (std::any_of(addresses.begin(), addresses.end(), [search](std::string addr) {
            return addr.find(search) != std::string::npos;
        })) {
            drop = false;
        }
        // search in amounts
        // character DOT '.' is not searched for: search "123" will find 1.23 and 12.3
        if (drop &&
            std::any_of(amounts.begin(), amounts.end(), [search](std::string amount) {
            return amount.find(search) != std::string::npos;
        })) {
            drop = false;
        }
        if (drop) {
            return;
        }
    }

    if (fWithReward && !listStaked.empty()) {
        CAmount nOutput = wtx.tx->GetValueOut();
        CAmount nInput = 0;

        // Remove treasury fund outputs
        if (wtx.tx->vpout.size() > 2 && wtx.tx->vpout[1]->IsStandardOutput()) {
            for (const auto &s : vTreasuryFundScripts) {
                if (s == *wtx.tx->vpout[1]->GetPScriptPubKey()) {
                    nOutput -= wtx.tx->vpout[1]->GetValue();
                    break;
                }
            }
        }

        for (const auto &vin : wtx.tx->vin) {
            if (vin.IsAnonInput()) {
                continue;
            }
            nInput += pwallet->GetOutputValue(vin.prevout, true);
        }
        entry.pushKV("reward", ValueFromAmount(nOutput - nInput));
    }

    if (show_smsg_fees) {
        CAmount smsg_fees = 0;
        int num_funded = 0;
        for (const auto &v : wtx.tx->vpout) {
            if (!v->IsType(OUTPUT_DATA)) {
                continue;
            }
            CTxOutData *txd = (CTxOutData*) v.get();
            if (txd->vData.size() < 25 || txd->vData[0] != DO_FUND_MSG) {
                continue;
            }
            size_t n = (txd->vData.size()-1) / 24;
            for (size_t k = 0; k < n; ++k) {
                uint32_t nAmount;
                memcpy(&nAmount, &txd->vData[1+k*24+20], 4);
                nAmount = le32toh(nAmount);
                smsg_fees += nAmount;
                num_funded += 1;
            }
        }
        if (num_funded > 0) {
            entry.pushKV("smsg_fees", ValueFromAmount(smsg_fees));
            entry.pushKV("smsges_funded", num_funded);
        }
    }

    entries.push_back(entry);
}

static void ParseRecords(
    UniValue                   &entries,
    const uint256              &hash,
    const CTransactionRecord   &rtx,
    CHDWallet *const            pwallet,
    const isminefilter         &watchonly_filter,
    const std::string          &search,
    const std::string          &category_filter,
    int                         type,
    bool                        show_blinding_factors,
    bool                        show_anon_spends,
    bool                        show_change,
    bool                        show_smsg_fees
) EXCLUSIVE_LOCKS_REQUIRED(pwallet->cs_wallet)
{
    std::vector<std::string> addresses, amounts;
    UniValue entry(UniValue::VOBJ);
    UniValue outputs(UniValue::VARR);
    size_t  nOwned      = 0;
    size_t  nFrom       = 0;
    size_t  nWatchOnly  = 0;
    CAmount totalAmount = 0;

    int confirmations = pwallet->GetDepthInMainChain(rtx);
    entry.__pushKV("confirmations", confirmations);
    if (confirmations > 0) {
        entry.__pushKV("blockhash", rtx.blockHash.GetHex());
        entry.__pushKV("blockindex", rtx.nIndex);
        PushTime(entry, "blocktime", rtx.nBlockTime);
    } else {
        entry.__pushKV("trusted", pwallet->IsTrusted(hash, rtx));
    }

    entry.__pushKV("txid", hash.ToString());
    UniValue conflicts(UniValue::VARR);
    std::set<uint256> setconflicts = pwallet->GetConflicts(hash);
    setconflicts.erase(hash);
    for (const auto &conflict : setconflicts) {
        conflicts.push_back(conflict.GetHex());
    }
    if (conflicts.size() > 0) {
        entry.__pushKV("walletconflicts", conflicts);
    }
    PushTime(entry, "time", rtx.GetTxTime());

    bool have_stx = false;
    CStoredTransaction stx;
    if (show_blinding_factors) {
        CHDWalletDB wdb(pwallet->GetDatabase());
        if (wdb.ReadStoredTx(hash, stx)) {
            have_stx = true;
        }
    }
    if (show_anon_spends && (rtx.nFlags & ORF_ANON_IN)) {
        UniValue anon_inputs(UniValue::VARR);
        CCmpPubKey ki;
        for (const auto &prevout : rtx.vin) {
            UniValue anon_prevout(UniValue::VOBJ);
            anon_prevout.__pushKV("txid", prevout.hash.ToString());
            anon_prevout.__pushKV("n", (int) prevout.n);
            anon_inputs.push_back(anon_prevout);
        }
        entry.__pushKV("anon_inputs", anon_inputs);
    }

    int nStd = 0, nBlind = 0, nAnon = 0;
    size_t nLockedOutputs = 0;
    for (const auto &record : rtx.vout) {
        UniValue output(UniValue::VOBJ);

        bool is_change = record.nFlags & ORF_CHANGE;
        if (is_change) {
            nFrom++;
            if (!show_change) {
                continue;
            }
        } else {
            if (record.nFlags & ORF_OWN_ANY) {
                nOwned++;
            }
            if (record.nFlags & ORF_FROM) {
                nFrom++;
            }
            if (record.nFlags & ORF_OWN_WATCH) {
                nWatchOnly++;
            }
            if (record.nFlags & ORF_LOCKED) {
                nLockedOutputs++;
            }
            // Skip over watchonly outputs if not requested
            // TODO: Improve
            if (nWatchOnly >= nOwned && !(watchonly_filter & ISMINE_WATCH_ONLY)) {
                if (!nFrom) {
                    continue;
                }
                // Check for non-watchonly inputs
                CAmount nInput = 0;
                for (const auto &vin : rtx.vin) {
                    // Keyimage is embedded in CTransactionRecord outpoints, IsAnonInput() will be false
                    nInput += pwallet->GetOwnedOutputValue(vin, watchonly_filter);
                }
                if (nInput == 0) {
                    continue;
                }
            }
        }

        CBitcoinAddress addr;
        CTxDestination  dest;
        bool extracted = ExtractDestination(record.scriptPubKey, dest);

        // Get account name
        if (extracted && !record.scriptPubKey.IsUnspendable()) {
            addr.Set(dest);
            auto mai = pwallet->m_address_book.find(dest);
            if (mai != pwallet->m_address_book.end() && !mai->second.GetLabel().empty()) {
                output.__pushKV("account", mai->second.GetLabel());
            }
        }

        // Stealth addresses
        CStealthAddress sx;
        if (record.vPath.size() > 0) {
            if (record.vPath[0] == ORA_STEALTH) {
                if (record.vPath.size() < 5) {
                    LogPrintf("%s: Warning, malformed vPath.\n", __func__);
                } else {
                    uint32_t sidx;
                    memcpy(&sidx, &record.vPath[1], 4);
                    if (pwallet->GetStealthByIndex(sidx, sx)) {
                        output.__pushKV("stealth_address", sx.Encoded());
                        addresses.push_back(sx.Encoded());
                    }
                }
            }
        } else {
            if (extracted && dest.index() == DI::_PKHash) {
                CKeyID idK = ToKeyID(std::get<PKHash>(dest));
                if (pwallet->GetStealthLinked(idK, sx)) {
                    output.__pushKV("stealth_address", sx.Encoded());
                    addresses.push_back(sx.Encoded());
                }
            }
        }

        if (extracted && dest.index() == DI::_CNoDestination) {
            output.__pushKV("address", "none");
        } else
        if (extracted) {
            output.__pushKV("address", addr.ToString());
            addresses.push_back(addr.ToString());
        }

        switch (record.nType) {
            case OUTPUT_STANDARD: ++nStd; break;
            case OUTPUT_CT: ++nBlind; break;
            case OUTPUT_RINGCT: ++nAnon; break;
            default: ++nStd = 0;
        }
        output.__pushKV("type",
              record.nType == OUTPUT_STANDARD ? "standard"
            : record.nType == OUTPUT_CT       ? "blind"
            : record.nType == OUTPUT_RINGCT   ? "anon"
            : "unknown");

        if (!record.sNarration.empty()) {
            output.__pushKV("narration", record.sNarration);
        }

        CAmount amount = record.nValue;
        if (!(record.nFlags & ORF_OWN_ANY)) {
            amount *= -1;
        }
        if (record.nFlags & ORF_CHANGE) {
            output.__pushKV("is_change", "true");
        } else {
            totalAmount += amount;
        }
        amounts.push_back(ToString(amount));
        output.__pushKV("amount", ValueFromAmount(amount));
        output.__pushKV("vout", record.n);

        if (record.nType == OUTPUT_CT || record.nType == OUTPUT_RINGCT) {
            uint256 blinding_factor;
            if (show_blinding_factors && have_stx &&
                stx.GetBlind(record.n, blinding_factor.begin())) {
                output.__pushKV("blindingfactor", blinding_factor.ToString());
            }
        }
        outputs.push_back(output);
    }

    if (type > 0) {
        if (type == OUTPUT_STANDARD && !nStd) {
            return;
        }
        if (type == OUTPUT_CT && !nBlind && !(rtx.nFlags & ORF_BLIND_IN)) {
            return;
        }
        if (type == OUTPUT_RINGCT && !nAnon && !(rtx.nFlags & ORF_ANON_IN)) {
            return;
        }
    }

    if (nFrom > 0) {
        entry.__pushKV("abandoned", rtx.IsAbandoned());
        entry.__pushKV("fee", ValueFromAmount(-rtx.nFee));
    }

    std::string category;
    if (nOwned && nFrom) {
        category = "internal_transfer";
    } else if (nOwned && !nFrom) {
        category = "receive";
    } else if (nFrom) {
        category = "send";
    } else {
        category = "unknown";
    }
    if (category_filter != "all" && category_filter != category) {
        return;
    }
    entry.__pushKV("category", category);

    if (rtx.nFlags & ORF_ANON_IN) {
        entry.__pushKV("type_in", "anon");
    } else
    if (rtx.nFlags & ORF_BLIND_IN) {
        entry.__pushKV("type_in", "blind");
    }

    if (nLockedOutputs) {
        entry.__pushKV("requires_unlock", "true");
    }
    if (nWatchOnly) {
        entry.__pushKV("involvesWatchonly", "true");
    }

    entry.__pushKV("outputs", outputs);
    if (nOwned && nFrom) {
        // Must check against the owned input value
        CAmount nInput = 0;
        for (const auto &vin : rtx.vin) {
            nInput += pwallet->GetOwnedOutputValue(vin, watchonly_filter);
        }
        CAmount nOutput = 0;
        for (const auto &record : rtx.vout) {
            if ((record.nFlags & ORF_OWNED && watchonly_filter & ISMINE_SPENDABLE)
                || (record.nFlags & ORF_OWN_WATCH && watchonly_filter & ISMINE_WATCH_ONLY)) {
                nOutput += record.nValue;
            }
        }
        entry.__pushKV("amount", ValueFromAmount(nOutput - nInput));
    } else {
        entry.__pushKV("amount", ValueFromAmount(totalAmount));
    }
    amounts.push_back(ToString(totalAmount));

    if (search != "") {
        bool drop = true;
        // search in addresses
        if (std::any_of(addresses.begin(), addresses.end(), [search](std::string addr) {
            return addr.find(search) != std::string::npos;
        })) {
            drop = false;
        }
        // search in amounts
        // character DOT '.' is not searched for: search "123" will find 1.23 and 12.3
        if (drop &&
            std::any_of(amounts.begin(), amounts.end(), [search](std::string amount) {
            return amount.find(search) != std::string::npos;
        })) {
            drop = false;
        }
        if (drop) {
            return;
        }
    }

    if (show_smsg_fees) {
        mapRTxValue_t::const_iterator mvi = rtx.mapValue.find(RTXVT_SMSG_FEES);
        if (mvi != rtx.mapValue.end() &&
            mvi->second.size() >= 12) {
            CAmount smsg_fees = 0;
            int num_funded = 0;

            memcpy(&num_funded, mvi->second.data(), 4);
            memcpy(&smsg_fees, mvi->second.data() + 4, 8);

            entry.pushKV("smsg_fees", ValueFromAmount(smsg_fees));
            entry.pushKV("smsges_funded", num_funded);
        }
    }

    entries.push_back(entry);
}

static std::string getAddress(UniValue const & transaction)
{
    if (transaction["stealth_address"].getType() != 0) {
        return transaction["stealth_address"].get_str();
    }
    if (transaction["address"].getType() != 0) {
        return transaction["address"].get_str();
    }
    if (transaction["outputs"][0]["stealth_address"].getType() != 0) {
        return transaction["outputs"][0]["stealth_address"].get_str();
    }
    if (transaction["outputs"][0]["address"].getType() != 0) {
        return transaction["outputs"][0]["address"].get_str();
    }
    return std::string();
}

static RPCHelpMan filtertransactions()
{
    return RPCHelpMan{"filtertransactions",
                "\nList transactions.\n",
                {
                    {"options", RPCArg::Type::OBJ, RPCArg::Default{UniValue::VOBJ}, "",
                        {
                            {"count", RPCArg::Type::NUM, RPCArg::Default{10}, "Number of transactions to be displayed, 0 for unlimited."},
                            {"skip", RPCArg::Type::NUM, RPCArg::Default{0}, "Number of transactions to skip."},
                            {"include_watchonly", RPCArg::Type::BOOL, RPCArg::Default{false}, "Whether to include watchOnly transactions"},
                            {"search", RPCArg::Type::STR, RPCArg::Default{""}, "Filter on addresses and amounts\n"
                    "                  character DOT '.' is not searched for:\n"
                    "                  search \"123\" will find 1.23 and 12.3"},
                            {"category", RPCArg::Type::STR, RPCArg::Default{"all"}, "Return only one category of transactions, possible categories:\n"
                    "                  all, send, orphan, immature, coinbase, receive,\n"
                    "                  orphaned_stake, stake, internal_transfer"},
                            {"type", RPCArg::Type::STR, RPCArg::Default{"all"}, "Return only one type of transactions, possible types:\n"
                    "                  all, standard, anon, blind\n"},
                            {"sort", RPCArg::Type::STR, RPCArg::Default{"time"}, "Filter transactions by criteria:\n"
                                                    "                       time          most recent first\n"
                    "                  address       alphabetical\n"
                    "                  category      alphabetical\n"
                    "                  amount        largest first\n"
                    "                  confirmations most confirmations first\n"
                    "                  txid          alphabetical\n"},
                            {"from", RPCArg::Type::STR, RPCArg::Default{0}, "Unix timestamp or string \"yyyy-mm-ddThh:mm:ss\""},
                            {"to", RPCArg::Type::STR, RPCArg::Default{9999}, "Unix timestamp or string \"yyyy-mm-ddThh:mm:ss\""},
                            {"collate", RPCArg::Type::BOOL, RPCArg::Default{false}, "Display number of records and sum of amount fields"},
                            {"with_reward", RPCArg::Type::BOOL, RPCArg::Default{false}, "Calculate reward explicitly from txindex if necessary"},
                            {"use_bech32", RPCArg::Type::BOOL, RPCArg::Default{false}, "Display addresses in bech32 encoding"},
                            {"hide_zero_coinstakes", RPCArg::Type::BOOL, RPCArg::Default{false}, "Hide coinstake transactions without a balance change"},
                            {"show_blinding_factors", RPCArg::Type::BOOL, RPCArg::Default{false}, "Display blinding factors for blinded outputs"},
                            {"show_anon_spends", RPCArg::Type::BOOL, RPCArg::Default{false}, "Display inputs for anon transactions"},
                            {"show_change", RPCArg::Type::BOOL, RPCArg::Default{false}, "Display change outputs (for anon and blind txns)"},
                            {"show_smsg_fees", RPCArg::Type::BOOL, RPCArg::Default{false}, "List the smsgids funded by the transactions"},
                        },
                        "options"},
                },
                RPCResult{
                    RPCResult::Type::ANY, "", ""
                },
                RPCExamples{
            "\nList only when category is 'stake'\n"
            + HelpExampleCli("filtertransactions", "\"{\\\"category\\\":\\\"stake\\\"}\"") +
            "\nMultiple arguments\n"
            + HelpExampleCli("filtertransactions", "\"{\\\"sort\\\":\\\"amount\\\", \\\"category\\\":\\\"receive\\\"}\"") +
            "\nAs a JSON-RPC call\n"
            + HelpExampleRpc("filtertransactions", "{\\\"category\\\":\\\"stake\\\"}")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
    if (!wallet) return NullUniValue;
    CHDWallet *const pwallet = GetParticlWallet(wallet.get());

    // Make sure the results are valid at least up to the most recent block
    // the user could have gotten from another RPC command prior to now
    pwallet->BlockUntilSyncedToCurrentChain();

    LOCK(pwallet->cs_wallet);

    unsigned int count     = 10;
    int          skip      = 0;
    isminefilter watchonly = ISMINE_SPENDABLE;
    std::string  search    = "";
    std::string  category  = "all";
    std::string  type      = "all";
    std::string  sort      = "time";

    int64_t timeFrom = 0;
    int64_t timeTo = 0x3AFE130E00; // 9999
    bool fCollate = false;
    bool fWithReward = false;
    bool fBech32 = false;
    bool hide_zero_coinstakes = false;
    bool show_blinding_factors = false;
    bool show_anon_spends = false;
    bool show_change = false;
    bool show_smsg_fees = false;

    if (!request.params[0].isNull()) {
        const UniValue &options = request.params[0].get_obj();
        RPCTypeCheckObj(options,
            {
                {"count",                   UniValueType(UniValue::VNUM)},
                {"skip",                    UniValueType(UniValue::VNUM)},
                {"include_watchonly",       UniValueType(UniValue::VBOOL)},
                {"search",                  UniValueType(UniValue::VSTR)},
                {"category",                UniValueType(UniValue::VSTR)},
                {"type",                    UniValueType(UniValue::VSTR)},
                {"sort",                    UniValueType(UniValue::VSTR)},
                {"collate",                 UniValueType(UniValue::VBOOL)},
                {"with_reward",             UniValueType(UniValue::VBOOL)},
                {"use_bech32",              UniValueType(UniValue::VBOOL)},
                {"hide_zero_coinstakes",    UniValueType(UniValue::VBOOL)},
                {"show_blinding_factors",   UniValueType(UniValue::VBOOL)},
                {"show_anon_spends",        UniValueType(UniValue::VBOOL)},
                {"show_change",             UniValueType(UniValue::VBOOL)},
                {"show_smsg_fees",       UniValueType(UniValue::VBOOL)},
            },
            true, // allow null
            false // strict
        );
        if (options.exists("count")) {
            int _count = options["count"].get_int();
            if (_count < 0) {
                throw JSONRPCError(RPC_INVALID_PARAMETER,
                    strprintf("Invalid count: %i.", _count));
            }
            count = _count;
        }
        if (options.exists("skip")) {
            skip = options["skip"].get_int();
            if (skip < 0) {
                throw JSONRPCError(RPC_INVALID_PARAMETER,
                    strprintf("Invalid skip number: %i.", skip));
            }
        }
        if (options.exists("include_watchonly")) {
            if (options["include_watchonly"].get_bool()) {
                watchonly = watchonly | ISMINE_WATCH_ONLY;
            }
        }
        if (options.exists("search")) {
            search = options["search"].get_str();
        }
        if (options.exists("category")) {
            category = options["category"].get_str();
            std::vector<std::string> categories = {
                "all",
                "send",
                "orphan",
                "immature",
                "coinbase",
                "receive",
                "orphaned_stake",
                "stake",
                "internal_transfer"
            };
            auto it = std::find(categories.begin(), categories.end(), category);
            if (it == categories.end()) {
                throw JSONRPCError(RPC_INVALID_PARAMETER,
                    strprintf("Invalid category: %s.", category));
            }
        }
        if (options.exists("type")) {
            type = options["type"].get_str();
            std::vector<std::string> types = {
                "all",
                "standard",
                "anon",
                "blind"
            };
            auto it = std::find(types.begin(), types.end(), type);
            if (it == types.end()) {
                throw JSONRPCError(RPC_INVALID_PARAMETER,
                    strprintf("Invalid type: %s.", type));
            }
        }
        if (options.exists("sort")) {
            sort = options["sort"].get_str();
            std::vector<std::string> sorts = {
                "time",
                "address",
                "category",
                "amount",
                "confirmations",
                "txid"
            };
            auto it = std::find(sorts.begin(), sorts.end(), sort);
            if (it == sorts.end()) {
                throw JSONRPCError(RPC_INVALID_PARAMETER,
                    strprintf("Invalid sort: %s.", sort));
            }
        }

        if (options["from"].isStr()) {
            timeFrom = part::strToEpoch(options["from"].get_str().c_str());
        } else
        if (options["from"].isNum()) {
            timeFrom = options["from"].get_int64();
        }
        if (options["to"].isStr()) {
            timeTo = part::strToEpoch(options["to"].get_str().c_str(), true);
        } else
        if (options["to"].isNum()) {
            timeTo = options["to"].get_int64();
        }
        if (options["collate"].isBool()) {
            fCollate = options["collate"].get_bool();
        }
        if (options["with_reward"].isBool()) {
            fWithReward = options["with_reward"].get_bool();
        }
        if (options["use_bech32"].isBool()) {
            fBech32 = options["use_bech32"].get_bool();
        }
        if (options["hide_zero_coinstakes"].isBool()) {
            hide_zero_coinstakes = options["hide_zero_coinstakes"].get_bool();
        }
        if (options["show_blinding_factors"].isBool()) {
            show_blinding_factors = options["show_blinding_factors"].get_bool();
        }
        if (options["show_anon_spends"].isBool()) {
            show_anon_spends = options["show_anon_spends"].get_bool();
        }
        if (options["show_change"].isBool()) {
            show_change = options["show_change"].get_bool();
        }
        if (options["show_smsg_fees"].isBool()) {
            show_smsg_fees = options["show_smsg_fees"].get_bool();
        }
    }

    if (show_blinding_factors || show_anon_spends) {
        EnsureWalletIsUnlocked(pwallet);
    }

    std::vector<CScript> vTreasuryFundScripts;
    if (fWithReward) {
        const auto v = Params().GetTreasuryFundSettings();
        for (const auto &s : v) {
            CTxDestination dfDest = CBitcoinAddress(s.second.sTreasuryFundAddresses).Get();
            if (dfDest.index() == DI::_CNoDestination) {
                continue;
            }
            CScript script = GetScriptForDestination(dfDest);
            vTreasuryFundScripts.push_back(script);
        }
    }

    // for transactions and records
    UniValue transactions(UniValue::VARR);

    // transaction processing
    const CHDWallet::TxItems &txOrdered = pwallet->wtxOrdered;
    CWallet::TxItems::const_reverse_iterator tit = txOrdered.rbegin();
    if (type == "all" || type == "standard")
    while (tit != txOrdered.rend()) {
        CWalletTx *const pwtx = tit->second;
        int64_t txTime = pwtx->GetTxTime();
        if (txTime < timeFrom) break;
        if (txTime <= timeTo)
            ParseOutputs(
                transactions,
                *pwtx,
                pwallet,
                watchonly,
                search,
                category,
                fWithReward,
                fBech32,
                hide_zero_coinstakes,
                vTreasuryFundScripts,
                show_change,
                show_smsg_fees);
        tit++;
    }

    int type_i = WordToType(type);
    // records processing
    const RtxOrdered_t &rtxOrdered = pwallet->rtxOrdered;
    RtxOrdered_t::const_reverse_iterator rit = rtxOrdered.rbegin();
    while (rit != rtxOrdered.rend()) {
        const uint256 &hash = rit->second->first;
        const CTransactionRecord &rtx = rit->second->second;
        int64_t txTime = rtx.GetTxTime();
        if (txTime < timeFrom) break;
        if (txTime <= timeTo)
            ParseRecords(
                transactions,
                hash,
                rtx,
                pwallet,
                watchonly,
                search,
                category,
                type_i,
                show_blinding_factors,
                show_anon_spends,
                show_change,
                show_smsg_fees);
        rit++;
    }

    // Sort
    std::vector<UniValue> values = transactions.getValues();
    std::sort(values.begin(), values.end(), [sort] (UniValue a, UniValue b) -> bool {
        std::string a_address = getAddress(a);
        std::string b_address = getAddress(b);
        double a_amount =   a["category"].get_str() == "send"
                        ? -(a["amount"  ].get_real())
                        :   a["amount"  ].get_real();
        double b_amount =   b["category"].get_str() == "send"
                        ? -(b["amount"  ].get_real())
                        :   b["amount"  ].get_real();
        return (
              sort == "address"
                ? a_address < b_address
            : sort == "category" || sort == "txid"
                ? a[sort].get_str() < b[sort].get_str()
            : sort == "time" || sort == "confirmations"
                ? a[sort].get_real() > b[sort].get_real()
            : sort == "amount"
                ? a_amount > b_amount
            : false);
    });

    // Filter, skip, count and sum
    CAmount nTotalAmount = 0, nTotalReward = 0;
    UniValue result(UniValue::VARR);
    if (count == 0) {
        count = values.size();
    }
    // for every value while count is positive
    for (unsigned int i = 0; i < values.size() && count != 0; i++) {
        // if we've skipped enough valid values
        if (skip-- <= 0) {
            result.push_back(values[i]);
            count--;

            if (fCollate) {
                if (!values[i]["amount"].isNull()) {
                    nTotalAmount += AmountFromValue(values[i]["amount"]);
                }
                if (!values[i]["reward"].isNull()) {
                    nTotalReward += AmountFromValue(values[i]["reward"]);
                }
            }
        }
    }

    if (fCollate) {
        UniValue retObj(UniValue::VOBJ);
        UniValue stats(UniValue::VOBJ);
        stats.pushKV("records", (int)result.size());
        stats.pushKV("total_amount", ValueFromAmount(nTotalAmount));
        if (fWithReward) {
            stats.pushKV("total_reward", ValueFromAmount(nTotalReward));
        }
        retObj.pushKV("tx", result);
        retObj.pushKV("collated", stats);
        return retObj;
    }

    return result;
},
    };
}

enum SortCodes
{
    SRT_LABEL_ASC,
    SRT_LABEL_DESC,
};

class AddressComp {
public:
    int nSortCode;
    AddressComp(int nSortCode_) : nSortCode(nSortCode_) {}
    bool operator() (
        const std::map<CTxDestination, CAddressBookData>::iterator a,
        const std::map<CTxDestination, CAddressBookData>::iterator b) const
    {
        switch (nSortCode)
        {
            case SRT_LABEL_DESC:
                return b->second.GetLabel().compare(a->second.GetLabel()) < 0;
            default:
                break;
        };
        //default: case SRT_LABEL_ASC:
        return a->second.GetLabel().compare(b->second.GetLabel()) < 0;
    }
};

static RPCHelpMan filteraddresses()
{
    return RPCHelpMan{"filteraddresses",
                "\nList addresses.\n"
                "\nNotes:\n"
                "filteraddresses offset count will list 'count' addresses starting from 'offset'\n"
                "filteraddresses -1 will count addresses\n",
                {
                    {"offset", RPCArg::Type::NUM, RPCArg::Default{0}, ""},
                    {"count", RPCArg::Type::NUM, RPCArg::Default{0x7FFFFFFF}, "Max no. of addresses to return"},
                    {"sort_code", RPCArg::Type::NUM, RPCArg::Default{0}, "0: sort by label ascending, 1: sort by label descending."},
                    {"match_str", RPCArg::Type::STR, RPCArg::Default{""}, "Filter by label."},
                    {"match_owned", RPCArg::Type::NUM, RPCArg::Default{0}, "0: off, 1: owned, 2: non-owned"},
                    {"show_path", RPCArg::Type::BOOL, RPCArg::Default{true}, ""},
                },
                RPCResult{
                    RPCResult::Type::ANY, "", ""
                },
                RPCExamples{""},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
    if (!wallet) return NullUniValue;
    CHDWallet *const pwallet = GetParticlWallet(wallet.get());

    // Make sure the results are valid at least up to the most recent block
    // the user could have gotten from another RPC command prior to now
    pwallet->BlockUntilSyncedToCurrentChain();

    int nOffset = 0, nCount = 0x7FFFFFFF;
    if (request.params.size() > 0)
        nOffset = request.params[0].get_int();

    std::map<CTxDestination, CAddressBookData>::iterator it;
    if (request.params.size() == 1 && nOffset == -1) {
        LOCK(pwallet->cs_wallet);
        // Count addresses
        UniValue result(UniValue::VOBJ);

        result.pushKV("total", (int)pwallet->m_address_book.size());

        int nReceive = 0, nSend = 0;
        for (it = pwallet->m_address_book.begin(); it != pwallet->m_address_book.end(); ++it) {
            if (it->second.nOwned == 0)
                it->second.nOwned = pwallet->HaveAddress(it->first) ? 1 : 2;

            if (it->second.nOwned == 1)
                nReceive++;
            else
            if (it->second.nOwned == 2)
                nSend++;
        }

        result.pushKV("num_receive", nReceive);
        result.pushKV("num_send", nSend);
        return result;
    }

    if (request.params.size() > 1) {
        nCount = request.params[1].get_int();
    }
    if (nOffset < 0) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "offset must be 0 or greater.");
    }
    if (nCount < 1) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "count must be 1 or greater.");
    }

    // TODO: Make better
    int nSortCode = SRT_LABEL_ASC;
    if (request.params.size() > 2) {
        std::string sCode = request.params[2].get_str();
        if (sCode == "0") {
            nSortCode = SRT_LABEL_ASC;
        } else
        if (sCode == "1") {
            nSortCode = SRT_LABEL_DESC;
        } else {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Unknown sort_code.");
        }
    }

    int nMatchOwned = 0; // 0 off/all, 1 owned, 2 non-owned
    int nMatchMode = 0; // 1 contains


    std::string sMatch;
    if (request.params.size() > 3) {
        sMatch = request.params[3].get_str();
    }

    if (sMatch != "") {
        nMatchMode = 1;
    }

    if (request.params.size() > 4) {
        std::string s = request.params[4].get_str();
        if (s != "" && !ParseInt32(s, &nMatchOwned)) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Unknown nMatchOwned.");
        }
    }

    int nShowPath = request.params.size() > 5 ? (GetBool(request.params[5]) ? 1 : 0) : 1;

    UniValue result(UniValue::VARR);
    {
        LOCK(pwallet->cs_wallet);

        CHDWalletDB wdb(pwallet->GetDatabase());

        if (nOffset >= (int)pwallet->m_address_book.size()) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("offset is beyond last address (%d).", nOffset));
        }
        std::vector<std::map<CTxDestination, CAddressBookData>::iterator> vitMapAddressBook;
        vitMapAddressBook.reserve(pwallet->m_address_book.size());

        for (it = pwallet->m_address_book.begin(); it != pwallet->m_address_book.end(); ++it) {
            if (it->second.nOwned == 0) {
                it->second.nOwned = pwallet->HaveAddress(it->first) ? 1 : 2;
            }
            if (nMatchOwned && it->second.nOwned != nMatchOwned) {
                continue;
            }
            if (nMatchMode) {
                if (!part::stringsMatchI(it->second.GetLabel(), sMatch, nMatchMode-1)) {
                    continue;
                }
            }

            vitMapAddressBook.push_back(it);
        }

        std::sort(vitMapAddressBook.begin(), vitMapAddressBook.end(), AddressComp(nSortCode));

        std::map<uint32_t, std::string> mapKeyIndexCache;
        std::vector<std::map<CTxDestination, CAddressBookData>::iterator>::iterator vit;
        int nEntries = 0;
        for (vit = vitMapAddressBook.begin()+nOffset;
            vit != vitMapAddressBook.end() && nEntries < nCount; ++vit) {
            auto &item = *vit;
            UniValue entry(UniValue::VOBJ);

            CBitcoinAddress address(item->first, item->second.fBech32);
            entry.pushKV("address", address.ToString());
            entry.pushKV("label", item->second.GetLabel());
            entry.pushKV("owned", item->second.nOwned == 1 ? "true" : "false");

            if (nShowPath > 0) {
                if (item->second.vPath.size() > 0) {
                    uint32_t index = item->second.vPath[0];
                    std::map<uint32_t, std::string>::iterator mi = mapKeyIndexCache.find(index);

                    if (mi != mapKeyIndexCache.end()) {
                        entry.pushKV("root", mi->second);
                    } else {
                        CKeyID accId;
                        if (!wdb.ReadExtKeyIndex(index, accId)) {
                            entry.pushKV("root", "error");
                        } else {
                            CBitcoinAddress addr;
                            addr.Set(accId, CChainParams::EXT_ACC_HASH);
                            std::string sTmp = addr.ToString();
                            entry.pushKV("root", sTmp);
                            mapKeyIndexCache[index] = sTmp;
                        }
                    }
                }

                if (item->second.vPath.size() > 1) {
                    std::string sPath;
                    if (0 == PathToString(item->second.vPath, sPath, '\'', 1)) {
                        entry.pushKV("path", sPath);
                    }
                }
            }

            result.push_back(entry);
            nEntries++;
        }
    } // cs_wallet

    return result;
},
    };
}

static RPCHelpMan manageaddressbook()
{
    return RPCHelpMan{"manageaddressbook",
                "\nManage the address book.\n",
                {
                    {"action", RPCArg::Type::STR, RPCArg::Optional::NO, "'add/edit/del/info/newsend' The action to take."},
                    {"address", RPCArg::Type::STR, RPCArg::Optional::NO, "The address to affect."},
                    {"label", RPCArg::Type::STR, RPCArg::Default{""}, "Optional label."},
                    {"purpose", RPCArg::Type::STR, RPCArg::Default{""}, "Optional purpose label."},
                },
                RPCResult{
                    RPCResult::Type::ANY, "", ""
                },
                RPCExamples{""},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
    if (!wallet) return NullUniValue;
    CHDWallet *const pwallet = GetParticlWallet(wallet.get());

    // Make sure the results are valid at least up to the most recent block
    // the user could have gotten from another RPC command prior to now
    pwallet->BlockUntilSyncedToCurrentChain();

    std::string sAction = request.params[0].get_str();
    std::string sAddress = request.params[1].get_str();
    std::string sLabel, sPurpose;

    if (sAction != "info") {
        EnsureWalletIsUnlocked(pwallet);
    }

    bool label_was_set = false;
    bool fHavePurpose = false;
    if (request.params.size() > 2) {
        sLabel = request.params[2].get_str();
        label_was_set = true;
    }
    if (request.params.size() > 3) {
        sPurpose = request.params[3].get_str();
        fHavePurpose = true;
    }

    CBitcoinAddress address(sAddress);
    CTxDestination dest;

    if (address.IsValid()) {
        dest = address.Get();
    } else {
        // Try decode as segwit address
        dest = DecodeDestination(sAddress);
        if (!IsValidDestination(dest)) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid Particl address");
        }
    }

    LOCK(pwallet->cs_wallet);

    std::map<CTxDestination, CAddressBookData>::iterator mabi;
    mabi = pwallet->m_address_book.find(dest);

    std::vector<uint32_t> vPath;

    UniValue objDestData(UniValue::VOBJ);

    if (sAction == "add") {
        if (mabi != pwallet->m_address_book.end()) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("Address '%s' is recorded in the address book.", sAddress));
        }

        if (!pwallet->SetAddressBook(nullptr, dest, sLabel, sPurpose, vPath, true)) {
            throw JSONRPCError(RPC_WALLET_ERROR, "SetAddressBook failed.");
        }
    } else
    if (sAction == "edit") {
        if (request.params.size() < 3) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Need a parameter to change.");
        }
        if (mabi == pwallet->m_address_book.end()) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("Address '%s' is not in the address book.", sAddress));
        }

        if (!pwallet->SetAddressBook(nullptr, dest, sLabel,
            fHavePurpose ? sPurpose : mabi->second.purpose, mabi->second.vPath, true)) {
            throw JSONRPCError(RPC_WALLET_ERROR, "SetAddressBook failed.");
        }

        sLabel = mabi->second.GetLabel();
        sPurpose = mabi->second.purpose;

        for (const auto &pair : mabi->second.destdata) {
            objDestData.pushKV(pair.first, pair.second);
        }
    } else
    if (sAction == "del") {
        if (mabi == pwallet->m_address_book.end()) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("Address '%s' is not in the address book.", sAddress));
        }
        sLabel = mabi->second.GetLabel();
        sPurpose = mabi->second.purpose;

        if (!pwallet->DelAddressBook(dest)) {
            throw JSONRPCError(RPC_WALLET_ERROR, "DelAddressBook failed.");
        }
    } else
    if (sAction == "info") {
        if (mabi == pwallet->m_address_book.end()) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("Address '%s' is not in the address book.", sAddress));
        }

        UniValue result(UniValue::VOBJ);

        result.pushKV("action", sAction);
        result.pushKV("address", sAddress);

        result.pushKV("label", mabi->second.GetLabel());
        result.pushKV("purpose", mabi->second.purpose);

        if (mabi->second.nOwned == 0) {
            mabi->second.nOwned = pwallet->HaveAddress(mabi->first) ? 1 : 2;
        }

        result.pushKV("owned", mabi->second.nOwned == 1 ? "true" : "false");

        if (mabi->second.vPath.size() > 1) {
            std::string sPath;
            if (0 == PathToString(mabi->second.vPath, sPath, '\'', 1)) {
                result.pushKV("path", sPath);
            }
        }

        for (const auto &pair : mabi->second.destdata) {
            objDestData.pushKV(pair.first, pair.second);
        }
        if (objDestData.size() > 0) {
            result.pushKV("destdata", objDestData);
        }

        result.pushKV("result", "success");

        return result;
    } else
    if (sAction == "newsend") {
        // Only update the purpose field if address does not yet exist
        if (mabi != pwallet->m_address_book.end()) {
            sPurpose = ""; // "" means don't change purpose
            if (!label_was_set) {
                sLabel = mabi->second.GetLabel();
            }
        }
        if (!pwallet->SetAddressBook(dest, sLabel, sPurpose)) {
            throw JSONRPCError(RPC_WALLET_ERROR, "SetAddressBook failed.");
        }
        if (mabi != pwallet->m_address_book.end()) {
            sPurpose = mabi->second.purpose;
        }
    } else {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Unknown action, must be one of 'add/edit/del'.");
    }

    UniValue result(UniValue::VOBJ);

    result.pushKV("action", sAction);
    result.pushKV("address", sAddress);

    if (sLabel.size() > 0) {
        result.pushKV("label", sLabel);
    }
    if (sPurpose.size() > 0) {
        result.pushKV("purpose", sPurpose);
    }
    if (objDestData.size() > 0) {
        result.pushKV("destdata", objDestData);
    }

    result.pushKV("result", "success");

    return result;
},
    };
}

static RPCHelpMan getstakinginfo()
{
    return RPCHelpMan{"getstakinginfo",
                "\nReturns an object containing staking-related information.\n",
                {
                },
                RPCResult{
                    RPCResult::Type::OBJ, "", "", {
                        {RPCResult::Type::BOOL, "enabled", "If staking is enabled on this wallet"},
                        {RPCResult::Type::BOOL, "staking", "If this wallet is currently staking"},
                        {RPCResult::Type::ARR, "errors", "any error messages", {
                            {RPCResult::Type::STR, "", ""},
                        }},
                        {RPCResult::Type::STR_AMOUNT, "percentyearreward", "Current stake reward percentage"},
                        {RPCResult::Type::STR_AMOUNT, "moneysupply", "The total amount of particl in the network"},
                        {RPCResult::Type::STR_AMOUNT, "reserve", "The reserve balance of the wallet in " + CURRENCY_UNIT},
                        {RPCResult::Type::STR_AMOUNT, "wallettreasurydonationpercent", "User set percentage of the block reward ceded to the treasury"},
                        {RPCResult::Type::STR_AMOUNT, "treasurydonationpercent", "Network enforced percentage of the block reward ceded to the treasury"},
                        {RPCResult::Type::STR_AMOUNT, "minstakeablevalue", "The minimum value for an output to attempt staking in " + CURRENCY_UNIT},
                        {RPCResult::Type::NUM, "minstakeabledepth", "Minimum depth required in the chain for an output to stake"},
                        {RPCResult::Type::NUM, "currentblocksize", "The last approximate block size in bytes"},
                        {RPCResult::Type::NUM, "currentblockweight", "The last block weight"},
                        {RPCResult::Type::NUM, "currentblocktx", "The number of transactions in the last block"},
                        {RPCResult::Type::NUM, "pooledtx", "The number of transactions in the mempool"},
                        {RPCResult::Type::NUM, "difficulty", "The current difficulty"},
                        {RPCResult::Type::NUM, "lastsearchtime", "The last time this wallet searched for a coinstake"},
                        {RPCResult::Type::NUM, "weight", "The current stake weight of this wallet"},
                        {RPCResult::Type::NUM, "netstakeweight", "The current stake weight of the network"},
                        {RPCResult::Type::NUM, "expectedtime", "Estimated time for next stake"},
                }},
                RPCExamples{
            HelpExampleCli("getstakinginfo", "") +
            "\nAs a JSON-RPC call\n"
            + HelpExampleRpc("getstakinginfo", "")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
    if (!wallet) return NullUniValue;
    CHDWallet *const pwallet = GetParticlWallet(wallet.get());
    ChainstateManager *pchainman{nullptr};
    if (pwallet->HaveChain()) {
        pchainman = pwallet->chain().getChainman();
    }
    if (!pchainman) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Chainstate manager not found");
    }

    // Make sure the results are valid at least up to the most recent block
    // the user could have gotten from another RPC command prior to now
    pwallet->BlockUntilSyncedToCurrentChain();

    UniValue obj(UniValue::VOBJ);

    int64_t nTipTime;
    float rCoinYearReward;
    CAmount nMoneySupply;
    CBlockIndex *pblockindex = nullptr;
    {
        LOCK(cs_main);
        pblockindex = pchainman->ActiveChain().Tip();
        nTipTime = pblockindex->nTime;
        rCoinYearReward = Params().GetCoinYearReward(nTipTime) / CENT;
        nMoneySupply = pblockindex->nMoneySupply;
    }

    uint64_t nWeight = pwallet->GetStakeWeight();

    uint64_t nNetworkWeight = GetPoSKernelPS(pblockindex);

    bool fStaking = nWeight && fIsStaking;
    uint64_t nExpectedTime = fStaking ? (Params().GetTargetSpacing() * nNetworkWeight / nWeight) : 0;

    obj.pushKV("enabled", gArgs.GetBoolArg("-staking", true)); // enabled on node, vs enabled on wallet
    obj.pushKV("staking", fStaking && pwallet->m_is_staking == CHDWallet::IS_STAKING);
    CHDWallet::eStakingState state = pwallet->m_is_staking;
    switch (state) {
        case CHDWallet::NOT_STAKING_BALANCE:
            obj.pushKV("cause", "low_balance");
            break;
        case CHDWallet::NOT_STAKING_DEPTH:
            obj.pushKV("cause", "low_depth");
            break;
        case CHDWallet::NOT_STAKING_LOCKED:
            obj.pushKV("cause", "locked");
            break;
        case CHDWallet::NOT_STAKING_LIMITED:
            obj.pushKV("cause", "limited");
            break;
        case CHDWallet::NOT_STAKING_DISABLED:
            obj.pushKV("cause", "disabled");
            break;
        default:
            break;
    }

    obj.pushKV("errors", GetWarnings(false).original);

    obj.pushKV("percentyearreward", rCoinYearReward);
    obj.pushKV("moneysupply", ValueFromAmount(nMoneySupply));

    if (pwallet->nReserveBalance > 0) {
        obj.pushKV("reserve", ValueFromAmount(pwallet->nReserveBalance));
    }

    if (pwallet->nWalletTreasuryFundCedePercent > 0) {
        obj.pushKV("wallettreasurydonationpercent", pwallet->nWalletTreasuryFundCedePercent);
    }

    const TreasuryFundSettings *pTreasuryFundSettings = Params().GetTreasuryFundSettings(nTipTime);
    if (pTreasuryFundSettings && pTreasuryFundSettings->nMinTreasuryStakePercent > 0) {
        obj.pushKV("treasurydonationpercent", pTreasuryFundSettings->nMinTreasuryStakePercent);
    }

    obj.pushKV("minstakeablevalue", ValueFromAmount(pwallet->m_min_stakeable_value));

    int nHeight = pwallet->chain().getHeightInt();
    int nRequiredDepth = std::min((int)(Params().GetStakeMinConfirmations() - 1), (int)(nHeight / 2));
    obj.pushKV("minstakeabledepth", nRequiredDepth);
    obj.pushKV("currentblocksize", (uint64_t)nLastBlockSize);
    obj.pushKV("currentblocktx", (uint64_t)nLastBlockTx);

    CTxMemPool *mempool = pwallet->HaveChain() ? pwallet->chain().getMempool() : nullptr;
    if (mempool) {
        LOCK(mempool->cs);
        obj.pushKV("pooledtx", (int64_t)mempool->size());
    } else {
        obj.pushKV("pooledtx", "unknown");
    }


    obj.pushKV("difficulty", GetDifficulty(pchainman->ActiveChain().Tip()));
    obj.pushKV("lastsearchtime", (uint64_t)pwallet->nLastCoinStakeSearchTime);

    obj.pushKV("weight", (uint64_t)nWeight);
    obj.pushKV("netstakeweight", (uint64_t)nNetworkWeight);

    obj.pushKV("expectedtime", nExpectedTime);

    return obj;
},
    };
};

static RPCHelpMan getcoldstakinginfo()
{
    return RPCHelpMan{"getcoldstakinginfo",
                "\nReturns an object containing coldstaking related information.\n",
                {
                },
                RPCResult{
                    RPCResult::Type::OBJ, "", "", {
                        {RPCResult::Type::BOOL, "enabled", "If a valid coldstakingaddress is loaded or not on this wallet"},
                        {RPCResult::Type::STR, "coldstaking_extkey_id", /*optional=*/true, "The id of the current coldstakingaddress"},
                        {RPCResult::Type::STR_AMOUNT, "coin_in_stakeable_script", "Current amount of coin in scripts stakeable by this wallet"},
                        {RPCResult::Type::STR_AMOUNT, "coin_in_coldstakeable_script", "Current amount of coin in scripts stakeable by the wallet with the coldstakingaddress"},
                        {RPCResult::Type::STR_AMOUNT, "percent_in_coldstakeable_script", "Percentage of coin in coldstakeable scripts"},
                        {RPCResult::Type::STR_AMOUNT, "pending_depth", "Amount of coin in this wallet that will stake once it reaches the required depth"},
                        {RPCResult::Type::STR_AMOUNT, "currently_staking", "Amount of coin estimated to be currently staking by this wallet"},
                }},
                RPCExamples{
            HelpExampleCli("getcoldstakinginfo", "") +
            "\nAs a JSON-RPC call\n"
            + HelpExampleRpc("getcoldstakinginfo", "")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
    if (!wallet) return NullUniValue;
    CHDWallet *const pwallet = GetParticlWallet(wallet.get());
    if (!pwallet->HaveChain()) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Unable to get chain");
    }

    // Make sure the results are valid at least up to the most recent block
    // the user could have gotten from another RPC command prior to now
    pwallet->BlockUntilSyncedToCurrentChain();

    UniValue obj(UniValue::VOBJ);

    std::vector<COutput> vecOutputs;

    bool include_unsafe = false;
    CAmount nMinimumAmount = 0;
    CAmount nMaximumAmount = MAX_MONEY;
    CAmount nMinimumSumAmount = MAX_MONEY;
    uint64_t nMaximumCount = 0;
    int nHeight, nRequiredDepth;

    {
        CCoinControl cctl;
        cctl.m_avoid_address_reuse = false;
        cctl.m_min_depth = 0;
        cctl.m_max_depth = 0x7FFFFFFF;
        cctl.m_include_unsafe_inputs = include_unsafe;
        cctl.m_include_immature = true;
        LOCK(pwallet->cs_wallet);
        nHeight = pwallet->chain().getHeightInt();
        nRequiredDepth = std::min((int)(Params().GetStakeMinConfirmations() - 1), (int)(nHeight / 2));
        pwallet->AvailableCoins(vecOutputs, &cctl, nMinimumAmount, nMaximumAmount, nMinimumSumAmount, nMaximumCount);
    }

    LOCK(pwallet->cs_wallet);

    CAmount nStakeable{0}, nColdStakeable{0}, nWalletStaking{0}, nWalletPendingDepth{0};
    CKeyID keyID;
    CScript coinstakePath;
    for (const auto &out : vecOutputs) {
        const CScript *scriptPubKey = out.tx->tx->vpout[out.i]->GetPScriptPubKey();
        CAmount nValue = out.tx->tx->vpout[out.i]->GetValue();

        if (scriptPubKey->IsPayToPublicKeyHash() || scriptPubKey->IsPayToPublicKeyHash256()) {
            if (!out.fSpendable) {
                continue;
            }
            nStakeable += nValue;
        } else
        if (scriptPubKey->IsPayToPublicKeyHash256_CS() || scriptPubKey->IsPayToScriptHash256_CS() || scriptPubKey->IsPayToScriptHash_CS()) {
            // Show output on both the spending and staking wallets
            if (!out.fSpendable) {
                if (!particl::ExtractStakingKeyID(*scriptPubKey, keyID) ||
                    !pwallet->HaveKey(keyID)) {
                    continue;
                }
            }
            nColdStakeable += nValue;
        } else {
            continue;
        }

        if (!particl::ExtractStakingKeyID(*scriptPubKey, keyID)) {
            continue;
        }

        if (pwallet->HaveKey(keyID)) {
            if (out.nDepth < nRequiredDepth) {
                nWalletPendingDepth += nValue;
            } else {
                nWalletStaking += nValue;
            }
        }
    }

    bool fEnabled = false;
    UniValue jsonSettings;
    CBitcoinAddress addrColdStaking;
    if (pwallet->GetSetting("changeaddress", jsonSettings) &&
        jsonSettings["coldstakingaddress"].isStr()) {
        std::string sAddress;
        try { sAddress = jsonSettings["coldstakingaddress"].get_str();
        } catch (std::exception &e) {
            return error("%s: Get coldstakingaddress failed %s.", __func__, e.what());
        }

        addrColdStaking = CBitcoinAddress(sAddress);
        if (addrColdStaking.IsValid()) {
            fEnabled = true;
        }
    }

    obj.pushKV("enabled", fEnabled);
    if (addrColdStaking.IsValid(CChainParams::EXT_PUBLIC_KEY)) {
        CTxDestination dest = addrColdStaking.Get();
        CExtPubKey kp = std::get<CExtPubKey>(dest);
        CKeyID idk = kp.GetID();
        CBitcoinAddress addr;
        addr.Set(idk, CChainParams::EXT_KEY_HASH);
        obj.pushKV("coldstaking_extkey_id", addr.ToString());
    }
    obj.pushKV("coin_in_stakeable_script", ValueFromAmount(nStakeable));
    obj.pushKV("coin_in_coldstakeable_script", ValueFromAmount(nColdStakeable));
    CAmount nTotal = nColdStakeable + nStakeable;
    obj.pushKV("percent_in_coldstakeable_script",
        UniValue(UniValue::VNUM, strprintf("%.2f", nTotal == 0 ? 0.0 : (nColdStakeable * 10000 / nTotal) / 100.0)));
    obj.pushKV("pending_depth", ValueFromAmount(nWalletPendingDepth));
    obj.pushKV("currently_staking", ValueFromAmount(nWalletStaking));

    return obj;
},
    };
};


static RPCHelpMan listunspentanon()
{
    return RPCHelpMan{"listunspentanon",
                "\nReturns array of unspent transaction anon outputs\n"
                "with between minconf and maxconf (inclusive) confirmations.\n"
                "Optionally filter to only include txouts paid to specified addresses.\n",
                {
                    {"minconf", RPCArg::Type::NUM, RPCArg::Default{1}, "The minimum confirmations to filter"},
                    {"maxconf", RPCArg::Type::NUM, RPCArg::Default{9999999}, "The maximum confirmations to filter"},
                    {"addresses", RPCArg::Type::ARR, RPCArg::Default{UniValue::VARR}, "A json array of particl addresses to filter",
                        {
                            {"address", RPCArg::Type::STR, RPCArg::Default{""}, "particl address"},
                        },
                    },
                    {"include_unsafe", RPCArg::Type::BOOL, RPCArg::Default{true}, "Include outputs that are not safe to spend\n"
            "                  See description of \"safe\" attribute below."},
                    {"query_options", RPCArg::Type::OBJ, RPCArg::Default{UniValue::VOBJ}, "JSON with query options",
                        {
                            {"minimumAmount", RPCArg::Type::AMOUNT, RPCArg::Default{FormatMoney(1)}, "Minimum value of each UTXO in " + CURRENCY_UNIT + ""},
                            {"maximumAmount", RPCArg::Type::AMOUNT, RPCArg::DefaultHint{"unlimited"}, "Maximum value of each UTXO in " + CURRENCY_UNIT + ""},
                            {"maximumCount", RPCArg::Type::NUM, RPCArg::DefaultHint{"unlimited"}, "Maximum number of UTXOs"},
                            {"minimumSumAmount", RPCArg::Type::AMOUNT, RPCArg::DefaultHint{"unlimited"}, "Minimum sum value of all UTXOs in " + CURRENCY_UNIT + ""},
                            {"cc_format", RPCArg::Type::BOOL, RPCArg::Default{false}, "Format output for coincontrol"},
                            {"include_immature", RPCArg::Type::BOOL, RPCArg::Default{false}, "Include immature staked outputs"},
                            {"frozen", RPCArg::Type::BOOL, RPCArg::Default{false}, "Show frozen outputs only"},
                            {"include_tainted_frozen", RPCArg::Type::BOOL, RPCArg::Default{false}, "Show tainted frozen outputs"},
                            {"show_pubkeys", RPCArg::Type::BOOL, RPCArg::Default{false}, "Show anon output public keys"},
                        },
                        "query_options"},
                },
                RPCResult{
                    RPCResult::Type::ARR, "", "", {
                        {RPCResult::Type::OBJ, "", "",
                        {
                            {RPCResult::Type::STR_HEX, "txid", "the transaction id"},
                            {RPCResult::Type::NUM, "vout", "the vout value"},
                            {RPCResult::Type::STR, "address", "the particl address"},
                            {RPCResult::Type::STR, "label", "The associated label, or \"\" for the default label"},
                            {RPCResult::Type::STR_AMOUNT, "amount", "the transaction output amount in " + CURRENCY_UNIT},
                            {RPCResult::Type::NUM, "confirmations", "The number of confirmations"},
                            {RPCResult::Type::STR_HEX, "pubkey", "If \"show_pubkeys\""},
                        }},
                    }
                },
                RPCExamples{
            HelpExampleCli("listunspentanon", "")
            + HelpExampleCli("listunspentanon", "6 9999999 \"[\\\"PfqK97PXYfqRFtdYcZw82x3dzPrZbEAcYa\\\",\\\"Pka9M2Bva8WetQhQ4ngC255HAbMJf5P5Dc\\\"]\"")
            + HelpExampleCli("listunspentanon", "0 9999999 \"[]\" true \"{\\\"show_pubkeys\\\":true}\"") +
            "\nAs a JSON-RPC call\n"
            + HelpExampleRpc("listunspentanon", "6, 9999999, \"[\\\"PfqK97PXYfqRFtdYcZw82x3dzPrZbEAcYa\\\",\\\"Pka9M2Bva8WetQhQ4ngC255HAbMJf5P5Dc\\\"]\"")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
    if (!wallet) return NullUniValue;
    CHDWallet *const pwallet = GetParticlWallet(wallet.get());

    int nMinDepth = 1;
    if (request.params.size() > 0 && !request.params[0].isNull()) {
        RPCTypeCheckArgument(request.params[0], UniValue::VNUM);
        nMinDepth = request.params[0].get_int();
    }

    int nMaxDepth = 0x7FFFFFFF;
    if (request.params.size() > 1 && !request.params[1].isNull()) {
        RPCTypeCheckArgument(request.params[1], UniValue::VNUM);
        nMaxDepth = request.params[1].get_int();
    }

    std::set<CBitcoinAddress> setAddress;
    if (request.params.size() > 2 && !request.params[2].isNull()) {
        RPCTypeCheckArgument(request.params[2], UniValue::VARR);
        UniValue inputs = request.params[2].get_array();
        for (unsigned int idx = 0; idx < inputs.size(); idx++) {
            const UniValue& input = inputs[idx];
            CBitcoinAddress address(input.get_str());
            if (!address.IsValidStealthAddress()) {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, std::string("Invalid Particl stealth address: ") + input.get_str());
            }
            if (setAddress.count(address)) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, std::string("Invalid parameter, duplicated address: ") + input.get_str());
            }
           setAddress.insert(address);
        }
    }

    bool include_unsafe = true;
    if (request.params.size() > 3 && !request.params[3].isNull()) {
        RPCTypeCheckArgument(request.params[3], UniValue::VBOOL);
        include_unsafe = request.params[3].get_bool();
    }

    CCoinControl cctl;
    bool fCCFormat = false;
    bool fIncludeImmature = false;
    bool show_pubkeys = false;
    CAmount nMinimumAmount = 1;
    CAmount nMaximumAmount = MAX_MONEY;
    CAmount nMinimumSumAmount = MAX_MONEY;
    uint64_t nMaximumCount = 0;

    if (!request.params[4].isNull()) {
        const UniValue& options = request.params[4].get_obj();

        RPCTypeCheckObj(options,
            {
                {"maximumCount",            UniValueType(UniValue::VNUM)},
                {"cc_format",               UniValueType(UniValue::VBOOL)},
                {"frozen",                  UniValueType(UniValue::VBOOL)},
                {"include_tainted_frozen",  UniValueType(UniValue::VBOOL)},
                {"show_pubkeys",            UniValueType(UniValue::VBOOL)},
            }, true, false);

        if (options.exists("minimumAmount")) {
            nMinimumAmount = AmountFromValue(options["minimumAmount"]);
        }
        if (options.exists("maximumAmount")) {
            nMaximumAmount = AmountFromValue(options["maximumAmount"]);
        }
        if (options.exists("minimumSumAmount")) {
            nMinimumSumAmount = AmountFromValue(options["minimumSumAmount"]);
        }
        if (options.exists("maximumCount")) {
            nMaximumCount = options["maximumCount"].get_int64();
        }
        if (options.exists("cc_format")) {
            fCCFormat = options["cc_format"].get_bool();
        }
        if (options.exists("include_immature")) {
            fIncludeImmature = options["include_immature"].get_bool();
        }
        if (options.exists("frozen")) {
            cctl.m_spend_frozen_blinded = options["frozen"].get_bool();
        }
        if (options.exists("include_tainted_frozen")) {
            cctl.m_include_tainted_frozen = options["include_tainted_frozen"].get_bool();
        }
        if (options.exists("show_pubkeys")) {
            show_pubkeys = options["show_pubkeys"].get_bool();
        }
    }

    // Make sure the results are valid at least up to the most recent block
    // the user could have gotten from another RPC command prior to now
    pwallet->BlockUntilSyncedToCurrentChain();

    UniValue results(UniValue::VARR);
    std::vector<COutputR> vecOutputs;

    {
        cctl.m_min_depth = nMinDepth;
        cctl.m_max_depth = nMaxDepth;
        cctl.m_include_immature = fIncludeImmature;
        cctl.m_include_unsafe_inputs = include_unsafe;
        LOCK(pwallet->cs_wallet);
        // TODO: filter on stealth address
        pwallet->AvailableAnonCoins(vecOutputs, &cctl, nMinimumAmount, nMaximumAmount, nMinimumSumAmount, nMaximumCount);
    }

    LOCK(pwallet->cs_wallet);

    CHDWalletDB wdb(pwallet->GetDatabase());

    for (const auto &out : vecOutputs)
    {
        if (out.nDepth < nMinDepth || out.nDepth > nMaxDepth)
            continue;

        const COutputRecord *pout = out.rtx->second.GetOutput(out.i);

        if (!pout) {
            LogPrintf("%s: ERROR - Missing output %s %d\n", __func__, out.txhash.ToString(), out.i);
            continue;
        }

        CAmount nValue = pout->nValue;

        UniValue entry(UniValue::VOBJ);
        entry.pushKV("txid", out.txhash.GetHex());
        entry.pushKV("vout", out.i);

        if (pout->vPath.size() > 0 && pout->vPath[0] == ORA_STEALTH) {
            if (pout->vPath.size() < 5) {
                LogPrintf("%s: Warning, malformed vPath.\n", __func__);
            } else {
                uint32_t sidx;
                memcpy(&sidx, &pout->vPath[1], 4);
                CStealthAddress sx;
                if (pwallet->GetStealthByIndex(sidx, sx)) {
                    entry.pushKV("address", sx.Encoded());

                    auto i = pwallet->m_address_book.find(sx);
                    if (i != pwallet->m_address_book.end()) {
                        entry.pushKV("label", i->second.GetLabel());
                    }
                    if (setAddress.size() && !setAddress.count(CBitcoinAddress(CTxDestination(sx)))) {
                        continue;
                    }
                }
            }
        }

        if (!entry.exists("address")) {
            entry.pushKV("address", "unknown");
            if (setAddress.size()) {
                continue;
            }
        }
        if (fCCFormat) {
            entry.pushKV("time", out.rtx->second.GetTxTime());
            entry.pushKV("amount", nValue);
        } else {
            entry.pushKV("amount", ValueFromAmount(nValue));
        }
        entry.pushKV("confirmations", out.nDepth);
        //entry.pushKV("spendable", out.fSpendable);
        //entry.pushKV("solvable", out.fSolvable);
        entry.pushKV("safe", out.fSafe);
        if (fIncludeImmature) {
            entry.pushKV("mature", out.fMature);
        }

        if (show_pubkeys) {
            CStoredTransaction stx;
            CCmpPubKey anon_pubkey;
            if (!wdb.ReadStoredTx(out.txhash, stx)) {
                entry.pushKV("error", "Missing stored txn.");
            } else
            if (!stx.GetAnonPubkey(out.i, anon_pubkey)) {
                entry.pushKV("error", "Could not get anon pubkey.");
            } else {
                entry.pushKV("pubkey", HexStr(anon_pubkey));
            }
        }

        results.push_back(entry);
    }

    return results;
},
    };
};

static RPCHelpMan listunspentblind()
{
    return RPCHelpMan{"listunspentblind",
                "\nReturns array of unspent transaction blinded outputs\n"
                "with between minconf and maxconf (inclusive) confirmations.\n"
                "Optionally filter to only include txouts paid to specified addresses.\n",
                {
                    {"minconf", RPCArg::Type::NUM, RPCArg::Default{1}, "The minimum confirmations to filter"},
                    {"maxconf", RPCArg::Type::NUM, RPCArg::Default{9999999}, "The maximum confirmations to filter"},
                    {"addresses", RPCArg::Type::ARR, RPCArg::Default{UniValue::VARR}, "A json array of particl addresses to filter",
                        {
                            {"address", RPCArg::Type::STR, RPCArg::Default{""}, "particl address"},
                        },
                    },
                    {"include_unsafe", RPCArg::Type::BOOL, RPCArg::Default{true}, "Include outputs that are not safe to spend\n"
            "                  See description of \"safe\" attribute below."},
                    {"query_options", RPCArg::Type::OBJ, RPCArg::Default{UniValue::VOBJ}, "JSON with query options",
                        {
                            {"minimumAmount", RPCArg::Type::AMOUNT, RPCArg::Default{FormatMoney(0)}, "Minimum value of each UTXO in " + CURRENCY_UNIT + ""},
                            {"maximumAmount", RPCArg::Type::AMOUNT, RPCArg::DefaultHint{"unlimited"}, "Maximum value of each UTXO in " + CURRENCY_UNIT + ""},
                            {"maximumCount", RPCArg::Type::NUM, RPCArg::DefaultHint{"unlimited"}, "Maximum number of UTXOs"},
                            {"minimumSumAmount", RPCArg::Type::AMOUNT, RPCArg::DefaultHint{"unlimited"}, "Minimum sum value of all UTXOs in " + CURRENCY_UNIT + ""},
                            {"cc_format", RPCArg::Type::BOOL, RPCArg::Default{false}, "Format output for coincontrol"},
                            {"frozen", RPCArg::Type::BOOL, RPCArg::Default{false}, "Show frozen outputs only"},
                            {"include_tainted_frozen", RPCArg::Type::BOOL, RPCArg::Default{false}, "Show tainted frozen outputs"},
                        },
                        "query_options"},
                },
                RPCResult{
                    RPCResult::Type::ARR, "", "", {
                        {RPCResult::Type::OBJ, "", "",
                        {
                            {RPCResult::Type::STR_HEX, "txid", "the transaction id"},
                            {RPCResult::Type::NUM, "vout", "the vout value"},
                            {RPCResult::Type::STR, "address", "the particl address"},
                            {RPCResult::Type::STR, "label", "The associated label, or \"\" for the default label"},
                            {RPCResult::Type::STR, "scriptPubKey", "the script key"},
                            {RPCResult::Type::STR_AMOUNT, "amount", "the transaction output amount in " + CURRENCY_UNIT},
                            {RPCResult::Type::NUM, "confirmations", "The number of confirmations"},
                            {RPCResult::Type::STR_HEX, "redeemScript", "The redeemScript if scriptPubKey is P2SH"},
                            {RPCResult::Type::BOOL, "spendable", "Whether we have the private keys to spend this output"},
                            {RPCResult::Type::BOOL, "solvable", "Whether we know how to spend this output, ignoring the lack of keys"},
                            {RPCResult::Type::BOOL, "reused", "(only present if avoid_reuse is set) Whether this output is reused/dirty (sent to an address that was previously spent from)"},
                            {RPCResult::Type::STR, "desc", "(only when solvable) A descriptor for spending this output"},
                            {RPCResult::Type::BOOL, "safe", "Whether this output is considered safe to spend. Unconfirmed transactions"
            "                              from outside keys and unconfirmed replacement transactions are considered unsafe\n"
                                "and are not eligible for spending by fundrawtransaction and sendtoaddress."},
                        }},
                    }
                },
                RPCExamples{
            HelpExampleCli("listunspentblind", "")
            + HelpExampleCli("listunspentblind", "6 9999999 \"[\\\"PfqK97PXYfqRFtdYcZw82x3dzPrZbEAcYa\\\",\\\"Pka9M2Bva8WetQhQ4ngC255HAbMJf5P5Dc\\\"]\"") +
            "\nAs a JSON-RPC call\n"
            + HelpExampleRpc("listunspentblind", "6, 9999999, \"[\\\"PfqK97PXYfqRFtdYcZw82x3dzPrZbEAcYa\\\",\\\"Pka9M2Bva8WetQhQ4ngC255HAbMJf5P5Dc\\\"]\"")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
    if (!wallet) return NullUniValue;
    CHDWallet *const pwallet = GetParticlWallet(wallet.get());

    bool avoid_reuse = pwallet->IsWalletFlagSet(WALLET_FLAG_AVOID_REUSE);

    int nMinDepth = 1;
    if (request.params.size() > 0 && !request.params[0].isNull()) {
        RPCTypeCheckArgument(request.params[0], UniValue::VNUM);
        nMinDepth = request.params[0].get_int();
    }

    int nMaxDepth = 0x7FFFFFFF;
    if (request.params.size() > 1 && !request.params[1].isNull()) {
        RPCTypeCheckArgument(request.params[1], UniValue::VNUM);
        nMaxDepth = request.params[1].get_int();
    }

    CCoinControl cctl;
    bool fCCFormat = false;
    CAmount nMinimumAmount = 0;
    CAmount nMaximumAmount = MAX_MONEY;
    CAmount nMinimumSumAmount = MAX_MONEY;
    uint64_t nMaximumCount = 0;

    if (!request.params[4].isNull()) {
        const UniValue& options = request.params[4].get_obj();

        RPCTypeCheckObj(options,
            {
                {"maximumCount",            UniValueType(UniValue::VNUM)},
                {"cc_format",               UniValueType(UniValue::VBOOL)},
                {"frozen",                  UniValueType(UniValue::VBOOL)},
                {"include_tainted_frozen",  UniValueType(UniValue::VBOOL)},

            }, true, false);

        if (options.exists("minimumAmount")) {
            nMinimumAmount = AmountFromValue(options["minimumAmount"]);
        }
        if (options.exists("maximumAmount")) {
            nMaximumAmount = AmountFromValue(options["maximumAmount"]);
        }
        if (options.exists("minimumSumAmount")) {
            nMinimumSumAmount = AmountFromValue(options["minimumSumAmount"]);
        }
        if (options.exists("maximumCount")) {
            nMaximumCount = options["maximumCount"].get_int64();
        }
        if (options.exists("cc_format")) {
            fCCFormat = options["cc_format"].get_bool();
        }
        if (options.exists("frozen")) {
            cctl.m_spend_frozen_blinded = options["frozen"].get_bool();
        }
        if (options.exists("include_tainted_frozen")) {
            cctl.m_include_tainted_frozen = options["include_tainted_frozen"].get_bool();
        }
    }

    std::set<CTxDestination> setAddress;
    if (request.params.size() > 2 && !request.params[2].isNull()) {
        RPCTypeCheckArgument(request.params[2], UniValue::VARR);
        UniValue inputs = request.params[2].get_array();
        for (unsigned int idx = 0; idx < inputs.size(); idx++) {
            const UniValue& input = inputs[idx];
            CBitcoinAddress address(input.get_str());
            if (!address.IsValidStealthAddress() && !address.IsValid()) {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, std::string("Invalid Particl address or stealth address: ")+input.get_str());
            }
            if (setAddress.count(address.Get())) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, std::string("Invalid parameter, duplicated address: ")+input.get_str());
            }
           setAddress.insert(address.Get());
        }
    }

    bool include_unsafe{true};
    if (request.params.size() > 3 && !request.params[3].isNull()) {
        RPCTypeCheckArgument(request.params[3], UniValue::VBOOL);
        include_unsafe = request.params[3].get_bool();
    }

    // Make sure the results are valid at least up to the most recent block
    // the user could have gotten from another RPC command prior to now
    pwallet->BlockUntilSyncedToCurrentChain();

    UniValue results(UniValue::VARR);
    std::vector<COutputR> vecOutputs;

    {
        cctl.m_min_depth = nMinDepth;
        cctl.m_max_depth = nMaxDepth;
        cctl.m_include_unsafe_inputs = include_unsafe;
        LOCK(pwallet->cs_wallet);
        pwallet->AvailableBlindedCoins(vecOutputs, &cctl, nMinimumAmount, nMaximumAmount, nMinimumSumAmount, nMaximumCount);
    }

    LOCK(pwallet->cs_wallet);

    for (const auto &out : vecOutputs) {
        if (out.nDepth < nMinDepth || out.nDepth > nMaxDepth) {
            continue;
        }

        const COutputRecord *pout = out.rtx->second.GetOutput(out.i);
        if (!pout)  {
            LogPrintf("%s: ERROR - Missing output %s %d\n", __func__, out.txhash.ToString(), out.i);
            continue;
        }

        CAmount nValue = pout->nValue;

        bool address_is_whitelisted{false};
        CTxDestination address;
        const CScript *scriptPubKey = &pout->scriptPubKey;
        bool fValidAddress = ExtractDestination(*scriptPubKey, address);
        bool reused = avoid_reuse && pwallet->IsSpentKey(out.txhash, out.i);
        if (fValidAddress && setAddress.count(address)) {
            address_is_whitelisted = true;
        }

        UniValue entry(UniValue::VOBJ);
        entry.pushKV("txid", out.txhash.GetHex());
        entry.pushKV("vout", out.i);

        if (fValidAddress) {
            entry.pushKV("address", EncodeDestination(address));

            const auto i = pwallet->m_address_book.find(address);
            if (i != pwallet->m_address_book.end()) {
                entry.pushKV("label", i->second.GetLabel());
            }

            if (address.index() == DI::_PKHash) {
                CStealthAddress sx;
                CKeyID idk = ToKeyID(std::get<PKHash>(address));
                if (pwallet->GetStealthLinked(idk, sx)) {
                    entry.pushKV("stealth_address", sx.Encoded());
                    if (!entry.exists("label")) {
                        auto i = pwallet->m_address_book.find(sx);
                        if (i != pwallet->m_address_book.end()) {
                            entry.pushKV("label", i->second.GetLabel());
                        }
                    }
                    if (!address_is_whitelisted && setAddress.count(sx)) {
                        address_is_whitelisted = true;
                    }
                }
            }

            std::unique_ptr<SigningProvider> provider = pwallet->GetSolvingProvider(*scriptPubKey);
            if (scriptPubKey->IsPayToScriptHash()) {
                const CScriptID& hash = CScriptID(std::get<ScriptHash>(address));
                CScript redeemScript;
                if (provider->GetCScript(hash, redeemScript))
                    entry.pushKV("redeemScript", HexStr(redeemScript));
            } else
            if (scriptPubKey->IsPayToScriptHash256()) {
                const CScriptID256& hash = std::get<CScriptID256>(address);
                CScriptID scriptID;
                scriptID.Set(hash);
                CScript redeemScript;
                if (provider->GetCScript(scriptID, redeemScript))
                    entry.pushKV("redeemScript", HexStr(redeemScript));
            }
        }

        if (setAddress.size() && !address_is_whitelisted) {
            continue;
        }

        entry.pushKV("scriptPubKey", HexStr(*scriptPubKey));

        if (fCCFormat) {
            entry.pushKV("time", out.rtx->second.GetTxTime());
            entry.pushKV("amount", nValue);
        } else {
            entry.pushKV("amount", ValueFromAmount(nValue));
        }
        entry.pushKV("confirmations", out.nDepth);
        entry.pushKV("spendable", out.fSpendable);
        entry.pushKV("solvable", out.fSolvable);
        if (out.fSolvable) {
            auto descriptor = InferDescriptor(*scriptPubKey, *pwallet->GetLegacyScriptPubKeyMan());
            entry.pushKV("desc", descriptor->ToString());
        }
        if (avoid_reuse) entry.pushKV("reused", reused);
        entry.pushKV("safe", out.fSafe);
        results.push_back(entry);
    }

    return results;
},
    };
};

static RPCHelpMan getlockedbalances()
{
    return RPCHelpMan{"getlockedbalances",
                "\nReturns an object with locked balances in " + CURRENCY_UNIT + ".\n",
                {
                },
                RPCResult{
                    RPCResult::Type::OBJ, "", "", {
                        {RPCResult::Type::STR_AMOUNT, "trusted_plain", "Total locked trusted plain balance"},
                        {RPCResult::Type::STR_AMOUNT, "trusted_blind", "Total locked trusted blind balance"},
                        {RPCResult::Type::STR_AMOUNT, "trusted_anon", "Total locked trusted anon balance"},
                        {RPCResult::Type::STR_AMOUNT, "untrusted_plain", "Total locked untrusted plain balance"},
                        {RPCResult::Type::STR_AMOUNT, "untrusted_blind", "Total locked untrusted blind balance"},
                        {RPCResult::Type::STR_AMOUNT, "untrusted_anon", "Total locked untrusted anon balance"},
                        {RPCResult::Type::NUM, "num_locked", "Count of locked outputs"},
                }},
                RPCExamples{
            HelpExampleCli("getlockedbalances", "") +
            "\nAs a JSON-RPC call\n"
            + HelpExampleRpc("getlockedbalances", "")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
    if (!wallet) return NullUniValue;
    CHDWallet *const pwallet = GetParticlWallet(wallet.get());

    // Make sure the results are valid at least up to the most recent block
    // the user could have gotten from another RPC command prior to now
    pwallet->BlockUntilSyncedToCurrentChain();

    UniValue balances{UniValue::VOBJ};

    CAmount trusted_plain = 0, trusted_blind = 0, trusted_anon = 0;
    CAmount untrusted_plain = 0, untrusted_blind = 0, untrusted_anon = 0;

    LOCK(pwallet->cs_wallet);

    MapRecords_t::const_iterator mri;
    MapWallet_t::const_iterator mwi;

    // All outputs in setLockedCoins are assumed to be unspent as spending would remove output from setLockedCoins

    for (std::set<COutPoint>::const_iterator it = pwallet->setLockedCoins.begin();
         it != pwallet->setLockedCoins.end(); it++) {
        const auto &locked_outpoint = *it;

        if ((mri = pwallet->mapRecords.find(locked_outpoint.hash)) != pwallet->mapRecords.end()) {
            const auto &prevtx = mri->second;
            const COutputRecord *oR = mri->second.GetOutput(locked_outpoint.n);
            if (!oR || !(oR->nFlags & ORF_OWNED)) {
                continue;
            }
            if (pwallet->IsTrusted(locked_outpoint.hash, prevtx)) {
                switch (oR->nType) {
                    case OUTPUT_RINGCT:     trusted_anon += oR->nValue;     break;
                    case OUTPUT_CT:         trusted_blind += oR->nValue;    break;
                    case OUTPUT_STANDARD:   trusted_plain += oR->nValue;    break;
                    default:                break;
                }
            } else {
                switch (oR->nType) {
                    case OUTPUT_RINGCT:     untrusted_anon += oR->nValue;   break;
                    case OUTPUT_CT:         untrusted_blind += oR->nValue;  break;
                    case OUTPUT_STANDARD:   untrusted_plain += oR->nValue;  break;
                    default:                break;
                }
            }
        } else
        if ((mwi = pwallet->mapWallet.find(locked_outpoint.hash)) != pwallet->mapWallet.end()) {
            const auto &prevtx = mwi->second;
            if (locked_outpoint.n >= prevtx.tx->vpout.size() ||
                pwallet->IsMine(prevtx.tx->vpout[locked_outpoint.n].get()) != ISMINE_SPENDABLE) {
                continue;
            }
            CAmount value = prevtx.tx->vpout[locked_outpoint.n]->GetValue();
            if (prevtx.IsTrusted()) {
                trusted_plain += value;
            } else {
                untrusted_plain += value;
            }
        }
    }

    balances.pushKV("trusted_plain", ValueFromAmount(trusted_plain));
    balances.pushKV("trusted_blind", ValueFromAmount(trusted_blind));
    balances.pushKV("trusted_anon", ValueFromAmount(trusted_anon));
    balances.pushKV("untrusted_plain", ValueFromAmount(untrusted_plain));
    balances.pushKV("untrusted_blind", ValueFromAmount(untrusted_blind));
    balances.pushKV("untrusted_anon", ValueFromAmount(untrusted_anon));
    balances.pushKV("num_locked", (int)pwallet->setLockedCoins.size());

    return balances;
},
    };
};

static int AddOutput(uint8_t nType, std::vector<CTempRecipient> &vecSend, const CTxDestination &address, CAmount nValue,
    bool fSubtractFeeFromAmount, std::string &sNarr, std::string &sBlind, std::string &sError)
{
    CTempRecipient r;
    r.nType = nType;
    r.SetAmount(nValue);
    r.fSubtractFeeFromAmount = fSubtractFeeFromAmount;
    r.address = address;
    r.sNarration = sNarr;

    if (!sBlind.empty()) {
        uint256 blind;
        blind.SetHex(sBlind);

        r.vBlind.resize(32);
        memcpy(r.vBlind.data(), blind.begin(), 32);
    }

    vecSend.push_back(r);
    return 0;
};

static UniValue SendToInner(const JSONRPCRequest &request, OutputTypes typeIn, OutputTypes typeOut)
{
    const Consensus::Params& consensusParams = Params().GetConsensus();

    bool exploit_fix_2_active = GetTime() >= consensusParams.exploit_fix_2_time;
    bool default_accept_anon = exploit_fix_2_active ? true : particl::DEFAULT_ACCEPT_ANON_TX;
    bool default_accept_blind = exploit_fix_2_active ? true : particl::DEFAULT_ACCEPT_BLIND_TX;
    if (!gArgs.GetBoolArg("-acceptanontxn", default_accept_anon) &&
        (typeIn == OUTPUT_RINGCT || typeOut == OUTPUT_RINGCT)) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Disabled output type.");
    }
    if (!gArgs.GetBoolArg("-acceptblindtxn", default_accept_blind) &&
        (typeIn == OUTPUT_CT || typeOut == OUTPUT_CT)) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Disabled output type.");
    }
    if (typeOut == OUTPUT_RINGCT && GetTime() < consensusParams.rct_time) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Anon transactions not yet activated.");
    }

    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
    if (!wallet) return NullUniValue;
    CHDWallet *const pwallet = GetParticlWallet(wallet.get());

    // Make sure the results are valid at least up to the most recent block
    // the user could have gotten from another RPC command prior to now
    if (!request.fSkipBlock) {
        pwallet->BlockUntilSyncedToCurrentChain();
    }

    EnsureWalletIsUnlocked(pwallet);

    if (!pwallet->GetBroadcastTransactions()) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Error: Wallet transaction broadcasting is disabled with -walletbroadcast");
    }

    CAmount nTotal = 0;

    std::vector<CTempRecipient> vecSend;
    std::string sError;

    size_t nCommentOfs = 2;
    size_t nRingSizeOfs = 6;
    size_t nTestFeeOfs = 99;
    size_t nCoinControlOfs = 99;

    RPCTypeCheckArgument(request.params[0], UniValue::VARR);
    const UniValue &outputs = request.params[0].get_array();

    for (size_t k = 0; k < outputs.size(); ++k) {
        if (!outputs[k].isObject()) {
            throw JSONRPCError(RPC_TYPE_ERROR, "Not an object");
        }
        const UniValue &obj = outputs[k].get_obj();

        std::string sAddress, str_stake_address;
        CAmount nAmount;

        if (obj.exists("address")) {
            sAddress = obj["address"].get_str();
        } else {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Must provide an address.");
        }

        CBitcoinAddress address(sAddress);
        CTxDestination dest;

        if (typeOut == OUTPUT_RINGCT
            && !address.IsValidStealthAddress()) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid Particl stealth address");
        }

        if (address.IsValid() || obj.exists("script")) {
            dest = address.Get();
        } else {
            // Try decode as segwit address
            dest = DecodeDestination(sAddress);
            if (!IsValidDestination(dest)) {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid Particl address");
            }
        }

        if (address.getVchVersion() == Params().Bech32Prefix(CChainParams::STAKE_ONLY_PKADDR)) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Can't send to stake-only address version.");
        }

        if (obj.exists("amount")) {
            nAmount = AmountFromValue(obj["amount"]);
        } else {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Must provide an amount.");
        }

        if (nAmount <= 0) {
            throw JSONRPCError(RPC_TYPE_ERROR, "Invalid amount");
        }
        nTotal += nAmount;

        bool fSubtractFeeFromAmount = false;
        if (obj.exists("subfee")) {
            fSubtractFeeFromAmount = obj["subfee"].get_bool();
        }

        if (obj.exists("stakeaddress") && obj.exists("script")) {
            throw JSONRPCError(RPC_TYPE_ERROR, "\"script\" and \"stakeaddress\" can't be used together.");
        }

        std::string sNarr, sBlind;
        if (obj.exists("narr")) {
            sNarr = obj["narr"].get_str();
        }
        if (obj.exists("blindingfactor")) {
            std::string s = obj["blindingfactor"].get_str();
            if (!IsHex(s) || !(s.size() == 64)) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Blinding factor must be 32 bytes and hex encoded.");
            }
            sBlind = s;
        }

        if (0 != AddOutput(typeOut, vecSend, dest, nAmount, fSubtractFeeFromAmount, sNarr, sBlind, sError)) {
            throw JSONRPCError(RPC_MISC_ERROR, strprintf("AddOutput failed: %s.", sError));
        }

        if (obj.exists("stakeaddress")) {
            if (typeOut != OUTPUT_STANDARD) {
                throw std::runtime_error("\"stakeaddress\" is only valid for standard outputs.");
            }
            CTempRecipient &r = vecSend.back();
            str_stake_address = obj["stakeaddress"].get_str();
            if (!IsValidDestinationString(str_stake_address, true)) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "\"stakeaddress\" is invalid");
            }
            r.addressColdStaking = DecodeDestination(str_stake_address, true);
            if (r.address.index() == DI::_PKHash) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid addrspend, can't be p2pkh.");
            }
        } else
        if (obj.exists("script")) {
            if (typeOut != OUTPUT_STANDARD) {
                throw std::runtime_error("TODO: Currently setting a script only works for standard outputs.");
            }
            CTempRecipient &r = vecSend.back();

            if (sAddress != "script") {
                JSONRPCError(RPC_INVALID_PARAMETER, "Address parameter must be 'script' to set script explicitly.");
            }

            std::string sScript = obj["script"].get_str();
            std::vector<uint8_t> scriptData = ParseHex(sScript);
            r.scriptPubKey = CScript(scriptData.begin(), scriptData.end());
            r.fScriptSet = true;
        }
    }
    nCommentOfs = 1;
    nRingSizeOfs = 3;
    nTestFeeOfs = 5;
    nCoinControlOfs = 6;

    // Wallet comments
    CTransactionRef tx_new;
    CWalletTx wtx(pwallet, tx_new);
    CTransactionRecord rtx;

    size_t nv = nCommentOfs;
    if (request.params.size() > nv && !request.params[nv].isNull()) {
        std::string s = request.params[nv].get_str();
        part::TrimQuotes(s);
        if (!s.empty()) {
            std::vector<uint8_t> v(s.begin(), s.end());
            wtx.mapValue["comment"] = s;
            rtx.mapValue[RTXVT_COMMENT] = v;
        }
    }
    nv++;
    if (request.params.size() > nv && !request.params[nv].isNull()) {
        std::string s = request.params[nv].get_str();
        part::TrimQuotes(s);
        if (!s.empty()) {
            std::vector<uint8_t> v(s.begin(), s.end());
            wtx.mapValue["to"] = s;
            rtx.mapValue[RTXVT_TO] = v;
        }
    }

    nv = nRingSizeOfs;
    size_t nRingSize = DEFAULT_RING_SIZE;
    if (request.params.size() > nv) {
        nRingSize = request.params[nv].get_int();
    }
    nv++;
    size_t nInputsPerSig = DEFAULT_INPUTS_PER_SIG;
    if (request.params.size() > nv) {
        nInputsPerSig = request.params[nv].get_int();
    }

    bool fShowHex = false;
    bool fShowFee = false;
    bool fDebug = false;
    bool fCheckFeeOnly = false;
    bool fTestMempoolAccept = false;
    bool fSubmitTx = true;

    nv = nTestFeeOfs;
    if (request.params.size() > nv) {
        fCheckFeeOnly = request.params[nv].get_bool();
    }

    CCoinControl coincontrol;
    coincontrol.m_avoid_address_reuse = pwallet->IsWalletFlagSet(WALLET_FLAG_AVOID_REUSE);

    nv = nCoinControlOfs;
    if (request.params.size() > nv) {
        if (!request.params[nv].isObject()) {
            throw JSONRPCError(RPC_TYPE_ERROR, "coin_control must be an object");
        }
        const UniValue &uvCoinControl = request.params[nv].get_obj();

        ParseCoinControlOptions(uvCoinControl, pwallet, coincontrol);

        if (uvCoinControl["debug"].isBool()) {
            fDebug = uvCoinControl["debug"].get_bool();
        }
        if (uvCoinControl["show_hex"].isBool()) {
            fShowHex = uvCoinControl["show_hex"].get_bool();
        }
        if (uvCoinControl["show_fee"].isBool()) {
            fShowFee = uvCoinControl["show_fee"].get_bool();
        }
        if (uvCoinControl["submit_tx"].isBool()) {
            fSubmitTx = uvCoinControl["submit_tx"].get_bool();
        }
        if (uvCoinControl["blind_watchonly_visible"].isBool() && uvCoinControl["blind_watchonly_visible"].get_bool() == true) {
            coincontrol.m_blind_watchonly_visible = true;
        }
        if (uvCoinControl["spend_frozen_blinded"].isBool() && uvCoinControl["spend_frozen_blinded"].get_bool() == true) {
            coincontrol.m_spend_frozen_blinded = true;
            coincontrol.m_addChangeOutput = false;
        }
        if (uvCoinControl["test_mempool_accept"].isBool() && uvCoinControl["test_mempool_accept"].get_bool() == true) {
            fTestMempoolAccept = true;
        }
        const UniValue &uvMixins = uvCoinControl["use_mixins"];
        if (uvMixins.isArray()) {
            coincontrol.m_use_mixins.clear();
            coincontrol.m_use_mixins.reserve(uvMixins.size());
            for (size_t i = 0; i < uvMixins.size(); ++i) {
                const UniValue &uvi = uvMixins[i];
                if (!uvi.isNum()) {
                    JSONRPCError(RPC_INVALID_PARAMETER, "Mixin index must be an integer.");
                }
                coincontrol.m_use_mixins.push_back(uvi.get_int64());
            }
        }
        if (uvCoinControl["mixin_selection_mode"].isNum()) {
            coincontrol.m_mixin_selection_mode = uvCoinControl["mixin_selection_mode"].get_int();
        } else {
            coincontrol.m_mixin_selection_mode = pwallet->m_mixin_selection_mode_default;
        }
    }
    coincontrol.m_avoid_partial_spends |= coincontrol.m_avoid_address_reuse;

    CHDWalletBalances balances;
    if (!pwallet->GetBalances(balances)) {
        throw JSONRPCError(RPC_WALLET_ERROR, "GetBalances failed.");
    }
    CAmount with_watchonly = coincontrol.fAllowWatchOnly ? 1.0 : 0.0;
    switch (typeIn) {
        case OUTPUT_STANDARD:
            if (nTotal > balances.nPart + with_watchonly * balances.nPartWatchOnly) {
                throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS, "Insufficient funds");
            }
            break;
        case OUTPUT_CT:
            if (nTotal > balances.nBlind + with_watchonly * balances.nBlindWatchOnly) {
                throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS, "Insufficient blinded funds");
            }
            break;
        case OUTPUT_RINGCT:
            if (nTotal > balances.nAnon + with_watchonly * balances.nAnonWatchOnly) {
                throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS, "Insufficient anon funds");
            }
            break;
        default:
            throw JSONRPCError(RPC_WALLET_ERROR, strprintf("Unknown input type: %d.", typeIn));
    }

    CAmount nFeeRet = 0;
    switch (typeIn) {
        case OUTPUT_STANDARD:
            if (0 != pwallet->AddStandardInputs(wtx, rtx, vecSend, !fCheckFeeOnly, nFeeRet, &coincontrol, sError)) {
                throw JSONRPCError(RPC_WALLET_ERROR, strprintf("AddStandardInputs failed: %s.", sError));
            }
            break;
        case OUTPUT_CT:
            if (0 != pwallet->AddBlindedInputs(wtx, rtx, vecSend, !fCheckFeeOnly, nFeeRet, &coincontrol, sError)) {
                throw JSONRPCError(RPC_WALLET_ERROR, strprintf("AddBlindedInputs failed: %s.", sError));
            }
            break;
        case OUTPUT_RINGCT:
            if (0 != pwallet->AddAnonInputs(wtx, rtx, vecSend, !fCheckFeeOnly, nRingSize, nInputsPerSig, nFeeRet, &coincontrol, sError)) {
                throw JSONRPCError(RPC_WALLET_ERROR, strprintf("AddAnonInputs failed: %s.", sError));
            }
            break;
        default:
            throw JSONRPCError(RPC_WALLET_ERROR, strprintf("Unknown input type: %d.", typeIn));
    }

    UniValue result(UniValue::VOBJ);
    bool mempool_allowed = false;
    if (fTestMempoolAccept) {
        std::string mempool_test_error;
        mempool_allowed = pwallet->TestMempoolAccept(wtx.tx, mempool_test_error);
        if (!mempool_allowed) {
            result.pushKV("mempool-reject-reason", mempool_test_error);
        }
        result.pushKV("mempool-allowed", mempool_allowed);
    }
    if (fCheckFeeOnly || fShowFee || fTestMempoolAccept || !fSubmitTx || fShowHex) {
        if (fDebug) {
            result.pushKV("fee", nFeeRet);
        } else {
            result.pushKV("fee", ValueFromAmount(nFeeRet));
        }
        result.pushKV("bytes", (int)GetVirtualTransactionSize(*(wtx.tx)));
        result.pushKV("need_hwdevice", UniValue(coincontrol.fNeedHardwareKey ? true : false));

        if (fShowHex) {
            std::string strHex = EncodeHexTx(*(wtx.tx), RPCSerializationFlags());
            result.pushKV("hex", strHex);
        }

        UniValue objChangedOutputs(UniValue::VOBJ);
        std::map<std::string, CAmount> mapChanged; // Blinded outputs are split, join the values for display
        for (const auto &r : vecSend) {
            if (!r.fChange
                && r.nAmount != r.nAmountSelected) {
                std::string sAddr = CBitcoinAddress(r.address).ToString();

                if (mapChanged.count(sAddr)) {
                    mapChanged[sAddr] += r.nAmount;
                } else {
                    mapChanged[sAddr] = r.nAmount;
                }
            }
        }

        for (const auto &v : mapChanged) {
            objChangedOutputs.pushKV(v.first, v.second);
        }

        result.pushKV("outputs_fee", objChangedOutputs);
        if (fCheckFeeOnly || (fTestMempoolAccept && !mempool_allowed) || !fSubmitTx) {
            return result;
        }
    }

    // Store sent narrations
    for (const auto &r : vecSend) {
        if (r.nType != OUTPUT_STANDARD
            || r.sNarration.size() < 1) {
            continue;
        }
        std::string sKey = strprintf("n%d", r.n);
        wtx.mapValue[sKey] = r.sNarration;
    }

    TxValidationState state;
    bool is_record = !(typeIn == OUTPUT_STANDARD && typeOut == OUTPUT_STANDARD);
    if (!pwallet->CommitTransaction(wtx, rtx, state, wtx.mapValue, wtx.vOrderForm, is_record)) {
        throw JSONRPCError(RPC_WALLET_ERROR, strprintf("Transaction commit failed: %s", state.ToString()));
    }

    /*
    UniValue vErrors(UniValue::VARR);
    if (!state.IsValid()) // Should be caught in CommitTransaction
    {
        // This can happen if the mempool rejected the transaction.  Report
        // what happened in the "errors" response.
        vErrors.push_back(strprintf("Error: The transaction was rejected: %s", state.ToString()));

        UniValue result(UniValue::VOBJ);
        result.pushKV("txid", wtx.GetHash().GetHex());
        result.pushKV("errors", vErrors);
        return result;
    };
    */

    pwallet->PostProcessTempRecipients(vecSend);

    if (fShowFee || fTestMempoolAccept) {
        result.pushKV("txid", wtx.GetHash().GetHex());
        return result;
    } else {
        return wtx.GetHash().GetHex();
    }
}

UniValue SendTypeToInner(const JSONRPCRequest &request)
{
    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
    if (!wallet) return NullUniValue;

    std::string sTypeIn = request.params[0].get_str();
    std::string sTypeOut = request.params[1].get_str();

    OutputTypes typeIn = WordToType(sTypeIn);
    OutputTypes typeOut = WordToType(sTypeOut);

    if (typeIn == OUTPUT_NULL) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Unknown input type.");
    }
    if (typeOut == OUTPUT_NULL) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Unknown output type.");
    }

    JSONRPCRequest req = request;
    req.params.erase(0, 2);

    return SendToInner(req, typeIn, typeOut);
}

static RPCHelpMan sendtypeto()
{
    return RPCHelpMan{"sendtypeto",
                "\nSend part to multiple outputs." +
                HELP_REQUIRING_PASSPHRASE,
                {
                    {"typein", RPCArg::Type::STR, RPCArg::Optional::NO, "part/blind/anon"},
                    {"typeout", RPCArg::Type::STR, RPCArg::Optional::NO, "part/blind/anon"},
                    {"outputs", RPCArg::Type::ARR, RPCArg::Optional::NO, "A json array of json objects",
                        {
                            {"", RPCArg::Type::OBJ, RPCArg::Optional::NO, "",
                                {
                                    {"address", RPCArg::Type::STR, RPCArg::Default{""}, "The particl address to send to."},
                                    {"amount", RPCArg::Type::AMOUNT, RPCArg::Default{""}, "The amount in " + CURRENCY_UNIT + " to send. eg 0.1."},
                                    {"narr", RPCArg::Type::STR, RPCArg::Default{""}, "Up to 24 character narration sent with the transaction."},
                                    {"blindingfactor", RPCArg::Type::STR_HEX, RPCArg::Default{""}, "The blinding factor, 32 bytes and hex encoded."},
                                    {"subfee", RPCArg::Type::BOOL, RPCArg::Default{""}, "The fee will be deducted from the amount being sent."},
                                    {"script", RPCArg::Type::STR_HEX, RPCArg::Default{""}, "Hex encoded script, will override the address. \"address\" must be set to a blank string or placeholder value when \"script\" is used. "},
                                    {"stakeaddress", RPCArg::Type::STR, RPCArg::Default{""}, "If set the output will be sent to a coldstaking script."},
                                },
                            },
                        },
                    },
                    {"comment", RPCArg::Type::STR, RPCArg::Default{""}, "A comment used to store what the transaction is for.\n"
            "                             This is not part of the transaction, just kept in your wallet."},
                    {"comment_to", RPCArg::Type::STR, RPCArg::Default{""}, "A comment to store the name of the person or organization\n"
            "                             to which you're sending the transaction. This is not part of the \n"
            "                             transaction, just kept in your wallet."},
                    {"ringsize", RPCArg::Type::NUM, RPCArg::Default{(int)DEFAULT_RING_SIZE}, "Only applies when typein is anon."},
                    {"inputs_per_sig", RPCArg::Type::NUM, RPCArg::Default{(int)DEFAULT_INPUTS_PER_SIG}, "Only applies when typein is anon."},
                    {"test_fee", RPCArg::Type::BOOL, RPCArg::Default{false}, "Only return the fee it would cost to send, txn is discarded."},
                    {"coin_control", RPCArg::Type::OBJ, RPCArg::Default{UniValue::VOBJ}, "",
                        {
                            {"changeaddress", RPCArg::Type::STR, RPCArg::Default{""}, "The particl address to receive the change"},
                            {"inputs", RPCArg::Type::ARR, RPCArg::Default{UniValue::VARR}, "A json array of json objects",
                                {
                                    {"", RPCArg::Type::OBJ, RPCArg::Default{UniValue::VOBJ}, "",
                                        {
                                            {"tx", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "txn id"},
                                            {"n", RPCArg::Type::NUM, RPCArg::Optional::NO, "txn vout"},
                                        },
                                    },
                                },
                            },
                            {"replaceable", RPCArg::Type::BOOL, RPCArg::DefaultHint{"wallet default"}, "Marks this transaction as BIP125 replaceable.\n"
                            "                              Allows this transaction to be replaced by a transaction with higher fees"},
                            {"conf_target", RPCArg::Type::NUM, RPCArg::Default{""}, "Confirmation target (in blocks)"},
                            {"estimate_mode", RPCArg::Type::STR, RPCArg::Default{"UNSET"}, "The fee estimate mode, must be one of:\n"
                            "         \"UNSET\"\n"
                            "         \"ECONOMICAL\"\n"
                            "         \"CONSERVATIVE\""},
                            {"avoid_reuse", RPCArg::Type::BOOL, RPCArg::Default{true}, "(only available if avoid_reuse wallet flag is set) Avoid spending from dirty addresses; addresses are considered\n"
                            "                             dirty if they have previously been used in a transaction."},
                            {"feeRate", RPCArg::Type::AMOUNT, RPCArg::Default{"not set: makes wallet determine the fee"}, "Set a specific fee rate in " + CURRENCY_UNIT + "/kB"},
                            {"blind_watchonly_visible", RPCArg::Type::BOOL, RPCArg::Default{false}, "Reveal amounts of blinded outputs sent to stealth addresses to the scan_secret"},
                            {"spend_frozen_blinded", RPCArg::Type::BOOL, RPCArg::Default{false}, "Enable spending frozen blinded outputs"},
                            {"test_mempool_accept", RPCArg::Type::BOOL, RPCArg::Default{false}, "Test if transaction would be accepted to the mempool, return if not"},
                            {"use_mixins", RPCArg::Type::ARR, RPCArg::Default{UniValue::VARR}, "A json array of anonoutput indices to use as mixins",
                                {
                                    {"ao_index", RPCArg::Type::NUM, RPCArg::Default{""}, "anonoutput index"},
                                },
                            },
                            {"mixin_selection_mode", RPCArg::Type::NUM, RPCArg::Default{""}, "Mixin selection mode: 1 select from ranges, 2 select nearby, 3 random full range"},
                            {"show_hex", RPCArg::Type::BOOL, RPCArg::Default{false}, "Display the hex encoded tx"},
                            {"show_fee", RPCArg::Type::BOOL, RPCArg::Default{false}, "Return the fee"},
                            {"submit_tx", RPCArg::Type::BOOL, RPCArg::Default{true}, "Send the tx"},
                            {"includeWatching", RPCArg::Type::BOOL, RPCArg::Default{false}, "Also select inputs which are watch only."},
                            {"minimumAmount", RPCArg::Type::AMOUNT, RPCArg::Default{FormatMoney(0)}, "Minimum value of each UTXO to select in " + CURRENCY_UNIT + ""},
                            {"maximumAmount", RPCArg::Type::AMOUNT, RPCArg::DefaultHint{"unlimited"}, "Maximum value of each UTXO to select in " + CURRENCY_UNIT + ""},
                        },
                    },
                },
                {
                    RPCResult{"Default", RPCResult::Type::STR_HEX, "", "The transaction id"},
                    RPCResult{"With certain options", RPCResult::Type::OBJ, "", "", {
                        {RPCResult::Type::STR_HEX, "txid", "The transaction id"}
                    }}
                },
                RPCExamples{
            HelpExampleCli("sendtypeto", "anon part \"[{\\\"address\\\":\\\"PbpVcjgYatnkKgveaeqhkeQBFwjqR7jKBR\\\",\\\"amount\\\":0.1}]\"")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    return SendTypeToInner(request);
},
    };
}


static UniValue createsignatureinner(const JSONRPCRequest &request, ChainstateManager *pchainman, CHDWallet *const pwallet)
{
    RPCTypeCheck(request.params, {UniValue::VSTR, UniValue::VOBJ, UniValue::VSTR, UniValue::VSTR}, true);

    CMutableTransaction mtx;
    if (!DecodeHexTx(mtx, request.params[0].get_str(), true)) {
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "TX decode failed");
    }

    UniValue prevOut = request.params[1].get_obj();

    RPCTypeCheckObj(prevOut,
        {
            {"txid", UniValueType(UniValue::VSTR)},
            {"vout", UniValueType(UniValue::VNUM)},
        }, true);

    uint256 txid = ParseHashO(prevOut, "txid");

    int nOut = find_value(prevOut, "vout").get_int();
    if (nOut < 0) {
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "vout must be positive");
    }

    COutPoint prev_out(txid, nOut);

    // Find the prevout if it exists in the wallet or chain
    CTxOutBaseRef txout;
    CTxMemPool *mempool = nullptr;
    if (pwallet) {
        LOCK(pwallet->cs_wallet);
        pwallet->GetPrevout(prev_out, txout);
        mempool = pwallet->HaveChain() ? pwallet->chain().getMempool() : nullptr;
    } else {
        mempool = &EnsureAnyMemPool(request.context);
    }
    if (!txout.get()) {
        // Try fetch from utxodb first
        LOCK(cs_main);
        Coin coin;
        if (pchainman->ActiveChainstate().CoinsTip().GetCoin(prev_out, coin)) {
            if (coin.nType == OUTPUT_STANDARD) {
                txout = MAKE_OUTPUT<CTxOutStandard>(coin.out.nValue, coin.out.scriptPubKey);
            } else {
                txout = MAKE_OUTPUT<CTxOutCT>();
                CTxOutCT *txoct = (CTxOutCT*)txout.get();
                txoct->commitment = coin.commitment;
                txoct->scriptPubKey = coin.out.scriptPubKey;
            }
        } else {
            uint256 hashBlock;
            CTransactionRef txn = GetTransaction(nullptr, mempool, prev_out.hash, Params().GetConsensus(), hashBlock);
            if (txn) {
                if (txn->GetNumVOuts() > prev_out.n) {
                    txout = txn->vpout[prev_out.n];
                }
            }
        }
    }

    CScript scriptRedeem, scriptPubKey;
    if (prevOut.exists("scriptPubKey")) {
        std::vector<unsigned char> pkData(ParseHexO(prevOut, "scriptPubKey"));
        scriptPubKey = CScript(pkData.begin(), pkData.end());
    } else {
        if (txout.get() && txout->GetPScriptPubKey()) {
            const CScript *ps = txout->GetPScriptPubKey();
            scriptPubKey = CScript(ps->begin(), ps->end());
        } else {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "\"scriptPubKey\" is required");
        }
    }

    std::vector<uint8_t> vchAmount;
    if (prevOut.exists("amount")) {
        if (prevOut.exists("amount_commitment")) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Both \"amount\" and \"amount_commitment\" found.");
        }
        CAmount nValue = AmountFromValue(prevOut["amount"]);
        vchAmount.resize(8);
        part::SetAmount(vchAmount, nValue);
    } else
    if (prevOut.exists("amount_commitment")) {
        std::string s = prevOut["amount_commitment"].get_str();
        if (!IsHex(s) || !(s.size() == 66)) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "\"amount_commitment\" must be 33 bytes and hex encoded.");
        }
        vchAmount = ParseHex(s);
    } else {
        if (!txout.get() || !txout->PutValue(vchAmount)) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "\"amount\" or \"amount_commitment\" is required");
        }
    }

    if (prevOut.exists("redeemScript")) {
        std::vector<unsigned char> redeemData(ParseHexO(prevOut, "redeemScript"));
        scriptRedeem = CScript(redeemData.begin(), redeemData.end());
    } else
    if (scriptPubKey.IsPayToScriptHashAny(mtx.IsCoinStake())) {
        if (pwallet) {
            CTxDestination redeemDest;
            std::unique_ptr<SigningProvider> provider = pwallet->GetSolvingProvider(scriptPubKey);
            if (ExtractDestination(scriptPubKey, redeemDest)) {
                if (redeemDest.index() == DI::_ScriptHash) {
                    const CScriptID& scriptID = CScriptID(std::get<ScriptHash>(redeemDest));
                    provider->GetCScript(scriptID, scriptRedeem);
                } else
                if (redeemDest.index() == DI::_CScriptID256) {
                    const CScriptID256& hash = std::get<CScriptID256>(redeemDest);
                    CScriptID scriptID;
                    scriptID.Set(hash);
                    provider->GetCScript(scriptID, scriptRedeem);
                }
            }
        }

        if (scriptRedeem.size() == 0) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "\"redeemScript\" is required");
        }
    }

    FillableSigningProvider keystore, *pkeystore;
    CKeyID idSign;
    if (pwallet) {
        CTxDestination destSign = DecodeDestination(request.params[2].get_str());
        if (!IsValidDestination(destSign)) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid address");
        }

        if (destSign.index() == DI::_PKHash) {
            idSign = ToKeyID(std::get<PKHash>(destSign));
        } else {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Unsupported signing key type.");
        }
        pkeystore = pwallet->GetLegacyScriptPubKeyMan();
    } else {
        std::string strPrivkey = request.params[2].get_str();
        CKey key = DecodeSecret(strPrivkey);
        if (!key.IsValid()) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid private key");
        }

        keystore.AddKey(key);
        idSign = key.GetPubKey().GetID();
        pkeystore = &keystore;
    }

    const UniValue &hashType = request.params[3];
    int nHashType = SIGHASH_ALL;
    if (!hashType.isNull()) {
        static std::map<std::string, int> mapSigHashValues = {
            {std::string("ALL"), int(SIGHASH_ALL)},
            {std::string("ALL|ANYONECANPAY"), int(SIGHASH_ALL|SIGHASH_ANYONECANPAY)},
            {std::string("NONE"), int(SIGHASH_NONE)},
            {std::string("NONE|ANYONECANPAY"), int(SIGHASH_NONE|SIGHASH_ANYONECANPAY)},
            {std::string("SINGLE"), int(SIGHASH_SINGLE)},
            {std::string("SINGLE|ANYONECANPAY"), int(SIGHASH_SINGLE|SIGHASH_ANYONECANPAY)},
        };
        std::string strHashType = hashType.get_str();
        if (mapSigHashValues.count(strHashType)) {
            nHashType = mapSigHashValues[strHashType];
        } else {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid sighash param");
        }
    }

    SigVersion sigversion = SigVersion::BASE;
    if (!request.params[4].isNull()) {
        const UniValue &options = request.params[4].get_obj();
        if (options.exists("force_segwit") && options["force_segwit"].get_bool()) {
            sigversion = SigVersion::WITNESS_V0;
        }
    }

    // Sign the transaction
    std::vector<uint8_t> vchSig;
    unsigned int i;
    for (i = 0; i < mtx.vin.size(); i++) {
        CTxIn& txin = mtx.vin[i];

        if (txin.prevout == prev_out) {
            MutableTransactionSignatureCreator creator(&mtx, i, vchAmount, nHashType);
            CScript &scriptSig = (sigversion == SigVersion::WITNESS_V0
                                  || scriptPubKey.IsPayToScriptHashAny(mtx.IsCoinStake()))
                                 ? scriptRedeem : scriptPubKey;

            if (!creator.CreateSig(*pkeystore, vchSig, idSign, scriptSig, sigversion)) {
                throw JSONRPCError(RPC_MISC_ERROR, "CreateSig failed.");
            }
            break;
        }
    }

    if (i >= mtx.vin.size()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "No matching input found.");
    }

    return HexStr(vchSig);
}

static RPCHelpMan createsignaturewithwallet()
{
    return RPCHelpMan{"createsignaturewithwallet",
                "\nSign inputs for raw transaction (serialized, hex-encoded)." +
                HELP_REQUIRING_PASSPHRASE,
                {
                    {"hexstring", RPCArg::Type::STR, RPCArg::Optional::NO, "The transaction hex string."},
                    {"prevtxn", RPCArg::Type::OBJ, RPCArg::Optional::NO, "The previous output to sign for",
                        {
                            {"txid", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The transaction id"},
                            {"vout", RPCArg::Type::NUM, RPCArg::Optional::NO, "The output number"},
                            {"scriptPubKey", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "script key"},
                            {"redeemScript", RPCArg::Type::STR_HEX, RPCArg::Default{""}, "(required for P2SH or P2WSH)"},
                            {"amount", RPCArg::Type::AMOUNT, RPCArg::Optional::NO, "The amount spent"},
                            {"amount_commitment", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The amount commitment spent"},
                        }, "prevtxn"
                    },
                    {"address", RPCArg::Type::STR, RPCArg::Optional::NO, "The address of the private key to sign with."},
                    {"sighashtype", RPCArg::Type::STR, RPCArg::Default{"ALL"}, "The signature hash type. Must be one of\n"
            "       \"ALL\"\n"
            "       \"NONE\"\n"
            "       \"SINGLE\"\n"
            "       \"ALL|ANYONECANPAY\"\n"
            "       \"NONE|ANYONECANPAY\"\n"
            "       \"SINGLE|ANYONECANPAY\""},
                    {"options", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED_NAMED_ARG, "JSON with options",
                        {
                            {"force_segwit", RPCArg::Type::BOOL, RPCArg::Default{false}, "Force creating a segwit compatible signature"},
                        },
                        "options"},
                },
                RPCResult{
                    RPCResult::Type::STR_HEX, "", "The hex encoded signature",
                },
                RPCExamples{
            HelpExampleCli("createsignaturewithwallet", "\"myhex\" \"{\\\"txid\\\":\\\"hex\\\",\\\"vout\\\":n}\" \"myaddress\"") +
            "\nAs a JSON-RPC call\n"
            + HelpExampleRpc("createsignaturewithwallet", "\"myhex\", \"{\\\"txid\\\":\\\"hex\\\",\\\"vout\\\":n}\", \"myaddress\"")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
    if (!wallet) return NullUniValue;
    CHDWallet *const pwallet = GetParticlWallet(wallet.get());

    EnsureWalletIsUnlocked(pwallet);
    ChainstateManager *pchainman{nullptr};
    if (pwallet->HaveChain()) {
        pchainman = pwallet->chain().getChainman();
    }
    if (!pchainman) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Chainstate manager not found");
    }


    LOCK(pwallet->cs_wallet);

    return createsignatureinner(request, pchainman, pwallet);
},
    };
}

static RPCHelpMan createsignaturewithkey()
{
    return RPCHelpMan{"createsignaturewithkey",
                "\nSign inputs for raw transaction (serialized, hex-encoded).\n",
                {
                    {"hexstring", RPCArg::Type::STR, RPCArg::Optional::NO, "The transaction hex string."},
                    {"prevtxn", RPCArg::Type::OBJ, RPCArg::Optional::NO, "The previous output to sign for",
                        {
                            {"txid", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The transaction id"},
                            {"vout", RPCArg::Type::NUM, RPCArg::Optional::NO, "The output number"},
                            {"scriptPubKey", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "script key"},
                            {"redeemScript", RPCArg::Type::STR_HEX, RPCArg::Default{""}, "(required for P2SH or P2WSH)"},
                            {"amount", RPCArg::Type::AMOUNT, RPCArg::Optional::NO, "The amount spent"},
                            {"amount_commitment", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The amount commitment spent"},
                        }, "prevtxn"
                    },
                    {"privkey", RPCArg::Type::STR, RPCArg::Optional::NO, "A base58-encoded private key to sign with."},
                    {"sighashtype", RPCArg::Type::STR, RPCArg::Default{"ALL"}, "The signature hash type. Must be one of\n"
            "       \"ALL\"\n"
            "       \"NONE\"\n"
            "       \"SINGLE\"\n"
            "       \"ALL|ANYONECANPAY\"\n"
            "       \"NONE|ANYONECANPAY\"\n"
            "       \"SINGLE|ANYONECANPAY\""},
                    {"options", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED_NAMED_ARG, "JSON with options",
                        {
                            {"force_segwit", RPCArg::Type::BOOL, RPCArg::Default{false}, "Force creating a segwit compatible signature"},
                        },
                        "options"},
                },
                RPCResult{
                    RPCResult::Type::STR_HEX, "", "The hex encoded signature",
                },
                RPCExamples{
            HelpExampleCli("createsignaturewithkey", "\"myhex\" \"{\\\"txid\\\":\\\"hex\\\",\\\"vout\\\":n}\" \"myprivkey\"") +
            "\nAs a JSON-RPC call\n"
            + HelpExampleRpc("createsignaturewithkey", "\"myhex\", \"{\\\"txid\\\":\\\"hex\\\",\\\"vout\\\":n}\", \"myprivkey\"")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    ChainstateManager &chainman = EnsureAnyChainman(request.context);
    return createsignatureinner(request, &chainman, nullptr);
},
    };
}

struct TracedOutput {
    int m_n = -1;
    OutputTypes m_type = OUTPUT_NULL;
    CAmount m_value = 0;
    uint256 m_blinding_factor;
    uint256 m_spentby;  // Output could show in multiple tx histories
    bool m_is_spent = false;
    bool m_forced_include = false;
    bool m_spendable = false;
    int64_t m_anon_index = -1;
    CKey m_anon_spend_key;
};
struct TracedTx {
    OutputTypes m_input_type;
    std::string m_wallet_name;
    std::vector<COutPoint> m_inputs;
    std::map<int, TracedOutput> m_outputs;
    CAmount m_input_amount_traced_to_plain = 0;
};

static void traceFrozenPrevout(const COutPoint &op_trace, const uint256 &txid_spentby, std::map<uint256, TracedTx> &traced_txs, UniValue &warnings)
{
    auto mi_tx = traced_txs.find(op_trace.hash);
    if (mi_tx != traced_txs.end()) {
        auto mi_o = mi_tx->second.m_outputs.find(op_trace.n);
        if (mi_o != mi_tx->second.m_outputs.end()) {
            LogPrintf("traceFrozenPrevout: Skipping %s, %d, already have.\n", op_trace.hash.ToString(), op_trace.n);
            return;
        }
    }

    std::vector<std::shared_ptr<CWallet> > wallets = GetWallets();
    for (auto &wallet : wallets) {
        CHDWallet *pwallet = GetParticlWallet(wallet.get());
        CTransactionRecord rtx;
        {
        LOCK(pwallet->cs_wallet);

        MapRecords_t::const_iterator mri = pwallet->mapRecords.find(op_trace.hash);
        if (mri == pwallet->mapRecords.end()) {
            continue;
        }
        rtx = mri->second;
        }

        auto ret = traced_txs.insert(std::pair<uint256, TracedTx>(op_trace.hash, TracedTx()));
        auto &traced_tx = ret.first->second;
        //if (ret.second)  Always search inputs
        traced_tx.m_input_type = rtx.nFlags & ORF_ANON_IN ? OUTPUT_RINGCT : rtx.nFlags & ORF_BLIND_IN ? OUTPUT_CT : OUTPUT_STANDARD;
        std::string wallet_name = pwallet->GetDisplayName();
        if (traced_tx.m_wallet_name.find(wallet_name) == std::string::npos) {
            traced_tx.m_wallet_name += (traced_tx.m_wallet_name.empty() ? "" : ", ") + wallet_name;
        }
        if (traced_tx.m_input_type != OUTPUT_STANDARD) {
            for (const auto &op : rtx.vin) {
                traceFrozenPrevout(op, op_trace.hash, traced_txs, warnings);
                if (std::find(traced_tx.m_inputs.begin(), traced_tx.m_inputs.end(), op) == traced_tx.m_inputs.end()) {
                    traced_tx.m_inputs.push_back(op);
                }
            }
        }

        const COutputRecord *pout = rtx.GetOutput(op_trace.n);
        if (!pout) {
            continue;
        }
        const auto &r = *pout;

        {
        LOCK(pwallet->cs_wallet);
        CHDWalletDB wdb(pwallet->GetDatabase());
        CStoredTransaction stx;
        if (!wdb.ReadStoredTx(op_trace.hash, stx)) {
            warnings.push_back(strprintf("ReadStoredTx failed %s", op_trace.hash.ToString()));
            continue;
        }

        int64_t anon_index = 0;
        CCmpPubKey anon_pubkey;
        if (r.nType == OUTPUT_RINGCT) {
            anon_pubkey = ((CTxOutRingCT*)stx.tx->vpout[r.n].get())->pk;
            if (!pblocktree->ReadRCTOutputLink(anon_pubkey, anon_index)) {
                warnings.push_back(strprintf("ReadRCTOutputLink failed %s", op_trace.ToString()));
            }
        }

        auto ret_to = traced_tx.m_outputs.insert(std::pair<int, TracedOutput>(r.n, TracedOutput()));
        auto &traced_output = ret_to.first->second;
        traced_output.m_type = r.nType == OUTPUT_RINGCT ? OUTPUT_RINGCT : OUTPUT_CT;
        traced_output.m_n = r.n;
        traced_output.m_anon_index = anon_index;
        traced_output.m_spentby = txid_spentby;
        if (traced_output.m_blinding_factor.IsNull()) {
            traced_output.m_value = r.nValue;
            traced_output.m_is_spent = pwallet->IsSpent(op_trace.hash, op_trace.n);
            if (!stx.GetBlind(r.n, traced_output.m_blinding_factor.begin())) {
                warnings.push_back(strprintf("GetBlind failed %s", op_trace.ToString()));
            }
        }
        if (r.nType == OUTPUT_RINGCT && !traced_output.m_anon_spend_key.IsValid()) {
            CKeyID apkid = anon_pubkey.GetID();
            if (!pwallet->GetKey(apkid, traced_output.m_anon_spend_key)) {
                warnings.push_back(strprintf("GetKey failed %s", op_trace.ToString()));
            }
        }
    }
    }
}

static void placeTracedPrevout(const TracedOutput &txo, bool trace_frozen_dump_privkeys, UniValue &rv)
{
    rv.pushKV("n", txo.m_n);
    rv.pushKV("type", txo.m_type == OUTPUT_RINGCT ? "anon" : txo.m_type == OUTPUT_CT ? "blind" : "plain");
    rv.pushKV("value", txo.m_value);
    rv.pushKV("blind", txo.m_blinding_factor.ToString());
    if (txo.m_type == OUTPUT_RINGCT) {
        rv.pushKV("anon_index", txo.m_anon_index);
    }
    rv.pushKV("spent", txo.m_is_spent);
    if (txo.m_is_spent && txo.m_type == OUTPUT_RINGCT
        && txo.m_anon_spend_key.IsValid() && trace_frozen_dump_privkeys) {
        rv.pushKV("anon_spend_key", EncodeSecret(txo.m_anon_spend_key));
    }
    if (!txo.m_spentby.IsNull()) {
        rv.pushKV("spent_by", txo.m_spentby.ToString());
    }
    if (txo.m_forced_include) {
        rv.pushKV("forced_include", txo.m_forced_include);
    }
}

static std::set<std::pair<uint256, uint256> > set_placed;
static void placeTracedInputTxns(const uint256 &spend_txid, const std::vector<COutPoint> &inputs, const std::map<uint256, TracedTx> &traced_txs, bool trace_frozen_dump_privkeys, UniValue &rv)
{
    std::set<uint256> added_txids;

    for (size_t i = 0; i < inputs.size(); ++i) {
        const auto &op = inputs[i];

        CAmount spent_value = 0;
        if (added_txids.count(op.hash)) {
            continue;
        }
        UniValue uvtx(UniValue::VOBJ);
        uvtx.pushKV("txid", op.hash.ToString());

        std::map<uint256, TracedTx>::const_iterator mi = traced_txs.find(op.hash);
        if (mi == traced_txs.end()) {
            continue;
        }
        const auto &tx = mi->second;

        UniValue uv_prevouts(UniValue::VARR);
        for (const auto &itxo : tx.m_outputs) {
            const auto &txo = itxo.second;
            UniValue uv_prevout(UniValue::VOBJ);
            placeTracedPrevout(txo, trace_frozen_dump_privkeys, uv_prevout);
            uv_prevouts.push_back(uv_prevout);

            if (txo.m_spentby == spend_txid) {
                spent_value += txo.m_value;
            }
        }
        uvtx.pushKV("outputs", uv_prevouts);
        uvtx.pushKV("input_type", tx.m_input_type == OUTPUT_RINGCT ? "anon" : tx.m_input_type == OUTPUT_CT ? "blind" : "plain");
        uvtx.pushKV("wallet", tx.m_wallet_name);

        UniValue uv_inputs(UniValue::VARR);
        auto placed_pair = std::make_pair(op.hash, spend_txid);
        if (set_placed.count(placed_pair)) {
            uvtx.pushKV("inputs", "repeat");
        } else {
            placeTracedInputTxns(op.hash, tx.m_inputs, traced_txs, trace_frozen_dump_privkeys, uv_inputs);
            set_placed.insert(placed_pair);
        }
        if (uv_inputs.size() > 0) {
            uvtx.pushKV("inputs", uv_inputs);
        }
        uvtx.pushKV("spent_outputs_value", spent_value);

        rv.push_back(uvtx);
        added_txids.insert(op.hash);
    }
}

static void traceFrozenOutputs(UniValue &rv, CAmount min_value, CAmount max_frozen_output_spendable, const UniValue &uv_extra_outputs, bool trace_frozen_dump_privkeys)
{
    // Dump information necessary for an external script to trace blinded amounts back to plain values
    // Intentionally trace blacklisted anon outputs, will be picked up by the validation script
    UniValue errors(UniValue::VARR);
    UniValue warnings(UniValue::VARR);

    std::map<uint256, TracedTx> traced_txs;
    std::vector<std::shared_ptr<CWallet> > wallets = GetWallets();
    std::set<COutPoint> extra_txouts;  // Trace these outputs even if spent
    std::set<COutPoint> top_level, set_forced;
    int64_t time_now = GetAdjustedTime();

    if (uv_extra_outputs.isArray()) {
        for (size_t i = 0; i < uv_extra_outputs.size(); ++i) {
            const UniValue &uvi = uv_extra_outputs[i];
            RPCTypeCheckObj(uvi,
            {
                {"tx", UniValueType(UniValue::VSTR)},
                {"n", UniValueType(UniValue::VNUM)},
            });
            COutPoint op(ParseHashO(uvi, "tx"), uvi["n"].get_int());
            extra_txouts.insert(op);
        }
    }

    // Ensure all wallets are unlocked
    for (auto &wallet : wallets) {
        CHDWallet *const pwallet = GetParticlWallet(wallet.get());
        if (pwallet->IsLocked() || pwallet->fUnlockForStakingOnly) {
            throw JSONRPCError(RPC_WALLET_UNLOCK_NEEDED,
                strprintf("Error: Wallet %s is locked, please unlock all loaded wallets for this command.", pwallet->GetDisplayName()));
        }
    }

    std::map<uint256, TracedTx> traced_txns;
    CAmount total_traced = 0;
    size_t num_traced = 0;
    size_t num_searched = 0;

    const Consensus::Params &consensusParams = Params().GetConsensus();
    for (auto &wallet : wallets) {
        CHDWallet *pwallet = GetParticlWallet(wallet.get());
        LOCK(pwallet->cs_wallet);

        CHDWalletDB wdb(pwallet->GetDatabase());
        for (MapRecords_t::const_iterator it = pwallet->mapRecords.begin(); it != pwallet->mapRecords.end(); ++it) {
            const uint256 &txid = it->first;
            const CTransactionRecord &rtx = it->second;

            bool in_height = true;
            num_searched += 1;
            if (rtx.block_height < 1 || // height 0 is mempool
                rtx.block_height > consensusParams.m_frozen_blinded_height) {
                in_height = false;
            }

            for (const auto &r : rtx.vout) {
                bool force_include = extra_txouts.count(COutPoint(txid, r.n));
                if (!in_height && !force_include) {
                    continue;
                }
                if ((r.nType != OUTPUT_RINGCT && r.nType != OUTPUT_CT) ||
                    !(r.nFlags & ORF_OWNED) ||
                    r.nValue < min_value) {
                    if (!force_include) {
                        continue;
                    }
                }

                bool is_spent = pwallet->IsSpent(txid, r.n);
                if (is_spent && !force_include) {
                    continue;
                }

                bool is_spendable = true;
                int64_t anon_index = -1;
                if (r.nType == OUTPUT_RINGCT) {
                    CStoredTransaction stx;
                    if (!wdb.ReadStoredTx(txid, stx) ||
                        !stx.tx->vpout[r.n]->IsType(OUTPUT_RINGCT) ||
                        !pblocktree->ReadRCTOutputLink(((CTxOutRingCT*)stx.tx->vpout[r.n].get())->pk, anon_index)) {
                        warnings.push_back(strprintf("Failed to get anon index for %s.%d", txid.ToString(), r.n));
                        continue;
                    }
                    if (IsBlacklistedAnonOutput(anon_index)) {
                        is_spendable = false;
                    }
                }
                if (r.nValue > max_frozen_output_spendable) {
                    // TODO: Store pubkey on COutputRecord - in scriptPubKey
                    if (r.nType == OUTPUT_RINGCT) {
                        if (!IsWhitelistedAnonOutput(anon_index, time_now, consensusParams)) {
                            is_spendable = false;
                        }
                    } else
                    if (r.nType == OUTPUT_CT) {
                        if (IsFrozenBlindOutput(txid)) {
                            is_spendable = false;
                        }
                    }
                }
                if (is_spendable) {
                    if (!force_include) {
                        continue;
                    }
                }
                COutPoint op_trace(txid, r.n);
                if (top_level.count(op_trace)) {
                    continue;
                }
                total_traced += r.nValue;
                num_traced++;

                top_level.insert(op_trace);
                if (force_include) {
                    set_forced.insert(op_trace);
                }
            }
        }
    }

    for (const auto &op : top_level) {
        uint256 spent_by; // null
        traceFrozenPrevout(op, spent_by, traced_txns, warnings);
        auto ret = traced_txns.insert(std::pair<uint256, TracedTx>(op.hash, TracedTx()));
        auto &traced_tx = ret.first->second;

        if (set_forced.count(op)) {
            traced_tx.m_outputs[op.n].m_forced_include = true;
        }
    }

    // Fill in all known tx outputs, external script needs to know them all to check tx outputs == txinputs
    for (auto &wallet : wallets) {
        CHDWallet *pwallet = GetParticlWallet(wallet.get());
        LOCK(pwallet->cs_wallet);

        CHDWalletDB wdb(pwallet->GetDatabase());
        for (MapRecords_t::const_iterator it = pwallet->mapRecords.begin(); it != pwallet->mapRecords.end(); ++it) {
            const uint256 &txid = it->first;
            const CTransactionRecord &rtx = it->second;

            std::map<uint256, TracedTx>::iterator traced_txnsi = traced_txns.find(txid);
            if (traced_txnsi == traced_txns.end()) {
                continue;
            }
            TracedTx &traced_tx = traced_txnsi->second;

            CStoredTransaction stx;
            if (!wdb.ReadStoredTx(txid, stx)) {
                warnings.push_back(strprintf("ReadStoredTx failed %s", txid.ToString()));
                continue;
            }
            for (const auto &r : rtx.vout) {
                if ((r.nType != OUTPUT_RINGCT && r.nType != OUTPUT_CT) ||
                    !(r.nFlags & ORF_OWNED)) {
                    continue;
                }
                if (traced_tx.m_outputs.count(r.n)) {
                    continue;
                }
                TracedOutput traced_output;
                traced_output.m_type = r.nType == OUTPUT_RINGCT ? OUTPUT_RINGCT : OUTPUT_CT;
                traced_output.m_value = r.nValue;
                traced_output.m_n = r.n;
                if (r.nType == OUTPUT_RINGCT &&
                    !pblocktree->ReadRCTOutputLink(((CTxOutRingCT*)stx.tx->vpout[r.n].get())->pk, traced_output.m_anon_index)) {
                    warnings.push_back(strprintf("ReadRCTOutputLink failed %s %d", txid.ToString(), r.n));
                }
                traced_output.m_is_spent = pwallet->IsSpent(txid, r.n);
                if (!stx.GetBlind(r.n, traced_output.m_blinding_factor.begin())) {
                    warnings.push_back(strprintf("GetBlind failed %s %d", txid.ToString(), r.n));
                }
                traced_tx.m_outputs[r.n] = traced_output;
            }
        }
    }

    UniValue rv_txns(UniValue::VARR);
    std::set<uint256> set_added;
    for (const auto &op : top_level) {
        if (set_added.count(op.hash)) {
            continue;
        }
        set_added.insert(op.hash);
        UniValue rv_tx(UniValue::VOBJ);
        rv_tx.pushKV("txid", op.hash.ToString());

        const auto &tx = traced_txns[op.hash];
        UniValue uv_outputs(UniValue::VARR);
        for (const auto &itxo : tx.m_outputs) {
            const auto &txo = itxo.second;
            UniValue uvo(UniValue::VOBJ);
            placeTracedPrevout(txo, trace_frozen_dump_privkeys, uvo);
            uv_outputs.push_back(uvo);
        }
        rv_tx.pushKV("outputs", uv_outputs);
        rv_tx.pushKV("input_type", tx.m_input_type == OUTPUT_RINGCT ? "anon" : tx.m_input_type == OUTPUT_CT ? "blind" : "plain");
        rv_tx.pushKV("wallet", tx.m_wallet_name);

        UniValue uv_inputs(UniValue::VARR);
        placeTracedInputTxns(op.hash, tx.m_inputs, traced_txns, trace_frozen_dump_privkeys, uv_inputs);
        if (uv_inputs.size() > 0) {
            rv_tx.pushKV("inputs", uv_inputs);
        }

        rv_txns.push_back(rv_tx);
    }
    set_placed.clear();

    LogPrintf("traceFrozenOutputs() searched %d transactions.\n", num_searched);

    rv.pushKV("transactions", rv_txns);
    rv.pushKV("num_traced", (int)num_traced);
    rv.pushKV("total_traced", total_traced);

    if (warnings.size() > 0) {
        rv.pushKV("warnings", warnings);
    }
    if (errors.size() > 0) {
        rv.pushKV("errors", errors);
    }
}

static RPCHelpMan debugwallet()
{
    return RPCHelpMan{"debugwallet",
                "\nDetect problems in wallet." +
                HELP_REQUIRING_PASSPHRASE,
                {
                    {"options", RPCArg::Type::OBJ, RPCArg::Default{UniValue::VOBJ}, "JSON with options",
                        {
                            {"list_frozen_outputs", RPCArg::Type::BOOL, RPCArg::Default{false}, "List frozen anon and blinded outputs."},
                            {"spend_frozen_output", RPCArg::Type::BOOL, RPCArg::Default{false}, "Withdraw one frozen output to plain balance."},
                            {"trace_frozen_outputs", RPCArg::Type::BOOL, RPCArg::Default{false}, "Attempt to trace frozen blinded outputs back to plain inputs.\n"
                                                                                                "Will search all loaded wallets.\n"
                                                                                                "All loaded wallets must be unlocked."},
                            {"trace_frozen_extra", RPCArg::Type::ARR, RPCArg::Default{UniValue::VARR}, "A json array of extra outputs to trace, use with trace_frozen_outputs.",
                                {
                                    {"", RPCArg::Type::OBJ, RPCArg::Default{UniValue::VOBJ}, "",
                                        {
                                            {"tx", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "txn id"},
                                            {"n", RPCArg::Type::NUM, RPCArg::Optional::NO, "txn vout"},
                                        },
                                    },
                                },
                            },
                            {"trace_frozen_dump_privkeys", RPCArg::Type::BOOL, RPCArg::Default{false}, "Dump anon spending keys, use with trace_frozen_outputs."},
                            {"max_frozen_output_spendable", RPCArg::Type::AMOUNT, RPCArg::Default{"unset"}, "Override the default value over which frozen outputs need to be explicitly whitelisted."},
                            {"attempt_repair", RPCArg::Type::BOOL, RPCArg::Default{""}, "Attempt to repair if possible."},
                            {"clear_stakes_seen", RPCArg::Type::BOOL, RPCArg::Default{false}, "Clear seen stakes - for use in regtest networks."},
                            {"downgrade_wallets", RPCArg::Type::BOOL, RPCArg::Default{false}, "Downgrade all loaded wallets for older releases then shutdown.\n"
                                                                                             "All loaded wallets must be unlocked."},
                            {"exit_ibd", RPCArg::Type::BOOL, RPCArg::Default{false}, "Exit initial block download state."},
                        },
                        "options"},
                },
                RPCResult{
                    RPCResult::Type::ANY, "", ""
                },
                RPCExamples{
                    HelpExampleCli("debugwallet", "\"{\\\"attempt_repair\\\":true}\"") + "\n"},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
    if (!wallet) return NullUniValue;
    CHDWallet *const pwallet = GetParticlWallet(wallet.get());

    // Make sure the results are valid at least up to the most recent block
    // the user could have gotten from another RPC command prior to now
    pwallet->BlockUntilSyncedToCurrentChain();

    bool list_frozen_outputs = false;
    bool spend_frozen_output = false;
    bool trace_frozen_outputs = false;
    bool trace_frozen_dump_privkeys = false;
    bool attempt_repair = false;
    bool clear_stakes_seen = false;
    bool downgrade_wallets = false;
    bool exit_ibd = false;
    CAmount max_frozen_output_spendable = Params().GetConsensus().m_max_tainted_value_out;
    int64_t time_now = GetAdjustedTime();

    if (!request.params[0].isNull()) {
        const UniValue &options = request.params[0].get_obj();
        RPCTypeCheckObj(options,
            {
                {"list_frozen_outputs",                 UniValueType(UniValue::VBOOL)},
                {"spend_frozen_output",                 UniValueType(UniValue::VBOOL)},
                {"trace_frozen_outputs",                UniValueType(UniValue::VBOOL)},
                {"trace_frozen_extra",                  UniValueType(UniValue::VARR)},
                {"trace_frozen_dump_privkeys",          UniValueType(UniValue::VBOOL)},
                {"attempt_repair",                      UniValueType(UniValue::VBOOL)},
                {"clear_stakes_seen",                   UniValueType(UniValue::VBOOL)},
                {"downgrade_wallets",                   UniValueType(UniValue::VBOOL)},
                {"max_frozen_output_spendable",         UniValueType()},
                {"exit_ibd",                            UniValueType(UniValue::VBOOL)},
            }, true, true);
        if (options.exists("list_frozen_outputs")) {
            list_frozen_outputs = options["list_frozen_outputs"].get_bool();
        }
        if (options.exists("spend_frozen_output")) {
            spend_frozen_output = options["spend_frozen_output"].get_bool();
        }
        if (options.exists("trace_frozen_outputs")) {
            trace_frozen_outputs = options["trace_frozen_outputs"].get_bool();
        }
        if (options.exists("trace_frozen_dump_privkeys")) {
            trace_frozen_dump_privkeys = options["trace_frozen_dump_privkeys"].get_bool();
        }
        if (options.exists("attempt_repair")) {
            attempt_repair = options["attempt_repair"].get_bool();
        }
        if (options.exists("clear_stakes_seen")) {
            clear_stakes_seen = options["clear_stakes_seen"].get_bool();
        }
        if (options.exists("downgrade_wallets")) {
            downgrade_wallets = options["downgrade_wallets"].get_bool();
        }
        if (options.exists("max_frozen_output_spendable")) {
            max_frozen_output_spendable = AmountFromValue(options["max_frozen_output_spendable"]);
        }
        if (options.exists("exit_ibd")) {
            exit_ibd = options["exit_ibd"].get_bool();
        }
    }
    if (list_frozen_outputs + spend_frozen_output + trace_frozen_outputs > 1) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Multiple frozen blinded methods selected.");
    }

    UniValue result(UniValue::VOBJ);
    UniValue errors(UniValue::VARR);
    UniValue warnings(UniValue::VARR);

    CAmount min_frozen_blinded_value = 10000;

    if (trace_frozen_outputs) {
        const UniValue &options = request.params[0].get_obj();
        UniValue empty_array(UniValue::VARR);
        const UniValue &extra_outputs = options.exists("trace_frozen_extra") ? options["trace_frozen_extra"] : empty_array;
        traceFrozenOutputs(result, min_frozen_blinded_value, max_frozen_output_spendable, extra_outputs, trace_frozen_dump_privkeys);
        return result;
    }

    if (exit_ibd) {
        pwallet->chain().getChainman()->ActiveChainstate().m_cached_finished_ibd = true;
        return "Exited IBD.";
    }

    if (downgrade_wallets) {
        std::vector<std::shared_ptr<CWallet> > wallets = GetWallets();
        for (auto &wallet : wallets) {
            CHDWallet *pw = GetParticlWallet(wallet.get());
            pw->Downgrade();
        }
        StartShutdown();
        return "Wallet downgraded - Shutting down.";
    }

    EnsureWalletIsUnlocked(pwallet);

    if (list_frozen_outputs || spend_frozen_output) {
        {
        LOCK(pwallet->cs_wallet);

        CHDWalletDB wdb(pwallet->GetDatabase());

        UniValue blinded_outputs(UniValue::VARR);
        CAmount total_spendable = 0;
        CAmount total_unspendable = 0;
        size_t num_spendable = 0, num_unspendable = 0;

        const Consensus::Params &consensusParams = Params().GetConsensus();
        bool exploit_fix_2_active = GetTime() >= consensusParams.exploit_fix_2_time;
        for (MapRecords_t::const_iterator it = pwallet->mapRecords.begin(); it != pwallet->mapRecords.end(); ++it) {
            const uint256 &txid = it->first;
            const CTransactionRecord &rtx = it->second;

            if (rtx.block_height < 1 || // height 0 is mempool
                rtx.block_height > consensusParams.m_frozen_blinded_height) {
                continue;
            }

            for (const auto &r : rtx.vout) {
                if ((r.nType != OUTPUT_RINGCT && r.nType != OUTPUT_CT) ||
                    !(r.nFlags & ORF_OWNED) ||
                    r.nValue < min_frozen_blinded_value ||
                    pwallet->IsSpent(txid, r.n)) {
                    continue;
                }

                bool is_spendable = true;
                int64_t anon_index = 0;
                // TODO: Store pubkey on COutputRecord - in scriptPubKey
                if (r.nType == OUTPUT_RINGCT) {
                    CStoredTransaction stx;

                    if (!wdb.ReadStoredTx(txid, stx) ||
                        !stx.tx->vpout[r.n]->IsType(OUTPUT_RINGCT) ||
                        !pblocktree->ReadRCTOutputLink(((CTxOutRingCT*)stx.tx->vpout[r.n].get())->pk, anon_index) ||
                        IsBlacklistedAnonOutput(anon_index) ||
                        (!IsWhitelistedAnonOutput(anon_index, time_now, consensusParams) && r.nValue > max_frozen_output_spendable)) {
                        is_spendable = false;
                    }
                } else
                if (r.nType == OUTPUT_CT) {
                    if (IsFrozenBlindOutput(txid) && r.nValue > max_frozen_output_spendable) {
                        is_spendable = false;
                    }
                }
                if (is_spendable) {
                    total_spendable += r.nValue;
                    num_spendable++;
                } else {
                    total_unspendable += r.nValue;
                    num_unspendable++;
                }
                UniValue output(UniValue::VOBJ);
                output.pushKV("type", r.nType == OUTPUT_RINGCT ? "anon" : "blind");
                output.pushKV("spendable", is_spendable);
                output.pushKV("txid", txid.ToString());
                output.pushKV("n", r.n);
                output.pushKV("amount", ValueFromAmount(r.nValue));
                if (r.nType == OUTPUT_RINGCT) {
                    output.pushKV("anon_index", (int)anon_index);
                    if (IsBlacklistedAnonOutput(anon_index)) {
                        output.pushKV("blacklisted", true);
                    }
                }
                blinded_outputs.push_back(output);
            }
        }

        // Sort
        std::vector<UniValue> &values = blinded_outputs.getValues_nc();
        std::sort(values.begin(), values.end(), [] (const UniValue &a, const UniValue &b) -> bool {
            return a["amount"].get_real() > b["amount"].get_real();
        });

        if (list_frozen_outputs) {
            result.pushKV("frozen_outputs", blinded_outputs);
            result.pushKV("num_spendable", (int)num_spendable);
            result.pushKV("total_spendable", ValueFromAmount(total_spendable));
            result.pushKV("num_unspendable", (int)num_unspendable);
            result.pushKV("total_unspendable", ValueFromAmount(total_unspendable));
            return result;
        }

        // spend_frozen_output
        if (!exploit_fix_2_active) {
            result.pushKV("error", "Exploit repair fork is not active yet.");
            return result;
        }
        if (num_spendable < 1) {
            result.pushKV("error", "No spendable outputs.");
            return result;
        }

        // Withdraw the largest spendable frozen blinded output
        for (const auto &v : values) {
            if (!v["spendable"].get_bool()) {
                continue;
            }
            std::string label = "Redeem frozen blinded";
            CPubKey pubkey;
            if (0 != pwallet->NewKeyFromAccount(pubkey, false, false, false, false, label.c_str())) {
                throw JSONRPCError(RPC_WALLET_ERROR, "NewKeyFromAccount failed.");
            }

            uint256 input_txid = ParseHashO(v, "txid");
            int rv, input_n = v["n"].get_int();
            CCoinControl cctl;
            cctl.m_spend_frozen_blinded = true;
            cctl.m_addChangeOutput = false;
            cctl.Select(COutPoint(input_txid, input_n));

            std::vector<CTempRecipient> vec_send;
            std::string sError;
            CTempRecipient r;
            r.nType = OUTPUT_STANDARD;
            CAmount output_amount = AmountFromValue(v["amount"]);
            r.SetAmount(output_amount);
            r.address = GetDestinationForKey(pubkey, OutputType::LEGACY);
            r.fSubtractFeeFromAmount = true;
            vec_send.push_back(r);

            CTransactionRef tx_new;
            CWalletTx wtx(pwallet, tx_new);
            CTransactionRecord rtx;
            CAmount nFee;

            if (v["type"].get_str() == "anon") {
                rv = pwallet->AddAnonInputs(wtx, rtx, vec_send, true, 1, 1, nFee, &cctl, sError);
                if (rv != 0) {
                    throw JSONRPCError(RPC_WALLET_ERROR, "AddAnonInputs failed " + sError);
                }
            } else {
                rv = pwallet->AddBlindedInputs(wtx, rtx, vec_send, true, nFee, &cctl, sError);
                if (rv != 0) {
                    throw JSONRPCError(RPC_WALLET_ERROR, "AddBlindedInputs failed " + sError);
                }
            }

            rv = wtx.SubmitMemoryPoolAndRelay(sError, true);
            if (rv != 1) {
                throw JSONRPCError(RPC_WALLET_ERROR, "SubmitMemoryPoolAndRelay failed " + sError);
            }
            uint256 txid = wtx.GetHash();
            result.pushKV("txid", txid.ToString());
            result.pushKV("spent_txid", input_txid.ToString());
            result.pushKV("spent_n", input_n);
            result.pushKV("amount", ValueFromAmount(output_amount));
            result.pushKV("fee", ValueFromAmount(nFee));
            break;
        }
        }
        SyncWithValidationInterfaceQueue();
        return result;
    }

    if (clear_stakes_seen) {
        LOCK(cs_main);
        particl::mapStakeConflict.clear();
        particl::mapStakeSeen.clear();
        particl::listStakeSeen.clear();
        return "Cleared stakes seen.";
    }

    result.pushKV("wallet_name", pwallet->GetName());
    result.pushKV("core_version", CLIENT_VERSION);

    size_t nUnabandonedOrphans = 0;
    size_t nCoinStakes = 0;
    size_t nAbandonedOrphans = 0;

    {
        LOCK(pwallet->cs_wallet);

        result.pushKV("mapWallet_size", (int)pwallet->mapWallet.size());
        result.pushKV("mapRecords_size", (int)pwallet->mapRecords.size());
        result.pushKV("mapTxSpends_size", (int)pwallet->CountTxSpends());
        result.pushKV("mapTxCollapsedSpends_size", (int)pwallet->mapTxCollapsedSpends.size());
        result.pushKV("m_collapsed_txns_size", (int)pwallet->m_collapsed_txns.size());
        result.pushKV("m_collapsed_txn_inputs_size", (int)pwallet->m_collapsed_txn_inputs.size());
        result.pushKV("m_is_only_instance", pwallet->m_is_only_instance);
        result.pushKV("map_ext_accounts_size", (int)pwallet->mapExtAccounts.size());
        result.pushKV("map_ext_keys_size", (int)pwallet->mapExtKeys.size());                    // Includes account keys
        result.pushKV("map_loose_keys_size", (int)pwallet->mapLooseKeys.size());                // Child keys derived from ext keys not in accounts
        result.pushKV("map_loose_lookahead_size", (int)pwallet->mapLooseLookAhead.size());      // Includes account keys

        for (auto it = pwallet->mapWallet.cbegin(); it != pwallet->mapWallet.cend(); ++it) {
            const uint256 &wtxid = it->first;
            const CWalletTx &wtx = it->second;

            if (wtx.IsCoinStake()) {
                nCoinStakes++;
                if (wtx.GetDepthInMainChain() < 1) {
                    if (wtx.isAbandoned()) {
                        nAbandonedOrphans++;
                    } else {
                        nUnabandonedOrphans++;
                        LogPrintf("Unabandoned orphaned stake: %s\n", wtxid.ToString());

                        if (attempt_repair) {
                            if (!pwallet->AbandonTransaction(wtxid)) {
                                LogPrintf("ERROR: %s - Orphaning stake, AbandonTransaction failed for %s\n", __func__, wtxid.ToString());
                            }
                        }
                    }
                }
            }
        }

        LogPrintf("nUnabandonedOrphans %d\n", nUnabandonedOrphans);
        LogPrintf("nCoinStakes %d\n", nCoinStakes);
        LogPrintf("nAbandonedOrphans %d\n", nAbandonedOrphans);
        result.pushKV("unabandoned_orphans", (int)nUnabandonedOrphans);

        int64_t rv = 0;
        if (pwallet->CountRecords("sxkm", rv)) {
            result.pushKV("locked_stealth_outputs", (int)rv);
        } else {
            result.pushKV("locked_stealth_outputs", "error");
        }

        if (pwallet->CountRecords("lao", rv)) {
            result.pushKV("locked_blinded_outputs", (int)rv);
        } else {
            result.pushKV("locked_blinded_outputs", "error");
        }

        // Check for gaps in the hd key chains
        ExtKeyAccountMap::const_iterator itam = pwallet->mapExtAccounts.begin();
        for ( ; itam != pwallet->mapExtAccounts.end(); ++itam) {
            CExtKeyAccount *sea = itam->second;
            LogPrintf("Checking account %s\n", sea->GetIDString58());
            for (CStoredExtKey *sek : sea->vExtKeys) {
                if (!(sek->nFlags & EAF_ACTIVE)
                    || !(sek->nFlags & EAF_RECEIVE_ON)) {
                    continue;
                }

                if ((sek->nFlags & EAF_HARDWARE_DEVICE)) {
                    std::vector<uint8_t> vPath;
                    auto mi = sek->mapValue.find(EKVT_PATH);
                    if (mi != sek->mapValue.end()) {
                        vPath = mi->second;
                    }
                    if (vPath.size() > 8) {
                        // Trim the 44h/44h appended to hardware accounts
                        std::vector<uint32_t> vPathTest;
                        if (0 == ConvertPath(vPath, vPathTest) &&
                            vPathTest.size() > 1 &&
                            vPathTest[0] == WithHardenedBit(44)) {

                            UniValue tmp(UniValue::VOBJ);
                            CKeyID idChain = sek->GetID();
                            CBitcoinAddress addr;
                            addr.Set(idChain, CChainParams::EXT_KEY_HASH);
                            tmp.pushKV("type", "HW device account chain path too long.");
                            tmp.pushKV("chain", addr.ToString());
                            tmp.pushKV("attempt_fix", attempt_repair);
                            if (attempt_repair) {
                                vPath.erase(vPath.begin(), vPath.begin() + 8);
                                sek->mapValue[EKVT_PATH] = vPath;

                                CHDWalletDB wdb(pwallet->GetDatabase());
                                if (!wdb.WriteExtKey(idChain, *sek)) {
                                    tmp.pushKV("error", "WriteExtKey failed");
                                }
                            }
                            warnings.push_back(tmp);
                        }
                    }
                }

                UniValue rva(UniValue::VARR);
                LogPrintf("Checking chain %s\n", sek->GetIDString58());
                uint32_t nGenerated = sek->GetCounter(false);
                LogPrintf("Generated %d\n", nGenerated);

                bool fHardened = false;
                CPubKey newKey;

                for (uint32_t i = 0; i < nGenerated; ++i) {
                    uint32_t nChildOut;
                    if (0 != sek->DeriveKey(newKey, i, nChildOut, fHardened)) {
                        throw JSONRPCError(RPC_WALLET_ERROR, "DeriveKey failed.");
                    }

                    if (i != nChildOut) {
                        LogPrintf("Warning: %s - DeriveKey skipped key %d, %d.\n", __func__, i, nChildOut);
                    }

                    CEKAKey ak;
                    CKeyID idk = newKey.GetID();
                    CPubKey pk;
                    if (!sea->GetPubKey(idk, pk)) {
                        UniValue tmp(UniValue::VOBJ);
                        tmp.pushKV("position", (int)i);
                        tmp.pushKV("address", CBitcoinAddress(PKHash(idk)).ToString());

                        if (attempt_repair) {
                            uint32_t nChain;
                            if (!sea->GetChainNum(sek, nChain)) {
                                throw JSONRPCError(RPC_WALLET_ERROR, "GetChainNum failed.");
                            }

                            CEKAKey ak(nChain, nChildOut);
                            if (0 != pwallet->ExtKeySaveKey(sea, idk, ak)) {
                                throw JSONRPCError(RPC_WALLET_ERROR, "ExtKeySaveKey failed.");
                            }

                            UniValue b;
                            b.setBool(true);
                            tmp.pushKV("attempt_fix", b);
                        }

                        rva.push_back(tmp);
                    }
                }

                if (rva.size() > 0) {
                    UniValue tmp(UniValue::VOBJ);
                    tmp.pushKV("account", sea->GetIDString58());
                    tmp.pushKV("chain", sek->GetIDString58());
                    tmp.pushKV("missing_keys", rva);
                    errors.push_back(tmp);
                }

                // TODO: Check hardened keys, must detect stealth key chain
            }
        }

        {
            auto add_error = [&] (std::string message, const uint256 &txid, int n=-1) {
                UniValue tmp(UniValue::VOBJ);
                tmp.pushKV("type", message);
                tmp.pushKV("txid", txid.ToString());
                if (n > -1) {
                    tmp.pushKV("n", n);
                }
                errors.push_back(tmp);
            };
            pwallet->WalletLogPrintf("Checking mapRecord plain values, blinding factors and anon spends.\n");
            CHDWalletDB wdb(pwallet->GetDatabase());
            for (const auto &ri : pwallet->mapRecords) {
                const uint256 &txhash = ri.first;
                const CTransactionRecord &rtx = ri.second;

                if (!pwallet->IsTrusted(txhash, rtx)) {
                    continue;
                }
                CStoredTransaction stx;
                if (!wdb.ReadStoredTx(txhash, stx)) {
                    add_error("Missing stored txn.", txhash);
                    continue;
                }
                for (const auto &r : rtx.vout) {
                    if (r.nType == OUTPUT_STANDARD && r.n != OR_PLACEHOLDER_N) {
                        if (r.n >= stx.tx->GetNumVOuts() || r.nValue != stx.tx->vpout[r.n]->GetValue()) {
                            add_error("Plain value mismatch.", txhash, r.n);
                        }
                        continue;
                    }
                    if ((r.nType == OUTPUT_CT || r.nType == OUTPUT_RINGCT) &&
                        (r.nFlags & ORF_OWNED || r.nFlags & ORF_STAKEONLY) &&
                        !pwallet->IsSpent(txhash, r.n)) {
                        uint256 tmp;
                        if (!stx.GetBlind(r.n, tmp.begin())) {
                            add_error("Missing blinding factor.", txhash, r.n);
                        }
                    }
                    if (r.nType == OUTPUT_RINGCT &&
                        (r.nFlags & ORF_OWNED)) {
                        CCmpPubKey anon_pubkey, ki;
                        if (!stx.GetAnonPubkey(r.n, anon_pubkey)) {
                            add_error("Could not get anon pubkey.", txhash, r.n);
                            continue;
                        }
                        CKey spend_key;
                        CKeyID apkid = anon_pubkey.GetID();
                        if (!pwallet->GetKey(apkid, spend_key)) {
                            add_error("Could not get anon spend key.", txhash, r.n);
                            continue;
                        }
                        if (0 != GetKeyImage(ki, anon_pubkey, spend_key)) {
                            add_error("Could not get keyimage.", txhash, r.n);
                            continue;
                        }
                        CAnonKeyImageInfo ki_data;
                        bool spent_in_chain = pblocktree->ReadRCTKeyImage(ki, ki_data);
                        uint256 spent_by;
                        bool spent_in_wallet = pwallet->GetSpendingTxid(txhash, r.n, spent_by);

                        if (spent_in_chain && !spent_in_wallet) {
                            add_error("Spent in chain but not wallet.", txhash, r.n);
                            errors.get(errors.size() - 1).pushKV("spent_by", ki_data.txid.ToString());
                        } else
                        if (!spent_in_chain && spent_in_wallet) {
                            add_error("Spent in wallet but not chain.", txhash, r.n);
                            errors.get(errors.size() - 1).pushKV("spent_by", spent_by.ToString());
                        }
                    }
                }
            }
        }
        if (pwallet->CountColdstakeOutputs() > 0) {
            UniValue jsonSettings;
            if (!pwallet->GetSetting("changeaddress", jsonSettings)
                || !jsonSettings["coldstakingaddress"].isStr()) {
                UniValue tmp(UniValue::VOBJ);
                tmp.pushKV("type", "Wallet has coldstaking outputs with coldstakingaddress unset.");
                warnings.push_back(tmp);
            }
        }
    }

    result.pushKV("errors", errors);
    result.pushKV("warnings", warnings);

    return result;
},
    };
}

static RPCHelpMan walletsettings()
{
    return RPCHelpMan{"walletsettings",
                "\nManage wallet settings.\n"
                "Each settings group is set as a block, unspecified options will be set to the default value."
                "\nSettings Groups:\n"
                "\"changeaddress\" {\n"
                "  \"address_standard\"          (string, optional, default=none) Change address for standard inputs.\n"
                "  \"coldstakingaddress\"        (string, optional, default=none) Cold staking address for standard inputs.\n"
                "}\n"
                "\"stakingoptions\" {\n"
                "  \"enabled\"                   (bool, optional, default=true) Toggle staking enabled on this wallet.\n"
                "  \"stakecombinethreshold\"     (amount, optional, default=1000) Join outputs below this value.\n"
                "  \"stakesplitthreshold\"       (amount, optional, default=2000) Split outputs above this value.\n"
                "  \"minstakeablevalue\"         (amount, optional, default=0.00000001) Won't try stake outputs below this value.\n"
                "  \"treasurydonationpercent\"   (int, optional, default=0) Set the percentage of each block reward to donate to the treasury.\n"
                "  \"rewardaddress\"             (string, optional, default=none) An address which the user portion of the block reward gets sent to.\n"
                "  \"smsgfeeratetarget\"         (amount, optional, default=0) If non-zero an amount to move the smsgfeerate towards.\n"
                "  \"smsgdifficultytarget\"      (string, optional, default=0) A 32 byte hex value to move the smsgdifficulty towards.\n"
                "}\n"
                "\"stakelimit\" {\n"
                "  \"height\"                    (int, optional, default=0) Prevent staking above chain height, used in functional testing.\n"
                "}\n"
                "\"anonoptions\" {\n"
                "  \"mixinselection\"            (int, optional, default=1) Switch mixin selection mode.\n"
                "}\n"
                "\"unloadspent\" Remove spent outputs from memory, removed outputs still exist in the wallet file.\n"
                "WARNING: Experimental feature.\n"
                "{\n"
                "  \"mode\"                      (int, optional, default=0) Mode, 0 disabled, 1 coinstake only, 2 all txns.\n"
                "  \"mindepth\"                  (int, optional, default=3) Number of spends before outputs are unloaded.\n"
                "}\n"
                "\"other\" {\n"
                "  \"onlyinstance\"              (bool, optional, default=true) Set to false if other wallets spending from the same keys exist.\n"
                "  \"smsgenabled\"               (bool, optional, default=true) Set to false to have smsg ignore the wallet.\n"
                "  \"minownedvalue\"             (amount, optional, default=0.00000001) Will ignore outputs below this value.\n"
                "}\n"
                "Omit the json object to print the settings group.\n"
                "Pass an empty json object to clear the settings group.\n" +
                HELP_REQUIRING_PASSPHRASE,
                {
                    {"setting_name", RPCArg::Type::STR, RPCArg::Optional::NO, "Settings group to view or modify."},
                    {"setting_value", RPCArg::Type::OBJ, RPCArg::Default{UniValue::VOBJ}, "",
                        {
                            {"...", RPCArg::Type::STR, RPCArg::Default{""}, ""},
                        },
                    "setting_value"},
                },
                RPCResult{
                    RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::OBJ, "setting_name", "",
                        {
                            {RPCResult::Type::STR, "time", /*optional=*/true, "Timestamp from when setting was last changed."},
                        }
                    }}
                },
                RPCExamples{
            "Set coldstaking changeaddress extended public key:\n"
            + HelpExampleCli("walletsettings", "changeaddress \"{\\\"coldstakingaddress\\\":\\\"extpubkey\\\"}\"") + "\n"
            "Clear changeaddress settings\n"
            + HelpExampleCli("walletsettings", "changeaddress \"{}\"") + "\n"
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
    if (!wallet) return NullUniValue;
    CHDWallet *const pwallet = GetParticlWallet(wallet.get());

    // Make sure the results are valid at least up to the most recent block
    // the user could have gotten from another RPC command prior to now
    pwallet->BlockUntilSyncedToCurrentChain();

    EnsureWalletIsUnlocked(pwallet);

    UniValue result(UniValue::VOBJ);
    UniValue json;
    UniValue warnings(UniValue::VARR);

    std::string sSetting = request.params[0].get_str();
    std::string sError;

    // Special case for stakelimit. Todo: Merge stakelimit into stakingoptions with option to update only one key
    if (sSetting == "stakelimit") {
        if (request.params.size() == 1) {
            result.pushKV("height", WITH_LOCK(pwallet->cs_wallet, return pwallet->nStakeLimitHeight));
            return result;
        }
        if (!request.params[1].isObject()) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Must be json object.");
        }
        json = request.params[1].get_obj();
        const std::vector<std::string> &vKeys = json.getKeys();
        if (vKeys.size() < 1) {
            pwallet->SetStakeLimitHeight(0);
            result.pushKV(sSetting, "cleared");
        } else {
            for (const auto &sKey : vKeys) {
                if (sKey == "height") {
                    if (!json["height"].isNum()) {
                        throw JSONRPCError(RPC_INVALID_PARAMETER, "height must be a number.");
                    }

                    int stake_limit = json["height"].get_int();
                    pwallet->SetStakeLimitHeight(stake_limit);
                    result.pushKV(sSetting, stake_limit);
                } else {
                    warnings.push_back("Unknown key " + sKey);
                }
            }
        }
        if (warnings.size() > 0) {
            result.pushKV("warnings", warnings);
        }
        WakeThreadStakeMiner(pwallet);
        return result;
    } else
    if (sSetting != "changeaddress" &&
        sSetting != "stakingoptions" &&
        sSetting != "anonoptions" &&
        sSetting != "unloadspent" &&
        sSetting != "other") {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Unknown setting");
    }

    if (request.params.size() == 1) {
        if (!pwallet->GetSetting(sSetting, json)) {
            result.pushKV(sSetting, "default");
        } else {
            result.pushKV(sSetting, json);
        }
        return result;
    }

    if (!request.params[1].isObject()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Must be json object.");
    }
    json = request.params[1].get_obj();
    const std::vector<std::string> &vKeys = json.getKeys();
    UniValue jsonOld;
    bool fHaveOldSetting = pwallet->GetSetting(sSetting, jsonOld);
    bool erasing = false;
    if (vKeys.size() < 1) {
        if (!pwallet->EraseSetting(sSetting)) {
            throw JSONRPCError(RPC_WALLET_ERROR, "EraseSetting failed.");
        }
        result.pushKV(sSetting, "cleared");
        erasing = true;
    }

    if (sSetting == "changeaddress") {
        for (const auto &sKey : vKeys) {
            if (sKey == "address_standard") {
                if (!json["address_standard"].isStr()) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "address_standard must be a string.");
                }

                std::string sAddress = json["address_standard"].get_str();
                CTxDestination dest = DecodeDestination(sAddress);
                if (!IsValidDestination(dest)) {
                    throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid address_standard.");
                }
            } else
            if (sKey == "coldstakingaddress") {
                if (!json["coldstakingaddress"].isStr()) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "coldstakingaddress must be a string.");
                }

                std::string sAddress = json["coldstakingaddress"].get_str();
                CBitcoinAddress addr(sAddress);
                if (!addr.IsValid()) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid coldstakingaddress.");
                }
                if (addr.IsValidStealthAddress()) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "coldstakingaddress can't be a stealthaddress.");
                }

                // TODO: override option?
                if (pwallet->HaveAddress(addr.Get())) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, sAddress + " is spendable from this wallet.");
                }
                if (pwallet->idDefaultAccount.IsNull()) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "Wallet must have a default account set.");
                }

                const Consensus::Params& consensusParams = Params().GetConsensus();
                if (GetAdjustedTime() < consensusParams.OpIsCoinstakeTime) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "OpIsCoinstake is not active yet.");
                }
            } else {
                warnings.push_back("Unknown key " + sKey);
            }
        }
    } else
    if (sSetting == "stakingoptions") {
        for (const auto &sKey : vKeys) {
            if (sKey == "enabled") {
            } else
            if (sKey == "stakecombinethreshold") {
                if (AmountFromValue(json["stakecombinethreshold"]) < 0) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "stakecombinethreshold can't be negative.");
                }
            } else
            if (sKey == "stakesplitthreshold") {
                if (AmountFromValue(json["stakesplitthreshold"]) < 0) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "stakesplitthreshold can't be negative.");
                }
            } else
            if (sKey == "minstakeablevalue") {
                if (AmountFromValue(json["minstakeablevalue"]) < 0) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "minstakeablevalue can't be negative.");
                }
            } else
            if (sKey == "treasurydonationpercent") {
                if (!json["treasurydonationpercent"].isNum()) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "treasurydonationpercent must be a number.");
                }
            } else
            if (sKey == "rewardaddress") {
                if (!json["rewardaddress"].isStr()) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "rewardaddress must be a string.");
                }

                CBitcoinAddress addr(json["rewardaddress"].get_str());
                if (!addr.IsValid() || addr.Get().index() == DI::_CNoDestination) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid rewardaddress.");
                }
            } else
            if (sKey == "smsgfeeratetarget") {
                if (AmountFromValue(json["smsgfeeratetarget"]) < 0) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "smsgfeeratetarget can't be negative.");
                }
            } else
            if (sKey == "smsgdifficultytarget") {
            } else {
                warnings.push_back("Unknown key " + sKey);
            }
        }
    } else
    if (sSetting == "anonoptions") {
        for (const auto &sKey : vKeys) {
            if (sKey == "mixinselection") {
                if (!json["mixinselection"].isNum()) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "mixinselection must be a number.");
                }
            } else {
                warnings.push_back("Unknown key " + sKey);
            }
        }
    } else
    if (sSetting == "unloadspent") {
        for (const auto &sKey : vKeys) {
            if (sKey == "mode") {
                if (!json["mode"].isNum()) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "mode must be a number.");
                }
            } else
            if (sKey == "mindepth") {
                if (!json["mindepth"].isNum()) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "mindepth must be a number.");
                }
            } else {
                warnings.push_back("Unknown key " + sKey);
            }
        }
    } else
    if (sSetting == "other") {
        for (const auto &sKey : vKeys) {
            if (sKey == "onlyinstance") {
                if (!json["onlyinstance"].isBool()) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "onlyinstance must be boolean.");
                }
            } else
            if (sKey == "smsgenabled") {
                if (!json["smsgenabled"].isBool()) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "smsgenabled must be boolean.");
                }
            } else
            if (sKey == "minownedvalue") {
                if (AmountFromValue(json["minownedvalue"]) < 0) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "minownedvalue can't be negative.");
                }
            } else {
                warnings.push_back("Unknown key " + sKey);
            }
        }
    } else {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Unknown setting");
    }

    if (!erasing) {
        json.pushKV("time", GetTime());
        if (!pwallet->SetSetting(sSetting, json)) {
            throw JSONRPCError(RPC_WALLET_ERROR, "SetSetting failed.");
        }
    }
    // Re-apply settings if cleared
    if (sSetting == "stakingoptions") {
        pwallet->ProcessStakingSettings(sError);
    } else {
        pwallet->ProcessWalletSettings(sError);
    }
    if (!erasing) {
        if (!sError.empty()) {
            result.pushKV("error", sError);
            if (fHaveOldSetting) {
                pwallet->SetSetting(sSetting, jsonOld);
            } else {
                pwallet->EraseSetting(sSetting);
            }
        }
        result.pushKV(sSetting, json);
    }

    if (warnings.size() > 0) {
        result.pushKV("warnings", warnings);
    }

    return result;
},
    };
}

static RPCHelpMan transactionblinds()
{
    return RPCHelpMan{"transactionblinds",
                "\nShow known blinding factors for transaction." +
                HELP_REQUIRING_PASSPHRASE,
                {
                    {"txnid", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The transaction id."},
                },
                RPCResult{
                    RPCResult::Type::OBJ, "", "", {
                        {RPCResult::Type::STR_HEX, "hex", "The blinding factor for output n"},
                }},
                RPCExamples{
            HelpExampleCli("transactionblinds", "\"txnid\"") +
            "\nAs a JSON-RPC call\n"
            + HelpExampleRpc("transactionblinds", "\"txnid\"")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
    if (!wallet) return NullUniValue;
    CHDWallet *const pwallet = GetParticlWallet(wallet.get());

    EnsureWalletIsUnlocked(pwallet);

    uint256 hash;
    hash.SetHex(request.params[0].get_str());

    MapRecords_t::const_iterator mri = pwallet->mapRecords.find(hash);
    if (mri == pwallet->mapRecords.end()) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid or non-wallet transaction id");
    }

    UniValue result(UniValue::VOBJ);
    CStoredTransaction stx;
    if (!CHDWalletDB(pwallet->GetDatabase()).ReadStoredTx(hash, stx)) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "No stored data found for txn");
    }

    for (size_t i = 0; i < stx.tx->vpout.size(); ++i) {
        uint256 tmp;
        if (stx.GetBlind(i, tmp.begin())) {
            result.pushKV(strprintf("%d", i), tmp.ToString());
        }
    }

    return result;
},
    };
}

static RPCHelpMan derivefromstealthaddress()
{
    return RPCHelpMan{"derivefromstealthaddress",
                "\nDerive a pubkey from a stealth address and random value." +
                HELP_REQUIRING_PASSPHRASE,
                {
                    {"stealthaddress", RPCArg::Type::STR, RPCArg::Optional::NO, "The stealth address."},
                    {"ephemeralvalue", RPCArg::Type::STR, RPCArg::Default{""}, "The ephemeral value, interpreted as private key if 32 bytes or public key if 33.\n"
                    "   If an ephemeral public key is provided the spending private key will be derived, wallet must be unlocked\n"},
                },
                RPCResult{
                    RPCResult::Type::OBJ, "", "", {
                        {RPCResult::Type::STR, "address", "The derived address"},
                        {RPCResult::Type::STR_HEX, "pubkey", "The derived public key"},
                        {RPCResult::Type::STR_HEX, "ephemeral", "The ephemeral public key"},
                        {RPCResult::Type::STR, "privatekey", "The derived privatekey, if \"ephempubkey\" is provided"},
                }},
                RPCExamples{
            HelpExampleCli("derivefromstealthaddress", "\"stealthaddress\"") +
            "\nAs a JSON-RPC call\n"
            + HelpExampleRpc("derivefromstealthaddress", "\"stealthaddress\"")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
    if (!wallet) return NullUniValue;
    CHDWallet *const pwallet = GetParticlWallet(wallet.get());

    CBitcoinAddress addr(request.params[0].get_str());
    if (!addr.IsValidStealthAddress()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Must input a stealthaddress.");
    }

    CStealthAddress sx = std::get<CStealthAddress>(addr.Get());


    UniValue result(UniValue::VOBJ);

    CKey sSpendR, sShared, sEphem;
    CPubKey pkEphem, pkDest;
    CTxDestination dest;

    if (request.params[1].isStr()) {
        EnsureWalletIsUnlocked(pwallet);

        std::string s = request.params[1].get_str();
        if (!IsHex(s)) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "ephemeralvalue must be hex encoded.");
        }

        if (s.size() == 64) {
            std::vector<uint8_t> v = ParseHex(s);
            sEphem.Set(v.data(), true);
            if (!sEphem.IsValid()) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid ephemeral private key.");
            }
        } else
        if (s.size() == 66) {
            std::vector<uint8_t> v = ParseHex(s);
            pkEphem = CPubKey(v.begin(), v.end());

            if (!pkEphem.IsValid()) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid ephemeral public key.");
            }

            CKey sSpend;
            if (!pwallet->GetStealthAddressScanKey(sx)) {
                throw JSONRPCError(RPC_WALLET_ERROR, "Scan key not found for stealth address.");
            }
            if (!pwallet->GetStealthAddressSpendKey(sx, sSpend)) {
                throw JSONRPCError(RPC_WALLET_ERROR, "Spend key not found for stealth address.");
            }

            ec_point pEphem;
            pEphem.resize(EC_COMPRESSED_SIZE);
            memcpy(&pEphem[0], pkEphem.begin(), pkEphem.size());

            if (StealthSecretSpend(sx.scan_secret, pEphem, sSpend, sSpendR) != 0) {
                throw JSONRPCError(RPC_WALLET_ERROR, "StealthSecretSpend failed.");
            }

            pkDest = sSpendR.GetPubKey();
        } else {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "ephemeralvalue must be 33 byte public key or 32 byte private key.");
        }
    } else {
        sEphem.MakeNewKey(true);
    }

    if (sEphem.IsValid()) {
        ec_point pkSendTo;
        if (0 != StealthSecret(sEphem, sx.scan_pubkey, sx.spend_pubkey, sShared, pkSendTo)) {
            throw JSONRPCError(RPC_INTERNAL_ERROR, "StealthSecret failed, try again.");
        }

        pkEphem = sEphem.GetPubKey();
        pkDest = CPubKey(pkSendTo);
    }

    dest = GetDestinationForKey(pkDest, OutputType::LEGACY);

    result.pushKV("address", EncodeDestination(dest));
    result.pushKV("pubkey", HexStr(pkDest));
    result.pushKV("ephemeral_pubkey", HexStr(pkEphem));
    if (sEphem.IsValid()) {
        result.pushKV("ephemeral_privatekey", HexStr(Span<const unsigned char>(sEphem.begin(), 32)));
    }
    if (sSpendR.IsValid()) {
        result.pushKV("privatekey", CBitcoinSecret(sSpendR).ToString());
    }

    return result;
},
    };
}

static RPCHelpMan getkeyimage()
{
    return RPCHelpMan{"getkeyimage",
            "\nShow the keyimage for an anon output pubkey if owned." +
            HELP_REQUIRING_PASSPHRASE,
            {
                {"pubkey", RPCArg::Type::STR, RPCArg::Optional::NO, "The pubkey of the anon output."},
            },
            RPCResult{
                RPCResult::Type::OBJ, "", "", {
                    {RPCResult::Type::STR_HEX, "keyimage", "The derived public key"},
            }},
            RPCExamples{
        HelpExampleCli("getkeyimage", "\"pubkey\"") +
        "\nAs a JSON-RPC call\n"
        + HelpExampleRpc("getkeyimage", "\"pubkey\"")
            },
    [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
    if (!wallet) return NullUniValue;
    CHDWallet *const pwallet = GetParticlWallet(wallet.get());

    EnsureWalletIsUnlocked(pwallet);

    RPCTypeCheck(request.params, {UniValue::VSTR}, true);

    std::string s = request.params[0].get_str();
    if (!IsHex(s) || !(s.size() == 66)) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Public key must be 33 bytes and hex encoded.");
    }
    std::vector<uint8_t> v = ParseHex(s);
    CCmpPubKey ki, anon_pubkey(v.begin(), v.end());

    UniValue result(UniValue::VOBJ);

    CKey spend_key;
    CKeyID apkid = anon_pubkey.GetID();
    if (!pwallet->GetKey(apkid, spend_key)) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Private key not found.");
    }
    if (0 != GetKeyImage(ki, anon_pubkey, spend_key)) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Could not get keyimage.");
    }

    result.pushKV("keyimage", HexStr(ki));
    result.pushKV("warning", "Sharing keyimages could impact privacy.");  // Although knowledge of a keyimage does not prove ownership of an anon output.

    return result;
},
    };
}

static RPCHelpMan setvote()
{
    return RPCHelpMan{"setvote",
                "\nSet voting token.\n"
                "Wallet will include this token in staked blocks from height_start to height_end.\n"
                "Set proposal and/or option to 0 to stop voting.\n"
                "Set all parameters to 0 to clear all vote settings.\n"
                "Vote includes the height_start and height_end blocks.\n"
                "The last added option valid for the current chain height will be applied." +
                HELP_REQUIRING_PASSPHRASE,
                {
                    {"proposal", RPCArg::Type::NUM, RPCArg::Optional::NO, "The proposal to vote on."},
                    {"option", RPCArg::Type::NUM, RPCArg::Optional::NO, "The option to vote for."},
                    {"height_start", RPCArg::Type::NUM, RPCArg::Optional::NO, "Start voting from this block height."},
                    {"height_end", RPCArg::Type::NUM, RPCArg::Optional::NO, "Stop voting after this block height."},
                },
                RPCResult{
                    RPCResult::Type::OBJ, "", "", {
                        {RPCResult::Type::STR, "result", "Result."},
                        {RPCResult::Type::NUM, "from_height", "Block from (including)."},
                        {RPCResult::Type::NUM, "to_height", "Block to (including)."}
                    }
                },
                RPCExamples{
            HelpExampleCli("setvote", "1 1 1000 2000") +
            "\nAs a JSON-RPC call\n"
            + HelpExampleRpc("setvote", "1, 1, 1000, 2000")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
    if (!wallet) return NullUniValue;
    CHDWallet *const pwallet = GetParticlWallet(wallet.get());

    EnsureWalletIsUnlocked(pwallet);

    // Make sure the results are valid at least up to the most recent block
    // the user could have gotten from another RPC command prior to now
    pwallet->BlockUntilSyncedToCurrentChain();

    uint32_t issue = request.params[0].get_int();
    uint32_t option = request.params[1].get_int();

    if (issue > 0xFFFF) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Proposal out of range.");
    }
    if (option > 0xFFFF) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Option out of range.");
    }

    int nStartHeight = request.params[2].get_int();
    int nEndHeight = request.params[3].get_int();

    if (nEndHeight < nStartHeight && !(nEndHeight + nStartHeight + issue + option)) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "height_end must be after height_start.");
    }

    UniValue result(UniValue::VOBJ);
    uint32_t voteToken = issue | (option << 16);

    {
        LOCK(pwallet->cs_wallet);
        CHDWalletDB wdb(pwallet->GetDatabase());
        std::vector<CVoteToken> vVoteTokens;

        if (!(nEndHeight + nStartHeight + issue + option)) {
            if (!wdb.EraseVoteTokens()) {
                throw JSONRPCError(RPC_WALLET_ERROR, "EraseVoteTokens failed.");
            }
            pwallet->LoadVoteTokens(&wdb);
            result.pushKV("result", "Erased all vote tokens.");
            return result;
        }

        wdb.ReadVoteTokens(vVoteTokens);

        CVoteToken v(voteToken, nStartHeight, nEndHeight, GetTime());
        vVoteTokens.push_back(v);

        if (!wdb.WriteVoteTokens(vVoteTokens)) {
            throw JSONRPCError(RPC_WALLET_ERROR, "WriteVoteTokens failed.");
        }

        pwallet->LoadVoteTokens(&wdb);
    }

    if (issue < 1) {
        result.pushKV("result", "Cleared vote token.");
    } else {
        result.pushKV("result", strprintf("Voting for option %u on proposal %u", option, issue));
    }

    result.pushKV("from_height", nStartHeight);
    result.pushKV("to_height", nEndHeight);

    return result;
},
    };
}

static RPCHelpMan votehistory()
{
    return RPCHelpMan{"votehistory",
                "\nDisplay voting history of wallet.\n",
                {
                    {"current_only", RPCArg::Type::BOOL, RPCArg::Default{false}, "Show only the currently active vote."},
                    {"include_future", RPCArg::Type::BOOL, RPCArg::Default{false}, "Show future scheduled votes with \"current_only\"."},
                },
                RPCResult{
                    RPCResult::Type::ARR, "", "", {
                        {RPCResult::Type::OBJ, "", "", {
                            {RPCResult::Type::NUM, "proposal", "The proposal id"},
                            {RPCResult::Type::NUM, "option", "The option marked"},
                            {RPCResult::Type::NUM, "from_height", "The starting chain height"},
                            {RPCResult::Type::NUM, "to_height", "The ending chain height"},
                        }},
                    }
                },
                RPCExamples{
            HelpExampleCli("votehistory", "true") +
            "\nAs a JSON-RPC call\n"
            + HelpExampleRpc("votehistory", "true")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
    if (!wallet) return NullUniValue;
    CHDWallet *const pwallet = GetParticlWallet(wallet.get());
    if (!pwallet->HaveChain()) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Unable to get chain");
    }

    std::vector<CVoteToken> vVoteTokens;
    {
        LOCK(pwallet->cs_wallet);
        CHDWalletDB wdb(pwallet->GetDatabase());
        wdb.ReadVoteTokens(vVoteTokens);
    }

    // Make sure the results are valid at least up to the most recent block
    // the user could have gotten from another RPC command prior to now
    pwallet->BlockUntilSyncedToCurrentChain();

    bool current_only = request.params.size() > 0 ? GetBool(request.params[0]) : false;
    bool include_future = request.params.size() > 1 ? GetBool(request.params[1]) : false;

    UniValue result(UniValue::VARR);

    if (current_only) {
        int nNextHeight = pwallet->chain().getHeightInt() + 1;

        for (int i = (int) vVoteTokens.size(); i-- > 0; ) {
            const auto &v = vVoteTokens[i];

            int vote_start = v.nStart;
            int vote_end = v.nEnd;
            if (include_future) {
                if (v.nEnd < nNextHeight) {
                    continue;
                }

                // Check if occluded, result is ordered by start_height ASC
                for (size_t ir = 0; ir < result.size(); ++ir) {
                    int rs = result[ir]["from_height"].get_int();
                    int re = result[ir]["to_height"].get_int();

                    if (rs <= vote_start && vote_end >= re) {
                        vote_start = re;
                    }
                    if (rs <= vote_end && re >= vote_end) {
                        vote_end = rs;  // -1
                    }
                }
                if (vote_end <= vote_start) {
                    continue;
                }
            } else {
                if (vote_end < nNextHeight
                    || vote_start > nNextHeight) {
                    continue;
                }
            }

            UniValue vote(UniValue::VOBJ);
            vote.pushKV("proposal", (int)(v.nToken & 0xFFFF));
            vote.pushKV("option", (int)(v.nToken >> 16));
            vote.pushKV("from_height", vote_start);
            vote.pushKV("to_height", vote_end);

            size_t k = 0;
            for (k = 0; k < result.size(); k++) {
                if (v.nStart < result[k]["from_height"].get_int()) {
                    result.insert(k, vote);
                    break;
                }
            }
            if (k >= result.size()) {
                result.push_back(vote);
            }

            if (!include_future) {
                break;
            }
        }
        return result;
    }

    for (auto i = vVoteTokens.crbegin(); i != vVoteTokens.crend(); ++i) {
        const auto &v = *i;
        UniValue vote(UniValue::VOBJ);
        vote.pushKV("proposal", (int)(v.nToken & 0xFFFF));
        vote.pushKV("option", (int)(v.nToken >> 16));
        vote.pushKV("from_height", v.nStart);
        vote.pushKV("to_height", v.nEnd);
        vote.pushKV("added", v.nTimeAdded);
        result.push_back(vote);
    }

    return result;
},
    };
}

static RPCHelpMan tallyvotes()
{
    return RPCHelpMan{"tallyvotes",
                "\nCount votes."
                "\nStart and end blocks are included in the count.\n",
                {
                    {"proposal", RPCArg::Type::NUM, RPCArg::Optional::NO, "The proposal id."},
                    {"height_start", RPCArg::Type::NUM, RPCArg::Optional::NO, "The chain starting height, including."},
                    {"height_end", RPCArg::Type::NUM, RPCArg::Optional::NO, "The chain ending height, including."},
                },
                RPCResult{
                    RPCResult::Type::OBJ, "", "", {
                        {RPCResult::Type::NUM, "proposal", "The proposal id"},
                        {RPCResult::Type::NUM, "option", "The option marked"},
                        {RPCResult::Type::NUM, "height_start", "The starting chain height"},
                        {RPCResult::Type::NUM, "height_end", "The ending chain height"},
                        {RPCResult::Type::NUM, "blocks_counted", "Number of blocks inspected"},
                        {RPCResult::Type::NUM, "Option n", "The number of votes cast for option n"},
                }},
                RPCExamples{
            HelpExampleCli("tallyvotes", "1 2000 30000") +
            "\nAs a JSON-RPC call\n"
            + HelpExampleRpc("tallyvotes", "1, 2000, 30000")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    ChainstateManager &chainman = EnsureAnyChainman(request.context);

    int issue = request.params[0].get_int();
    if (issue < 1 || issue >= (1 << 16))
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Proposal out of range.");

    int nStartHeight = request.params[1].get_int();
    int nEndHeight = request.params[2].get_int();

    CBlock block;
    const Consensus::Params& consensusParams = Params().GetConsensus();

    std::map<int, int> mapVotes;
    std::pair<std::map<int, int>::iterator, bool> ri;

    int nBlocks = 0;
    CBlockIndex *pindex = chainman.ActiveChain().Tip();
    if (pindex)
    do {
        if (pindex->nHeight < nStartHeight) {
            break;
        }
        if (pindex->nHeight <= nEndHeight) {
            if (!ReadBlockFromDisk(block, pindex, consensusParams)) {
                continue;
            }

            if (block.vtx.size() < 1
                || !block.vtx[0]->IsCoinStake()) {
                continue;
            }

            std::vector<uint8_t> &vData = ((CTxOutData*)block.vtx[0]->vpout[0].get())->vData;
            if (vData.size() < 9 || vData[4] != DO_VOTE) {
                ri = mapVotes.insert(std::pair<int, int>(0, 1));
                if (!ri.second) ri.first->second++;
            } else {
                uint32_t voteToken;
                memcpy(&voteToken, &vData[5], 4);
                voteToken = le32toh(voteToken);
                int option = 0; // default to abstain

                // count only if related to current issue:
                if ((int) (voteToken & 0xFFFF) == issue) {
                    option = (voteToken >> 16) & 0xFFFF;
                }

                ri = mapVotes.insert(std::pair<int, int>(option, 1));
                if (!ri.second) ri.first->second++;
            }

            nBlocks++;
        }
    } while ((pindex = pindex->pprev));

    UniValue result(UniValue::VOBJ);
    result.pushKV("proposal", issue);
    result.pushKV("height_start", nStartHeight);
    result.pushKV("height_end", nEndHeight);
    result.pushKV("blocks_counted", nBlocks);

    float fnBlocks = (float) nBlocks;
    for (const auto &i : mapVotes) {
        std::string sKey = i.first == 0 ? "Abstain" : strprintf("Option %d", i.first);
        result.pushKV(sKey, strprintf("%d, %.02f%%", i.second, ((float) i.second / fnBlocks) * 100.0));
    }

    return result;
},
    };
};

static RPCHelpMan buildscript()
{
return RPCHelpMan{"buildscript",
                "\nCreate a script from inputs.\n"
                "\nRecipes:\n"
                " {\"recipe\":\"ifcoinstake\", \"addrstake\":\"addrA\", \"addrspend\":\"addrB\"}\n",
                {
                    {"recipe", RPCArg::Type::OBJ, RPCArg::Optional::NO, "",
                        {
                            {"recipe", RPCArg::Type::STR, RPCArg::Optional::NO, ""},
                            {"recipeinputs ...", RPCArg::Type::STR, RPCArg::Default{""}, ""},
                        },
                    },
                },
                RPCResult{
                    RPCResult::Type::OBJ, "", "", {
                        {RPCResult::Type::STR_HEX, "hex", "Script as hex"},
                        {RPCResult::Type::STR, "asm", "Script as asm"},
                }},
                RPCExamples{
            HelpExampleCli("buildscript", "\"{\\\"recipe\\\":\\\"ifcoinstake\\\", \\\"addrstake\\\":\\\"addrA\\\", \\\"addrspend\\\":\\\"addrB\\\"}\"") +
            "\nAs a JSON-RPC call\n"
            + HelpExampleRpc("buildscript", "\"{\\\"recipe\\\":\\\"ifcoinstake\\\", \\\"addrstake\\\":\\\"addrA\\\", \\\"addrspend\\\":\\\"addrB\\\"}\"")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    if (!request.params[0].isObject()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Input must be a json object.");
    }

    const UniValue &params = request.params[0].get_obj();

    const UniValue &recipe = params["recipe"];
    if (!recipe.isStr()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Missing recipe.");
    }

    std::string sRecipe = recipe.get_str();

    UniValue obj(UniValue::VOBJ);
    obj.pushKV("recipe", sRecipe);

    CScript scriptOut;

    if (sRecipe == "ifcoinstake") {
        RPCTypeCheckObj(params,
        {
            {"addrstake", UniValueType(UniValue::VSTR)},
            {"addrspend", UniValueType(UniValue::VSTR)},
        });

        CTxDestination destStake = DecodeDestination(params["addrstake"].get_str(), true);
        CTxDestination destSpend = DecodeDestination(params["addrspend"].get_str());

        if (!IsValidDestination(destStake)) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid addrstake.");
        }
        if (!IsValidDestination(destSpend)) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid addrspend.");
        }
        if (destSpend.index() == DI::_PKHash) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid addrspend, can't be p2pkh.");
        }

        CScript scriptTrue = GetScriptForDestination(destStake);
        CScript scriptFalse = GetScriptForDestination(destSpend);

        if (scriptTrue.size() == 0) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid stake destination.");
        }
        if (scriptFalse.size() == 0) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid spend destination.");
        }

        scriptOut = CScript() << OP_ISCOINSTAKE << OP_IF;
        scriptOut.append(scriptTrue);
        scriptOut << OP_ELSE;
        scriptOut.append(scriptFalse);
        scriptOut << OP_ENDIF;
    } else {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Unknown recipe.");
    }

    obj.pushKV("hex", HexStr(scriptOut));
    obj.pushKV("asm", ScriptToAsmStr(scriptOut));

    return obj;
},
    };
};

static RPCHelpMan createrawparttransaction()
{
    return RPCHelpMan{"createrawparttransaction",
                "\nCreate a transaction spending the given inputs and creating new confidential outputs.\n"
                "Outputs can be addresses or data.\n"
                "Returns hex-encoded raw transaction.\n"
                "Note that the transaction's inputs are not signed, and\n"
                "it is not stored in the wallet or transmitted to the network.\n",
                {
                    {"inputs", RPCArg::Type::ARR, RPCArg::Optional::NO, "A json array of json objects",
                        {
                            {"", RPCArg::Type::OBJ, RPCArg::Optional::NO, "",
                                {
                                    {"txid", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The transaction id"},
                                    {"vout", RPCArg::Type::NUM, RPCArg::Optional::NO, "The output number"},
                                    {"sequence", RPCArg::Type::NUM, RPCArg::Default{""}, "The sequence number"},
                                    {"blindingfactor", RPCArg::Type::STR_HEX, RPCArg::Default{""}, "The blinding factor of the prevout, required if blinded input is unknown to wallet"},
                                },
                            },
                        },
                    },
                    {"outputs", RPCArg::Type::ARR, RPCArg::Default{UniValue::VARR}, "a json array with outputs (key-value pairs).",
                        {
                            {"", RPCArg::Type::OBJ, RPCArg::Default{UniValue::VOBJ}, "",
                                {
                                    {"address", RPCArg::Type::STR, RPCArg::Default{""}, "The particl address."},
                                    {"amount", RPCArg::Type::AMOUNT, RPCArg::Default{""}, "The numeric value (can be string) in " + CURRENCY_UNIT + " of the output."},
                                    {"data", RPCArg::Type::STR_HEX, RPCArg::Default{""}, "The key is \"data\", the value is hex encoded data."},
                                    {"data_ct_fee", RPCArg::Type::AMOUNT, RPCArg::Default{""}, "If type is \"data\" and output is at index 0, then it will be treated as a CT fee output."},
                                    {"script", RPCArg::Type::STR_HEX, RPCArg::Default{""}, "Specify script directly."},
                                    {"type", RPCArg::Type::STR, RPCArg::Default{"plain"}, "The type of output to create, plain, blind or anon."},
                                    {"pubkey", RPCArg::Type::STR, RPCArg::Default{""}, "The key is \"pubkey\", the value is hex encoded public key for encrypting the metadata."},
                                    {"narration", RPCArg::Type::STR, RPCArg::Default{""}, "Up to 24 character narration sent with the transaction."},
                                    {"blindingfactor", RPCArg::Type::STR_HEX, RPCArg::Default{""}, "Blinding factor to use. Blinding factor is randomly generated if not specified."},
                                    {"rangeproof_params", RPCArg::Type::OBJ, RPCArg::Default{UniValue::VOBJ}, "",
                                        {
                                            {"min_value", RPCArg::Type::NUM, RPCArg::Default{""}, "The minimum value to prove for."},
                                            {"ct_exponent", RPCArg::Type::NUM, RPCArg::Default{""}, "The exponent to use."},
                                            {"ct_bits", RPCArg::Type::NUM, RPCArg::Default{""}, "The amount of bits to prove for."},
                                        },
                                    },
                                    {"ephemeral_key", RPCArg::Type::STR_HEX, RPCArg::Default{""}, "Ephemeral secret key for blinded outputs."},
                                    {"nonce", RPCArg::Type::STR_HEX, RPCArg::Default{""}, "Nonce for blinded outputs."},
                                },
                            },
                        },
                    },
                    {"locktime", RPCArg::Type::NUM, RPCArg::Default{0}, "Raw locktime. Non-0 value also locktime-activates inputs\n"},
                    {"replaceable", RPCArg::Type::BOOL, RPCArg::DefaultHint{"wallet default"}, "Marks this transaction as BIP125 replaceable.\n"
                            "                              Allows this transaction to be replaced by a transaction with higher fees"},
                },
            //"5. \"fundfrombalance\"       (string, optional, default=none) Fund transaction from standard, blinded or anon balance.\n"
                RPCResult{
                    RPCResult::Type::OBJ, "", "", {
                        {RPCResult::Type::STR_HEX, "transaction", "hex string of the transaction"},
                        {RPCResult::Type::NUM, "fee", "Fee in " + CURRENCY_UNIT + " the resulting transaction pays"},
                        {RPCResult::Type::NUM, "changepos", "The position of the added change output, or -1"},
                        {RPCResult::Type::OBJ, "amounts", "Coin values of outputs with blinding factors of blinded outputs", {
                            {RPCResult::Type::OBJ, "n", "", {
                                {RPCResult::Type::STR_AMOUNT, "value", "The amount of the output in " + CURRENCY_UNIT},
                                {RPCResult::Type::STR_HEX, "blind", "Blinding factor"},
                                {RPCResult::Type::STR_HEX, "nonce", "Nonce"},
                            }}
                        }},
                }},
                RPCExamples{
            HelpExampleCli("createrawparttransaction", "\"[{\\\"txid\\\":\\\"myid\\\",\\\"vout\\\":0}]\" \"{\\\"address\\\":0.01}\"")
            + HelpExampleCli("createrawparttransaction", "\"[{\\\"txid\\\":\\\"myid\\\",\\\"vout\\\":0}]\" \"{\\\"data\\\":\\\"00010203\\\"}\"") +
            "\nAs a JSON-RPC call\n"
            + HelpExampleRpc("createrawparttransaction", "\"[{\\\"txid\\\":\\\"myid\\\",\\\"vout\\\":0}]\", \"{\\\"address\\\":0.01}\"")
            + HelpExampleRpc("createrawparttransaction", "\"[{\\\"txid\\\":\\\"myid\\\",\\\"vout\\\":0}]\", \"{\\\"data\\\":\\\"00010203\\\"}\"")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
    if (!wallet) return NullUniValue;
    CHDWallet *const pwallet = GetParticlWallet(wallet.get());

    EnsureWalletIsUnlocked(pwallet);

    RPCTypeCheck(request.params, {UniValue::VARR, UniValue::VARR, UniValue::VNUM, UniValue::VBOOL, UniValue::VSTR}, true);
    if (request.params[0].isNull() || request.params[1].isNull()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, arguments 1 and 2 must be non-null");
    }

    UniValue inputs = request.params[0].get_array();
    UniValue outputs = request.params[1].get_array();

    CMutableTransaction rawTx;
    rawTx.nVersion = PARTICL_TXN_VERSION;


    if (!request.params[2].isNull()) {
        int64_t nLockTime = request.params[2].get_int64();
        if (nLockTime < 0 || nLockTime > std::numeric_limits<uint32_t>::max()) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, locktime out of range");
        }
        rawTx.nLockTime = nLockTime;
    }

    bool rbfOptIn = request.params[3].isTrue();

    CAmount nCtFee = 0;
    std::map<int, uint256> mInputBlinds;
    for (unsigned int idx = 0; idx < inputs.size(); idx++) {
        const UniValue& input = inputs[idx];
        const UniValue& o = input.get_obj();

        uint256 txid = ParseHashO(o, "txid");

        const UniValue& vout_v = find_value(o, "vout");
        if (!vout_v.isNum()) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, missing vout key");
        }
        int nOutput = vout_v.get_int();
        if (nOutput < 0) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, vout must be positive");
        }

        uint32_t nSequence;
        if (rbfOptIn) {
            nSequence = MAX_BIP125_RBF_SEQUENCE;
        } else if (rawTx.nLockTime) {
            nSequence = std::numeric_limits<uint32_t>::max() - 1;
        } else {
            nSequence = std::numeric_limits<uint32_t>::max();
        }

        // set the sequence number if passed in the parameters object
        const UniValue& sequenceObj = find_value(o, "sequence");
        if (sequenceObj.isNum()) {
            int64_t seqNr64 = sequenceObj.get_int64();
            if (seqNr64 < 0 || seqNr64 > std::numeric_limits<uint32_t>::max()) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, sequence number is out of range");
            } else {
                nSequence = (uint32_t)seqNr64;
            }
        }

        const UniValue &blindObj = find_value(o, "blindingfactor");
        if (blindObj.isStr()) {
            std::string s = blindObj.get_str();
            if (!IsHex(s) || !(s.size() == 64)) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Blinding factor must be 32 bytes and hex encoded.");
            }

            uint256 blind;
            blind.SetHex(s);
            mInputBlinds[rawTx.vin.size()] = blind;
        }

        CTxIn in(COutPoint(txid, nOutput), CScript(), nSequence);

        rawTx.vin.push_back(in);
    }

    std::vector<CTempRecipient> vecSend;
    for (size_t idx = 0; idx < outputs.size(); idx++) {
        const UniValue &o = outputs[idx].get_obj();
        CTempRecipient r;

        uint8_t nType = OUTPUT_STANDARD;
        const UniValue &typeObj = find_value(o, "type");
        if (typeObj.isStr()) {
            std::string s = typeObj.get_str();
            nType = WordToType(s, true);
            if (nType == OUTPUT_NULL) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Unknown output type.");
            }
        }

        CAmount nAmount = AmountFromValue(o["amount"]);

        bool fSubtractFeeFromAmount = false;
        //if (o.exists("subfee"))
        //    fSubtractFeeFromAmount = obj["subfee"].get_bool();

        if (o["pubkey"].isStr()) {
            std::string s = o["pubkey"].get_str();
            if (!IsHex(s) || !(s.size() == 66)) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Public key must be 33 bytes and hex encoded.");
            }
            std::vector<uint8_t> v = ParseHex(s);
            r.pkTo = CPubKey(v.begin(), v.end());
        }
        if (o["ephemeral_key"].isStr()) {
            std::string s = o["ephemeral_key"].get_str();
            if (!IsHex(s) || !(s.size() == 64)) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "\"ephemeral_key\" must be 32 bytes and hex encoded.");
            }
            std::vector<uint8_t> v = ParseHex(s);
            r.sEphem.Set(v.data(), true);
        }
        if (o["nonce"].isStr()) {
            std::string s = o["nonce"].get_str();
            if (!IsHex(s) || !(s.size() == 64)) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "\"nonce\" must be 32 bytes and hex encoded.");
            }
            std::vector<uint8_t> v = ParseHex(s);
            r.nonce.SetHex(s);
            r.fNonceSet = true;
        }

        if (o["data"].isStr()) {
            std::string s = o["data"].get_str();
            if (!IsHex(s)) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "\"data\" must be hex encoded.");
            }
            r.vData = ParseHex(s);
        }

        if (o["data_ct_fee"].isStr() || o["data_ct_fee"].isNum())
        {
            if (nType != OUTPUT_DATA) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "\"data_ct_fee\" can only appear in output of type \"data\".");
            }
            if (idx != 0) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "\"data_ct_fee\" can only appear in vout 0.");
            }
            nCtFee = AmountFromValue(o["data_ct_fee"]);
        };

        if (o["address"].isStr() && o["script"].isStr()) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Can't specify both \"address\" and \"script\".");
        }

        if (o["address"].isStr()) {
            CTxDestination dest = DecodeDestination(o["address"].get_str());
            if (!IsValidDestination(dest)) {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid address");
            }
            r.address = dest;
        }

        if (o["script"].isStr()) {
            r.scriptPubKey = ParseScript(o["script"].get_str());
            r.fScriptSet = true;
        }


        std::string sNarr;
        if (o["narration"].isStr()) {
            sNarr = o["narration"].get_str();
        }

        r.nType = nType;
        r.SetAmount(nAmount);
        r.fSubtractFeeFromAmount = fSubtractFeeFromAmount;
        //r.address = address;
        r.sNarration = sNarr;

        // Need to know the fee before calculating the blind sum
        if (r.nType == OUTPUT_CT || r.nType == OUTPUT_RINGCT) {
            r.vBlind.resize(32);
            if (o["blindingfactor"].isStr()) {
                std::string s = o["blindingfactor"].get_str();
                if (!IsHex(s) || !(s.size() == 64)) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "Blinding factor must be 32 bytes and hex encoded.");
                }

                uint256 blind;
                blind.SetHex(s);
                memcpy(r.vBlind.data(), blind.begin(), 32);
            } else {
                // Generate a random blinding factor if not provided
                GetStrongRandBytes(r.vBlind.data(), 32);
            }

            if (o["rangeproof_params"].isObject())
            {
                const UniValue &rangeproofParams = o["rangeproof_params"].get_obj();

                if (!rangeproofParams["min_value"].isNum() || !rangeproofParams["ct_exponent"].isNum() || !rangeproofParams["ct_bits"].isNum()) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "All range proof parameters must be numeric.");
                }

                r.fOverwriteRangeProofParams = true;
                r.min_value = rangeproofParams["min_value"].get_int64();
                r.ct_exponent = rangeproofParams["ct_exponent"].get_int();
                r.ct_bits = rangeproofParams["ct_bits"].get_int();
            }
        }

        vecSend.push_back(r);
    }

    LOCK(pwallet->cs_wallet);

    std::string sError;
    // Note: wallet is only necessary when sending to  an extkey address
    if (0 != pwallet->ExpandTempRecipients(vecSend, nullptr, sError)) {
        throw JSONRPCError(RPC_WALLET_ERROR, strprintf("ExpandTempRecipients failed: %s.", sError));
    }

    UniValue amounts(UniValue::VOBJ);

    CAmount nFeeRet = 0;
    //bool fFirst = true;
    for (size_t i = 0; i < vecSend.size(); ++i) {
        auto &r = vecSend[i];

        //r.ApplySubFee(nFeeRet, nSubtractFeeFromAmount, fFirst);

        OUTPUT_PTR<CTxOutBase> txbout;
        if (0 != CreateOutput(txbout, r, sError)) {
            throw JSONRPCError(RPC_WALLET_ERROR, strprintf("CreateOutput failed: %s.", sError));
        }

        if (!CheckOutputValue(pwallet->chain(), r, &*txbout, nFeeRet, sError)) {
            throw JSONRPCError(RPC_WALLET_ERROR, strprintf("CheckOutputValue failed: %s.", sError));
        }
        /*
        if (r.nType == OUTPUT_STANDARD)
            nValueOutPlain += r.nAmount;

        if (r.fChange && r.nType == OUTPUT_CT)
            nChangePosInOut = i;
        */
        r.n = rawTx.vpout.size();
        rawTx.vpout.push_back(txbout);

        if (nCtFee != 0 && i == 0) {
            txbout->SetCTFee(nCtFee);
            continue;
        }

        UniValue amount(UniValue::VOBJ);
        amount.pushKV("value", ValueFromAmount(r.nAmount));

        if (r.nType == OUTPUT_CT || r.nType == OUTPUT_RINGCT) {
            uint256 blind(r.vBlind.data(), 32);
            amount.pushKV("blind", blind.ToString());

            CCoinControl cctl;
            if (0 != pwallet->AddCTData(&cctl, txbout.get(), r, sError)) {
                throw JSONRPCError(RPC_WALLET_ERROR, strprintf("AddCTData failed: %s.", sError));
            }
            amount.pushKV("nonce", r.nonce.ToString());
        }

        if (r.nType != OUTPUT_DATA) {
            amounts.pushKV(strprintf("%d", r.n), amount);
        }
    }

    UniValue result(UniValue::VOBJ);
    result.pushKV("hex", EncodeHexTx(CTransaction(rawTx)));
    result.pushKV("amounts", amounts);

    return result;
},
    };
};


static RPCHelpMan fundrawtransactionfrom()
{
    return RPCHelpMan{"fundrawtransactionfrom",
                "\nAdd inputs to a transaction until it has enough in value to meet its out value.\n"
                "This will not modify existing inputs, and will add at most one change output to the outputs.\n"
                "No existing outputs will be modified unless \"subtractFeeFromOutputs\" is specified.\n"
                "Note that inputs which were signed may need to be resigned after completion since in/outputs have been added.\n"
                "Note that all existing inputs must have their previous output transaction be in the wallet or have their amount and blinding factor specified in input_amounts.\n"
                /*"Note that all inputs selected must be of standard form and P2SH scripts must be\n"
                "in the wallet using importaddress or addmultisigaddress (to calculate fees).\n"
                "You can see whether this is the case by checking the \"solvable\" field in the listunspent output.\n"
                "Only pay-to-pubkey, multisig, and P2SH versions thereof are currently supported for watch-only\n"*/,
                {
                    {"input_type", RPCArg::Type::STR, RPCArg::Optional::NO, "The type of inputs to use standard/anon/blind."},
                    {"hexstring", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The hex string of the raw transaction."},
                    {"input_amounts", RPCArg::Type::OBJ, RPCArg::Default{UniValue::VOBJ}, "",
                        {
                            {"value", RPCArg::Type::AMOUNT, RPCArg::Optional::NO, ""},
                            {"blind", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, ""},
                            {"witnessstack", RPCArg::Type::ARR, RPCArg::Default{UniValue::VARR}, "A json array of witness elements, used for the fee.\n",
                                {
                                    {"witnesselement", RPCArg::Type::STR_HEX, RPCArg::Default{""}, ""},
                                },
                            },
                            {"type", RPCArg::Type::STR, RPCArg::Default{"standard"}, "Type of input"},
                        },
                    },
                    {"output_amounts", RPCArg::Type::OBJ, RPCArg::Default{UniValue::VOBJ}, "",
                        {
                            {"value", RPCArg::Type::AMOUNT, RPCArg::Optional::NO, ""},
                            {"blind", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, ""},
                            {"nonce", RPCArg::Type::STR_HEX, RPCArg::Default{""}, ""},
                        },
                    },
                    {"options", RPCArg::Type::OBJ, RPCArg::Default{UniValue::VOBJ}, "",
                        {
                            {"inputs", RPCArg::Type::ARR, RPCArg::Default{UniValue::VARR}, "A json array of json objects, anon inputs must exist in the chain,",
                                {
                                    {"", RPCArg::Type::OBJ, RPCArg::Default{UniValue::VOBJ}, "",
                                        {
                                            {"tx", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "txn id"},
                                            {"n", RPCArg::Type::NUM, RPCArg::Optional::NO, "txn vout"},
                                            {"type", RPCArg::Type::STR, RPCArg::Default{""}, ""},
                                            {"blind", RPCArg::Type::STR_HEX, RPCArg::Default{""}, ""},
                                            {"commitment", RPCArg::Type::STR_HEX, RPCArg::Default{""}, ""},
                                            {"value", RPCArg::Type::AMOUNT, RPCArg::Default{""}, ""},
                                            {"privkey", RPCArg::Type::STR_HEX, RPCArg::Default{""}, ""},
                                            {"pubkey", RPCArg::Type::STR_HEX, RPCArg::Default{""}, ""},
                                        },
                                    },
                                },
                            },
                            {"changeAddress", RPCArg::Type::STR, RPCArg::Default{""}, "The particl address to receive the change."},
                            {"changepubkey", RPCArg::Type::STR, RPCArg::Default{""}, "The public key to use for the change output if changeAddress isn't set."},
                            {"changePosition", RPCArg::Type::NUM, RPCArg::Default{"random"}, "The index of the change output."},
                            //{"change_type", RPCArg::Type::STR, RPCArg::Default{""}, "The output type to use. Only valid if changeAddress is not specified. Options are \"legacy\", \"p2sh-segwit\", and \"bech32\". Default is set by -changetype."},
                            {"includeWatching", RPCArg::Type::BOOL, RPCArg::Default{false}, "Also select inputs which are watch only."},
                            {"lockUnspents", RPCArg::Type::BOOL, RPCArg::Default{false}, "Lock selected unspent outputs."},
                            {"feeRate", RPCArg::Type::AMOUNT, RPCArg::Default{"not set: makes wallet determine the fee"}, "Set a specific fee rate in " + CURRENCY_UNIT + "/kB"},
                            {"subtractFeeFromOutputs", RPCArg::Type::ARR, RPCArg::Default{UniValue::VARR}, "A json array of integers.\n"
                            "                              The fee will be equally deducted from the amount of each specified output.\n"
                            "                              The outputs are specified by their zero-based index, before any change output is added.\n"
                            "                              Those recipients will receive less particl than you enter in their corresponding amount field.\n"
                            "                              If no outputs are specified here, the sender pays the fee.",
                                {
                                    {"vout_index", RPCArg::Type::NUM, RPCArg::Default{""}, ""},
                                },
                            },
                            {"replaceable", RPCArg::Type::BOOL, RPCArg::DefaultHint{"wallet default"}, "Marks this transaction as BIP125 replaceable.\n"
                            "                              Allows this transaction to be replaced by a transaction with higher fees"},
                            {"conf_target", RPCArg::Type::NUM, RPCArg::Default{""}, "Confirmation target (in blocks)"},
                            {"estimate_mode", RPCArg::Type::STR, RPCArg::Default{"UNSET"}, "The fee estimate mode, must be one of:\n"
                            "         \"UNSET\"\n"
                            "         \"ECONOMICAL\"\n"
                            "         \"CONSERVATIVE\""},
                            {"avoid_reuse", RPCArg::Type::BOOL, RPCArg::Default{true}, "(only available if avoid_reuse wallet flag is set) Avoid spending from dirty addresses; addresses are considered\n"
            "                             dirty if they have previously been used in a transaction."},
                            {"allow_other_inputs", RPCArg::Type::BOOL, RPCArg::Default{true}, "Allow inputs to be added if any inputs already exist."},
                            {"allow_change_output", RPCArg::Type::BOOL, RPCArg::Default{true}, "Allow change output to be added if needed (only for 'blind' input_type).\n"
            "                              Allows this transaction to be replaced by a transaction with higher fees."},
                            {"sign_tx", RPCArg::Type::BOOL, RPCArg::Default{false}, "Sign transaction."},
                            {"anon_ring_size", RPCArg::Type::NUM, RPCArg::Default{(int)DEFAULT_RING_SIZE}, "Ring size for anon transactions."},
                            {"anon_inputs_per_sig", RPCArg::Type::NUM, RPCArg::Default{(int)DEFAULT_INPUTS_PER_SIG}, "Real inputs per ring signature."},
                            {"blind_watchonly_visible", RPCArg::Type::BOOL, RPCArg::Default{false}, "Reveal amounts of blinded outputs sent to stealth addresses to the scan_secret"},
                            {"minimumAmount", RPCArg::Type::AMOUNT, RPCArg::Default{FormatMoney(0)}, "Minimum value of each UTXO to select in " + CURRENCY_UNIT + ""},
                            {"maximumAmount", RPCArg::Type::AMOUNT, RPCArg::DefaultHint{"unlimited"}, "Maximum value of each UTXO to select in " + CURRENCY_UNIT + ""},
                        },
                    "options"},
                },
                RPCResult{
                    RPCResult::Type::OBJ, "", "", {
                        {RPCResult::Type::STR_HEX, "hex", "The resulting raw transaction"},
                        {RPCResult::Type::NUM, "fee", "Fee in " + CURRENCY_UNIT + " the resulting transaction pays"},
                        {RPCResult::Type::NUM, "changepos", "The position of the added change output, or -1"},
                        {RPCResult::Type::OBJ, "output_amounts", "Output values and blinding factors", {
                            {RPCResult::Type::OBJ, "n", "", {
                                {RPCResult::Type::STR_AMOUNT, "value", "The amount of the output in " + CURRENCY_UNIT},
                                {RPCResult::Type::STR_HEX, "blind", "Blinding factor"},
                            }}
                        }},
                }},
                RPCExamples{
            "\nCreate a transaction with no inputs\n"
            + HelpExampleCli("createrawctransaction", "\"[]\" \"{\\\"myaddress\\\":0.01}\"") +
            "\nAdd sufficient unsigned inputs to meet the output value\n"
            + HelpExampleCli("fundrawtransactionfrom", "\"blind\" \"rawtransactionhex\"") +
            "\nSign the transaction\n"
            + HelpExampleCli("signrawtransactionwithwallet", "\"fundedtransactionhex\"") +
            "\nSend the transaction\n"
            + HelpExampleCli("sendrawtransaction", "\"signedtransactionhex\"")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
    if (!wallet) return NullUniValue;
    CHDWallet *const pwallet = GetParticlWallet(wallet.get());

    RPCTypeCheck(request.params, {UniValue::VSTR, UniValue::VSTR, UniValue::VOBJ, UniValue::VOBJ, UniValue::VOBJ}, true);

    // Make sure the results are valid at least up to the most recent block
    // the user could have gotten from another RPC command prior to now
    pwallet->BlockUntilSyncedToCurrentChain();

    const std::string sInputType = request.params[0].get_str();
    OutputTypes input_type = WordToType(sInputType);
    if (input_type == OUTPUT_NULL) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Unknown input type.");
    }

    CCoinControl coinControl;
    int changePosition = -1;
    bool lockUnspents = false;
    UniValue subtractFeeFromOutputs;
    std::set<int> setSubtractFeeFromOutputs;

    coinControl.fAllowOtherInputs = true;
    coinControl.m_avoid_address_reuse = pwallet->IsWalletFlagSet(WALLET_FLAG_AVOID_REUSE);

    bool sign_tx = false;
    int rct_ring_size = DEFAULT_RING_SIZE;
    int rct_inputs_per_sig = DEFAULT_INPUTS_PER_SIG;

    if (request.params[4].isObject()) {
        UniValue options = request.params[4];

        RPCTypeCheckObj(options,
            {
                {"changeaddress", UniValueType(UniValue::VSTR)},
                {"changeAddress", UniValueType(UniValue::VSTR)},
                {"changepubkey", UniValueType(UniValue::VSTR)},
                {"changePosition", UniValueType(UniValue::VNUM)},
                {"inputs", UniValueType(UniValue::VARR)},
                {"includeWatching", UniValueType(UniValue::VBOOL)},
                {"lockUnspents", UniValueType(UniValue::VBOOL)},
                {"feeRate", UniValueType()}, // will be checked below
                {"subtractFeeFromOutputs", UniValueType(UniValue::VARR)},
                {"replaceable", UniValueType(UniValue::VBOOL)},
                {"allow_other_inputs", UniValueType(UniValue::VBOOL)},
                {"allow_change_output", UniValueType(UniValue::VBOOL)},
                {"conf_target", UniValueType(UniValue::VNUM)},
                {"estimate_mode", UniValueType(UniValue::VSTR)},
                {"avoid_reuse", UniValueType(UniValue::VBOOL)},
                {"sign_tx", UniValueType(UniValue::VBOOL)},
                {"anon_ring_size", UniValueType(UniValue::VNUM)},
                {"anon_inputs_per_sig", UniValueType(UniValue::VNUM)},
                {"blind_watchonly_visible", UniValueType(UniValue::VBOOL)},
                {"minimumAmount", UniValueType()},
                {"maximumAmount", UniValueType()},
            },
            true, true);

        ParseCoinControlOptions(options, pwallet, coinControl);

        if (options.exists("changePosition")) {
            changePosition = options["changePosition"].get_int();
        }
        if (options.exists("lockUnspents")) {
            lockUnspents = options["lockUnspents"].get_bool();
        }
        if (options.exists("subtractFeeFromOutputs")) {
            subtractFeeFromOutputs = options["subtractFeeFromOutputs"].get_array();
        }
        if (options.exists("allow_other_inputs")) {
            coinControl.fAllowOtherInputs = options["allow_other_inputs"].get_bool();
        }
        if (options.exists("allow_change_output")) {
            coinControl.m_addChangeOutput = options["allow_change_output"].get_bool();
        }

        if (options.exists("sign_tx")) {
            sign_tx = options["sign_tx"].get_bool();
        }
        if (options.exists("anon_ring_size")) {
            rct_ring_size = options["anon_ring_size"].get_int();
        }
        if (options.exists("anon_inputs_per_sig")) {
            rct_inputs_per_sig = options["anon_inputs_per_sig"].get_int();
        }
        if (options["blind_watchonly_visible"].isBool() && options["blind_watchonly_visible"].get_bool() == true) {
            coinControl.m_blind_watchonly_visible = true;
        }
    }
    coinControl.m_avoid_partial_spends |= coinControl.m_avoid_address_reuse;

    // parse hex string from parameter
    CMutableTransaction tx;
    tx.nVersion = PARTICL_TXN_VERSION;
    if (!DecodeHexTx(tx, request.params[1].get_str(), true)) {
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "TX decode failed");
    }

    size_t nOutputs = tx.GetNumVOuts();
    if (nOutputs == 0) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "TX must have at least one output");
    }

    if (changePosition != -1 && (changePosition < 0 || (unsigned int)changePosition > nOutputs)) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "changePosition out of bounds");
    }
    coinControl.nChangePos = changePosition;

    for (unsigned int idx = 0; idx < subtractFeeFromOutputs.size(); idx++) {
        int pos = subtractFeeFromOutputs[idx].get_int();
        if (setSubtractFeeFromOutputs.count(pos)) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("Invalid parameter, duplicated position: %d", pos));
        }
        if (pos < 0) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("Invalid parameter, negative position: %d", pos));
        }
        if (pos >= int(nOutputs)) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("Invalid parameter, position too large: %d", pos));
        }
        setSubtractFeeFromOutputs.insert(pos);
    }

    UniValue inputAmounts = request.params[2];
    UniValue outputAmounts = request.params[3];
    std::map<int, uint256> mInputBlinds, mOutputBlinds;
    std::map<int, CAmount> mOutputAmounts;

    std::vector<CTempRecipient> vecSend(nOutputs);

    const std::vector<std::string> &vInputKeys = inputAmounts.getKeys();
    for (const std::string &sKey : vInputKeys) {
        int64_t n;
        if (!ParseInt64(sKey, &n) || n >= (int64_t)tx.vin.size() || n < 0) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Bad index for input blinding factor.");
        }

        CInputData im;
        if (tx.vin[n].prevout.n >= OR_PLACEHOLDER_N) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Input offset too large for output record.");
        }

        if (inputAmounts[sKey]["blind"].isStr()) {
            std::string s = inputAmounts[sKey]["blind"].get_str();
            if (!IsHex(s) || !(s.size() == 64)) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Blinding factor must be 32 bytes and hex encoded.");
            }

            im.blind.SetHex(s);
            mInputBlinds[n] = im.blind;
            im.nType = OUTPUT_CT;
        }
        const UniValue &typeObj = find_value(inputAmounts[sKey], "type");
        if (typeObj.isStr()) {
            std::string s = typeObj.get_str();
            im.nType = WordToType(s);
            if (im.nType == OUTPUT_NULL) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Unknown input type.");
            }
        }

        if (inputAmounts[sKey]["value"].isNull()) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Missing 'value' for input.");
        }
        im.nValue = AmountFromValue(inputAmounts[sKey]["value"]);

        if (inputAmounts[sKey]["witnessstack"].isArray()) {
            const UniValue &stack = inputAmounts[sKey]["witnessstack"].get_array();

            for (size_t k = 0; k < stack.size(); ++k) {
                std::string s = stack[k].get_str();
                if (!IsHex(s) && s.size() > 0) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "Input witness must be hex encoded.");
                }
                std::vector<uint8_t> v = ParseHex(s);
                im.scriptWitness.stack.push_back(v);
            }
        }
        coinControl.m_inputData[tx.vin[n].prevout] = im;
    }

    const std::vector<std::string> &vOutputKeys = outputAmounts.getKeys();
    for (const std::string &sKey : vOutputKeys) {
        int64_t n;
        if (!ParseInt64(sKey, &n) || n >= (int64_t)tx.GetNumVOuts() || n < 0) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Bad index for output blinding factor.");
        }

        const auto &txout = tx.vpout[n];

        if (!outputAmounts[sKey]["value"].isNull()) {
            mOutputAmounts[n] = AmountFromValue(outputAmounts[sKey]["value"]);
        }

        if (outputAmounts[sKey]["nonce"].isStr()
            && txout->GetPRangeproof()) {
            CTempRecipient &r = vecSend[n];
            std::string s = outputAmounts[sKey]["nonce"].get_str();
            if (!IsHex(s) || !(s.size() == 64)) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Nonce must be 32 bytes and hex encoded.");
            }

            r.fNonceSet = true;
            r.nonce.SetHex(s);

            uint64_t min_value, max_value;
            uint8_t blindOut[32];
            unsigned char msg[256]; // Currently narration is capped at 32 bytes
            size_t mlen = sizeof(msg);
            memset(msg, 0, mlen);
            uint64_t amountOut;
            uint256 blind;
            if (txout->GetPRangeproof()->size() < 1000) {
                if (1 != secp256k1_bulletproof_rangeproof_rewind(secp256k1_ctx_blind, blind_gens,
                    &amountOut, blindOut, txout->GetPRangeproof()->data(), txout->GetPRangeproof()->size(),
                    0, txout->GetPCommitment(), &secp256k1_generator_const_h, r.nonce.begin(), NULL, 0)) {
                    throw JSONRPCError(RPC_MISC_ERROR, strprintf("secp256k1_bulletproof_rangeproof_rewind failed, output %d.", n));
                }

                ExtractNarration(r.nonce, r.vData, r.sNarration);
            } else
            if (1 != secp256k1_rangeproof_rewind(secp256k1_ctx_blind,
                blindOut, &amountOut, msg, &mlen, r.nonce.begin(),
                &min_value, &max_value,
                txout->GetPCommitment(), txout->GetPRangeproof()->data(), txout->GetPRangeproof()->size(),
                nullptr, 0,
                secp256k1_generator_h)) {
                throw JSONRPCError(RPC_MISC_ERROR, strprintf("secp256k1_rangeproof_rewind failed, output %d.", n));
            }

            memcpy(blind.begin(), blindOut, 32);

            mOutputBlinds[n] = blind;
            mOutputAmounts[n] = amountOut;

            msg[mlen-1] = '\0';
            size_t nNarr = strlen((const char*)msg);
            if (nNarr > 0) {
                r.sNarration.assign((const char*)msg, nNarr);
            }
        } else {
            if (txout->GetPRangeproof()) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("Missing nonce for output %d.", n));
            }
        }
        /*
        if (outputAmounts[sKey]["blind"].isStr())
        {
            std::string s = outputAmounts[sKey]["blind"].get_str();
            if (!IsHex(s) || !(s.size() == 64))
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Blinding factor must be 32 bytes and hex encoded.");

            uint256 blind;
            blind.SetHex(s);
            mOutputBlinds[n] = blind;
        };
        */
        vecSend[n].SetAmount(mOutputAmounts[n]);
    };

    for (size_t i = 0; i < tx.vpout.size(); ++i) {
        const auto &txout = tx.vpout[i];
        CTempRecipient &r = vecSend[i];

        if (txout->IsType(OUTPUT_CT) || txout->IsType(OUTPUT_RINGCT)) {
            // Check commitment matches
            std::map<int, CAmount>::iterator ita = mOutputAmounts.find(i);
            std::map<int, uint256>::iterator itb = mOutputBlinds.find(i);

            if (ita == mOutputAmounts.end()) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("Missing amount for blinded output %d.", i));
            }
            if (itb == mOutputBlinds.end()) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("Missing blinding factor for blinded output %d.", i));
            }

            secp256k1_pedersen_commitment commitment;
            if (!secp256k1_pedersen_commit(secp256k1_ctx_blind,
                &commitment, (const uint8_t*)(itb->second.begin()),
                ita->second, &secp256k1_generator_const_h, &secp256k1_generator_const_g)) {
                throw JSONRPCError(RPC_MISC_ERROR, strprintf("secp256k1_pedersen_commit failed, output %d.", i));
            }

            if (memcmp(txout->GetPCommitment()->data, commitment.data, 33) != 0) {
                throw JSONRPCError(RPC_MISC_ERROR, strprintf("Bad blinding factor, output %d.", i));
            }

            r.vBlind.resize(32);
            memcpy(r.vBlind.data(), itb->second.begin(), 32);
        } else
        if (txout->IsType(OUTPUT_STANDARD)) {
            mOutputAmounts[i] = txout->GetValue();
        }

        r.nType = txout->GetType();
        if (txout->IsType(OUTPUT_DATA)) {
            r.vData = ((CTxOutData*)txout.get())->vData;
        } else {
            r.SetAmount(mOutputAmounts[i]);
            r.fSubtractFeeFromAmount = setSubtractFeeFromOutputs.count(i);

            if (txout->IsType(OUTPUT_CT)) {
                r.vData = ((CTxOutCT*)txout.get())->vData;
            } else
            if (txout->IsType(OUTPUT_RINGCT)) {
                CTxOutRingCT *p = (CTxOutRingCT*)txout.get();
                r.vData = p->vData;
                r.pkTo = CPubKey(p->pk.begin(), p->pk.end());
            }

            if (txout->GetPScriptPubKey()) {
                r.fScriptSet = true;
                r.scriptPubKey = *txout->GetPScriptPubKey();
            }
        }
    }

    std::set<COutPoint> set_existing_inputs;
    for (const CTxIn& txin : tx.vin) {
        coinControl.Select(txin.prevout);
        set_existing_inputs.insert(txin.prevout);
    }

    CTransactionRef tx_new;
    CWalletTx wtx(pwallet, tx_new);
    CTransactionRecord rtx;
    CAmount nFee;
    std::string sError;
    {
        LOCK(pwallet->cs_wallet);

        pwallet->ClearMapTempRecords();

        for (auto const& im : coinControl.m_inputData) {
            COutputRecord r;
            r.n = im.first.n;
            r.nType = im.second.nType;
            r.nValue = im.second.nValue;
            //r.scriptPubKey = ; // TODO
            std::pair<MapRecords_t::iterator, bool> ret = pwallet->mapTempRecords.insert(std::make_pair(im.first.hash, CTransactionRecord()));
            ret.first->second.InsertOutput(r);
        }

        if (input_type == OUTPUT_STANDARD) {
            if (0 != pwallet->AddStandardInputs(wtx, rtx, vecSend, sign_tx, nFee, &coinControl, sError)) {
                throw JSONRPCError(RPC_WALLET_ERROR, strprintf("AddStandardInputs failed: %s.", sError));
            }
        } else
        if (input_type == OUTPUT_RINGCT) {
            if (0 != pwallet->AddAnonInputs(wtx, rtx, vecSend, sign_tx, rct_ring_size, rct_inputs_per_sig, nFee, &coinControl, sError)) {
                throw JSONRPCError(RPC_WALLET_ERROR, strprintf("AddAnonInputs failed: %s.", sError));
            }
        } else
        if (input_type == OUTPUT_CT) {
            if (0 != pwallet->AddBlindedInputs(wtx, rtx, vecSend, sign_tx, nFee, &coinControl, sError)) {
                throw JSONRPCError(RPC_WALLET_ERROR, strprintf("AddBlindedInputs failed: %s.", sError));
            }
        } else {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Unknown input type.");
        }
        pwallet->ClearMapTempRecords(); // superfluous as cleared before set
    }

    tx.vpout = wtx.tx->vpout;
    // keep existing sequences
    for (const auto &txin : wtx.tx->vin) {
        if (!set_existing_inputs.count(txin.prevout)) {
            tx.vin.push_back(txin);
        }
        if (lockUnspents) {
            LOCK(pwallet->cs_wallet);
            pwallet->LockCoin(txin.prevout);
        }
    }

    UniValue outputValues(UniValue::VOBJ);
    for (size_t i = 0; i < vecSend.size(); ++i) {
        auto &r = vecSend[i];

        UniValue outputValue(UniValue::VOBJ);
        if (r.vBlind.size() == 32) {
            uint256 blind(r.vBlind.data(), 32);
            outputValue.pushKV("blind", blind.ToString());
        }
        if (r.nType != OUTPUT_DATA) {
            outputValue.pushKV("value", ValueFromAmount(r.nAmount));
            outputValues.pushKV(strprintf("%d", r.n), outputValue);
        }
    }

    if (nFee > pwallet->m_default_max_tx_fee) {
        throw JSONRPCError(RPC_WALLET_ERROR, TransactionErrorString(TransactionError::MAX_FEE_EXCEEDED).original);
    }

    pwallet->mapTempRecords.clear();

    UniValue result(UniValue::VOBJ);
    result.pushKV("hex", EncodeHexTx(CTransaction(tx)));
    result.pushKV("fee", ValueFromAmount(nFee));
    result.pushKV("changepos", coinControl.nChangePos);
    result.pushKV("output_amounts", outputValues);

    return result;
},
    };
};

static RPCHelpMan verifycommitment()
{
    return RPCHelpMan{"verifycommitment",
                "\nVerify a value commitment.\n",
                {
                    {"commitment", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "33byte commitment hex string."},
                    {"blind", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "32byte blinding factor hex string."},
                    {"amount", RPCArg::Type::AMOUNT, RPCArg::Optional::NO, "The amount committed to."},
                },
                RPCResult{
                    RPCResult::Type::OBJ, "", "", {
                        {RPCResult::Type::BOOL, "result", "If valid commitment, else throw error"},
                }},
                RPCExamples{
            HelpExampleCli("verifycommitment", "\"commitment\" \"blind\" 1.1") +
            "\nAs a JSON-RPC call\n"
            + HelpExampleRpc("verifycommitment", "\"commitment\", \"blind\", 1.1")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    RPCTypeCheck(request.params, {UniValue::VSTR, UniValue::VSTR});

    std::vector<uint8_t> vchCommitment;
    uint256 blind;

    std::string s = request.params[0].get_str();
    if (!IsHex(s) || !(s.size() == 66)) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Commitment must be 33 bytes and hex encoded.");
    }
    vchCommitment = ParseHex(s);
    s = request.params[1].get_str();
    if (!IsHex(s) || !(s.size() == 64)) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Blinding factor must be 32 bytes and hex encoded.");
    }
    blind.SetHex(s);

    CAmount nValue = AmountFromValue(request.params[2]);

    secp256k1_pedersen_commitment commitment;
    if (!secp256k1_pedersen_commit(secp256k1_ctx_blind,
        &commitment, blind.begin(),
        nValue, &secp256k1_generator_const_h, &secp256k1_generator_const_g)) {
        throw JSONRPCError(RPC_MISC_ERROR, strprintf("secp256k1_pedersen_commit failed."));
    }

    if (memcmp(vchCommitment.data(), commitment.data, 33) != 0) {
        throw JSONRPCError(RPC_MISC_ERROR, strprintf("Mismatched commitment, expected ") + HexStr(Span<const unsigned char>(commitment.data, 33)));
    }

    UniValue result(UniValue::VOBJ);
    bool rv = true;
    result.pushKV("result", rv);
    return result;
},
    };
};

static RPCHelpMan rewindrangeproof()
{
    return RPCHelpMan{"rewindrangeproof",
                "\nExtract data encoded in a rangeproof.\n",
                {
                    {"rangeproof", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Rangeproof as hex string."},
                    {"commitment", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "33byte commitment hex string."},
                    {"nonce_key", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "32byte hex string or WIF encoded key."},
                    {"ephemeral_key", RPCArg::Type::STR_HEX, RPCArg::Default{""}, "33byte ephemeral_key hex string, if not set nonce_key is used directly."},
                },
                RPCResult{
                    RPCResult::Type::OBJ, "", "", {
                        {RPCResult::Type::STR_HEX, "blind", "32byte blinding factor"},
                        {RPCResult::Type::STR_AMOUNT, "amount", "The amount committed to"},
                }},
                RPCExamples{
            HelpExampleCli("rewindrangeproof", "\"rangeproof\" \"commitment\" \"nonce_key\" \"ephemeral_key\"") +
            "\nAs a JSON-RPC call\n"
            + HelpExampleRpc("rewindrangeproof", "\"rangeproof\", \"commitment\", \"nonce_key\", \"ephemeral_key\"")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    RPCTypeCheck(request.params, {UniValue::VSTR, UniValue::VSTR, UniValue::VSTR, UniValue::VSTR});

    std::vector<uint8_t> vchRangeproof, vchCommitment;
    CKey nonce_key;
    CPubKey pkEphem;
    uint256 nonce;
    std::string s = request.params[0].get_str();
    if (!IsHex(s)) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Rangeproof must be hex encoded.");
    }
    vchRangeproof = ParseHex(s);
    s = request.params[1].get_str();
    if (!IsHex(s) || !(s.size() == 66)) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Commitment must be 33 bytes and hex encoded.");
    }
    vchCommitment = ParseHex(s);

    if (request.params.size() > 3) {
        s = request.params[2].get_str();
        ParseSecretKey(s, nonce_key);
        if (!nonce_key.IsValid()) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid nonce_key");
        }

        s = request.params[3].get_str();
        if (!IsHex(s) || !(s.size() == 66)) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Ephemeral public key must be 33 bytes and hex encoded.");
        }
        std::vector<uint8_t> v = ParseHex(s);
        pkEphem = CPubKey(v.begin(), v.end());
        if (!pkEphem.IsValid()) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid ephemeral public key.");
        }
        // Regenerate nonce
        nonce = nonce_key.ECDH(pkEphem);
        CSHA256().Write(nonce.begin(), 32).Finalize(nonce.begin());
    } else {
        s = request.params[2].get_str();
        if (!IsHex(s) || !(s.size() == 64)) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Nonce (without ephem pubkey) must be 32 bytes and hex encoded.");
        }
        nonce.SetHex(s);
    }

    std::vector<uint8_t> vchBlind;
    CAmount nValue;

    if (!RewindRangeProof(vchRangeproof, vchCommitment, nonce,
        vchBlind, nValue) || vchBlind.size() != 32) {
        throw JSONRPCError(RPC_MISC_ERROR, strprintf("RewindRangeProof failed."));
    }

    UniValue result(UniValue::VOBJ);

    uint256 blind(vchBlind.data(), 32);
    result.pushKV("blind", blind.ToString());
    result.pushKV("amount", ValueFromAmount(nValue));
    return result;
},
    };
};

static RPCHelpMan generatematchingblindfactor()
{
    return RPCHelpMan{"generatematchingblindfactor",
                "\nGenerates the last blinding factor for a set of inputs and outputs.\n",
                {
                    {"blind_in", RPCArg::Type::ARR, RPCArg::Optional::NO, "A json array of blinding factors",
                        {
                            {"blindingfactor", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "blinding factor"},
                        },
                    },
                    {"blind_out", RPCArg::Type::ARR, RPCArg::Optional::NO, "A json array of blinding factors",
                        {
                            {"blindingfactor", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "blinding factor"},
                        },
                    },
                },
                RPCResult{
                    RPCResult::Type::OBJ, "", "", {
                        {RPCResult::Type::STR_HEX, "blind", "32byte blind factor"},
                }},
                RPCExamples{
            HelpExampleCli("generatematchingblindfactor", "[\"blindfactor_input\",\"blindfactor_input2\"] [\"blindfactor_output\"]") +
            "\nAs a JSON-RPC call\n"
            + HelpExampleRpc("generatematchingblindfactor", "[\"blindfactor_input\",\"blindfactor_input2\"] [\"blindfactor_output\"]")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    RPCTypeCheck(request.params, {UniValue::VARR, UniValue::VARR});

    std::vector<uint8_t> vBlinds;
    std::vector<uint8_t*> vpBlinds;

    if (!request.params[0].isArray()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Inputs must be an array of hex encoded blind factors.");
    }

    if (!request.params[1].isArray()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Outputs must be an array of hex encoded blind factors.");
    }

    const UniValue &inputs = request.params[0].get_array();
    const UniValue &outputs = request.params[1].get_array();

    if (inputs.size() < 1) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Inputs should contain at least one element.");
    }

    if (outputs.size() < 1) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Outputs should contain at least one element.");
    }

    if (inputs.size() < outputs.size()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Outputs should be at least one element smaller than the inputs array.");
    }

    vBlinds.resize((inputs.size() + outputs.size()) * 32);

    for (unsigned int idx = 0; idx < inputs.size(); idx++) {
        std::string sBlind = inputs[idx].get_str();
        if (!IsHex(sBlind) || !(sBlind.size() == 64)) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Blinding factor must be 32 bytes and hex encoded.");
        }

        uint256 blind;
        blind.SetHex(sBlind);

        const int index = idx * 32;
        memcpy(&vBlinds[index], blind.begin(), 32);

        vpBlinds.push_back(&vBlinds[index]);
    }

    // size of inputs
    size_t nBlindedInputs = vpBlinds.size();

    for (unsigned int idx = 0; idx < outputs.size(); idx++) {
        std::string sBlind = outputs[idx].get_str();
        if (!IsHex(sBlind) || !(sBlind.size() == 64)) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Blinding factor must be 32 bytes and hex encoded.");
        }

        uint256 blind;
        blind.SetHex(sBlind);

        const int index = nBlindedInputs * 32 + idx * 32;
        memcpy(&vBlinds[index], blind.begin(), 32);

        vpBlinds.push_back(&vBlinds[index]);
    }

    // final matching blind factor
    std::vector<uint8_t> final;
    final.resize(32);

    // Last to-be-blinded value: compute from all other blinding factors.
    // sum of output blinding values must equal sum of input blinding values
    if (!secp256k1_pedersen_blind_sum(secp256k1_ctx_blind, &final[0], &vpBlinds[0], vpBlinds.size(), nBlindedInputs)) {
        throw JSONRPCError(RPC_INTERNAL_ERROR, "secp256k1_pedersen_blind_sum failed");
    }

    UniValue result(UniValue::VOBJ);
    if (final.size() == 32) {
        uint256 blind(final.data(), 32);
        result.pushKV("blind", blind.ToString());
    }

    return result;
},
    };
};

static RPCHelpMan verifyrawtransaction()
{
    return RPCHelpMan{"verifyrawtransaction",
                "\nVerify inputs for raw transaction (serialized, hex-encoded).\n"
                "The second optional argument (may be null) is an array of previous transaction outputs that\n"
                "this transaction depends on but may not yet be in the block chain.\n",
                {
                    {"hexstring", RPCArg::Type::STR, RPCArg::Optional::NO, "The transaction hex string."},
                    {"prevtxs", RPCArg::Type::ARR, RPCArg::Default{UniValue::VARR}, "A json array of previous dependent transaction outputs",
                        {
                            {"", RPCArg::Type::OBJ, RPCArg::Optional::NO, "",
                                {
                                    {"txid", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The transaction id"},
                                    {"vout", RPCArg::Type::NUM, RPCArg::Optional::NO, "The output number"},
                                    {"scriptPubKey", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "script key"},
                                    //{"redeemScript", RPCArg::Type::STR_HEX, RPCArg::Default{""}, "(required for P2SH or P2WSH)"},
                                    {"amount", RPCArg::Type::AMOUNT, RPCArg::Optional::NO, "The amount spent"},
                                    {"amount_commitment", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The amount commitment spent"},
                                    {"chainheight", RPCArg::Type::NUM, RPCArg::Default{"0x7FFFFFFF"}, "Height of prevout in chain, mempool height by default"},
                                },
                            },
                        },
                    },
                    {"options", RPCArg::Type::OBJ, RPCArg::Default{UniValue::VOBJ}, "",
                        {
                            {"returndecoded", RPCArg::Type::BOOL, RPCArg::Default{false}, "Return the decoded txn as a json object."},
                            {"checkvalues", RPCArg::Type::BOOL, RPCArg::Default{true}, "Check amounts and amount commitments match up."},
                            {"checkoutputs", RPCArg::Type::BOOL, RPCArg::Default{true}, "Check tx attributes and outputs."},
                            {"particlmode", RPCArg::Type::BOOL, RPCArg::Default{true}, "Check amounts and amount commitments match up."},
                            {"spendheight", RPCArg::Type::NUM, RPCArg::Default{"chainheight"}, "Height the tx is spent at, set to current chain height if not provided."},
                        },
                        "options"},
                },
                RPCResult{
                    RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::BOOL, "outputs_valid", "If the transaction passed output verification"},
                        {RPCResult::Type::BOOL, "inputs_valid", "If the transaction passed input verification"},
                        {RPCResult::Type::BOOL, "complete", "If the transaction has a complete set of signatures"},
                        {RPCResult::Type::NUM, "validscripts", "The number of scripts which passed verification"},
                        {RPCResult::Type::STR, "label", "The label of the receiving address. The default label is \"\""},
                        {RPCResult::Type::ARR, "errors", "Script verification errors (if there are any)",
                        {
                            {RPCResult::Type::OBJ, "", "",
                            {
                                {RPCResult::Type::STR_HEX, "txid", "The hash of the referenced, previous transaction"},
                                {RPCResult::Type::NUM, "vout", "The index of the output to spent and used as input"},
                                {RPCResult::Type::STR_HEX, "scriptSig", "The hex-encoded signature script"},
                                {RPCResult::Type::NUM, "sequence", "Script sequence number"},
                                {RPCResult::Type::STR, "error", "Verification or signing error related to the input"},
                            }},
                        }},
                    }
                },
                RPCExamples{
            HelpExampleCli("verifyrawtransaction", "\"myhex\"") +
            "\nAs a JSON-RPC call\n"
            + HelpExampleRpc("verifyrawtransaction", "\"myhex\"")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    RPCTypeCheck(request.params, {UniValue::VSTR, UniValue::VARR, UniValue::VOBJ}, true);

    ChainstateManager &chainman = EnsureAnyChainman(request.context);

    bool return_decoded = false;
    bool check_values = true;
    bool check_outputs = true;
    bool particl_mode = true;
    int nSpendHeight = -1;
    int64_t nSpendTime = 0;

    if (!request.params[2].isNull()) {
        const UniValue& options = request.params[2].get_obj();

        RPCTypeCheckObj(options,
            {
                {"returndecoded",            UniValueType(UniValue::VBOOL)},
                {"checkvalues",              UniValueType(UniValue::VBOOL)},
                {"checkoutputs",             UniValueType(UniValue::VBOOL)},
                {"particlmode",              UniValueType(UniValue::VBOOL)},
                {"spendheight",              UniValueType(UniValue::VNUM)},
            }, true, false);

        if (options.exists("returndecoded")) {
            return_decoded = options["returndecoded"].get_bool();
        }
        if (options.exists("checkvalues")) {
            check_values = options["checkvalues"].get_bool();
        }
        if (options.exists("checkoutputs")) {
            check_outputs = options["checkoutputs"].get_bool();
        }
        if (options.exists("particlmode")) {
            particl_mode = options["particlmode"].get_bool();
        }
        if (options.exists("spendheight")) {
            nSpendHeight = options["spendheight"].get_int();
        }
    }

    CMutableTransaction mtx;
    if (!DecodeHexTx(mtx, request.params[0].get_str(), true)) {
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "TX decode failed");
    }

    // Fetch previous transactions (inputs):
    CCoinsView viewDummy;
    CCoinsViewCache view(&viewDummy);

    {
        //CTxMemPool *pmempool = request.context.chain.getMempool();
        //LOCK2(cs_main, pmempool->cs);
        LOCK(cs_main);
        CCoinsViewCache &viewChain = chainman.ActiveChainstate().CoinsTip();
        //CCoinsViewMemPool viewMempool(&viewChain, *pmempool);
        //view.SetBackend(viewMempool); // temporarily switch cache backend to db+mempool view
        view.SetBackend(viewChain);

        for (const CTxIn& txin : mtx.vin) {
            view.AccessCoin(txin.prevout); // Load entries from viewChain into view; can fail.
        }

        view.SetBackend(viewDummy); // switch back to avoid locking mempool for too long
    }

    // Add previous txouts given in the RPC call:
    if (!request.params[1].isNull()) {
        UniValue prevTxs = request.params[1].get_array();
        for (unsigned int idx = 0; idx < prevTxs.size(); ++idx) {
            const UniValue& p = prevTxs[idx];
            if (!p.isObject()) {
                throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "expected object with {\"txid'\",\"vout\",\"scriptPubKey\"}");
            }

            UniValue prevOut = p.get_obj();

            RPCTypeCheckObj(prevOut,
                {
                    {"txid", UniValueType(UniValue::VSTR)},
                    {"vout", UniValueType(UniValue::VNUM)},
                    {"scriptPubKey", UniValueType(UniValue::VSTR)},
                });

            uint256 txid = ParseHashO(prevOut, "txid");

            int nOut = find_value(prevOut, "vout").get_int();
            if (nOut < 0) {
                throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "vout must be positive");
            }

            COutPoint out(txid, nOut);
            std::vector<unsigned char> pkData(ParseHexO(prevOut, "scriptPubKey"));
            CScript scriptPubKey(pkData.begin(), pkData.end());

            {
            const Coin& coin = view.AccessCoin(out);

            if (coin.nType != OUTPUT_STANDARD && coin.nType != OUTPUT_CT) {
                throw JSONRPCError(RPC_MISC_ERROR, strprintf("Bad input type: %d", coin.nType));
            }
            if (!coin.IsSpent() && coin.out.scriptPubKey != scriptPubKey) {
                std::string err("Previous output scriptPubKey mismatch:\n");
                err = err + ScriptToAsmStr(coin.out.scriptPubKey) + "\nvs:\n"+
                    ScriptToAsmStr(scriptPubKey);
                throw JSONRPCError(RPC_DESERIALIZATION_ERROR, err);
            }
            Coin newcoin;
            newcoin.out.scriptPubKey = scriptPubKey;
            newcoin.out.nValue = 0;
            if (prevOut.exists("amount")) {
                if (prevOut.exists("amount_commitment")) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "Both \"amount\" and \"amount_commitment\" found.");
                }
                newcoin.nType = OUTPUT_STANDARD;
                newcoin.out.nValue = AmountFromValue(find_value(prevOut, "amount"));
            } else
            if (prevOut.exists("amount_commitment")) {
                std::string s = prevOut["amount_commitment"].get_str();
                if (!IsHex(s) || !(s.size() == 66)) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "\"amount_commitment\" must be 33 bytes and hex encoded.");
                }
                std::vector<uint8_t> vchCommitment = ParseHex(s);
                CHECK_NONFATAL(vchCommitment.size() == 33);
                memcpy(newcoin.commitment.data, vchCommitment.data(), 33);
                newcoin.nType = OUTPUT_CT;
            } else {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "\"amount\" or \"amount_commitment\" is required");
            }

            if (!coin.IsSpent()) { // IsSpent is true if coin not found
                newcoin.nHeight = coin.nHeight;
            } else {
                if (prevOut.exists("chainheight")) {
                    newcoin.nHeight = prevOut["chainheight"].get_int();
                    if (newcoin.nHeight < 1) {
                        throw JSONRPCError(RPC_INVALID_PARAMETER, "\"chainheight\" Must be >= 1");
                    }
                } else {
                    // Set to the same height as a tx in the mempool would be
                    newcoin.nHeight = 0x7FFFFFFF;
                }
            }
            view.AddCoin(out, std::move(newcoin), true);
            }
        }
    }


    // Use CTransaction for the constant parts of the
    // transaction to avoid rehashing.
    const CTransaction txConst(mtx);

    // Script verification errors
    UniValue vErrors(UniValue::VARR);

    if (nSpendHeight < 0) {
        LOCK(cs_main);
        nSpendHeight = chainman.ActiveChain().Height();
        nSpendTime = chainman.ActiveChain().Time();
    } else {
        LOCK(cs_main);
        if (nSpendHeight > chainman.ActiveChain().Height()) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Spend height out of range");
        }
        const CBlockIndex *pblockindex = chainman.ActiveChain()[nSpendHeight];
        nSpendHeight = pblockindex->nHeight;
        nSpendTime = pblockindex->nTime;
    }

    const Consensus::Params& consensusParams = Params().GetConsensus();
    UniValue result(UniValue::VOBJ);

     if (check_outputs) {
        TxValidationState state;
        state.SetStateInfo(nSpendTime, nSpendHeight, consensusParams, particl_mode, false /* skip_rangeproof */);
        if (!CheckTransaction(txConst, state)) {
            result.pushKV("outputs_valid", false);
            vErrors.push_back("CheckTransaction: \"" + state.GetRejectReason() + "\"");
        } else {
            result.pushKV("outputs_valid", true);
        }
    }

    if (check_values) {
        TxValidationState state;
        state.SetStateInfo(nSpendTime, nSpendHeight, consensusParams, particl_mode, false /* skip_rangeproof */);
        CAmount nFee = 0;
        if (!Consensus::CheckTxInputs(txConst, state, view, nSpendHeight, nFee)) {
            result.pushKV("inputs_valid", false);
            vErrors.push_back("CheckTxInputs: \"" + state.GetRejectReason() + "\"");
        } else {
            result.pushKV("inputs_valid", true);
        }
    }

    // Verify inputs:
    int num_valid = 0;
    for (unsigned int i = 0; i < mtx.vin.size(); i++) {
        CTxIn& txin = mtx.vin[i];
        const Coin& coin = view.AccessCoin(txin.prevout);
        if (coin.IsSpent()) {
            TxInErrorToJSON(txin, vErrors, "Input not found or already spent");
            continue;
        }

        CScript prevPubKey = coin.out.scriptPubKey;

        std::vector<uint8_t> vchAmount;
        if (coin.nType == OUTPUT_STANDARD) {
            vchAmount.resize(8);
            part::SetAmount(vchAmount, coin.out.nValue);
        } else
        if (coin.nType == OUTPUT_CT) {
            vchAmount.resize(33);
            memcpy(vchAmount.data(), coin.commitment.data, 33);
        } else {
            throw JSONRPCError(RPC_MISC_ERROR, strprintf("Bad input type: %d", coin.nType));
        }

        ScriptError serror = SCRIPT_ERR_OK;
        if (!VerifyScript(txin.scriptSig, prevPubKey, &txin.scriptWitness, STANDARD_SCRIPT_VERIFY_FLAGS, TransactionSignatureChecker(&txConst, i, vchAmount, MissingDataBehavior::FAIL), &serror)) {
            TxInErrorToJSON(txin, vErrors, ScriptErrorString(serror));
        } else {
            num_valid++;
        }
    }
    bool fComplete = vErrors.empty();

    if (return_decoded) {
        UniValue txn(UniValue::VOBJ);
        TxToUniv(CTransaction(std::move(mtx)), uint256(), txn, false);
        result.pushKV("txn", txn);
    }

    result.pushKV("complete", fComplete);
    result.pushKV("validscripts", num_valid);
    if (!vErrors.empty()) {
        result.pushKV("errors", vErrors);
    }

    return result;
},
    };
};

static bool PruneBlockFile(ChainstateManager &chainman, FILE *fp, bool test_only, size_t &num_blocks_in_file, size_t &num_blocks_removed) EXCLUSIVE_LOCKS_REQUIRED(cs_main)
{
    fs::path tmp_filepath = gArgs.GetBlocksDirPath() / strprintf("tmp.dat");

    FILE *fpt = fopen(tmp_filepath.string().c_str(), "w");
    if (!fpt) {
        return error("%s: Couldn't open temp file.\n", __func__);
    }
    CAutoFile fileout(fpt, SER_DISK, CLIENT_VERSION);

    const CChainParams &chainparams = Params();
    CBufferedFile blkdat(fp, 2*MAX_BLOCK_SERIALIZED_SIZE, MAX_BLOCK_SERIALIZED_SIZE+8, SER_DISK, CLIENT_VERSION);
    uint64_t nRewind = blkdat.GetPos();

    while (!blkdat.eof()) {
        if (ShutdownRequested()) return false;

        blkdat.SetPos(nRewind);
        nRewind++; // start one byte further next time, in case of failure
        blkdat.SetLimit(); // remove former limit
        unsigned int nSize = 0;
        try {
            // locate a header
            unsigned char buf[CMessageHeader::MESSAGE_START_SIZE];
            blkdat.FindByte(chainparams.MessageStart()[0]);
            nRewind = blkdat.GetPos()+1;
            blkdat >> buf;
            if (memcmp(buf, chainparams.MessageStart(), CMessageHeader::MESSAGE_START_SIZE))
                continue;
            // read size
            blkdat >> nSize;
            if (nSize < 80 || nSize > MAX_BLOCK_SERIALIZED_SIZE)
                continue;
        } catch (const std::exception&) {
            // no valid block header found; don't complain
            break;
        }
        try {
            // read block
            uint64_t nBlockPos = blkdat.GetPos();
            blkdat.SetLimit(nBlockPos + nSize);
            blkdat.SetPos(nBlockPos);
            std::shared_ptr<CBlock> pblock = std::make_shared<CBlock>();
            CBlock& block = *pblock;
            blkdat >> block;
            uint256 blockhash = block.GetHash();
            nRewind = blkdat.GetPos();

            num_blocks_in_file++;
            BlockMap::iterator mi = chainman.BlockIndex().find(blockhash);
            if (mi == chainman.BlockIndex().end()
                || !chainman.ActiveChain().Contains(mi->second)) {
                num_blocks_removed++;
            } else
            if (!test_only) {
                fileout << chainparams.MessageStart() << nSize;
                fileout << block;
            }
        } catch (const std::exception& e) {
            return error("%s: Deserialize or I/O error - %s\n", __func__, e.what());
        }
    }

    return true;
};

static RPCHelpMan rewindchain()
{
    return RPCHelpMan{"rewindchain",
                "\nRemove blocks from chain until \"height\"." +
                HELP_REQUIRING_PASSPHRASE,
                {
                    {"height", RPCArg::Type::NUM, RPCArg::Default{1}, "Chain height to rewind to."},
                    //{"removeheaders", RPCArg::Type::BOOL, RPCArg::Default{false}, "Remove block headers too."},
                },
                RPCResult{
                    RPCResult::Type::OBJ, "", "", {
                        {RPCResult::Type::NUM, "to_height", "Height rewound to."},
                        {RPCResult::Type::NUM, "nBlocks", "Blocks removed."},
                        {RPCResult::Type::STR, "error", "Error, if failed."}
                    }
                },
                RPCExamples{""},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    ChainstateManager &chainman = EnsureAnyChainman(request.context);
    CTxMemPool  &mempool = EnsureAnyMemPool(request.context);

    LOCK(cs_main);

    UniValue result(UniValue::VOBJ);

    CCoinsViewCache &view = chainman.ActiveChainstate().CoinsTip();
    view.fForceDisconnect = true;
    CBlockIndex* pindexState = chainman.ActiveChain().Tip();

    int nBlocks = 0;

    int nToHeight = request.params[0].isNum() ? request.params[0].get_int() : pindexState->nHeight - 1;
    result.pushKV("to_height", nToHeight);

    std::string sError;
    if (!RewindToHeight(chainman, mempool, nToHeight, nBlocks, sError)) {
        result.pushKV("error", sError);
    }

    result.pushKV("nBlocks", nBlocks);

    return result;
},
    };
};

static RPCHelpMan pruneorphanedblocks()
{
    return RPCHelpMan{"pruneorphanedblocks",
                "\nRemove blocks not in the main chain.\n"
                "Will shutdown node and cause a reindex at next startup.\n"
                "WARNING: Experimental feature.\n",
                {
                    {"testonly", RPCArg::Type::BOOL, RPCArg::Default{true}, "Apply changes if false."},
                },
                RPCResult{
                    RPCResult::Type::ANY, "", ""
                },
                RPCExamples{
            HelpExampleCli("pruneorphanedblocks", "\"myhex\"") +
            "\nAs a JSON-RPC call\n"
            + HelpExampleRpc("pruneorphanedblocks", "\"myhex\"")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    bool test_only = request.params.size() > 0 ? GetBool(request.params[0]) : true;

    ChainstateManager &chainman = EnsureAnyChainman(request.context);

    UniValue files(UniValue::VARR);
    {
        LOCK(cs_main);
        int nFile = 0;
        FILE *fp;
        for (;;) {
            FlatFilePos pos(nFile, 0);
            fs::path blk_filepath = GetBlockPosFilename(pos);
            if (!fs::exists(blk_filepath)
                || !(fp = OpenBlockFile(pos, true)))
                break;
            LogPrintf("Pruning block file blk%05u.dat...\n", (unsigned int)nFile);
            size_t num_blocks_in_file = 0, num_blocks_removed = 0;
            PruneBlockFile(chainman, fp, test_only, num_blocks_in_file, num_blocks_removed);

            if (!test_only) {
                fs::path tmp_filepath = gArgs.GetBlocksDirPath() / strprintf("tmp.dat");
                if (!RenameOver(tmp_filepath, blk_filepath)) {
                    LogPrintf("Unable to rename file %s to %s\n", tmp_filepath.string(), blk_filepath.string());
                    return false;
                }
            }

            UniValue obj(UniValue::VOBJ);
            obj.pushKV("test_mode", test_only);
            obj.pushKV("filename", GetBlockPosFilename(pos).string());
            obj.pushKV("blocks_in_file", (int)num_blocks_in_file);
            obj.pushKV("blocks_removed", (int)num_blocks_removed);
            files.push_back(obj);
            nFile++;
        }
    }
    UniValue response(UniValue::VOBJ);
    if (!test_only) {
        response.pushKV("note", "Node is shutting down.");
        // Force reindex on next startup
        pblocktree->WriteFlag("v1", false);
        StartShutdown();
    }

    response.pushKV("files", files);
    return response;
},
    };
};

static RPCHelpMan rehashblock()
{
    return RPCHelpMan{"rehashblock",
        "\nRecalculate merkle tree and block signature of submitted block.\n" +
        HELP_REQUIRING_PASSPHRASE,
        {
            {"blockhex", RPCArg::Type::STR, RPCArg::Optional::NO, "Input block hex."},
            {"signwith", RPCArg::Type::STR, RPCArg::Default{""}, "Address of key to sign block with."},
            {"addtxns", RPCArg::Type::ARR, RPCArg::Default{UniValue::VARR}, "Transaction to add to the block. A json array of objects.",
                {
                    {"", RPCArg::Type::OBJ, RPCArg::Default{UniValue::VOBJ}, "",
                        {
                            {"txn", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The transaction in hex form."},
                            {"pos", RPCArg::Type::NUM, RPCArg::Default{"end"}, "The position to place the txn in the block."},
                            {"replace", RPCArg::Type::BOOL, RPCArg::Default{false}, "Replace the txn at \"pos\"."},
                        },
                    },
                },
            },
        },
        RPCResult{
            RPCResult::Type::STR_HEX, "", "Output block hex"
        },
        RPCExamples{
            HelpExampleCli("rehashblock", "\"myhex\"") +
            "\nAs a JSON-RPC call\n"
            + HelpExampleRpc("rehashblock", "\"myhex\"")
        },[&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
    if (!wallet) return NullUniValue;
    CHDWallet *const pwallet = GetParticlWallet(wallet.get());


    std::shared_ptr<CBlock> blockptr = std::make_shared<CBlock>();
    CBlock& block = *blockptr;
    if (!DecodeHexBlk(block, request.params[0].get_str())) {
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "Block decode failed");
    }

    if (request.params.size() > 2) {
        RPCTypeCheckArgument(request.params[2], UniValue::VARR);
        const UniValue &addtxns = request.params[2];
        for (unsigned int idx = 0; idx < addtxns.size(); idx++) {
            const UniValue& o = addtxns[idx].get_obj();
            RPCTypeCheckObj(o,
            {
                {"txn", UniValueType(UniValue::VSTR)},
                {"pos", UniValueType(UniValue::VNUM)},
                {"replace", UniValueType(UniValue::VBOOL)},
            }, true);

            CMutableTransaction mtx;
            if (!DecodeHexTx(mtx, o["txn"].get_str(), true)) {
                throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "TX decode failed");
            }

            int pos = !o["pos"].isNull() ? o["pos"].get_int() : -1;
            bool replace = !o["replace"].isNull() ? o["replace"].get_bool() : false;

            if (pos == -1 || pos >= (int)block.vtx.size()) {
                block.vtx.push_back(MakeTransactionRef(std::move(mtx)));
            } else {
                if (replace) {
                    block.vtx.erase(block.vtx.begin() + pos);
                    block.vtx.insert(block.vtx.begin() + pos, MakeTransactionRef(std::move(mtx)));
                }
            }
        }
    }

    bool mutated;
    block.hashMerkleRoot = BlockMerkleRoot(block, &mutated);
    block.hashWitnessMerkleRoot = BlockWitnessMerkleRoot(block, &mutated);

    if (request.params.size() > 1 && request.params[1].get_str() != "") {
        EnsureWalletIsUnlocked(pwallet);

        std::string str_address = request.params[1].get_str();
        CTxDestination dest = DecodeDestination(str_address);
        if (!IsValidDestination(dest)) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid address");
        }
        CScript script = GetScriptForDestination(dest);
        std::unique_ptr<SigningProvider> provider = pwallet->GetSolvingProvider(script);
        auto keyid = GetKeyForDestination(*provider, dest);
        if (keyid.IsNull()) {
            throw JSONRPCError(RPC_TYPE_ERROR, "Address does not refer to a key");
        }
        CKey key;
        if (!pwallet->GetKey(keyid, key)) {
            throw JSONRPCError(RPC_WALLET_ERROR, "Private key for address " + str_address + " is not known");
        }
        key.Sign(block.GetHash(), block.vchBlockSig);
    }

    CDataStream ssBlock(SER_NETWORK, PROTOCOL_VERSION | RPCSerializationFlags());
    ssBlock << block;
    return HexStr(ssBlock);
},
    };
};

Span<const CRPCCommand> GetHDWalletRPCCommands()
{
// clang-format off
static const CRPCCommand commands[] =
{ //  category              actor (function)
  //  --------------------- -----------------------
    { "wallet",             &extkey                         },
    { "wallet",             &extkeyimportmaster             },
    { "wallet",             &extkeygenesisimport            },
    { "wallet",             &extkeyaltversion               },
    { "wallet",             &getnewextaddress               },
    { "wallet",             &getnewstealthaddress           },
    { "wallet",             &importstealthaddress           },
    { "wallet",             &liststealthaddresses           },

    { "wallet",             &reservebalance                 },
    { "wallet",             &deriverangekeys                },
    { "wallet",             &clearwallettransactions        },

    { "wallet",             &filtertransactions             },
    { "wallet",             &filteraddresses                },
    { "wallet",             &manageaddressbook              },

    { "wallet",             &getstakinginfo                 },
    { "wallet",             &getcoldstakinginfo             },

    { "wallet",             &listunspentanon                },
    { "wallet",             &listunspentblind               },

    { "wallet",             &getlockedbalances,             },

    { "wallet",             &sendtypeto                     },

    { "wallet",             &createsignaturewithwallet      },

    { "wallet",             &debugwallet                    },
    { "wallet",             &walletsettings                 },

    { "wallet",             &transactionblinds              },
    { "wallet",             &derivefromstealthaddress       },

    { "wallet",             &getkeyimage                    },


    { "governance",         &setvote                        },
    { "governance",         &votehistory                    },

    { "rawtransactions",    &createrawparttransaction       },
    { "rawtransactions",    &fundrawtransactionfrom         },

    { "wallet",             &rehashblock                    },
};
// clang-format on
    return MakeSpan(commands);
}

void RegisterNonWalletRPCCommands(CRPCTable &t)
{
// clang-format off
static const CRPCCommand commands[] =
{ //  category              actor (function)
  //  --------------------- -----------------------
    { "governance",         &tallyvotes                     },

    { "rawtransactions",    &rewindrangeproof               },
    { "rawtransactions",    &generatematchingblindfactor    },
    { "rawtransactions",    &buildscript                    },
    { "rawtransactions",    &verifycommitment               },
    { "rawtransactions",    &createsignaturewithkey         },
    { "rawtransactions",    &verifyrawtransaction           },
    { "blockchain",         &pruneorphanedblocks            },
    { "blockchain",         &rewindchain                    },
};
// clang-format on
    for (const auto& c : commands) {
        t.appendCommand(c.name, &c);
    }
}
