// Copyright (c) 2017-2022 The Particl Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <wallet/hdwallet.h>

#include <crypto/hmac_sha256.h>
#include <crypto/hmac_sha512.h>
#include <crypto/sha256.h>

#include <random.h>
#include <validation.h>
#include <consensus/validation.h>
#include <consensus/merkle.h>
#include <smsg/smessage.h>
#include <smsg/crypter.h>
#include <timedata.h>
#include <miner.h>
#include <pos/kernel.h>
#include <pos/miner.h>
#include <util/moneystr.h>
#include <util/translation.h>
#include <script/script.h>
#include <script/standard.h>
#include <script/sign.h>
#include <policy/fees.h>
#include <policy/policy.h>
#include <wallet/coincontrol.h>
#include <blind.h>
#include <anon.h>
#include <txdb.h>
#include <txmempool.h>
#include <rpc/util.h>
#include <util/fees.h>
#include <util/rbf.h>
#include <wallet/fees.h>
#include <node/ui_interface.h>

#if ENABLE_USBDEVICE
#include <usbdevice/usbdevice.h>
#endif

#include <univalue.h>

#include <secp256k1_mlsag.h>

#include <algorithm>
#include <thread>

#include <boost/algorithm/string/replace.hpp>

using interfaces::FoundBlock;

extern const std::string MESSAGE_MAGIC;

static uint8_t GetOutputType(ChainstateManager *pchainman, const COutPoint &prevout)
{
    LOCK(cs_main);
    Coin coin;
    if (pchainman && pchainman->ActiveChainstate().CoinsTip().GetCoin(prevout, coin)) {
        return coin.nType;
    }

    uint256 hash_block;
    const CTransactionRef tx = ::GetTransaction(nullptr, nullptr, prevout.hash, Params().GetConsensus(), hash_block);
    if (tx) {
        if (tx->vpout.size() > prevout.n) {
            return tx->vpout[prevout.n]->GetType();
        }
    }

    return 0;
}

static bool ExtractStealthPrefix(const std::vector<uint8_t> &vData, uint32_t &prefix, size_t offset = 33)
{
    prefix = 0;
    if (vData.size() >= offset + 5 // Have prefix
        && vData[offset] == DO_STEALTH_PREFIX) {
        memcpy(&prefix, &vData[offset + 1], 4);
        prefix = le32toh(prefix);
        return true;
    }
    return false;
}

static void AppendKey(const CHDWallet *pw, CKey &key, uint32_t nChild, UniValue &derivedKeys) EXCLUSIVE_LOCKS_REQUIRED(pw->cs_wallet)
{
    UniValue keyobj(UniValue::VOBJ);

    CKeyID idk = key.GetPubKey().GetID();

    bool fHardened = IsHardened(nChild);
    ClearHardenedBit(nChild);
    keyobj.pushKV("path", ToString((int64_t)nChild) + (fHardened ? "'" : ""));
    keyobj.pushKV("address", EncodeDestination(PKHash(idk)));
    keyobj.pushKV("privkey", CBitcoinSecret(key).ToString());

    std::map<CTxDestination, CAddressBookData>::const_iterator mi = pw->m_address_book.find(PKHash(idk));
    if (mi != pw->m_address_book.end()) {
        // TODO: confirm vPath?
        keyobj.pushKV("label", mi->second.GetLabel());
        if (!mi->second.purpose.empty()) {
            keyobj.pushKV("purpose", mi->second.purpose);
        }
        UniValue objDestData(UniValue::VOBJ);
        for (const auto &pair : mi->second.destdata) {
            objDestData.pushKV(pair.first, pair.second);
        }
        if (objDestData.size() > 0) {
            keyobj.pushKV("destdata", objDestData);
        }
    }
    derivedKeys.push_back(keyobj);
    return;
};

static bool HaveAnonOutputs(std::vector<CTempRecipient> &vecSend)
{
    for (const auto &r : vecSend)
    if (r.nType == OUTPUT_RINGCT) {
        return true;
    }
    return false;
}

int CHDWallet::Finalise()
{
    LOCK(cs_wallet);
    LogPrint(BCLog::HDWALLET, "%s %s\n", GetDisplayName(), __func__);

    FreeExtKeyMaps();
    m_address_book.clear();

    if (m_blind_scratch) {
        secp256k1_scratch_space_destroy(secp256k1_ctx_blind, m_blind_scratch);
        m_blind_scratch = nullptr;
    }
    return 0;
};

int CHDWallet::FreeExtKeyMaps()
{
    LogPrint(BCLog::HDWALLET, "%s %s\n", GetDisplayName(), __func__);

    for (auto it = mapExtAccounts.begin(); it != mapExtAccounts.end(); ++it) {
        if (it->second) {
            delete it->second;
        }
    }
    mapExtAccounts.clear();

    for (auto itl = mapExtKeys.begin(); itl != mapExtKeys.end(); ++itl) {
        if (itl->second) {
            delete itl->second;
        }
    }
    mapExtKeys.clear();

    mapLooseKeys.clear();
    mapLooseLookAhead.clear();

    return 0;
};

void CHDWallet::AddOptions(ArgsManager& argsman)
{
    argsman.AddArg("-defaultlookaheadsize=<n>", strprintf("Number of keys to load into the lookahead pool per chain. (default: %u)", DEFAULT_LOOKAHEAD_SIZE), ArgsManager::ALLOW_ANY, OptionsCategory::PART_WALLET);
    argsman.AddArg("-stealthv1lookaheadsize=<n>", strprintf("Number of V1 stealth keys to look ahead during a rescan. (default: %u)", DEFAULT_STEALTH_LOOKAHEAD_SIZE), ArgsManager::ALLOW_ANY, OptionsCategory::PART_WALLET);
    argsman.AddArg("-stealthv2lookaheadsize=<n>", strprintf("Number of V2 stealth keys to look ahead during a rescan. (default: %u)", DEFAULT_STEALTH_LOOKAHEAD_SIZE), ArgsManager::ALLOW_ANY, OptionsCategory::PART_WALLET);
    argsman.AddArg("-extkeysaveancestors", strprintf("On saving a key from the lookahead pool, save all unsaved keys leading up to it too. (default: %s)", "true"), ArgsManager::ALLOW_ANY, OptionsCategory::PART_WALLET);
    argsman.AddArg("-createdefaultmasterkey", strprintf("Generate a random master key and main account if no master key exists. (default: %s)", "false"), ArgsManager::ALLOW_ANY, OptionsCategory::PART_WALLET);

    argsman.AddArg("-staking", "Stake your coins to support network and gain reward (default: true)", ArgsManager::ALLOW_ANY, OptionsCategory::PART_STAKING);
    argsman.AddArg("-stakingthreads", "Number of threads to start for staking, max 1 per active wallet, will divide wallets evenly between threads (default: 1)", ArgsManager::ALLOW_ANY, OptionsCategory::PART_STAKING);
    argsman.AddArg("-stakethreadconddelayms", "Number of milliseconds to delay staking for on error condition (default: 60000)", ArgsManager::ALLOW_ANY, OptionsCategory::PART_STAKING);
    argsman.AddArg("-minstakeinterval=<n>", "Minimum time in seconds between successful stakes (default: 0)", ArgsManager::ALLOW_ANY, OptionsCategory::PART_STAKING);
    argsman.AddArg("-minersleep=<n>", "Milliseconds between stake attempts. Lowering this param will not result in more stakes. (default: 500)", ArgsManager::ALLOW_ANY, OptionsCategory::PART_STAKING);
    argsman.AddArg("-reservebalance=<amount>", "Ensure available balance remains above reservebalance. (default: 0)", ArgsManager::ALLOW_ANY, OptionsCategory::PART_STAKING);
    argsman.AddArg("-treasurydonationpercent=<n>", "Percentage of block reward donated to the treasury fund, overridden by system minimum. (default: 0)", ArgsManager::ALLOW_ANY, OptionsCategory::PART_STAKING);

    return;
};

bool CHDWallet::ShouldRescan()
{
    return mapExtAccounts.size() > 0 || CountKeys() > 0;
};

static void AppendError(std::string &sError, std::string s)
{
    if (!sError.empty()) {
        sError += "\n";
    }
    sError += s;
};

bool CHDWallet::ProcessStakingSettings(std::string &sError)
{
    LogPrint(BCLog::HDWALLET, "%s ProcessStakingSettings\n", GetDisplayName());

    // Set defaults
    fStakingEnabled = true;
    nStakeCombineThreshold = 1000 * COIN;
    nStakeSplitThreshold = 2000 * COIN;
    m_min_stakeable_value = 1;
    nMaxStakeCombine = 3;
    nWalletTreasuryFundCedePercent = gArgs.GetArg("-treasurydonationpercent", 0);
    m_reward_address = CNoDestination();
    m_smsg_fee_rate_target = 0;
    m_smsg_difficulty_target = 0;

    UniValue json;
    if (GetSetting("stakingoptions", json)) {
        if (!json["enabled"].isNull()) {
            try { fStakingEnabled = GetBool(json["enabled"]);
            } catch (std::exception &e) {
                AppendError(sError, "Setting \"enabled\" failed.");
            }
        }

        if (!json["stakecombinethreshold"].isNull()) {
            try { nStakeCombineThreshold = AmountFromValue(json["stakecombinethreshold"]);
            } catch (std::exception &e) {
                AppendError(sError, "\"stakecombinethreshold\" not an amount.");
            }
        }

        if (!json["stakesplitthreshold"].isNull()) {
            try { nStakeSplitThreshold = AmountFromValue(json["stakesplitthreshold"]);
            } catch (std::exception &e) {
                AppendError(sError, "\"stakesplitthreshold\" not an amount.");
            }
        }

        if (!json["minstakeablevalue"].isNull()) {
            try { m_min_stakeable_value = AmountFromValue(json["minstakeablevalue"]);
            } catch (std::exception &e) {
                AppendError(sError, "\"minstakeablevalue\" not an amount.");
            }
            if (m_min_stakeable_value < 0) {
                AppendError(sError, "\"minstakeablevalue\" must be >= 0.");
                m_min_stakeable_value = 0;
            }
        }

        if (!json["treasurydonationpercent"].isNull()) {
            try { nWalletTreasuryFundCedePercent = json["treasurydonationpercent"].get_int();
            } catch (std::exception &e) {
                AppendError(sError, "\"treasurydonationpercent\" not an integer.");
            }
        }

        if (!json["rewardaddress"].isNull()) {
            try { m_reward_address = DecodeDestination(json["rewardaddress"].get_str());
            } catch (std::exception &e) {
                AppendError(sError, "Setting \"rewardaddress\" failed.");
            }
        }

        if (!json["smsgfeeratetarget"].isNull()) {
            try { m_smsg_fee_rate_target = AmountFromValue(json["smsgfeeratetarget"]);
            } catch (std::exception &e) {
                AppendError(sError, "\"smsgfeeratetarget\" not an amount.");
            }
        }

        if (!json["smsgdifficultytarget"].isNull()) {
            try {
                std::string s = json["smsgdifficultytarget"].get_str();
                if (!IsHex(s) || !(s.size() == 64)) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "Must be 32 bytes and hex encoded.");
                }
                arith_uint256 target;
                target.SetHex(s);
                m_smsg_difficulty_target = target.GetCompact();
            } catch (std::exception &e) {
                AppendError(sError, "\"smsgdifficultytarget\" not valid.");
            }
        }
    }

    if (nStakeCombineThreshold < 100 * COIN || nStakeCombineThreshold > 5000 * COIN) {
        AppendError(sError, "\"stakecombinethreshold\" must be >= 100 and <= 5000.");
        nStakeCombineThreshold = 1000 * COIN;
    }

    if (nStakeSplitThreshold < nStakeCombineThreshold * 2 || nStakeSplitThreshold > 10000 * COIN) {
        AppendError(sError, "\"stakesplitthreshold\" must be >= 2x \"stakecombinethreshold\" and <= 10000.");
        nStakeSplitThreshold = nStakeCombineThreshold * 2;
    }

    if (nWalletTreasuryFundCedePercent < 0) {
        WalletLogPrintf("%s: Warning \"treasurydonationpercent\" out of range %d, clamped to %d\n", __func__, nWalletTreasuryFundCedePercent, 0);
        nWalletTreasuryFundCedePercent = 0;
    } else
    if (nWalletTreasuryFundCedePercent > 100) {
        WalletLogPrintf("%s: \"Warning treasurydonationpercent\" out of range %d, clamped to %d\n", __func__, nWalletTreasuryFundCedePercent, 100);
        nWalletTreasuryFundCedePercent = 100;
    }

    return true;
};

bool CHDWallet::ProcessWalletSettings(std::string &sError)
{
    LogPrint(BCLog::HDWALLET, "%s ProcessWalletSettings\n", GetDisplayName());

    // Set defaults
    m_collapse_spent_mode = 0;
    m_min_collapse_depth = 3;
    m_mixin_selection_mode_default = MIXIN_SEL_RECENT;
    m_min_owned_value = 0;

    UniValue json;
    if (GetSetting("unloadspent", json)) {
        if (!json["mode"].isNull()) {
            try { m_collapse_spent_mode = json["mode"].get_int();
            } catch (std::exception &e) {
                AppendError(sError, "\"mode\" not integer.");
            }
        }
        if (!json["mindepth"].isNull()) {
            try { m_min_collapse_depth = json["mindepth"].get_int();
            } catch (std::exception &e) {
                AppendError(sError, "\"mode\" not integer.");
            }
        }
    }

    if (GetSetting("anonoptions", json)) {
        if (!json["mixinselection"].isNull()) {
            try { m_mixin_selection_mode_default = json["mixinselection"].get_int();
            } catch (std::exception &e) {
                AppendError(sError, "\"mixinselection\" not integer.");
            }
        }
    }

    if (GetSetting("other", json)) {
        if (!json["onlyinstance"].isNull()) {
            try { m_is_only_instance = json["onlyinstance"].get_bool();
            } catch (std::exception &e) {
                AppendError(sError, "\"onlyinstance\" not boolean.");
            }
        }
        if (!json["smsgenabled"].isNull()) {
            try { m_smsg_enabled = json["smsgenabled"].get_bool();
            } catch (std::exception &e) {
                AppendError(sError, "\"smsgenabled\" not boolean.");
            }
        }
        if (!json["minownedvalue"].isNull()) {
            try { m_min_owned_value = AmountFromValue(json["minownedvalue"]);
            } catch (std::exception &e) {
                AppendError(sError, "\"minownedvalue\" not an amount.");
            }
            if (m_min_owned_value < 0) {
                AppendError(sError, "\"minownedvalue\" must be >= 0.");
                m_min_owned_value = 0;
            }
        }
    }

    if (m_min_collapse_depth < 2) {
        AppendError(sError, "\"mindepth\" must be >= 2.");
        m_min_collapse_depth = 2;
    }

    return true;
};

bool CHDWallet::IsInitialised() const
{
    return pEKMaster || !idDefaultAccount.IsNull();
}

bool CHDWallet::IsHDEnabled() const
{
    return mapExtAccounts.find(idDefaultAccount) != mapExtAccounts.end();
}

bool CHDWallet::CanGetAddresses(bool internal) const
{
    if (!idDefaultAccount.IsNull()) {
        return true;
    }
    if (CWallet::CanGetAddresses(internal)) {
        return true;
    }
    if (IsHardwareLinkedWallet()) {
        return true;
    }
    return false;
}

bool CHDWallet::IsHardwareLinkedWallet() const
{
    LOCK(cs_wallet);
    ExtKeyAccountMap::const_iterator mi = mapExtAccounts.find(idDefaultAccount);
    if (mi == mapExtAccounts.end()) {
        return false;
    }

    const CExtKeyAccount *pa = mi->second;
    if (pa->nFlags & EAF_HAVE_SECRET) {
        return false;
    }

    mapEKValue_t::const_iterator mvi = pa->mapValue.find(EKVT_HARDWARE_DEVICE);
    if (mvi != pa->mapValue.end()) {
        return true;
    }

    return false;
}

bool CHDWallet::UnsetWalletFlagRV(CHDWalletDB *pwdb, uint64_t flag)
{
    LOCK(cs_wallet);
    if (!IsWalletFlagSet(flag)) {
        return true;
    }
    m_wallet_flags &= ~flag;
    return pwdb->WriteWalletFlags(m_wallet_flags);
}

extern int ListLooseExtKeys(CHDWallet *pwallet, int nShowKeys, UniValue &ret, size_t &nKeys);
extern int ListAccountExtKeys(CHDWallet *pwallet, int nShowKeys, UniValue &ret, size_t &nKeys);
extern int ListLooseStealthAddresses(UniValue &arr, const CHDWallet *pwallet, bool fShowSecrets, bool fAddressBookInfo, bool show_pubkeys=false, bool bech32=false);
bool CHDWallet::DumpJson(UniValue &rv, std::string &sError)
{
    WalletLogPrintf("Dumping wallet to JSON.\n");

    if (IsLocked()) {
        return wserrorN(false, sError, __func__, "Wallet must be unlocked.");
    }

    LOCK(cs_wallet);

    CHDWalletDB wdb(*m_database);

    size_t nKeys, nAcc;
    UniValue extkeys(UniValue::VARR);
    UniValue extaccs(UniValue::VARR);
    ListLooseExtKeys(this, 2, extkeys, nKeys);
    ListAccountExtKeys(this, 3, extaccs, nAcc);

    CExtKey58 eKey58;
    for (size_t k = 0; k < extaccs.size(); ++k) {
        UniValue &acc = extaccs.get(k);
        size_t nChains = acc["chains"].size();

        std::vector<CExtKeyPair> vChains;
        vChains.resize(nChains);
        for (size_t c = 0; c < nChains; ++c) {
            UniValue &chain = acc.get("chains").get(c);

            const std::string &sEvkey = chain["evkey"].get_str();

            uint32_t nDerives = 0;
            uint32_t nDerivesH = 0;

            if (chain["num_derives"].isStr()
                && !ParseUInt32(chain["num_derives"].get_str(), &nDerives)) {
                return wserrorN(false, sError, __func__, "num_derives to int failed.");
            }
            if (chain["num_derives_h"].isStr()
                && !ParseUInt32(chain["num_derives_h"].get_str(), &nDerivesH)) {
                return wserrorN(false, sError, __func__, "num_derives_h to int failed.");
            }

            eKey58.Set58(sEvkey.c_str());
            CExtKeyPair kp = eKey58.GetKey();
            vChains[c] = kp;

            bool fIsStealth = false;
            if (chain["use_type"].isStr() && chain["use_type"].get_str() == "stealth") {
                fIsStealth = true;
            }

            UniValue derivedKeys(UniValue::VARR);
            UniValue derivedKeysH(UniValue::VARR);


            if (fIsStealth) {
                // Dump from pack instead
            } else {
                CKey key;
                uint32_t nChild = 0;
                for (uint32_t k = 0; k < nDerives; ++k) {
                    if (kp.Derive(key, nChild)) {
                        AppendKey(this, key, nChild, derivedKeys);
                    }
                    nChild++;
                }
                chain.pushKV("derived_keys", derivedKeys);

                for (uint32_t k = 0; k < nDerivesH; ++k) {
                    nChild = k;
                    SetHardenedBit(nChild);
                    if (kp.Derive(key, nChild)) {
                        AppendKey(this, key, nChild, derivedKeysH);
                    }
                }
                chain.pushKV("derived_keys_hardened", derivedKeysH);
            }
        }
        // Read stealth keys from packs to keep metadata such as prefix
        size_t nPackStealthAddrs = 0;
        size_t nPackStealthKeys = 0;

        if (acc["stealth_address_pack"].isNum()) {
            nPackStealthAddrs = acc["stealth_address_pack"].get_int();
        }
        if (acc["stealth_keys_received_pack"].isNum()) {
            nPackStealthKeys = acc["stealth_keys_received_pack"].get_int();
        }

        CKeyID idAcc;
        CBitcoinAddress accIdAddr(acc["id"].get_str());

        if (!accIdAddr.IsValid(CChainParams::EXT_ACC_HASH)) {
            WalletLogPrintf("%s: ERROR - Invalid account id %s\n", __func__, acc["id"].get_str());
            acc.pushKV("ERROR", "Invalid account id");
            continue;
        }

        accIdAddr.GetKeyID(idAcc, CChainParams::EXT_ACC_HASH);
        std::map<CKeyID, std::pair<CKey, std::string> > mapStealthKeySpend;
        UniValue stealthAddresses(UniValue::VARR);
        std::vector<CEKAStealthKeyPack> aksPak;
        for (uint32_t i = 0; i <= nPackStealthAddrs; ++i) {
            if (!wdb.ReadExtStealthKeyPack(idAcc, i, aksPak)) {
                continue;
            }

            for (const auto &sxPacked : aksPak) {
                UniValue sxAddr(UniValue::VOBJ);

                if (!sxPacked.aks.sLabel.empty()) {
                    sxAddr.pushKV("label", sxPacked.aks.sLabel);
                }

                CStealthAddress sx;
                sxPacked.aks.SetSxAddr(sx);
                std::string sxStr = sx.ToString();

                sxAddr.pushKV("address", sxStr);
                sxAddr.pushKV("scan_priv", CBitcoinSecret(sxPacked.aks.skScan).ToString());

                size_t p = sxPacked.aks.akSpend.nParent;
                if (p >= vChains.size()+1) {
                    WalletLogPrintf("%s: ERROR - chain out of range %d\n", __func__, p);
                    acc.pushKV("ERROR", "Invalid chain offset.");
                    continue;
                }

                // Chain0 is the account key
                CExtKeyPair &kp = vChains[p-1];

                CKey kSpend;
                uint32_t nChild = sxPacked.aks.akSpend.nKey;
                if (kp.Derive(kSpend, nChild)) {
                    sxAddr.pushKV("spend_priv", CBitcoinSecret(kSpend).ToString());
                } else {
                    WalletLogPrintf("%s: ERROR - Derive failed %u\n", __func__, nChild);
                    acc.pushKV("ERROR", "Derive spend key failed.");
                }
                mapStealthKeySpend[sxPacked.id] = std::make_pair(kSpend, sxStr);

                sxAddr.pushKV("account_chain", (int)sxPacked.aks.akSpend.nParent);

                uint32_t nScanKey = sxPacked.aks.nScanKey;
                ClearHardenedBit(nScanKey);
                sxAddr.pushKV("scan_key_offset", ToString((int64_t)nScanKey)+"'");

                std::map<CTxDestination, CAddressBookData>::const_iterator mi = m_address_book.find(sx);
                if (mi != m_address_book.end()) {
                    // TODO: confirm vPath?

                    if (mi->second.GetLabel() != sxPacked.aks.sLabel) {
                        sxAddr.pushKV("addr_book_label", mi->second.GetLabel());
                    }
                    if (!mi->second.purpose.empty()) {
                        sxAddr.pushKV("purpose", mi->second.purpose);
                    }

                    UniValue objDestData(UniValue::VOBJ);
                    for (const auto &pair : mi->second.destdata) {
                        sxAddr.pushKV(pair.first, pair.second);
                    }
                    if (objDestData.size() > 0) {
                        sxAddr.pushKV("destdata", objDestData);
                    }
                }

                stealthAddresses.push_back(sxAddr);
            }
        }

        acc.pushKV("stealth_addresses", stealthAddresses);

        UniValue stealthReceivedKeys(UniValue::VARR);
        std::vector<CEKASCKeyPack> asckPak;
        for (uint32_t i = 0; i <= nPackStealthKeys; ++i) {
            if (!wdb.ReadExtStealthKeyChildPack(idAcc, i, asckPak)) {
                continue;
            }

            for (const auto &keyPacked : asckPak) {
                UniValue obj(UniValue::VOBJ);
                obj.pushKV("address", EncodeDestination(PKHash(keyPacked.id)));

                CKey kOut, kSpend;

                std::map<CKeyID, std::pair<CKey, std::string> >::const_iterator mi;
                if ((mi = mapStealthKeySpend.find(keyPacked.asck.idStealthKey)) == mapStealthKeySpend.end()) {
                    WalletLogPrintf("%s: ERROR - Unknown stealth key %s\n", __func__, HexStr(keyPacked.asck.idStealthKey));
                    acc.pushKV("ERROR", "Unknown stealth key.");
                } else {
                    obj.pushKV("stealth_address", mi->second.second);

                    if (0 != StealthSharedToSecretSpend(keyPacked.asck.sShared, mi->second.first, kOut)) {
                        WalletLogPrintf("%s: ERROR - StealthSharedToSecretSpend failed\n", __func__);
                        acc.pushKV("ERROR", "StealthSharedToSecretSpend failed.");
                    } else {
                        obj.pushKV("privkey", CBitcoinSecret(kOut).ToString());
                    }
                }
                stealthReceivedKeys.push_back(obj);
            }
        }

        acc.pushKV("keys_received_on_stealth_addresses", stealthReceivedKeys);
    }


    rv.pushKV("loose_extkeys", extkeys);
    rv.pushKV("accounts", extaccs);

    UniValue stealthAddresses(UniValue::VARR);
    ListLooseStealthAddresses(stealthAddresses, this, true, true);
    rv.pushKV("imported_stealth_addresses", stealthAddresses);

    return true;
};

bool CHDWallet::LoadJson(const UniValue &inj, std::string &sError)
{
    WalletLogPrintf("Loading wallet from JSON.\n");

    if (IsLocked()) {
        return wserrorN(false, sError, __func__, "Wallet must be unlocked.");
    }

    LOCK(cs_wallet);

    return wserrorN(false, sError, __func__, "TODO: LoadJson.");

    return true;
};

bool CHDWallet::LoadAddressBook(CHDWalletDB *pwdb)
{
    LogPrint(BCLog::HDWALLET, "Loading address book for %s.\n", GetName());

    assert(pwdb);
    LOCK(cs_wallet);

    Dbc *pcursor;
    if (!(pcursor = pwdb->GetCursor())) {
        throw std::runtime_error(strprintf("%s: cannot create DB cursor", __func__).c_str());
    }

    CDataStream ssKey(SER_DISK, CLIENT_VERSION);
    CDataStream ssValue(SER_DISK, CLIENT_VERSION);

    std::string strType, strAddress, sPrefix = "abe";
    size_t nCount = 0;

    unsigned int fFlags = DB_SET_RANGE;
    ssKey << sPrefix;
    while (pwdb->ReadAtCursor(pcursor, ssKey, ssValue, fFlags) == 0) {
        fFlags = DB_NEXT;
        ssKey >> strType;
        if (strType != sPrefix) {
            break;
        }

        ssKey >> strAddress;

        CAddressBookData data;
        ssValue >> data;

        // Can't use m_address_book.insert, loses &name
        CTxDestination address = DecodeDestination(strAddress);
        std::map<CTxDestination, CAddressBookData>::iterator mi = m_address_book.find(address);
        bool fUpdated = (mi != m_address_book.end() && !mi->second.IsChange());

        m_address_book[address].Set(data);

        if (!fUpdated) {
            nCount++;
        }
    }

    LogPrint(BCLog::HDWALLET, "%s Loaded %d addresses.\n", GetDisplayName(), nCount);
    pcursor->close();

    return true;
};

bool CHDWallet::LoadVoteTokens(CHDWalletDB *pwdb)
{
    LogPrint(BCLog::HDWALLET, "%s Loading vote tokens.\n", GetDisplayName());

    vVoteTokens.clear();

    std::vector<CVoteToken> vVoteTokensRead;

    if (!pwdb->ReadVoteTokens(vVoteTokensRead)) {
        return false;
    }

    int nBestHeight = m_last_block_processed_height > -1 ? GetLastBlockHeight() : 0;

    for (const auto &v : vVoteTokensRead) {
        if (v.nEnd > nBestHeight - 1000) { // 1000 block buffer in case of reorg etc
            vVoteTokens.push_back(v);
            if (LogAcceptCategory(BCLog::HDWALLET)) {
                if ((v.nToken >> 16) < 1
                    || (v.nToken & 0xFFFF) < 1) {
                    WalletLogPrintf("Clearing vote from block %d to %d.\n",
                        v.nStart, v.nEnd);
                } else {
                    WalletLogPrintf("Voting for option %u on proposal %u from block %d to %d.\n",
                        v.nToken >> 16, v.nToken & 0xFFFF, v.nStart, v.nEnd);
                }
            }
        }
    }

    return true;
};

bool CHDWallet::GetVote(int nHeight, uint32_t &token)
{
    for (auto i = vVoteTokens.crbegin(); i != vVoteTokens.crend(); ++i) {
        if (i->nEnd < nHeight
            || i->nStart > nHeight) {
            continue;
        }
        if ((i->nToken >> 16) < 1
            || (i->nToken & 0xFFFF) < 1) {
            continue;
        }
        token = i->nToken;
        return true;
    }

    return false;
};

bool CHDWallet::LoadTxRecords(CHDWalletDB *pwdb)
{
    LogPrint(BCLog::HDWALLET, "Loading transaction records for %s.\n", GetName());

    assert(pwdb);
    LOCK(cs_wallet);

    Dbc *pcursor;
    if (!(pcursor = pwdb->GetCursor())) {
        throw std::runtime_error(strprintf("%s: cannot create DB cursor", __func__).c_str());
    }

    CDataStream ssKey(SER_DISK, CLIENT_VERSION);
    CDataStream ssValue(SER_DISK, CLIENT_VERSION);

    std::string strType, sPrefix = "rtx";
    uint256 txhash;

    unsigned int fFlags = DB_SET_RANGE;
    ssKey << sPrefix;
    while (pwdb->ReadAtCursor(pcursor, ssKey, ssValue, fFlags) == 0) {
        fFlags = DB_NEXT;
        ssKey >> strType;
        if (strType != sPrefix) {
            break;
        }

        ssKey >> txhash;
        CTransactionRecord data;
        ssValue >> data;
        LoadToWallet(txhash, data);
    }

    pcursor->close();

    int32_t flag;
    if (!pwdb->ReadFlag("anon_vin_v2", flag)) {
        WalletLogPrintf("Upgrading TransactionRecord format.\n");
        for (auto &ri : mapRecords) {
            const uint256 &txhash = ri.first;
            CTransactionRecord &rtx = ri.second;

            std::vector<COutPoint> new_vin;
            if (rtx.nFlags & ORF_ANON_IN) {
                for (const auto &prevout : rtx.vin) {
                    CCmpPubKey ki;
                    memcpy(ki.ncbegin(), prevout.hash.begin(), 32);
                    *(ki.ncbegin()+32) = prevout.n;

                    COutPoint kiPrevout;
                    if (!pwdb->ReadAnonKeyImage(ki, kiPrevout)) {
                        WalletLogPrintf("Warning: Unknown keyimage %s.\n", HexStr(Span<const unsigned char>(ki.begin(), 33)));
                        continue;
                    }
                    new_vin.push_back(kiPrevout);
                }
                rtx.vin = new_vin;
                pwdb->WriteTxRecord(txhash, rtx);
            }
        }
        pwdb->WriteFlag("anon_vin_v2", 1);
    }

    // Must load all records before marking spent.

    MapRecords_t::iterator mri;
    MapWallet_t::iterator mwi;
    for (const auto &ri : mapRecords) {
        const uint256 &txhash = ri.first;
        const CTransactionRecord &rtx = ri.second;

        for (const auto &prevout : rtx.vin) {
            AddToSpends(prevout, txhash);

            if ((mri = mapRecords.find(prevout.hash)) != mapRecords.end()) {
                CTransactionRecord &prevtx = mri->second;
                if (prevtx.nIndex == -1 && !prevtx.HashUnset()) {
                    MarkConflicted(prevtx.blockHash, prevtx.block_height, txhash);
                }
            } else
            if ((mwi = mapWallet.find(prevout.hash)) != mapWallet.end()) {
                CWalletTx &prevtx = mwi->second;
                if (prevtx.isConflicted()) {
                    MarkConflicted(prevtx.m_confirm.hashBlock, prevtx.m_confirm.block_height, txhash);
                }
            }
        }
    }

    WalletLogPrintf("mapRecords.size() = %u\n", mapRecords.size());

    return true;
};

bool CHDWallet::IsLocked() const
{
    LOCK(cs_wallet); // Lock cs_wallet to ensure any CHDWallet::Unlock has completed
    return CWallet::IsLocked();
};

bool CHDWallet::EncryptWallet(const SecureString &strWalletPassphrase)
{
    LogPrint(BCLog::HDWALLET, "%s %s\n", GetDisplayName(), __func__);

    if (IsCrypted()) {
        return false;
    }

    CKeyingMaterial vMasterKey;
    vMasterKey.resize(WALLET_CRYPTO_KEY_SIZE);
    GetStrongRandBytes(&vMasterKey[0], WALLET_CRYPTO_KEY_SIZE);

    CMasterKey kMasterKey;

    kMasterKey.vchSalt.resize(WALLET_CRYPTO_SALT_SIZE);
    GetStrongRandBytes(&kMasterKey.vchSalt[0], WALLET_CRYPTO_SALT_SIZE);

    CCrypter crypter;
    int64_t nStartTime = GetTimeMillis();
    crypter.SetKeyFromPassphrase(strWalletPassphrase, kMasterKey.vchSalt, 25000, kMasterKey.nDerivationMethod);
    kMasterKey.nDeriveIterations = 2500000 / ((double)(GetTimeMillis() - nStartTime));

    nStartTime = GetTimeMillis();
    crypter.SetKeyFromPassphrase(strWalletPassphrase, kMasterKey.vchSalt, kMasterKey.nDeriveIterations, kMasterKey.nDerivationMethod);
    kMasterKey.nDeriveIterations = (kMasterKey.nDeriveIterations + kMasterKey.nDeriveIterations * 100 / ((double)(GetTimeMillis() - nStartTime))) / 2;

    if (kMasterKey.nDeriveIterations < 25000)
        kMasterKey.nDeriveIterations = 25000;

    WalletLogPrintf("Encrypting wallet with an nDeriveIterations of %i\n", kMasterKey.nDeriveIterations);

    if (!crypter.SetKeyFromPassphrase(strWalletPassphrase, kMasterKey.vchSalt, kMasterKey.nDeriveIterations, kMasterKey.nDerivationMethod))
        return false;
    if (!crypter.Encrypt(vMasterKey, kMasterKey.vchCryptedKey))
        return false;

    {
        LOCK(cs_wallet);
        mapMasterKeys[++nMasterKeyMaxID] = kMasterKey;
        WalletBatch* encrypted_batch = new CHDWalletDB(*m_database);
        if (!encrypted_batch->TxnBegin()) {
            delete encrypted_batch;
            encrypted_batch = nullptr;
            return false;
        }
        encrypted_batch->WriteMasterKey(nMasterKeyMaxID, kMasterKey);

        for (const auto& spk_man_pair : m_spk_managers) {
            if (!spk_man_pair.second->Encrypt(vMasterKey, encrypted_batch)) {
                encrypted_batch->TxnAbort();
                delete encrypted_batch;
                encrypted_batch = nullptr;
                // We now probably have half of our keys encrypted in memory, and half not...
                // die and let the user reload the unencrypted wallet.
                assert(false);
            }
        }

        if (0 != ExtKeyEncryptAll((CHDWalletDB*)encrypted_batch, vMasterKey)) {
            WalletLogPrintf("Terminating - Error: ExtKeyEncryptAll failed.\n");
            //if (fFileBacked)
            {
                encrypted_batch->TxnAbort();
                delete encrypted_batch;
            }
            assert(false); // die and let the user reload the unencrypted wallet.
        }

        // Encryption was introduced in version 0.4.0
        SetMinVersion(FEATURE_WALLETCRYPT, encrypted_batch);

        //if (fFileBacked)
        {
            if (!encrypted_batch->TxnCommit()) {
                delete encrypted_batch;
                // We now have keys encrypted in memory, but not on disk...
                // die to avoid confusion and let the user reload the unencrypted wallet.
                assert(false);
            }

            delete encrypted_batch;
            encrypted_batch = nullptr;
        }

        if (!Lock())
            WalletLogPrintf("%s: ERROR: Lock wallet failed!\n", __func__);
        if (!Unlock(strWalletPassphrase, true))
            WalletLogPrintf("%s: ERROR: Unlock wallet failed!\n", __func__);
        if (!Lock())
            WalletLogPrintf("%s: ERROR: Lock wallet failed!\n", __func__);

        // Need to completely rewrite the wallet file; if we don't, bdb might keep
        // bits of the unencrypted private key in slack space in the database file.
        m_database->Rewrite();

        // BDB seems to have a bad habit of writing old data into
        // slack space in .dat files; that is bad if the old data is
        // unencrypted private keys. So:
        m_database->ReloadDbEnv();
    }
    NotifyStatusChanged(this);

    return true;
};

bool CHDWallet::Lock()
{
    LogPrint(BCLog::HDWALLET, "%s %s\n", GetDisplayName(), __func__);

    if (IsLocked()) {
        return true;
    }

    WalletLogPrintf("Locking wallet.\n");

    {
        LOCK(cs_wallet);
        ExtKeyLock();
    }

    return CWallet::Lock();
};

bool CHDWallet::Unlock(const SecureString &strWalletPassphrase, bool accept_no_keys)
{
    LogPrint(BCLog::HDWALLET, "%s %s\n", GetDisplayName(), __func__);

    if (!IsCrypted()) {
        return werror("%s: Wallet is not encrypted.\n", __func__);
    }

    bool fWasUnlocked = false;
    CKeyingMaterial vMasterKeyOld;
    if (!IsLocked()) {
        LogPrint(BCLog::HDWALLET, "%s %s: Wallet is already unlocked.\n", GetDisplayName(), __func__);
        // Possibly unlocked for staking
        LOCK(cs_wallet);
        fWasUnlocked = true;
        vMasterKeyOld = vMasterKey;
    }

    CCrypter crypter;
    CKeyingMaterial vMasterKeyNew;

    WalletLogPrintf("Unlocking wallet.\n");

    {
        bool fFoundKey = false;
        LOCK(cs_wallet);
        for (const auto &pMasterKey : mapMasterKeys) {
            if (!crypter.SetKeyFromPassphrase(strWalletPassphrase, pMasterKey.second.vchSalt, pMasterKey.second.nDeriveIterations, pMasterKey.second.nDerivationMethod)) {
                return false;
            }
            if (!crypter.Decrypt(pMasterKey.second.vchCryptedKey, vMasterKeyNew)) {
                continue; // try another master key
            }
            if (!CWallet::Unlock(vMasterKeyNew, true)) {
                return false;
            }
            if (0 != ExtKeyUnlock(vMasterKeyNew)) {
                if (fWasUnlocked) {
                    CWallet::Unlock(vMasterKeyOld, true);
                }
                return false;
            }
            fFoundKey = true;
            break;
        }

        if (!fFoundKey) {
            return false;
        }
        if (fWasUnlocked) {
            return true;
        }

        ProcessLockedStealthOutputs();
        ProcessLockedBlindedOutputs();
    }
    smsgModule.WalletUnlocked(this);

    WakeThreadStakeMiner(this);

    return true;
};

size_t CHDWallet::CountKeys() const
{
    auto spk_man = GetLegacyScriptPubKeyMan();
    if (!spk_man) {
        return 0;
    }
    return spk_man->CountKeys();
};

isminetype CHDWallet::HaveAddress(const CTxDestination &dest)
{
    LOCK(cs_wallet);

    if (dest.index() == DI::_PKHash) {
        CKeyID id = ToKeyID(std::get<PKHash>(dest));
        return IsMine(id);
    }

    if (dest.index() == DI::_CKeyID256) {
        CKeyID256 id256 = std::get<CKeyID256>(dest);
        CKeyID id(id256);
        return IsMine(id);
    }

    if (dest.index() == DI::_CExtPubKey) {
        CExtPubKey ek = std::get<CExtPubKey>(dest);
        CKeyID id = ek.GetID();
        return HaveExtKey(id);
    }

    if (dest.index() == DI::_CStealthAddress) {
        CStealthAddress sx = std::get<CStealthAddress>(dest);
        return HaveStealthAddress(sx);
    }

    return ISMINE_NO;
};

isminetype CHDWallet::HaveKey(const CKeyID &address, const CEKAKey *&pak, const CEKASCKey *&pasc, CExtKeyAccount *&pa) const
{
    AssertLockHeld(cs_wallet);

    pak = nullptr;
    pasc = nullptr;
    int rv;
    for (auto it = mapExtAccounts.cbegin(); it != mapExtAccounts.cend(); ++it) {
        pa = it->second;
        isminetype ismine = ISMINE_NO;
        rv = pa->HaveKey(address, true, pak, pasc, ismine);
        if (rv == HK_NO) {
            continue;
        }

        if (rv == HK_LOOKAHEAD_DO_UPDATE) {
            CEKAKey ak = *pak; // Must copy CEKAKey, ExtKeySaveKey modifies CExtKeyAccount
            if (0 != ExtKeySaveKey(pa, address, ak)) {
                WalletLogPrintf("%s: ExtKeySaveKey failed.\n", __func__);
                return ISMINE_NO;
            }
            // pak moved from mapLookAhead to mapKeys
            AccKeyMap::const_iterator mi = pa->mapKeys.find(address);
            if (mi != pa->mapKeys.end()) {
                pak = &mi->second;
            } else {
                WalletLogPrintf("%s: Key not moved.\n", __func__);
            }
        }
        return ismine;
    }

    auto itl = mapLooseLookAhead.find(address);
    if (itl != mapLooseLookAhead.end()) {
        auto itek = mapExtKeys.find(itl->second.chain_id);
        if (itek != mapExtKeys.end()) {
            CStoredExtKey *sek = itek->second;
            ExtKeyPromoteKey(sek, itl->second.nKey);
            // NOTE: itl is likely invalid after ExtKeyPromoteKey

            if (sek->IsTrackOnly()) {
                if (LogAcceptCategory(BCLog::HDWALLET)) {
                    WalletLogPrintf("Found lookahead key for track-only loose chain %s.\n", HDKeyIDToString(itek->first));
                }
                return ISMINE_NO;
            }
            return sek->IsMine();
        }
        WalletLogPrintf("Warning: Found lookahead key for missing loose chain %s.\n", HDKeyIDToString(itl->second.chain_id));
    }

    itl = mapLooseKeys.find(address);
    if (itl != mapLooseKeys.end()) {
        auto itek = mapExtKeys.find(itl->second.chain_id);
        if (itek != mapExtKeys.end()) {
            return itek->second->IsMine();
        }
        WalletLogPrintf("Warning: Found key for missing loose chain %s.\n", HDKeyIDToString(itl->second.chain_id));
    }

    pa = nullptr;
    return CWallet::IsMine(address);
};

isminetype CHDWallet::IsMine(const CKeyID &address) const
{
    LOCK(cs_wallet);

    const CEKAKey *pak = nullptr;
    const CEKASCKey *pasc = nullptr;
    CExtKeyAccount *pa = nullptr;
    return HaveKey(address, pak, pasc, pa);
};

bool CHDWallet::HaveKey(const CKeyID &address) const
{
    LOCK(cs_wallet);

    const CEKAKey *pak = nullptr;
    const CEKASCKey *pasc = nullptr;
    CExtKeyAccount *pa = nullptr;
    return HaveKey(address, pak, pasc, pa) & ISMINE_SPENDABLE ? true : false;
};

isminetype CHDWallet::HaveExtKey(const CKeyID &keyID) const
{
    LOCK(cs_wallet);
    // NOTE: This only checks the extkeys currently in memory (mapExtKeys)
    //       There may be other extkeys in the db.

    ExtKeyMap::const_iterator it = mapExtKeys.find(keyID);
    if (it != mapExtKeys.end()) {
        return it->second->IsMine();
    }

    return ISMINE_NO;
};

bool CHDWallet::GetExtKey(const CKeyID &keyID, CStoredExtKey &extKeyOut) const
{
    LOCK(cs_wallet);
    // NOTE: This only checks keys currently in memory (mapExtKeys)
    //       There may be other extkeys in the db.

    ExtKeyMap::const_iterator it = mapExtKeys.find(keyID);
    if (it != mapExtKeys.end()) {
        extKeyOut = *it->second;
        return true;
    }

    return false;
};


bool CHDWallet::HaveTransaction(const uint256 &txhash) const
{
    return mapWallet.count(txhash) || mapRecords.count(txhash);
};

bool CHDWallet::GetTransaction(const uint256 &txhash, CTransactionRef &tx) const
{
    const auto mi = mapWallet.find(txhash);
    if (mi != mapWallet.end()) {
        tx = mi->second.tx;
        return true;
    }
    const auto mri = mapRecords.find(txhash);
    if (mri != mapRecords.end()) {
        CStoredTransaction stx;
        if (!CHDWalletDB(*m_database).ReadStoredTx(txhash, stx)) {
            WalletLogPrintf("%s: ReadStoredTx failed for %s.\n", __func__, txhash.ToString());
            return false;
        }
        tx = stx.tx;  // CTransactionRef is a shared_ptr, should persist after stx is destroyed
        return true;
    }

    // TODO: Check ::GetTransaction
    return false;
};

int CHDWallet::GetKey(const CKeyID &address, CKey &keyOut, CExtKeyAccount *&pa, CEKAKey &ak, CKeyID &idStealth) const
{
    int rv = 0;

    LOCK(cs_wallet);

    for (auto it = mapExtAccounts.cbegin(); it != mapExtAccounts.cend(); ++it) {
        rv = it->second->GetKey(address, keyOut, ak, idStealth);

        if (!rv) {
            continue;
        }
        pa = it->second;
        return rv;
    }

    pa = nullptr;
    auto spk_man = GetLegacyScriptPubKeyMan();
    if (spk_man) {
        if (spk_man->GetKey_(address, keyOut)) {
            return KS_LEGACY;
        }
    }
    return KS_NONE;
};

bool CHDWallet::GetKey(const CKeyID &address, CKey &keyOut) const
{
    LOCK(cs_wallet);

    for (auto it = mapExtAccounts.cbegin(); it != mapExtAccounts.cend(); ++it) {
        if (it->second->GetKey(address, keyOut)) {
            return true;
        }
    }

    auto it = mapLooseKeys.find(address);
    if (it != mapLooseKeys.end()) {
        try {
            auto itc = mapExtKeys.find(it->second.chain_id);
            if (itc != mapExtKeys.end()) {
                const CStoredExtKey *chain = itc->second;
                if (chain->fLocked) {
                    throw std::runtime_error("locked");
                } else
                if (!chain->kp.Derive(keyOut, it->second.nKey)) {
                    throw std::runtime_error("derive failed");
                }
                return true;
            } else {
                throw std::runtime_error("not found");
            }
        } catch (const std::exception &e) {
            WalletLogPrintf("Error: extkey %s %s for loose derived key %s.\n",
                            HDKeyIDToString(it->second.chain_id), e.what(), EncodeDestination(PKHash(address)));
        }
    }

    auto spk_man = GetLegacyScriptPubKeyMan();
    if (spk_man) {
        if (spk_man->GetKey_(address, keyOut)) {
            return true;
        }
    }
    return false;
};

bool CHDWallet::GetPubKey(const CKeyID &address, CPubKey& pkOut) const
{
    LOCK(cs_wallet);
    for (auto it = mapExtAccounts.cbegin(); it != mapExtAccounts.cend(); ++it) {
        if (it->second->GetPubKey(address, pkOut)) {
            return true;
        }
    }

    auto it = mapLooseKeys.find(address);
    if (it != mapLooseKeys.end()) {
        try {
            auto itc = mapExtKeys.find(it->second.chain_id);
            if (itc != mapExtKeys.end()) {
                const CStoredExtKey *chain = itc->second;
                if (chain->fLocked) {
                    throw std::runtime_error("locked");
                } else
                if (!chain->kp.Derive(pkOut, it->second.nKey)) {
                    throw std::runtime_error("derive failed");
                }
                return true;
            } else {
                throw std::runtime_error("not found");
            }
        } catch (const std::exception &e) {
            WalletLogPrintf("Error: extkey %s %s for loose derived pubkey %s.\n",
                            HDKeyIDToString(it->second.chain_id), e.what(), EncodeDestination(PKHash(address)));
        }
    }

    auto spk_man = GetLegacyScriptPubKeyMan();
    if (spk_man) {
        if (spk_man->GetPubKey_(address, pkOut)) {
            return true;
        }
    }
    return false;
};

bool CHDWallet::GetKeyFromPool(CPubKey &key, bool internal)
{
    // Always return a key from the internal chain
    return 0 == NewKeyFromAccount(key, true, false, false, false, nullptr);
};

isminetype CHDWallet::HaveStealthAddress(const CStealthAddress &sxAddr) const
{
    const CExtKeyAccount *pa;
    const CEKAStealthKey *pask;
    return IsMine(sxAddr, pa, pask);
};

isminetype CHDWallet::IsMine(const CStealthAddress &sxAddr, const CExtKeyAccount *&pa, const CEKAStealthKey *&pask) const
{
    std::set<CStealthAddress>::const_iterator si = stealthAddresses.find(sxAddr);
    if (si != stealthAddresses.end()) {
        isminetype imSpend = IsMine(si->spend_secret_id);
        // Retain ISMINE_HARDWARE_DEVICE flag if present
        if (imSpend & ISMINE_SPENDABLE) {
            return imSpend;
        }
        return (isminetype)((int)ISMINE_WATCH_ONLY_ | (int)imSpend);
    }

    CKeyID sxId = CPubKey(sxAddr.scan_pubkey).GetID();

    for (auto mi = mapExtAccounts.cbegin(); mi != mapExtAccounts.cend(); ++mi) {
        CExtKeyAccount *ea = mi->second;

        if (ea->mapStealthKeys.size() < 1) {
            continue;
        }
        AccStealthKeyMap::const_iterator it = ea->mapStealthKeys.find(sxId);
        if (it != ea->mapStealthKeys.end()) {
            const CStoredExtKey *sek = ea->GetChain(it->second.akSpend.nParent);
            if (sek) {
                pa = ea;
                pask = &it->second;
                return sek->IsMine();
            }
            break;
        }
    }

    return ISMINE_NO;
};

isminetype CHDWallet::IsMineP2SH(const CScript& script) const
{
    isminetype result = ISMINE_NO;
    auto spk_man = GetLegacyScriptPubKeyMan();
    if (spk_man) {
        result = std::max(result, spk_man->IsMineP2SH(script));
    }
    return result;
}

bool CHDWallet::GetStealthAddressScanKey(CStealthAddress &sxAddr) const
{
    std::set<CStealthAddress>::const_iterator si = stealthAddresses.find(sxAddr);
    if (si != stealthAddresses.end()) {
        sxAddr.scan_secret = si->scan_secret;
        return true;
    }

    CKeyID sxId = CPubKey(sxAddr.scan_pubkey).GetID();

    for (auto mi = mapExtAccounts.cbegin(); mi != mapExtAccounts.cend(); ++mi) {
        CExtKeyAccount *ea = mi->second;

        if (ea->mapStealthKeys.size() < 1) {
            continue;
        }

        AccStealthKeyMap::const_iterator it = ea->mapStealthKeys.find(sxId);
        if (it != ea->mapStealthKeys.end()) {
            sxAddr.scan_secret = it->second.skScan;
            return true;
        }
    }

    return false;
};

bool CHDWallet::GetStealthAddressSpendKey(const CStealthAddress &sxAddr, CKey &key) const
{
    if (GetKey(sxAddr.spend_secret_id, key)) {
        return true;
    }

    CKeyID sxId = CPubKey(sxAddr.scan_pubkey).GetID();

    for (auto mi = mapExtAccounts.cbegin(); mi != mapExtAccounts.cend(); ++mi) {
        CExtKeyAccount *ea = mi->second;
        AccStealthKeyMap::iterator it = ea->mapStealthKeys.find(sxId);
        if (it != ea->mapStealthKeys.end()) {
            if (ea->GetKey(it->second.akSpend, key)) {
                return true;
            }
        }
    }
    return false;
};



bool CHDWallet::ImportStealthAddress(const CStealthAddress &sxAddr, const CKey &skSpend)
{
    if (LogAcceptCategory(BCLog::HDWALLET)) {
        WalletLogPrintf("%s: %s.\n", __func__, sxAddr.Encoded());
    }

    LOCK(cs_wallet);

    // Must add before changing spend_secret
    stealthAddresses.insert(sxAddr);

    bool fOwned = skSpend.IsValid();

    if (fOwned) {
        // Owned addresses can only be added when wallet is unlocked
        if (IsLocked()) {
            stealthAddresses.erase(sxAddr);
            return werror("%s: Wallet must be unlocked.", __func__);
        }

        CPubKey pk = skSpend.GetPubKey();
        auto spk_man = GetLegacyScriptPubKeyMan();
        if (spk_man) {
            if (!spk_man->AddKeyPubKey(skSpend, pk)) {
                stealthAddresses.erase(sxAddr);
                return werror("%s: AddKeyPubKey failed.", __func__);
            }
        }
    }

    if (!CHDWalletDB(*m_database).WriteStealthAddress(sxAddr)) {
        stealthAddresses.erase(sxAddr);
        return werror("%s: WriteStealthAddress failed.", __func__);
    }
    UnsetWalletFlag(WALLET_FLAG_BLANK_WALLET);

    return true;
};

bool CHDWallet::AddressBookChangedNotify(const CTxDestination &address, ChangeType nMode)
{
    // Must run without cs_wallet locked

    CAddressBookData entry;
    isminetype tIsMine;

    {
        LOCK(cs_wallet);

        std::map<CTxDestination, CAddressBookData>::const_iterator mi = m_address_book.find(address);
        if (mi == m_address_book.end()) {
            return false;
        }

        entry.SetLabel(mi->second.GetLabel());
        entry.purpose = mi->second.purpose;
        entry.vPath = mi->second.vPath;

        tIsMine = this->IsMine(address);
    }

    std::string str_path;
    if (entry.vPath.size() > 1) {
        PathToString(entry.vPath, str_path, '\'', 1);
    }
    NotifyAddressBookChanged(address, entry.GetLabel(), tIsMine != ISMINE_NO, entry.purpose, str_path, nMode);

    if (tIsMine == ISMINE_SPENDABLE
        && address.index() == DI::_PKHash) {
        CKeyID id = ToKeyID(std::get<PKHash>(address));
        smsgModule.WalletKeyChanged(id, entry.GetLabel(), nMode);
    }

    return true;
};

DBErrors CHDWallet::LoadWallet()
{
    if (!ParseMoney(gArgs.GetArg("-reservebalance", "0"), nReserveBalance)) {
        InitError(_("Invalid amount for -reservebalance=<amount>"));
        return DBErrors::LOAD_FAIL;
    }

    m_rescan_stealth_v1_lookahead = gArgs.GetArg("-stealthv1lookaheadsize", DEFAULT_STEALTH_LOOKAHEAD_SIZE);
    m_rescan_stealth_v2_lookahead = gArgs.GetArg("-stealthv2lookaheadsize", DEFAULT_STEALTH_LOOKAHEAD_SIZE);
    m_default_lookahead = gArgs.GetArg("-defaultlookaheadsize", DEFAULT_LOOKAHEAD_SIZE);

    std::string sError;
    ProcessStakingSettings(sError);
    ProcessWalletSettings(sError);

    LoadMasterKeys();

    {
        // Prepare extended keys
        ExtKeyLoadMaster();
        ExtKeyLoadAccounts();
        ExtKeyLoadAccountPacks();
        ExtKeyLoadLoose();
        LoadStealthAddresses();
        PrepareLookahead(); // Must happen after ExtKeyLoadAccountPacks
    }

    auto rv = CWallet::LoadWallet();
    if (rv != DBErrors::LOAD_OK) {
        return rv;
    }

    if (!IsWalletFlagSet(WALLET_FLAG_BLANK_WALLET)) {
        auto spk_man = GetOrCreateLegacyScriptPubKeyMan();
        assert(spk_man);
    }

    if (secp256k1_ctx_blind) {
        m_blind_scratch = secp256k1_scratch_space_create(secp256k1_ctx_blind, 1024 * 1024);
        assert(m_blind_scratch);
    }

    PostProcessUnloadSpent();

    LOCK(cs_wallet);

    {
        CHDWalletDB wdb(GetDatabase());

        LoadAddressBook(&wdb);
        LoadTxRecords(&wdb);
        LoadVoteTokens(&wdb);
    }

    if (!pEKMaster) {
        if (gArgs.GetBoolArg("-createdefaultmasterkey", false)) {
            std::string sMsg = "Generating random HD keys for wallet " + GetName();
#ifndef ENABLE_QT
            tfm::format(std::cout, "%s\n", sMsg.c_str());
#endif
            LogPrintf("%s\n", sMsg);
            if (MakeDefaultAccount() != 0) {
                tfm::format(std::cout, "Error: MakeDefaultAccount failed!\n");
            }
        } else {
            /*
            std::string sWarning = "Warning: Wallet " + pwallet->GetName() + " has no master HD key set, please view the readme.";
            #ifndef ENABLE_QT
            tfm::format(std::cout, "%s\n", sWarning.c_str());
            #endif
            LogPrintf("%s\n", sWarning);
            */
        }
    }
    if (idDefaultAccount.IsNull() && m_chain) { // If !m_chain, probably running from particl-wallet
        std::string sWarning = "Warning: Wallet " + GetName() + " has no active account, please view the readme.";
#ifndef ENABLE_QT
        tfm::format(std::cout, "%s\n", sWarning.c_str());
#endif
        LogPrintf("%s\n", sWarning);
    }
    return DBErrors::LOAD_OK;
}

void CHDWallet::Downgrade()
{
    WalletLogPrintf("Downgrading TransactionRecord format.\n");
    LOCK(cs_wallet);

    CHDWalletDB wdb(GetDatabase());

    for (auto &ri : mapRecords) {
        const uint256 &txhash = ri.first;
        CTransactionRecord &rtx = ri.second;

        if (!(rtx.nFlags & ORF_ANON_IN)) {
            continue;
        }

        CStoredTransaction stx;
        if (!wdb.ReadStoredTx(txhash, stx)) {
            WalletLogPrintf("Warning: ReadStoredTx failed for: %s.\n", txhash.ToString());
            continue;
        }

        COutPoint op;
        rtx.vin.clear();
        for (const auto &txin : stx.tx->vin) {
            if (!txin.IsAnonInput()) {
                continue;
            }
            uint32_t nInputs, nRingSize;
            txin.GetAnonInfo(nInputs, nRingSize);
            const std::vector<uint8_t> &vKeyImages = txin.scriptData.stack[0];
            assert(vKeyImages.size() == nInputs * 33);
            for (size_t k = 0; k < nInputs; ++k) {
                const CCmpPubKey &ki = *((CCmpPubKey*)&vKeyImages[k*33]);
                op.n = 0;
                memcpy(op.hash.begin(), ki.begin(), 32);
                op.n = *(ki.begin()+32);
                rtx.vin.push_back(op);
            }
        }
        wdb.WriteTxRecord(txhash, rtx);
    }
    wdb.EraseFlag("anon_vin_v2");
}

bool CHDWallet::SetAddressBook(CHDWalletDB *pwdb, const CTxDestination &address, const std::string &strName,
    const std::string &strPurpose, const std::vector<uint32_t> &vPath, bool fNotifyChanged, bool fBech32)
{
    ChangeType nMode;
    isminetype tIsMine;

    {
        LOCK(cs_wallet); // m_address_book

        CAddressBookData emptyEntry;
        std::pair<std::map<CTxDestination, CAddressBookData>::iterator, bool> ret;
        ret = m_address_book.insert(std::pair<CTxDestination, CAddressBookData>(address, emptyEntry));
        nMode = (ret.second) ? CT_NEW : CT_UPDATED;

        CAddressBookData *entry = &ret.first->second;
        entry->SetLabel(strName, strPurpose, vPath, fBech32);
        tIsMine = IsMine(address);

        if (pwdb) {
            if (!pwdb->WriteAddressBookEntry(EncodeDestination(address), *entry)) {
                return false;
            }
        } else {
            if (!CHDWalletDB(*m_database).WriteAddressBookEntry(EncodeDestination(address), *entry)) {
                return false;
            }
        }
    }

    if (fNotifyChanged) {
        // Must run without cs_wallet locked
        std::string str_path;
        if (vPath.size() > 1) {
            PathToString(vPath, str_path, '\'', 1);
        }
        NotifyAddressBookChanged(address, strName, tIsMine != ISMINE_NO, strPurpose, str_path, nMode);

        if (tIsMine == ISMINE_SPENDABLE
            && address.index() == DI::_PKHash) {
            CKeyID id = ToKeyID(std::get<PKHash>(address));
            smsgModule.WalletKeyChanged(id, strName, nMode);
        }
    }

    return true;
};

bool CHDWallet::SetAddressBook(const CTxDestination &address, const std::string &strName, const std::string &strPurpose, bool fBech32)
{
    isminetype tIsMine;
    ChangeType nMode;

    {
        LOCK(cs_wallet); // m_address_book
        std::vector<uint32_t> vPath;

        CAddressBookData emptyEntry;
        std::pair<std::map<CTxDestination, CAddressBookData>::iterator, bool> ret;
        ret = m_address_book.insert(std::pair<CTxDestination, CAddressBookData>(address, emptyEntry));
        nMode = (ret.second) ? CT_NEW : CT_UPDATED;

        CAddressBookData *entry = &ret.first->second;
        entry->SetLabel(strName, strPurpose, vPath, fBech32);
        tIsMine = IsMine(address);

        if (!CHDWalletDB(*m_database).WriteAddressBookEntry(EncodeDestination(address), *entry)) {
            return false;
        }
    }

    if (tIsMine == ISMINE_SPENDABLE &&
        address.index() == DI::_PKHash) {
        CKeyID id = ToKeyID(std::get<PKHash>(address));
        smsgModule.WalletKeyChanged(id, strName, nMode);
    }

    std::string str_path;
    NotifyAddressBookChanged(address, strName, tIsMine != ISMINE_NO,
                             strPurpose, str_path, nMode);

    return true;
};


bool CHDWallet::DelAddressBook(const CTxDestination &address)
{
    isminetype tIsMine;
    {
        LOCK(cs_wallet);
        tIsMine = IsMine(address);
        if (address.index() == DI::_CStealthAddress) {
            const CStealthAddress &sxAddr = std::get<CStealthAddress>(address);
            //bool fOwned; // must check on copy from wallet

            std::set<CStealthAddress>::iterator si = stealthAddresses.find(sxAddr);
            if (si == stealthAddresses.end()) {
                WalletLogPrintf("%s: Stealth address not found in wallet.\n", __func__);
                //return false;
            } else {
                //fOwned = si->scan_secret.size() < 32 ? false : true;

                if (stealthAddresses.erase(sxAddr) < 1
                    || !CHDWalletDB(*m_database).EraseStealthAddress(sxAddr)) {
                    WalletLogPrintf("%s: Error: Remove stealthAddresses failed.\n", __func__);
                    return false;
                }
            }
        }
    }

    if (tIsMine == ISMINE_SPENDABLE &&
        address.index() == DI::_PKHash) {
        CKeyID id = ToKeyID(std::get<PKHash>(address));
        smsgModule.WalletKeyChanged(id, "", CT_DELETED);
    }

    bool fErased = false; // CWallet::DelAddressBook can return false
    //if (fFileBacked)
    {
        fErased = CHDWalletDB(*m_database).EraseAddressBookEntry(EncodeDestination(address)) ? true : fErased;
    }
    fErased = CWallet::DelAddressBook(address) ? true : fErased;

    return fErased;
};

int64_t CHDWallet::GetOldestActiveAccountTime() const
{
    LOCK(cs_wallet);

    int64_t nTime = GetTime();

    for (const auto &mi : mapExtAccounts) {
        CExtKeyAccount *pa = mi.second;
        mapEKValue_t::iterator mvi = pa->mapValue.find(EKVT_CREATED_AT);
        if (mvi != pa->mapValue.end()) {
            int64_t nCreatedAt;
            GetCompressedInt64(mvi->second, (uint64_t&)nCreatedAt);
            if (nTime > nCreatedAt)
                nTime = nCreatedAt;
        }
    }

    return nTime;
};

int64_t CHDWallet::CountActiveAccountKeys() const
{
    LOCK(cs_wallet);
    int64_t nKeys = 0;

    for (const auto &mi : mapExtAccounts) {
        CExtKeyAccount *pa = mi.second;
        nKeys += pa->mapKeys.size();
        nKeys += pa->mapStealthChildKeys.size();
        //nKeys += pa->mapLookAhead.size();
    }

    return nKeys;
};

std::map<CTxDestination, CAmount> CHDWallet::GetAddressBalances() const
{
    std::map<CTxDestination, CAmount> balances;

    {
        LOCK(cs_wallet);
        for (const auto& walletEntry : mapWallet) {
            const CWalletTx *pcoin = &walletEntry.second;

            if (!pcoin->IsTrusted()) {
                continue;
            }

            if (pcoin->IsImmatureCoinBase()) {
                continue;
            }

            int nDepth = pcoin->GetDepthInMainChain();
            if (nDepth < (pcoin->IsFromMe(ISMINE_ALL) ? 0 : 1)) {
                continue;
            }

            for (unsigned int i = 0; i < pcoin->tx->GetNumVOuts(); i++) {
                const auto &txout = pcoin->tx->vpout[i];
                if (!txout->IsType(OUTPUT_STANDARD)) {
                    continue;
                }
                if (!IsMine(txout.get())) {
                    continue;
                }

                CTxDestination addr;
                if (!ExtractDestination(*txout->GetPScriptPubKey(), addr)) {
                    continue;
                }

                CAmount n = IsSpent(walletEntry.first, i) ? 0 : txout->GetValue();

                if (!balances.count(addr)) {
                    balances[addr] = 0;
                }
                balances[addr] += n;
            }
        }

        for (const auto &ri : mapRecords) {
            const uint256 &txhash = ri.first;
            const CTransactionRecord &rtx = ri.second;

            if (!IsTrusted(txhash, rtx)) {
                continue;
            }

            for (const auto &r : rtx.vout) {
                if (r.nType != OUTPUT_STANDARD
                    && r.nType != OUTPUT_CT
                    && r.nType != OUTPUT_RINGCT) {
                    continue;
                }

                if (!(r.nFlags & ORF_OWNED)) {
                    continue;
                }

                CTxDestination addr;
                if (!ExtractDestination(r.scriptPubKey, addr)) {
                    continue;
                }

                CAmount n =  IsSpent(txhash, r.n) ? 0 : r.nValue;

                std::pair<std::map<CTxDestination, CAmount>::iterator, bool> ret;
                ret = balances.insert(std::pair<CTxDestination, CAmount>(addr, n));
                if (!ret.second) { // update existing record
                    ret.first->second += n;
                }
            }
        }
    }

    return balances;
}

std::set< std::set<CTxDestination> > CHDWallet::GetAddressGroupings() const
{
    AssertLockHeld(cs_wallet); // mapWallet
    std::set< std::set<CTxDestination> > groupings;
    std::set<CTxDestination> grouping;

    for (const auto& walletEntry : mapWallet) {
        const CWalletTx *pcoin = &walletEntry.second;

        if (pcoin->tx->vin.size() > 0) {
            bool any_mine = false;
            // group all input addresses with each other
            for (CTxIn txin : pcoin->tx->vin) {
                const CScript *pScript = nullptr;
                CTxDestination address;

                MapRecords_t::const_iterator mri;
                MapWallet_t::const_iterator mi = mapWallet.find(txin.prevout.hash);
                if (mi != mapWallet.end()) {
                    const CWalletTx &prev = mi->second;
                    if (txin.prevout.n < prev.tx->vpout.size()) {
                        pScript = prev.tx->vpout[txin.prevout.n]->GetPScriptPubKey();
                    }
                } else
                if ((mri = mapRecords.find(txin.prevout.hash)) != mapRecords.end()) {
                    const COutputRecord *oR = mri->second.GetOutput(txin.prevout.n);
                    if (oR && (oR->nFlags & ORF_OWNED)) {
                        pScript = &oR->scriptPubKey;
                    }
                } else {
                    // If this input isn't mine, ignore it
                    continue;
                }
                if (!pScript) {
                    continue;
                }
                if (!ExtractDestination(*pScript, address)) {
                    continue;
                }
                grouping.insert(address);
                any_mine = true;
            }

            // group change with input addresses
            if (any_mine) {
                for (const auto &txout : pcoin->tx->vpout) {
                    if (IsChange(txout.get())) {
                        CTxDestination txoutAddr;
                        const CScript *pScript = txout->GetPScriptPubKey();
                        if (!pScript) {
                            continue;
                        }
                        if (!ExtractDestination(*pScript, txoutAddr)) {
                            continue;
                        }
                        grouping.insert(txoutAddr);
                    }
                }
            }
            if (grouping.size() > 0) {
                groupings.insert(grouping);
                grouping.clear();
            }
        }

        // group lone addrs by themselves
        for (const auto &txout : pcoin->tx->vpout) {
            if (IsMine(txout.get())) {
                CTxDestination address;
                const CScript *pScript = txout->GetPScriptPubKey();
                if (!pScript) {
                    continue;
                }
                if (!ExtractDestination(*pScript, address)) {
                    continue;
                }
                grouping.insert(address);
                groupings.insert(grouping);
                grouping.clear();
            }
        }
    }

    std::set< std::set<CTxDestination>* > uniqueGroupings; // a set of pointers to groups of addresses
    std::map< CTxDestination, std::set<CTxDestination>* > setmap;  // map addresses to the unique group containing it
    for (std::set<CTxDestination> _grouping : groupings) {
        // make a set of all the groups hit by this new group
        std::set< std::set<CTxDestination>* > hits;
        std::map< CTxDestination, std::set<CTxDestination>* >::iterator it;
        for (CTxDestination address : _grouping) {
            if ((it = setmap.find(address)) != setmap.end()) {
                hits.insert((*it).second);
            }
        }

        // merge all hit groups into a new single group and delete old groups
        std::set<CTxDestination>* merged = new std::set<CTxDestination>(_grouping);
        for (std::set<CTxDestination>* hit : hits) {
            merged->insert(hit->begin(), hit->end());
            uniqueGroupings.erase(hit);
            delete hit;
        }
        uniqueGroupings.insert(merged);

        // update setmap
        for (CTxDestination element : *merged) {
            setmap[element] = merged;
        }
    }

    std::set< std::set<CTxDestination> > ret;
    for (std::set<CTxDestination>* uniqueGrouping : uniqueGroupings) {
        ret.insert(*uniqueGrouping);
        delete uniqueGrouping;
    }

    return ret;
}

isminetype CHDWallet::IsMine(const CTxIn& txin) const
{
    if (txin.IsAnonInput()) {
        return ISMINE_NO;
    }

    MapWallet_t::const_iterator mi = mapWallet.find(txin.prevout.hash);
    if (mi != mapWallet.end()) {
        const CWalletTx &prev = (*mi).second;
        if (txin.prevout.n < prev.tx->vpout.size()) {
            return IsMine(prev.tx->vpout[txin.prevout.n].get());
        }
    }

    MapRecords_t::const_iterator mri = mapRecords.find(txin.prevout.hash);
    if (mri != mapRecords.end()) {
        const COutputRecord *oR = mri->second.GetOutput(txin.prevout.n);

        if (oR) {
            if (oR->nFlags & ORF_OWNED) {
                return ISMINE_SPENDABLE;
            }
            /* TODO
            if ((filter & ISMINE_WATCH_ONLY)
                && (oR->nFlags & ORF_WATCH_ONLY))
                return ISMINE_WATCH_ONLY;
            */
        }
    }

    return ISMINE_NO;
};

isminetype CHDWallet::IsMine(const CScript &scriptPubKey, CKeyID &keyID,
    const CEKAKey *&pak, const CEKASCKey *&pasc, CExtKeyAccount *&pa, bool &isInvalid, SigVersion sigversion) const
{
    if (scriptPubKey.StartsWithICS()) {
        CScript scriptA, scriptB;
        if (!SplitConditionalCoinstakeScript(scriptPubKey, scriptA, scriptB)) {
            return ISMINE_NO;
        }

        isminetype typeB = IsMine(scriptB, keyID, pak, pasc, pa, isInvalid, sigversion);
        if (typeB & ISMINE_SPENDABLE) {
            return typeB;
        }

        isminetype typeA = IsMine(scriptA, keyID, pak, pasc, pa, isInvalid, sigversion);
        if (typeA & ISMINE_SPENDABLE) {
            int ia = (int)typeA;
            ia &= ~ISMINE_SPENDABLE;
            ia |= ISMINE_WATCH_COLDSTAKE;
            typeA = (isminetype)ia;
        }

        return (isminetype)((int)typeA | (int)typeB);
    }

    std::vector<valtype> vSolutions;
    TxoutType whichType = Solver(scriptPubKey, vSolutions);

    isminetype mine = ISMINE_NO;
    switch (whichType)
    {
    case TxoutType::NONSTANDARD:
    case TxoutType::NULL_DATA:
        break;
    case TxoutType::PUBKEY:
        keyID = CPubKey(vSolutions[0]).GetID();
        if (sigversion != SigVersion::BASE && vSolutions[0].size() != 33) {
            isInvalid = true;
            return ISMINE_NO;
        }
        if ((mine = HaveKey(keyID, pak, pasc, pa))) {
            return mine;
        }
        break;
    case TxoutType::PUBKEYHASH:
    case TxoutType::PUBKEYHASH256:
        if (vSolutions[0].size() == 20) {
            keyID = CKeyID(uint160(vSolutions[0]));
        } else
        if (vSolutions[0].size() == 32) {
            keyID = CKeyID(uint256(vSolutions[0]));
        } else {
            return ISMINE_NO;
        }
        if (sigversion != SigVersion::BASE) {
            CPubKey pubkey;
            if (GetPubKey(keyID, pubkey) && !pubkey.IsCompressed()) {
                isInvalid = true;
                return ISMINE_NO;
            }
        }
        if ((mine = HaveKey(keyID, pak, pasc, pa))) {
            return mine;
        }
        break;
    case TxoutType::SCRIPTHASH:
    case TxoutType::SCRIPTHASH256:
    {
        CScriptID scriptID;
        if (vSolutions[0].size() == 20) {
            scriptID = CScriptID(uint160(vSolutions[0]));
        } else
        if (vSolutions[0].size() == 32) {
            scriptID.Set(uint256(vSolutions[0]));
        } else {
            return ISMINE_NO;
        }
        CScript subscript;
        std::unique_ptr<SigningProvider> provider = GetSolvingProvider(subscript);
        if (provider && provider->GetCScript(scriptID, subscript)) {
            auto spk_man = GetLegacyScriptPubKeyMan();
            if (spk_man) {
                isminetype ret = spk_man->IsMine(subscript, isInvalid);
                if (ret == ISMINE_SPENDABLE || ret == ISMINE_WATCH_ONLY_ || (ret == ISMINE_NO && isInvalid))
                    return ret;
            }
        }
        break;
    }
    case TxoutType::WITNESS_V0_KEYHASH:
    {
        keyID = CKeyID(uint160(vSolutions[0]));
        if ((mine = HaveKey(keyID, pak, pasc, pa))) {
            return mine;
        }
        break;
    }
    case TxoutType::WITNESS_V0_SCRIPTHASH:
        LogPrintf("%s: Ignoring WITNESS_V0_SCRIPTHASH script type.\n", __func__); // shouldn't happen
        return ISMINE_NO;
    case TxoutType::WITNESS_V1_TAPROOT:
        LogPrintf("%s: Ignoring WITNESS_V1_TAPROOT script type.\n", __func__); // shouldn't happen
        return ISMINE_NO;
    case TxoutType::WITNESS_UNKNOWN:
        LogPrintf("%s: Ignoring WITNESS_UNKNOWN script type.\n", __func__); // shouldn't happen
        return ISMINE_NO;
    case TxoutType::MULTISIG:
    {
        // Only consider transactions "mine" if we own ALL the
        // keys involved. Multi-signature transactions that are
        // partially owned (somebody else has a key that can spend
        // them) enable spend-out-from-under-you attacks, especially
        // in shared-wallet situations.
        std::vector<valtype> keys(vSolutions.begin()+1, vSolutions.begin()+vSolutions.size()-1);
        if (sigversion != SigVersion::BASE) {
            for (size_t i = 0; i < keys.size(); i++) {
                if (keys[i].size() != 33) {
                    isInvalid = true;
                    return ISMINE_NO;
                }
            }
        }
        if (HaveKeys(keys, *GetLegacyScriptPubKeyMan()) == keys.size())
            return ISMINE_SPENDABLE;
        break;
    }
    default:
        return ISMINE_NO;
    }

    auto spk_man = GetLegacyScriptPubKeyMan();
    if (spk_man) {
        if (spk_man->HaveWatchOnly(scriptPubKey)) {
            return ISMINE_WATCH_ONLY_;
        }
    }
    return ISMINE_NO;
};

isminetype CHDWallet::IsMine(const CTxOutBase *txout) const
{
    switch (txout->nVersion) {
        case OUTPUT_STANDARD:
            return IsMine(((CTxOutStandard*)txout)->scriptPubKey);
        case OUTPUT_CT:
            return IsMine(((CTxOutCT*)txout)->scriptPubKey);
        case OUTPUT_RINGCT:
            //CKeyID idk = ((CTxOutRingCT*)txout)->pk.GetID();
            //return HaveKey(idk);
            break;
        default:
            return ISMINE_NO;
    }

    return ISMINE_NO;
};

bool CHDWallet::IsMine(const CTransaction &tx) const
{
    for (const auto &txout : tx.vpout) {
        if (IsMine(txout.get())) {
            return true;
        }
    }
    return false;
}

bool CHDWallet::IsFromMe(const CTransaction& tx) const
{
    return (GetDebit(tx, ISMINE_ALL) > 0);
}

// Note that this function doesn't distinguish between a 0-valued input,
// and a not-"is mine" (according to the filter) input.
CAmount CHDWallet::GetDebit(const CTxIn &txin, const isminefilter &filter) const
{
    LOCK(cs_wallet);
    MapWallet_t::const_iterator mi = mapWallet.find(txin.prevout.hash);
    if (mi != mapWallet.end()) {
        const CWalletTx &prev = (*mi).second;
        if (txin.prevout.n < prev.tx->vpout.size())
            if (IsMine(prev.tx->vpout[txin.prevout.n].get()) & filter)
                return prev.tx->vpout[txin.prevout.n]->GetValue();
    }

    MapRecords_t::const_iterator mri = mapRecords.find(txin.prevout.hash);
    if (mri != mapRecords.end()) {
        const COutputRecord *oR = mri->second.GetOutput(txin.prevout.n);

        if (oR) {
            if ((filter & ISMINE_SPENDABLE)
                && (oR->nFlags & ORF_OWNED)) {
                return oR->nValue;
            }
            /* TODO
            if ((filter & ISMINE_WATCH_ONLY)
                && (oR->nFlags & ORF_WATCH_ONLY))
                return oR->nValue;
            */
        }
    }
    return 0;
};

CAmount CHDWallet::GetDebit(const CTransaction& tx, const isminefilter& filter) const
{
    if (!tx.IsParticlVersion())
        return CWallet::GetDebit(tx, filter);

    CAmount nDebit = 0;
    for (const auto &txin : tx.vin) {
        nDebit += GetDebit(txin, filter);
        if (!MoneyRange(nDebit)) {
            throw std::runtime_error(std::string(__func__) + ": value out of range");
        }
    }
    return nDebit;
};

CAmount CHDWallet::GetDebit(const CTransactionRecord &rtx, const isminefilter& filter) const
{
    CAmount nDebit = 0;

    LOCK(cs_wallet);

    for (const auto &prevout : rtx.vin) {
        MapWallet_t::const_iterator mi = mapWallet.find(prevout.hash);
        MapRecords_t::const_iterator mri;
        if (mi != mapWallet.end()) {
            const CWalletTx &prev = mi->second;
            if (prevout.n < prev.tx->vpout.size())
                if (IsMine(prev.tx->vpout[prevout.n].get()) & filter)
                    nDebit += prev.tx->vpout[prevout.n]->GetValue();
        } else
        if ((mri = mapRecords.find(prevout.hash)) != mapRecords.end()) {
            const COutputRecord *oR = mri->second.GetOutput(prevout.n);

            if (oR &&
                (filter & ISMINE_SPENDABLE) &&
                (oR->nFlags & ORF_OWNED)) {
                 nDebit += oR->nValue;
            }
        }
    }

    return nDebit;
};

bool CHDWallet::IsAllFromMe(const CTransaction& tx, const isminefilter& filter) const
{
    LOCK(cs_wallet);

    for (const CTxIn& txin : tx.vin)
    {
        auto mi = mapWallet.find(txin.prevout.hash);
        if (mi != mapWallet.end())
        {
            const CWalletTx& prev = (*mi).second;

            if (txin.prevout.n >= prev.tx->GetNumVOuts())
                return false; // invalid input!

            if (!(IsMine(prev.tx->vpout[txin.prevout.n].get()) & filter))
                return false;
            continue;
        }

        auto mri = mapRecords.find(txin.prevout.hash);
        if (mri != mapRecords.end()) {
            const COutputRecord *oR = mri->second.GetOutput(txin.prevout.n);
            if (!oR) {
                return false;
            }
            if ((filter & ISMINE_SPENDABLE)
                && (oR->nFlags & ORF_OWNED)) {
                continue;
            }
            /* TODO
            if ((filter & ISMINE_WATCH_ONLY)
                && (oR->nFlags & ORF_WATCH_ONLY))
                return oR->nValue;
            */
        }
        return false; // any unknown inputs can't be from us
    }
    return true;
};

CAmount CHDWallet::GetCredit(const CTxOutBase *txout, const isminefilter &filter) const
{
    if (!txout->IsStandardOutput()) {
        return 0;
    }
    CAmount value = txout->GetValue();
    if (!MoneyRange(value)) {
        throw std::runtime_error(std::string(__func__) + ": value out of range");
    }
    return ((IsMine(txout) & filter) ? value : 0);
}

CAmount CHDWallet::GetCredit(const CTransaction &tx, const isminefilter &filter) const
{
    CAmount nCredit = 0;

    for (const auto &txout : tx.vpout) {
        nCredit += GetCredit(txout.get(), filter);
        if (!MoneyRange(nCredit)) {
            throw std::runtime_error(std::string(__func__) + ": value out of range");
        }
    }
    return nCredit;
};

void CHDWallet::GetCredit(const CTransaction &tx, CAmount &nSpendable, CAmount &nWatchOnly) const
{
    LOCK(cs_wallet);
    nSpendable = 0;
    nWatchOnly = 0;
    for (const auto &txout : tx.vpout) {
        if (!txout->IsType(OUTPUT_STANDARD)) {
            continue;
        }

        isminetype ismine = IsMine(txout.get());

        if (ismine & ISMINE_SPENDABLE) {
            nSpendable += txout->GetValue();
        }
        if (ismine & ISMINE_WATCH_ONLY) {
            nWatchOnly += txout->GetValue();
        }
    }

    if (!MoneyRange(nSpendable)) {
        throw std::runtime_error(std::string(__func__) + ": value out of range");
    }
    if (!MoneyRange(nWatchOnly)) {
        throw std::runtime_error(std::string(__func__) + ": value out of range");
    }
    return;
};

CAmount CHDWallet::GetOutputValue(const COutPoint &op, bool fAllowTXIndex) const
{
    MapWallet_t::const_iterator itw;
    MapRecords_t::const_iterator itr;
    if ((itw = mapWallet.find(op.hash)) != mapWallet.end()) {
        const CWalletTx *pcoin = &itw->second;
        if (pcoin->tx->GetNumVOuts() > op.n) {
            return pcoin->tx->vpout[op.n]->GetValue();
        }
        return 0;
    }

    if ((itr = mapRecords.find(op.hash)) != mapRecords.end()) {
        const COutputRecord *rec = itr->second.GetOutput(op.n);
        if (rec) {
            return rec->nValue;
        }
        CStoredTransaction stx;
        if (!CHDWalletDB(*m_database).ReadStoredTx(op.hash, stx)) { // TODO: cache / use mapTempWallet
            WalletLogPrintf("%s: ReadStoredTx failed for %s.\n", __func__, op.hash.ToString());
            return 0;
        }
        if (stx.tx->GetNumVOuts() > op.n) {
            return stx.tx->vpout[op.n]->GetValue();
        }
        return 0;
    }

    uint256 hash_block;
    const CTransactionRef txOut = ::GetTransaction(nullptr, nullptr, op.hash, Params().GetConsensus(), hash_block);
    if (txOut) {
        if (txOut->GetNumVOuts() > op.n) {
            return txOut->vpout[op.n]->GetValue();
        }
        return 0;
    }

    return 0;
};

CAmount CHDWallet::GetOwnedOutputValue(const COutPoint &op, isminefilter filter) const
{
    MapWallet_t::const_iterator itw;
    MapRecords_t::const_iterator itr;
    if ((itw = mapWallet.find(op.hash)) != mapWallet.end()) {
        const CWalletTx *pcoin = &itw->second;
        if (pcoin->tx->GetNumVOuts() > op.n
            && IsMine(pcoin->tx->vpout[op.n].get()) & filter) {
            return pcoin->tx->vpout[op.n]->GetValue();
        }
        return 0;
    }

    if ((itr = mapRecords.find(op.hash)) != mapRecords.end()) {
        const COutputRecord *rec = itr->second.GetOutput(op.n);
        if (!rec) {
            return 0;
        }
        if ((filter & ISMINE_SPENDABLE && rec->nFlags & ORF_OWNED)
            || (filter & ISMINE_WATCH_ONLY && rec->nFlags & ORF_OWN_WATCH)) {
            return rec->nValue;
        }
        return 0;
    }

    return 0;
};

bool CHDWallet::InMempool(const uint256 &hash) const
{
    if (!HaveChain()) {
        return false;
    }
    return chain().transactionInMempool(hash);
};

bool hashUnset(const uint256 &hash)
{
    return (hash.IsNull() || hash == ABANDON_HASH);
}

int CHDWallet::GetDepthInMainChain(const CTransactionRecord &rtx) const
{
    if (hashUnset(rtx.blockHash)) {
        return 0;
    }

    return (GetLastBlockHeight() - rtx.block_height + 1) * (rtx.isConflicted() ? -1 : 1);
};

bool CHDWallet::IsTrusted(const uint256 &txhash, const CTransactionRecord &rtx, int *depth_out) const
{
    //if (!CheckFinalTx(*this))
    //    return false;
    //if (tx->IsCoinStake() && hashUnset()) // ignore failed stakes
    //    return false;
    int nDepth = GetDepthInMainChain(rtx);
    if (depth_out) *depth_out = nDepth;
    if (nDepth >= 1)
        return true;
    if (nDepth < 0)
        return false;
    //if (!m_spend_zero_conf_change || !IsFromMe(ISMINE_ALL)) // using wtx's cached debit
    //    return false;

    // Don't trust unconfirmed transactions from us unless they are in the mempool.
    CTransactionRef ptx = chain().transactionFromMempool(txhash);
    if (!ptx)
        return false;

    // Trusted if all inputs are from us and are in the mempool:
    for (const auto &txin : ptx->vin) {
        if (txin.IsAnonInput()) {
            if (ptx->vin.size() == rtx.vin.size()) { // All inputs are from wallet, rtx.vin is mapped
                return true;
            }
            return false;
        }
        // Transactions not sent by us: not trusted
        MapRecords_t::const_iterator rit = mapRecords.find(txin.prevout.hash);
        if (rit != mapRecords.end()) {
            const COutputRecord *oR = rit->second.GetOutput(txin.prevout.n);

            if (!oR
                || !(oR->nFlags & ORF_OWNED)) {
                return false;
            }
            continue;
        }
        const CWalletTx *parent = GetWalletTx(txin.prevout.hash);
        if (parent == nullptr) {
            return false;
        }
        const CTxOutBase *parentOut = parent->tx->vpout[txin.prevout.n].get();
        if (IsMine(parentOut) != ISMINE_SPENDABLE) {
            return false;
        }
    }

    return true;
};

CAmount CHDWallet::GetSpendableBalance() const
{
    // Returns a value to be compared against reservebalance, includes stakeable watch-only balance.
    if (m_have_spendable_balance_cached) {
        return m_spendable_balance_cached;
    }

    CAmount nBalance = 0;

    LOCK(cs_wallet);

    for (const auto &ri : mapRecords) {
        const auto &txhash = ri.first;
        const auto &rtx = ri.second;
        if (!IsTrusted(txhash, rtx)) {
            continue;
        }

        for (const auto &r : rtx.vout) {
            if (r.nType == OUTPUT_STANDARD &&
                (r.nFlags & ORF_OWNED || r.nFlags & ORF_STAKEONLY) &&
                 !IsSpent(txhash, r.n)) {
                nBalance += r.nValue;
            }
        }

        if (!MoneyRange(nBalance)) {
            throw std::runtime_error(std::string(__func__) + ": value out of range");
        }
    }

    for (const auto &walletEntry : mapWallet) {
        const auto &wtx = walletEntry.second;
        if (!wtx.IsTrusted()) {
            continue;
        }
        nBalance += wtx.GetAvailableCredit();
        if (wtx.GetAvailableCredit(true, ISMINE_WATCH_ONLY) > 0) {
            for (unsigned int i = 0; i < wtx.tx->GetNumVOuts(); i++) {
                if (!IsSpent(wtx.GetHash(), i)) {
                    nBalance += GetCredit(wtx.tx->vpout[i].get(), ISMINE_WATCH_COLDSTAKE);
                    if (!MoneyRange(nBalance))
                        throw std::runtime_error(std::string(__func__) + ": value out of range");
                }
            }
        }
    }

    m_spendable_balance_cached = nBalance;
    m_have_spendable_balance_cached = true;

    return m_spendable_balance_cached;
};

CAmount CHDWallet::GetBlindBalance()
{
    CAmount nBalance = 0;

    LOCK(cs_wallet);

    for (const auto &ri : mapRecords) {
        const auto &txhash = ri.first;
        const auto &rtx = ri.second;

        if (!IsTrusted(txhash, rtx)) {
            continue;
        }

        for (const auto &r : rtx.vout) {
            if (r.nType == OUTPUT_CT
                && r.nFlags & ORF_OWNED && !IsSpent(txhash, r.n)) {
                nBalance += r.nValue;
            }
        }

        if (!MoneyRange(nBalance)) {
            throw std::runtime_error(std::string(__func__) + ": value out of range");
        }
    }

    return nBalance;
};

CAmount CHDWallet::GetAnonBalance()
{
    CAmount nBalance = 0;

    LOCK(cs_wallet);

    for (const auto &ri : mapRecords) {
        const auto &txhash = ri.first;
        const auto &rtx = ri.second;

        if (!IsTrusted(txhash, rtx)) {
            continue;
        }

        for (const auto &r : rtx.vout) {
            if (r.nType == OUTPUT_RINGCT
                && r.nFlags & ORF_OWNED && !IsSpent(txhash, r.n)) {
                nBalance += r.nValue;
            }
        }

        if (!MoneyRange(nBalance)) {
            throw std::runtime_error(std::string(__func__) + ": value out of range");
        }
    }

    return nBalance;
};

/**
 * total coins staked (non-spendable until maturity)
 */
CAmount CHDWallet::GetStaked()
{
    int64_t nTotal = 0;

    LOCK(cs_wallet);

    for (const auto &item : mapWallet) {
        const CWalletTx &wtx = item.second;

        if (wtx.IsCoinStake()
            && wtx.GetDepthInMainChain() > 0 // checks for hashunset
            && wtx.GetBlocksToMaturity() > 0) {
            nTotal += CHDWallet::GetCredit(*wtx.tx, ISMINE_SPENDABLE);
        }
    }
    return nTotal;
};

CWallet::Balance CHDWallet::GetBalance(const int min_depth, bool avoid_reuse) const
{
    CWallet::Balance bal_records;
    LOCK(cs_wallet);

    bool allow_used_addresses = avoid_reuse || !IsWalletFlagSet(WALLET_FLAG_AVOID_REUSE);
    for (const auto &ri : mapRecords) {
        const auto &txhash = ri.first;
        const auto &rtx = ri.second;

        bool is_trusted = IsTrusted(txhash, rtx);
        int tx_depth = GetDepthInMainChain(rtx);
        for (const auto &r : rtx.vout) {
            if (r.nType != OUTPUT_STANDARD
                || IsSpent(txhash, r.n)
                || (!allow_used_addresses && IsSpentKey(&r.scriptPubKey))) {
                continue;
            }
            if (is_trusted && tx_depth >= min_depth) {
                if (r.nFlags & ORF_OWNED) {
                    bal_records.m_mine_trusted += r.nValue;
                }
                if (r.nFlags & ORF_OWN_WATCH) {
                    bal_records.m_watchonly_trusted += r.nValue;
                }
            }
            if (!is_trusted && tx_depth == 0) {
                CTransactionRef ptx = nullptr;
                if (HaveChain()) {
                    ptx = chain().transactionFromMempool(txhash);
                }
                if (!ptx) {
                    continue;
                }
                if (r.nFlags & ORF_OWNED) {
                    bal_records.m_mine_untrusted_pending += r.nValue;
                }
                if (r.nFlags & ORF_OWN_WATCH) {
                    bal_records.m_watchonly_untrusted_pending += r.nValue;
                }
            }
        }
    }

    Balance ret = CWallet::GetBalance(min_depth, avoid_reuse);

    ret.m_mine_trusted += bal_records.m_mine_trusted;
    ret.m_watchonly_trusted += bal_records.m_watchonly_trusted;
    ret.m_mine_untrusted_pending += bal_records.m_mine_untrusted_pending;
    ret.m_watchonly_untrusted_pending += bal_records.m_watchonly_untrusted_pending;

    return ret;
}

bool CHDWallet::GetBalances(CHDWalletBalances &bal, bool avoid_reuse) const
{
    bal = CHDWalletBalances();

    isminefilter reuse_filter = avoid_reuse ? 0 : ISMINE_USED;

    bool allow_used_addresses = !IsWalletFlagSet(WALLET_FLAG_AVOID_REUSE) || (!avoid_reuse);

    LOCK(cs_wallet);

    for (const auto &item : mapWallet) {
        const CWalletTx &wtx = item.second;

        bal.nPartImmature += wtx.GetImmatureCredit();
        //bal.nPartWatchOnlyImmature += wtx.GetImmatureWatchOnlyCredit(*locked_chain);

        int depth;
        if (wtx.IsCoinStake() &&
            (depth = wtx.GetDepthInMainChain()) > 0 && // checks for hashunset
             wtx.GetBlocksToMaturity() > 0) {
            CAmount nSpendable, nWatchOnly;
            CHDWallet::GetCredit(*wtx.tx, nSpendable, nWatchOnly);
            bal.nPartStaked += nSpendable;
            bal.nPartWatchOnlyStaked += nWatchOnly;
        }

        if (wtx.IsTrusted()) {
            bal.nPart += wtx.GetAvailableCredit(true, ISMINE_SPENDABLE | reuse_filter);
            bal.nPartWatchOnly += wtx.GetAvailableCredit(true, ISMINE_WATCH_ONLY | reuse_filter);
        } else if (wtx.GetDepthInMainChain() == 0 && wtx.InMempool()) {
            bal.nPartUnconf += wtx.GetAvailableCredit(true, ISMINE_SPENDABLE | reuse_filter);
            bal.nPartWatchOnlyUnconf += wtx.GetAvailableCredit(true, ISMINE_WATCH_ONLY | reuse_filter);
        }
    }

    const Consensus::Params &consensusParams = Params().GetConsensus();
    for (const auto &ri : mapRecords) {
        const auto &txhash = ri.first;
        const auto &rtx = ri.second;

        int depth;
        bool fTrusted = IsTrusted(txhash, rtx, &depth);
        bool fInMempool = false;
        if (!fTrusted) {
            CTransactionRef ptx = nullptr;
            if (HaveChain()) {
                ptx = chain().transactionFromMempool(txhash);
            }
            fInMempool = !ptx ? false : true;
        }

        for (const auto &r : rtx.vout) {
            if (!(r.nFlags & ORF_OWN_ANY)
                || IsSpent(txhash, r.n)) {
                continue;
            }
            bool watch_only = r.nFlags & ORF_OWN_WATCH;
            bool force_watch_only = false;
#if !ENABLE_USBDEVICE
            bool fNeedHardwareKey = (r.nFlags & ORF_HARDWARE_DEVICE);
            if (fNeedHardwareKey) {
                watch_only = true;
                force_watch_only = true;
            }
#endif
            switch (r.nType) {
                case OUTPUT_RINGCT:
                    if (!(r.nFlags & ORF_OWNED || r.nFlags & ORF_OWN_WATCH)) {
                        continue;
                    }
                    if (fTrusted) {
                        if (depth >= consensusParams.nMinRCTOutputDepth) {
                            if (watch_only) {
                                bal.nAnonWatchOnly += r.nValue;
                            } else {
                                bal.nAnon += r.nValue;
                            }
                        } else {
                            if (watch_only) {
                                bal.nAnonWatchOnlyImmature += r.nValue;
                            } else {
                                bal.nAnonImmature += r.nValue;
                            }
                        }
                    } else
                    if (fInMempool) {
                        if (watch_only) {
                            bal.nAnonWatchOnlyUnconf += r.nValue;
                        } else {
                            bal.nAnonUnconf += r.nValue;
                        }
                    }
                    break;
                case OUTPUT_CT:
                    if (!(r.nFlags & ORF_OWNED || r.nFlags & ORF_OWN_WATCH)) {
                        continue;
                    }
                    if (!allow_used_addresses && IsSpentKey(&r.scriptPubKey)) {
                        continue;
                    }
                    if (fTrusted) {
                        if (watch_only) {
                            bal.nBlindWatchOnly += r.nValue;
                        } else {
                            bal.nBlind += r.nValue;
                        }
                    } else
                    if (fInMempool) {
                        if (watch_only) {
                            bal.nBlindWatchOnlyUnconf += r.nValue;
                        } else {
                            bal.nBlindUnconf += r.nValue;
                        }
                    }
                    break;
                case OUTPUT_STANDARD:
                    if (!force_watch_only && (r.nFlags & ORF_OWNED)) {
                        if (!allow_used_addresses && IsSpentKey(&r.scriptPubKey)) {
                            continue;
                        }
                        if (fTrusted) {
                            bal.nPart += r.nValue;
                        } else
                        if (fInMempool) {
                            bal.nPartUnconf += r.nValue;
                        }
                    } else
                    if (watch_only) {
                        if (fTrusted) {
                            bal.nPartWatchOnly += r.nValue;
                        } else
                        if (fInMempool) {
                            bal.nPartWatchOnlyUnconf += r.nValue;
                        }
                    }
                    break;
                default:
                    break;
            }
        }
    }
    //if (!MoneyRange(nBalance))
    //    throw std::runtime_error(std::string(__func__) + ": value out of range");

    return true;
};

CAmount CHDWallet::GetAvailableBalance(const CCoinControl* coinControl) const
{
    LOCK(cs_wallet);

    CAmount balance = 0;
    std::vector<COutput> vCoins;
    AvailableCoins(vCoins, coinControl);
    for (const COutput& out : vCoins) {
        if (out.fSpendable) {
            balance += out.tx->tx->vpout[out.i]->GetValue();
        }
    }
    return balance;
}

CAmount CHDWallet::GetAvailableAnonBalance(const CCoinControl* coinControl) const
{
    LOCK(cs_wallet);

    CAmount balance = 0;
    std::vector<COutputR> vCoins;
    AvailableAnonCoins(vCoins, coinControl);
    for (const COutputR &out : vCoins) {
        if (out.fSpendable) {
            const COutputRecord *oR = out.rtx->second.GetOutput(out.i);
            if (!oR)
                continue;
            balance += oR->nValue;
        }
    }
    return balance;
}

CAmount CHDWallet::GetAvailableBlindBalance(const CCoinControl* coinControl) const
{
    LOCK(cs_wallet);

    CAmount balance = 0;
    std::vector<COutputR> vCoins;
    AvailableBlindedCoins(vCoins, coinControl);
    for (const COutputR &out : vCoins) {
        if (out.fSpendable) {
            const COutputRecord *oR = out.rtx->second.GetOutput(out.i);
            if (!oR) {
                continue;
            }
            balance += oR->nValue;
        }
    }
    return balance;
}

bool CHDWallet::IsChange(const CTxOutBase *txout) const
{
    const CScript *ps = txout->GetPScriptPubKey();
    if (!ps) {
        return false;
    }
    const CScript &scriptPubKey = *ps;

    LOCK(cs_wallet);

    CKeyID idk;
    const CEKAKey *pak = nullptr;
    const CEKASCKey *pasc = nullptr;
    CExtKeyAccount *pa = nullptr;
    bool isInvalid = false;
    isminetype mine = IsMine(scriptPubKey, idk, pak, pasc, pa, isInvalid);
    if (!mine) {
        return false;
    }

    // Change is sent to the internal change
    if (pa && pak && pa->nActiveInternal == pak->nParent) { // TODO: check EKVT_KEY_TYPE
        return true;
    }
    /*
    CTxDestination address;
    if (!ExtractDestination(scriptPubKey, address))
        return true;

    LOCK(cs_wallet);
    if (!mapAddressBook.count(address))
        return true;
    */

    return false;
};

bool CHDWallet::GetChangePath(const CScript &script_pubkey, std::vector<uint32_t> &change_path) const
{
    CKeyID idk;
    const CEKAKey *pak = nullptr;
    const CEKASCKey *pasc = nullptr;
    CExtKeyAccount *pa = nullptr;
    bool isInvalid = false;
    isminetype mine = IsMine(script_pubkey, idk, pak, pasc, pa, isInvalid);
    if (!mine) {
        return false;
    }

    // Change is sent to the internal change
    if (pa && pak && pa->nActiveInternal == pak->nParent) { // TODO: check EKVT_KEY_TYPE
        CStoredExtKey *sekAccount = pa->ChainAccount();
        CStoredExtKey *sek = pa->GetChain(pak->nParent);
        AppendPath(sekAccount, change_path);
        AppendChainPath(sek, change_path);
        change_path.push_back(pak->nKey);
        return true;
    }

    return false;
}

int CHDWallet::GetChangeAddress(CPubKey &pk)
{
    ExtKeyAccountMap::iterator mi = mapExtAccounts.find(idDefaultAccount);
    if (mi == mapExtAccounts.end()) {
        return werrorN(1, "%s Unknown account.", __func__);
    }

    // Return a key from the lookahead of the internal chain
    // Don't promote the key to the main map, that will happen when the transaction is processed.

    CStoredExtKey *pc;
    if ((pc = mi->second->ChainInternal()) == nullptr) {
        return werrorN(1, "%s Unknown chain.", __func__);
    }

    // Alternative: take 1st key of keypool
    for (size_t k = 0; k < 1000; ++k) {
        uint32_t nChild;
        if (0 != pc->DeriveNextKey(pk, nChild, false, false)) {
            return werrorN(1, "%s TryDeriveNext failed.", __func__);
        }

        CKeyID idk = pk.GetID();
        if (mi->second->HaveSavedKey(idk)) {
            if (LogAcceptCategory(BCLog::HDWALLET)) {
                WalletLogPrintf("%s: Skipping used address %s.\n", __func__, EncodeDestination(PKHash(idk)));
            }
            pc->nGenerated++;
        }
    }

    if (LogAcceptCategory(BCLog::HDWALLET)) {
        WalletLogPrintf("Change Address: %s\n", EncodeDestination(PKHash(pk.GetID())));
    }

    return 0;
};

void CHDWallet::ParseAddressForMetaData(const CTxDestination &addr, COutputRecord &rec)
{
    if (addr.index() == DI::_CStealthAddress) {
        CStealthAddress sx = std::get<CStealthAddress>(addr);

        CStealthAddressIndexed sxi;
        sx.ToRaw(sxi.addrRaw);
        uint32_t sxId;
        if (GetStealthKeyIndex(sxi, sxId)) {
            rec.vPath.resize(5);
            rec.vPath[0] = ORA_STEALTH;
            memcpy(&rec.vPath[1], &sxId, 4);
        }
    } else
    if (addr.index() == DI::_CExtPubKey) {
        /*
        CExtPubKey ek = boost::get<CExtPubKey>(addr);
        rec.vPath.resize(21);
        rec.vPath[0] = ORA_EXTKEY;
        CKeyID eid = ek.GetID()();
        memcpy(&rec.vPath[1], eid.begin(), 20)
        */
    } else
    if (addr.index() == DI::_PKHash) {
        //ORA_STANDARD
    }
    return;
};

void CHDWallet::AddOutputRecordMetaData(CTransactionRecord &rtx, std::vector<CTempRecipient> &vecSend)
{
    for (const auto &r : vecSend) {
        if (r.nType == OUTPUT_STANDARD) {
            COutputRecord rec;

            rec.n = r.n;
            if (r.fChange && HaveAddress(r.address)) {
                rec.nFlags |= ORF_CHANGE;
            }
            rec.nType = r.nType;
            rec.nValue = r.nAmount;
            rec.sNarration = r.sNarration;
            rec.scriptPubKey = r.scriptPubKey;
            rtx.InsertOutput(rec);
        } else
        if (r.nType == OUTPUT_CT) {
            COutputRecord rec;

            rec.n = r.n;
            rec.nType = r.nType;
            rec.nValue = r.nAmount;
            rec.nFlags |= ORF_FROM;
            rec.scriptPubKey = r.scriptPubKey;
            if (r.fChange && HaveAddress(r.address)) {
                rec.nFlags |= ORF_CHANGE;
            }
            rec.sNarration = r.sNarration;

            ParseAddressForMetaData(r.address, rec);

            rtx.InsertOutput(rec);
        } else
        if (r.nType == OUTPUT_RINGCT) {
            COutputRecord rec;

            rec.n = r.n;
            rec.nType = r.nType;
            rec.nValue = r.nAmount;
            rec.nFlags |= ORF_FROM;
            if (r.fChange && HaveAddress(r.address)) {
                rec.nFlags |= ORF_CHANGE;
            }
            rec.sNarration = r.sNarration;

            ParseAddressForMetaData(r.address, rec);

            rtx.InsertOutput(rec);
        }
    }

    return;
};

int CHDWallet::ExpandTempRecipients(std::vector<CTempRecipient> &vecSend, CStoredExtKey *pc, std::string &sError)
{
    LOCK(cs_wallet);
    for (size_t i = 0; i < vecSend.size(); ++i) {
        CTempRecipient &r = vecSend[i];

        if (r.nType == OUTPUT_STANDARD) {
            std::vector<CTempRecipient> insert_vec;
            if (r.address.index() == DI::_CStealthAddress) {
                CStealthAddress sx = std::get<CStealthAddress>(r.address);

                CKey sShared;
                ec_point pkSendTo;

                int k, nTries = 24;
                for (k = 0; k < nTries; ++k) { // if StealthSecret fails try again with new ephem key
                    r.sEphem.MakeNewKey(true);
                    if (StealthSecret(r.sEphem, sx.scan_pubkey, sx.spend_pubkey, sShared, pkSendTo) == 0) {
                        break;
                    }
                }
                if (k >= nTries) {
                    return wserrorN(1, sError, __func__, "Could not generate receiving public key.");
                }

                CPubKey pkEphem = r.sEphem.GetPubKey();
                r.pkTo = CPubKey(pkSendTo);
                CTxDestination dTo;
                if (IsValidDestination(r.addressColdStaking)) {
                    dTo = r.pkTo.GetID256();
                } else {
                    dTo = PKHash(r.pkTo);
                }
                r.scriptPubKey = GetScriptForDestination(dTo);
                if (LogAcceptCategory(BCLog::HDWALLET)) {
                    WalletLogPrintf("Stealth send to generated address: %s\n", EncodeDestination(dTo));
                }

                CTempRecipient rd;
                rd.nType = OUTPUT_DATA;
                if (0 != MakeStealthData(r.sNarration, sx.prefix, sShared, pkEphem, rd.vData, r.nStealthPrefix, sError)) {
                    return 1; // sError is set
                }
                insert_vec.push_back(rd);
            } else {
                if (r.address.index() == DI::_CExtPubKey) {
                    CExtKeyPair ek = CExtKeyPair(std::get<CExtPubKey>(r.address));
                    CPubKey pkDest;
                    uint32_t nChildKey;
                    if (0 != ExtKeyGetDestination(ek, pkDest, nChildKey)) {
                        return wserrorN(1, sError, __func__, "ExtKeyGetDestination failed.");
                    }

                    r.nChildKey = nChildKey;
                    r.pkTo = pkDest;
                    if (IsValidDestination(r.addressColdStaking)) {
                        r.scriptPubKey = GetScriptForDestination(r.pkTo.GetID256());
                    } else {
                        r.scriptPubKey = GetScriptForDestination(PKHash(r.pkTo));
                    }
                } else
                if (r.address.index() == DI::_PKHash) {
                    if (IsValidDestination(r.addressColdStaking)) {
                        return wserrorN(1, sError, __func__, "p2pkh is invalid in coldstakingscript.");
                    }
                    r.scriptPubKey = GetScriptForDestination(r.address);
                } else {
                    if (!r.fScriptSet) {
                        r.scriptPubKey = GetScriptForDestination(r.address);
                        if (r.scriptPubKey.size() < 1) {
                            return wserrorN(1, sError, __func__, "Unknown address type and no script set.");
                        }
                    }
                }
                if (r.sNarration.length() > 0) {
                    CTempRecipient rd;
                    rd.nType = OUTPUT_DATA;
                    rd.vData.push_back(DO_NARR_PLAIN);
                    std::copy(r.sNarration.begin(), r.sNarration.end(), std::back_inserter(rd.vData));
                    insert_vec.push_back(rd);
                }
            }

            if (IsValidDestination(r.addressColdStaking)) {
                CScript scriptTrue, scriptFalse = r.scriptPubKey;

                uint32_t nkey = 0;
                GetScriptForDest(scriptTrue, r.addressColdStaking, false, &r.vData, &nkey);
                r.nChildKeyColdStaking = nkey;

                if (scriptTrue.size() == 0) {
                    return wserrorN(1, sError, __func__, "Invalid stake destination.");
                }
                if (scriptFalse.size() == 0) {
                    return wserrorN(1, sError, __func__, "Invalid spend destination.");
                }

                r.scriptPubKey = CScript() << OP_ISCOINSTAKE << OP_IF;
                r.scriptPubKey.append(scriptTrue);
                r.scriptPubKey << OP_ELSE;
                r.scriptPubKey.append(scriptFalse);
                r.scriptPubKey << OP_ENDIF;
                r.fScriptSet = true;
            }
            // NOTE: r is unusable after vecSend is modified!
            if (insert_vec.size() > 0) {
                vecSend.insert(vecSend.begin() + (i + 1), insert_vec.begin(), insert_vec.end());
                i += insert_vec.size(); // skip over inserted outputs
            }
        } else
        if (r.nType == OUTPUT_CT) {
            CKey sEphem = r.sEphem;

            /*
            // TODO: Make optional
            if (0 != pc->DeriveNextKey(sEphem, nChild, true))
                return errorN(1, sError, __func__, "TryDeriveNext failed.");
            */
            if (!sEphem.IsValid()) {
                sEphem.MakeNewKey(true);
            }

            if (r.address.index() == DI::_CStealthAddress) {
                CStealthAddress sx = std::get<CStealthAddress>(r.address);

                CKey sShared;
                ec_point pkSendTo;

                int k, nTries = 24;
                for (k = 0; k < nTries; ++k) {
                    if (StealthSecret(sEphem, sx.scan_pubkey, sx.spend_pubkey, sShared, pkSendTo) == 0) {
                        break;
                    }
                    // if StealthSecret fails try again with new ephem key
                    /* TODO: Make optional
                    if (0 != pc->DeriveNextKey(sEphem, nChild, true))
                        return errorN(1, sError, __func__, "DeriveNextKey failed.");
                    */
                    sEphem.MakeNewKey(true);
                }
                if (k >= nTries) {
                    return wserrorN(1, sError, __func__, "Could not generate receiving public key.");
                }

                r.pkTo = CPubKey(pkSendTo);
                PKHash pkhash = PKHash(r.pkTo);

                r.scriptPubKey = GetScriptForDestination(pkhash);
                if (sx.prefix.number_bits > 0) {
                    r.nStealthPrefix = FillStealthPrefix(sx.prefix.number_bits, sx.prefix.bitfield);
                }

                if (LogAcceptCategory(BCLog::HDWALLET)) {
                    WalletLogPrintf("Creating blind output to stealth generated address: %s\n", EncodeDestination(pkhash));
                }
            } else
            if (r.address.index() == DI::_CExtPubKey) {
                CExtKeyPair ek = CExtKeyPair(std::get<CExtPubKey>(r.address));
                uint32_t nDestChildKey;
                if (0 != ExtKeyGetDestination(ek, r.pkTo, nDestChildKey)) {
                    return wserrorN(1, sError, __func__, "ExtKeyGetDestination failed.");
                }

                r.nChildKey = nDestChildKey;
                r.scriptPubKey = GetScriptForDestination(PKHash(r.pkTo));
            } else
            if (r.address.index() == DI::_PKHash) {
                // Need a matching public key
                PKHash pkhash = std::get<PKHash>(r.address);
                CKeyID idTo = ToKeyID(pkhash);
                r.scriptPubKey = GetScriptForDestination(PKHash(idTo));

                if (!r.pkTo.IsValid() && !GetPubKey(idTo, r.pkTo)) {
                    return wserrorN(1, sError, __func__, "No public key found for address %s.", EncodeDestination(r.address));
                }
                if (r.pkTo.GetID() != idTo) {
                    return wserrorN(1, sError, __func__, "Mismatched pubkey for address %s.", EncodeDestination(r.address));
                }
            } else
            if (r.address.index() == DI::_CKeyID256) {
                r.scriptPubKey = GetScriptForDestination(r.address);

                // Need a matching public key
                CKeyID256 id256 = std::get<CKeyID256>(r.address);
                CKeyID idTo(id256);
                if (!r.pkTo.IsValid() && !GetPubKey(idTo, r.pkTo)) {
                    return wserrorN(1, sError, __func__, "No public key found for address %s.", EncodeDestination(r.address));
                }
                if (r.pkTo.GetID() != idTo) {
                    return wserrorN(1, sError, __func__, "Mismatched pubkey for address %s.", EncodeDestination(r.address));
                }
            } else {
                if (!r.fScriptSet) {
                    r.scriptPubKey = GetScriptForDestination(r.address);
                    if (r.scriptPubKey.size() < 1) {
                        return wserrorN(1, sError, __func__, "Unknown address type and no script set.");
                    }
                }
            }

            r.sEphem = sEphem;
        } else
        if (r.nType == OUTPUT_RINGCT) {
            CKey sEphem = r.sEphem;
            /*
            // TODO: Make optional
            if (0 != pc->DeriveNextKey(sEphem, nChild, true))
                return errorN(1, sError, __func__, "TryDeriveNext failed.");
            */
            if (!sEphem.IsValid()) {
                sEphem.MakeNewKey(true);
            }

            if (r.pkTo.IsValid() && r.vData.size() >= 33 && r.fNonceSet) {
                // Output set from fundrawtransactionfrom
            } else
            if (r.address.index() == DI::_CStealthAddress) {
                CStealthAddress sx = std::get<CStealthAddress>(r.address);

                CKey sShared;
                ec_point pkSendTo;
                int k, nTries = 24;
                for (k = 0; k < nTries; ++k) {
                    if (StealthSecret(sEphem, sx.scan_pubkey, sx.spend_pubkey, sShared, pkSendTo) == 0) {
                        break;
                    }
                    // if StealthSecret fails try again with new ephem key
                    /* TODO: Make optional
                    if (0 != pc->DeriveNextKey(sEphem, nChild, true))
                        return errorN(1, sError, __func__, "DeriveNextKey failed.");
                    */
                    sEphem.MakeNewKey(true);
                }
                if (k >= nTries) {
                    return wserrorN(1, sError, __func__, "Could not generate receiving public key.");
                }

                r.pkTo = CPubKey(pkSendTo);
                CKeyID idTo = r.pkTo.GetID();

                if (sx.prefix.number_bits > 0) {
                    r.nStealthPrefix = FillStealthPrefix(sx.prefix.number_bits, sx.prefix.bitfield);
                }

                if (LogAcceptCategory(BCLog::HDWALLET)) {
                    WalletLogPrintf("Creating anon output to stealth generated address: %s\n", EncodeDestination(PKHash(idTo)));
                }
            } else {
                return wserrorN(1, sError, __func__, "Only able to send to stealth address for now."); // TODO: add more types?
            }

            r.sEphem = sEphem;
        }
    }

    return 0;
};

int CHDWallet::AddCTData(const CCoinControl *coinControl, CTxOutBase *txout, CTempRecipient &r, std::string &sError)
{
    secp256k1_pedersen_commitment *pCommitment = txout->GetPCommitment();
    std::vector<uint8_t> *pvRangeproof = txout->GetPRangeproof();

    if (!pCommitment || !pvRangeproof) {
        return wserrorN(1, sError, __func__, "Unable to get CT pointers for output type %d", txout->GetType());
    }

    uint64_t nValue = r.nAmount;
    if (coinControl && coinControl->m_debug_exploit_anon > 0) {
        nValue += coinControl->m_debug_exploit_anon;
    }
    if (!secp256k1_pedersen_commit(secp256k1_ctx_blind,
        pCommitment, (uint8_t*)r.vBlind.data(),
        nValue, &secp256k1_generator_const_h, &secp256k1_generator_const_g)) {
        return wserrorN(1, sError, __func__, "secp256k1_pedersen_commit failed.");
    }

    uint256 nonce;
    if (r.fNonceSet) {
        nonce = r.nonce;
    } else {
        if (!r.sEphem.IsValid()) {
            return wserrorN(1, sError, __func__, "Invalid ephemeral key.");
        }
        if (!r.pkTo.IsValid()) {
            return wserrorN(1, sError, __func__, "Invalid recipient pubkey.");
        }
        if (coinControl->m_blind_watchonly_visible &&
            r.address.index() == DI::_CStealthAddress) {
            CStealthAddress sx = std::get<CStealthAddress>(r.address);
            uint256 tweak(uint256S("0x444"));
            CKey tweaked = r.sEphem.Add(tweak.begin());
            nonce = tweaked.ECDH(CPubKey(sx.scan_pubkey));
        } else {
            nonce = r.sEphem.ECDH(r.pkTo);
        }
        CSHA256().Write(nonce.begin(), 32).Finalize(nonce.begin());
        r.nonce = nonce;
    }
    size_t nRangeProofLen = 5134;
    pvRangeproof->resize(nRangeProofLen);

    if (GetTime() >= Params().GetConsensus().bulletproof_time) {
        const uint8_t *bp[1];
        bp[0] = r.vBlind.data();
        assert(r.vBlind.size() == 32);

        if (1 != secp256k1_bulletproof_rangeproof_prove(secp256k1_ctx_blind, m_blind_scratch, blind_gens,
            pvRangeproof->data(), &nRangeProofLen, &nValue, nullptr, bp, 1,
            &secp256k1_generator_const_h, 64, nonce.begin(), nullptr, 0)) {
            return wserrorN(1, sError, __func__, "secp256k1_bulletproof_rangeproof_prove failed.");
        }

        if (1 != secp256k1_bulletproof_rangeproof_verify(secp256k1_ctx_blind, m_blind_scratch, blind_gens,
            pvRangeproof->data(), nRangeProofLen, nullptr, pCommitment, 1, 64, &secp256k1_generator_const_h, nullptr, 0)) {
            return wserrorN(1, sError, __func__, "secp256k1_bulletproof_rangeproof_verify failed.");
        }

        if (r.sNarration.size() > 0) {
            std::vector<uint8_t> vchNarr, &vData = *txout->GetPData();
            CPubKey pkEphem = r.sEphem.GetPubKey();
            SecMsgCrypter crypter;
            crypter.SetKey(r.nonce.begin(), pkEphem.begin());

            if (!crypter.Encrypt((uint8_t*)r.sNarration.data(), r.sNarration.length(), vchNarr)) {
                return errorN(1, sError, __func__, "Narration encryption failed.");
            }
            if (vchNarr.size() > MAX_STEALTH_NARRATION_SIZE) {
                return errorN(1, sError, __func__, "Encrypted narration is too long.");
            }

            size_t o = vData.size();
            vData.resize(o + vchNarr.size() + 1);
            vData[o++] = DO_NARR_CRYPT;
            memcpy(&vData[o], vchNarr.data(), vchNarr.size());
        }
    } else {
        uint64_t min_value = 0;
        int ct_exponent = 2;
        int ct_bits = 32;

        const char *message = r.sNarration.c_str();
        size_t mlen = strlen(message);

        if (0 != SelectRangeProofParameters(nValue, min_value, ct_exponent, ct_bits)) {
            return wserrorN(1, sError, __func__, "SelectRangeProofParameters failed.");
        }

        if (r.fOverwriteRangeProofParams == true) {
            min_value = r.min_value;
            ct_exponent = r.ct_exponent;
            ct_bits = r.ct_bits;
        }

        if (1 != secp256k1_rangeproof_sign(secp256k1_ctx_blind,
            &(*pvRangeproof)[0], &nRangeProofLen,
            min_value, pCommitment,
            &r.vBlind[0], nonce.begin(),
            ct_exponent, ct_bits,
            nValue,
            (const unsigned char*) message, mlen,
            nullptr, 0,
            secp256k1_generator_h)) {
            return wserrorN(1, sError, __func__, "secp256k1_rangeproof_sign failed.");
        }
    }

    pvRangeproof->resize(nRangeProofLen);

    return 0;
};

int CHDWallet::PostProcessTempRecipients(std::vector<CTempRecipient> &vecSend)
{
    LOCK(cs_wallet);
    for (size_t i = 0; i < vecSend.size(); ++i) {
        CTempRecipient &r = vecSend[i];

        if (r.address.index() == DI::_CExtPubKey) {
            CExtKeyPair ek = CExtKeyPair(std::get<CExtPubKey>(r.address));
            r.nChildKey += 1;
            ExtKeyUpdateLooseKey(ek, r.nChildKey, true);
        }

        if (r.addressColdStaking.index() == DI::_CExtPubKey) {
            CExtKeyPair ek = CExtKeyPair(std::get<CExtPubKey>(r.addressColdStaking));
            r.nChildKeyColdStaking += 1;
            ExtKeyUpdateLooseKey(ek, r.nChildKeyColdStaking, false);
        }
    }

    ClearTxCreationState();
    return 0;
};

bool CheckOutputValue(interfaces::Chain& chain, const CTempRecipient &r, const CTxOutBase *txbout, CAmount nFeeRet, std::string &sError)
{
    if ((r.nType == OUTPUT_STANDARD
            && IsDust(txbout, chain.relayDustFee()))
        || (r.nType != OUTPUT_DATA
            && r.nAmount < 0)) {
        if (r.fSubtractFeeFromAmount && nFeeRet > 0) {
            if (r.nAmount < 0) {
                sError = "The transaction amount is too small to pay the fee";
            } else {
                sError = "The transaction amount is too small to send after the fee has been deducted";
            }
        } else {
            sError = "Transaction amount too small";
        }
        LogPrintf("%s: Failed %s.\n", __func__, sError);
        return false;
    }
    return true;
};

void InspectOutputs(std::vector<CTempRecipient> &vecSend,
    CAmount &nValue, size_t &nSubtractFeeFromAmount, bool &fOnlyStandardOutputs)
{
    nValue = 0;
    nSubtractFeeFromAmount = 0;
    fOnlyStandardOutputs = true;

    for (auto &r : vecSend) {
        nValue += r.nAmount;
        if (r.nType != OUTPUT_STANDARD && r.nType != OUTPUT_DATA) {
            fOnlyStandardOutputs = false;
        }

        if (r.fSubtractFeeFromAmount) {
            if (r.fSplitBlindOutput && r.nAmount < 0.01) {
                r.fExemptFeeSub = true;
            } else {
                nSubtractFeeFromAmount++;
            }
        }
    }
    return;
};

bool CTempRecipient::ApplySubFee(CAmount nFee, size_t nSubtractFeeFromAmount, bool &fFirst)
{
    if (nType != OUTPUT_DATA) {
        nAmount = nAmountSelected;
        if (fSubtractFeeFromAmount && !fExemptFeeSub) {
            nAmount -= nFee / nSubtractFeeFromAmount; // Subtract fee equally from each selected recipient

            if (fFirst) { // first receiver pays the remainder not divisible by output count
                fFirst = false;
                nAmount -= nFee % nSubtractFeeFromAmount;
            }
            return true;
        }
    }
    return false;
};

static bool ExpandChangeAddress(CHDWallet *phdw, CTempRecipient &r, std::string &sError) EXCLUSIVE_LOCKS_REQUIRED(phdw->cs_wallet)
{
    if (r.address.index() == DI::_CStealthAddress) {
        CStealthAddress sx = std::get<CStealthAddress>(r.address);

        CKey sShared;
        ec_point pkSendTo;

        int k, nTries = 24;
        for (k = 0; k < nTries; ++k) {
            if (StealthSecret(r.sEphem, sx.scan_pubkey, sx.spend_pubkey, sShared, pkSendTo) == 0) {
                break;
            }
            // if StealthSecret fails try again with new ephem key
            /* TODO: Make optional
            if (0 != pc->DeriveNextKey(sEphem, nChild, true))
                return errorN(1, sError, __func__, "DeriveNextKey failed.");
            */
            r.sEphem.MakeNewKey(true);
        }
        if (k >= nTries) {
            return errorN(1, sError, __func__, "Could not generate receiving public key.");
        }

        CPubKey pkEphem = r.sEphem.GetPubKey();
        r.pkTo = CPubKey(pkSendTo);
        PKHash pkhash = PKHash(r.pkTo);
        r.scriptPubKey = GetScriptForDestination(pkhash);

        if (LogAcceptCategory(BCLog::HDWALLET)) {
            phdw->WalletLogPrintf("Stealth send to generated change address: %s\n", EncodeDestination(pkhash));
        }

        if (r.nType == OUTPUT_CT || r.nType == OUTPUT_RINGCT) {
            if (sx.prefix.number_bits > 0) {
                r.nStealthPrefix = FillStealthPrefix(sx.prefix.number_bits, sx.prefix.bitfield);
            }
        } else {
            if (0 != MakeStealthData(r.sNarration, sx.prefix, sShared, pkEphem, r.vData, r.nStealthPrefix, sError)) {
                return 1;
            }
        }
        return true;
    }

    if (r.address.index() == DI::_CExtPubKey) {
        CExtKeyPair ek = CExtKeyPair(std::get<CExtPubKey>(r.address));
        uint32_t nChildKey;

        if (0 != phdw->ExtKeyGetDestination(ek, r.pkTo, nChildKey)) {
            return errorN(false, sError, __func__, "ExtKeyGetDestination failed.");
        }

        r.nChildKey = nChildKey;
        r.scriptPubKey = GetScriptForDestination(PKHash(r.pkTo));

        return true;
    }

    if (r.address.index() == DI::_PKHash) {
        PKHash pkhash = std::get<PKHash>(r.address);

        CKeyID idk = ToKeyID(pkhash);
        if (!phdw->GetPubKey(idk, r.pkTo)) {
            return errorN(false, sError, __func__, "GetPubKey failed.");
        }
        r.scriptPubKey = GetScriptForDestination(pkhash);

        return true;
    }

    if (r.address.index() != DI::_CNoDestination
        // TODO OUTPUT_CT?
        && r.nType == OUTPUT_STANDARD) {
        r.scriptPubKey = GetScriptForDestination(r.address);
        return r.scriptPubKey.size() > 0;
    }

    return false;
}

bool CHDWallet::SetChangeDest(const CCoinControl *coinControl, CTempRecipient &r, std::string &sError)
{
    if (r.nType == OUTPUT_CT || r.nType == OUTPUT_RINGCT
        || r.address.index() == DI::_CStealthAddress) {
        /*
        // TODO: Make optional
        if (0 != pc->DeriveNextKey(r.sEphem, nChild, true))
            return errorN(1, sError, __func__, "TryDeriveNext failed.");
        */
        r.sEphem.MakeNewKey(true);
    }

    // coin control: send change to custom address
    if (coinControl && !std::get_if<CNoDestination>(&coinControl->destChange)) {
        WalletLogPrintf("%s: Set from coincontrol dest.\n", __func__);
        r.address = coinControl->destChange;
        return ExpandChangeAddress(this, r, sError);
    }
    if (coinControl && coinControl->scriptChange.size() > 0) {
        WalletLogPrintf("%s: Set from coincontrol script.\n", __func__);
        if (r.nType == OUTPUT_RINGCT) {
            return wserrorN(0, sError, __func__, "Change script on anon output.");
        }

        r.scriptPubKey = coinControl->scriptChange;

        if (r.nType == OUTPUT_CT) {
            if (!ExtractDestination(r.scriptPubKey, r.address)) {
                return wserrorN(0, sError, __func__, "Could not get pubkey from changescript.");
            }
            if (r.address.index() != DI::_PKHash) {
                return wserrorN(0, sError, __func__, "Could not get pubkey from changescript.");
            }
            CKeyID idk = ToKeyID(std::get<PKHash>(r.address));
            if (!GetPubKey(idk, r.pkTo)) {
                return wserrorN(0, sError, __func__, "Could not get pubkey from changescript.");
            }
        }

        return true;
    }
    if (coinControl && coinControl->m_changepubkey.IsValid()) {
        PKHash idChange = PKHash(coinControl->m_changepubkey);
        r.pkTo = coinControl->m_changepubkey;
        r.address = idChange;
        r.scriptPubKey = GetScriptForDestination(idChange);
        return true;
    }

    UniValue jsonSettings;
    GetSetting("changeaddress", jsonSettings);

    bool fIsSet = false;
    if (r.nType == OUTPUT_STANDARD) {
        if (jsonSettings["address_standard"].isStr()) {
            WalletLogPrintf("%s: Set from changeaddress address_standard.\n", __func__);
            std::string sAddress = jsonSettings["address_standard"].get_str();

            CTxDestination dest = DecodeDestination(sAddress);
            if (!IsValidDestination(dest)) {
                return wserrorN(0, sError, __func__, "Invalid address setting.");
            }
            r.address = dest;
            if (!ExpandChangeAddress(this, r, sError)) {
                return false;
            }

            fIsSet = true;
        }
    }

    if (!fIsSet) {
        CPubKey pkChange;
        if (0 != GetChangeAddress(pkChange)) {
            return wserrorN(0, sError, __func__, "GetChangeAddress failed.");
        }

        PKHash idChange = PKHash(pkChange);
        r.pkTo = pkChange;
        r.address = idChange;
        r.scriptPubKey = GetScriptForDestination(idChange);
    }

    if (r.nType == OUTPUT_STANDARD) {
        if (jsonSettings["coldstakingaddress"].isStr()) {
            WalletLogPrintf("%s: Adding coldstaking script.\n", __func__);
            std::string sAddress = jsonSettings["coldstakingaddress"].get_str();

            CTxDestination destStake = DecodeDestination(sAddress, true);
            if (destStake.index() == DI::_CNoDestination) {
                return wserrorN(0, sError, __func__, "Invalid coldstaking address setting.");
            }
            r.addressColdStaking = destStake;

            CScript scriptStaking;
            if (r.addressColdStaking.index() == DI::_CExtPubKey) {
                CExtKeyPair ek = CExtKeyPair(std::get<CExtPubKey>(r.addressColdStaking));
                uint32_t nChildKey;

                CPubKey pkTemp;
                if (0 != ExtKeyGetDestination(ek, pkTemp, nChildKey)) {
                    return wserrorN(false, sError, __func__, "ExtKeyGetDestination failed.");
                }

                r.nChildKeyColdStaking = nChildKey;
                scriptStaking = GetScriptForDestination(PKHash(pkTemp));
            } else
            if (r.addressColdStaking.index() == DI::_PKHash) {
                PKHash idk = std::get<PKHash>(r.addressColdStaking);
                scriptStaking = GetScriptForDestination(idk);
            }

            if (r.address.index() == DI::_ScriptHash ||
                r.address.index() == DI::_WitnessV0ScriptHash ||
                r.address.index() == DI::_CScriptID256) {
                // Pass through p2sh
            } else {
                // Switch to sha256 hash
                if (!r.pkTo.IsValid()) {
                    return wserrorN(false, sError, __func__, "Change pubkey is unset.");
                }
                CKeyID256 idChange = r.pkTo.GetID256();
                r.address = idChange;
                r.scriptPubKey = GetScriptForDestination(idChange);
            }

            if (scriptStaking.IsPayToPublicKeyHash()) {
                CScript script = CScript() << OP_ISCOINSTAKE << OP_IF;
                script.append(scriptStaking);
                script << OP_ELSE;
                script.append(r.scriptPubKey);
                script << OP_ENDIF;
                r.scriptPubKey = script;
            } else {
                return wserrorN(false, sError, __func__, "Unknown scriptStaking type, must be pay-to-public-key-hash.");
            }
        }
    }

    return true;
};

static bool InsertChangeAddress(CTempRecipient &r, std::vector<CTempRecipient> &vecSend, int &nChangePosInOut)
{
    r.fChange = true;
    if (nChangePosInOut < 0) {
        nChangePosInOut = GetRandInt(vecSend.size() + 1);
    } else {
        nChangePosInOut = std::min(nChangePosInOut, (int)vecSend.size());
    }

    if (nChangePosInOut < (int)vecSend.size()
        && vecSend[nChangePosInOut].nType == OUTPUT_DATA) {
        nChangePosInOut++;
    }

    vecSend.insert(vecSend.begin() + nChangePosInOut, r);

    // Insert data output for stealth address if required
    if (r.vData.size() > 0) {
        CTempRecipient rd;
        rd.nType = OUTPUT_DATA;
        rd.fChange = true;
        rd.vData = r.vData;
        r.vData.clear();
        vecSend.insert(vecSend.begin() + nChangePosInOut + 1, rd);
    }

    return true;
};

int PreAcceptMempoolTx(CHDWallet *wallet, CWalletTx &wtx, std::string &sError)
{
    // Check if wtx can get into the mempool

    // Limit size
    if (GetTransactionWeight(*wtx.tx) >= MAX_STANDARD_TX_WEIGHT) {
        return errorN(1, sError, __func__, "Transaction too large");
    }

    if (gArgs.GetBoolArg("-walletrejectlongchains", DEFAULT_WALLET_REJECT_LONG_CHAINS)) {
        // Lastly, ensure this tx will pass the mempool's chain limits
        if (!wallet->chain().checkChainLimits(wtx.tx)) {
            return errorN(1, sError, __func__, _("Transaction has too long of a mempool chain").translated.c_str());
        }
    }

    return 0;
}

int CHDWallet::AddStandardInputs(CWalletTx &wtx, CTransactionRecord &rtx,
    std::vector<CTempRecipient> &vecSend,
    CExtKeyAccount *sea, CStoredExtKey *pc,
    bool sign, CAmount &nFeeRet, const CCoinControl *coinControl, std::string &sError)
{
    assert(coinControl);
    const CCoinControl &coin_control = *coinControl;
    nFeeRet = 0;
    CAmount nValue{0};
    size_t nSubtractFeeFromAmount;
    bool fOnlyStandardOutputs;
    InspectOutputs(vecSend, nValue, nSubtractFeeFromAmount, fOnlyStandardOutputs);

    if (0 != ExpandTempRecipients(vecSend, pc, sError)) {
        return 1; // sError is set
    }

    wtx.fTimeReceivedIsTxTime = true;
    wtx.fFromMe = true;
    CMutableTransaction txNew;
    txNew.nVersion = PARTICL_TXN_VERSION;
    txNew.vout.clear();

    // Discourage fee sniping. See CWallet::CreateTransaction
    txNew.nLockTime = chain().getHeightInt();

    // 1/10 chance of random time further back to increase privacy
    if (GetRandInt(10) == 0) {
        txNew.nLockTime = std::max(0, (int)txNew.nLockTime - GetRandInt(100));
    }

    assert(txNew.nLockTime <= (unsigned int)chain().getHeightInt());
    assert(txNew.nLockTime < LOCKTIME_THRESHOLD);

    coinControl->fHaveAnonOutputs = HaveAnonOutputs(vecSend);
    FeeCalculation feeCalc;
    CAmount nFeeNeeded;
    unsigned int nBytes;
    int nChangePosInOut = -1;
    {
        LOCK(cs_wallet);

        std::set<CInputCoin> setCoins;
        std::vector<COutput> vAvailableCoins;
        AvailableCoins(vAvailableCoins, coinControl, coinControl->m_minimum_output_amount, coinControl->m_maximum_output_amount);
        CoinSelectionParams coin_selection_params; // Parameters for coin selection, init with dummy

        // Set discard feerate
        coin_selection_params.m_discard_feerate = GetDiscardRate(*this);

        // Get the fee rate to use effective values in coin selection
        coin_selection_params.m_effective_feerate = GetMinimumFeeRate(*this, coin_control, &feeCalc);

        // Do not, ever, assume that it's fine to change the fee rate if the user has explicitly
        // provided one
        if (coin_control.m_feerate && coin_selection_params.m_effective_feerate > *coin_control.m_feerate) {
            sError = strprintf(_("Fee rate (%s) is lower than the minimum fee rate setting (%s)").translated, coin_control.m_feerate->ToString(FeeEstimateMode::SAT_VB), coin_selection_params.m_effective_feerate.ToString(FeeEstimateMode::SAT_VB));
            return false;
        }
        if (feeCalc.reason == FeeReason::FALLBACK && !m_allow_fallback_fee) {
            // eventually allow a fallback fee
            sError = _("Fee estimation failed. Fallbackfee is disabled. Wait a few blocks or enable -fallbackfee.").translated;
            return false;
        }

        // Get long term estimate
        CCoinControl cc_temp;
        cc_temp.m_confirm_target = chain().estimateMaxBlocks();
        coin_selection_params.m_long_term_feerate = GetMinimumFeeRate(*this, cc_temp, nullptr);

        // Calculate the cost of change
        // Cost of change is the cost of creating the change output + cost of spending the change output in the future.
        // For creating the change output now, we use the effective feerate.
        // For spending the change output in the future, we use the discard feerate for now.
        // So cost of change = (change output size * effective feerate) + (size of spending change output * discard feerate)
        coin_selection_params.m_change_fee = coin_selection_params.m_effective_feerate.GetFee(coin_selection_params.change_output_size);
        coin_selection_params.m_cost_of_change = coin_selection_params.m_discard_feerate.GetFee(coin_selection_params.change_spend_size) + coin_selection_params.m_change_fee;

        coin_selection_params.m_subtract_fee_outputs = nSubtractFeeFromAmount != 0; // If we are doing subtract fee from recipient, don't use effective values


        nFeeRet = 0;
        size_t nSubFeeTries = 100;
        bool pick_new_inputs = true;
        CAmount nValueIn = 0;

        // Start with no fee and loop until there is enough fee
        for (;;) {
            txNew.vin.clear();
            txNew.vpout.clear();
            wtx.fFromMe = true;

            CAmount nValueToSelect = nValue;
            if (nSubtractFeeFromAmount == 0) {
                nValueToSelect += nFeeRet;
                nValueToSelect += coin_selection_params.m_effective_feerate.GetFee(coin_selection_params.tx_noinputs_size);
            }

            // Choose coins to us
            if (pick_new_inputs) {
                nValueIn = 0;
                setCoins.clear();
                if (!SelectCoins(vAvailableCoins, nValueToSelect, setCoins, nValueIn, *coinControl, coin_selection_params)) {
                    return wserrorN(1, sError, __func__, _("Insufficient funds.").translated);
                }
            }

            const CAmount nChange = nValueIn - nValueToSelect;

            // Remove fee outputs from last round
            for (int i = 0; i < (int) vecSend.size(); ++i) {
                if (vecSend[i].fChange) {
                    vecSend.erase(vecSend.begin() + i);
                    i--;
                }
            }

            CAmount extra_fee_from_change = 0;
            nChangePosInOut = -1;
            if (nChange > 0) {
                // Fill an output to ourself
                CTempRecipient r;
                r.nType = OUTPUT_STANDARD;
                r.SetAmount(nChange);

                if (!SetChangeDest(coinControl, r, sError)) {
                    return wserrorN(1, sError, __func__, ("SetChangeDest failed: " + sError));
                }

                CTxOutStandard tempOut;
                tempOut.scriptPubKey = r.scriptPubKey;
                tempOut.nValue = nChange;

                // Never create dust outputs; if we would, just
                // add the dust to the fee.
                if (IsDust(&tempOut, coin_selection_params.m_discard_feerate)) {
                    nChangePosInOut = -1;
                    // Raise the fee after it may be subtracted from outputs
                    extra_fee_from_change += nChange;
                    if (nSubtractFeeFromAmount > 0) { // Reduce the amount of the fee that must be funded from outputs
                        nFeeRet -= nFeeRet > extra_fee_from_change ? extra_fee_from_change : nFeeRet;
                    }

                } else {
                    nChangePosInOut = coinControl->nChangePos;
                    InsertChangeAddress(r, vecSend, nChangePosInOut);
                }
            }

            // Fill vin
            //
            // Note how the sequence number is set to non-maxint so that
            // the nLockTime set above actually works.
            //
            // BIP125 defines opt-in RBF as any nSequence < maxint-1, so
            // we use the highest possible value in that range (maxint-2)
            // to avoid conflicting with other possible uses of nSequence,
            // and in the spirit of "smallest possible change from prior
            // behavior."
            const uint32_t nSequence = coinControl->m_signal_bip125_rbf.value_or(m_signal_rbf) ? MAX_BIP125_RBF_SEQUENCE : (CTxIn::SEQUENCE_FINAL - 1);
            for (const auto& coin : setCoins) {
                txNew.vin.push_back(CTxIn(coin.outpoint,CScript(),
                                          nSequence));
            }

            CAmount nValueOutPlain = 0;
            int nLastBlindedOutput = -1;

            if (!fOnlyStandardOutputs) {
                OUTPUT_PTR<CTxOutData> outFee = MAKE_OUTPUT<CTxOutData>();
                outFee->vData.push_back(DO_FEE);
                outFee->vData.resize(9); // More bytes than varint fee could use
                txNew.vpout.push_back(outFee);
            }

            bool fFirst = true;
            for (size_t i = 0; i < vecSend.size(); ++i) {
                auto &r = vecSend[i];

                r.ApplySubFee(nFeeRet, nSubtractFeeFromAmount, fFirst);

                OUTPUT_PTR<CTxOutBase> txbout;
                if (0 != CreateOutput(txbout, r, sError)) {
                    return 1; // sError will be set
                }
                if (!CheckOutputValue(chain(), r, &*txbout, nFeeRet, sError)) {
                    return 1; // sError set
                }
                if (r.nType == OUTPUT_STANDARD) {
                    nValueOutPlain += r.nAmount;
                    if (r.fChange) {
                        nChangePosInOut = i;
                    }
                }
                if (r.nType == OUTPUT_CT || r.nType == OUTPUT_RINGCT) {
                    nLastBlindedOutput = i;
                }

                r.n = txNew.vpout.size();
                txNew.vpout.push_back(txbout);
            }

            nFeeRet += extra_fee_from_change;

            std::vector<uint8_t*> vpBlinds;
            uint8_t blind_plain[32] = {0};
            vpBlinds.push_back(blind_plain);

            size_t nBlindedInputs = 1;
            secp256k1_pedersen_commitment plainInputCommitment, plainCommitment;

            if (nValueIn > 0
                && !secp256k1_pedersen_commit(secp256k1_ctx_blind, &plainInputCommitment, blind_plain, (uint64_t) nValueIn, &secp256k1_generator_const_h, &secp256k1_generator_const_g)) {
                return wserrorN(1, sError, __func__, "secp256k1_pedersen_commit failed for plain in.");
            }

            if (nValueOutPlain > 0) {
                vpBlinds.push_back(blind_plain);
                if (!secp256k1_pedersen_commit(secp256k1_ctx_blind, &plainCommitment, blind_plain, (uint64_t) nValueOutPlain, &secp256k1_generator_const_h, &secp256k1_generator_const_g)) {
                    return wserrorN(1, sError, __func__, "secp256k1_pedersen_commit failed for plain out.");
                }
            }

            for (size_t i = 0; i < vecSend.size(); ++i) {
                auto &r = vecSend[i];

                if (r.nType == OUTPUT_CT || r.nType == OUTPUT_RINGCT) {
                    if ((int)i == nLastBlindedOutput && coinControl->m_debug_exploit_anon == 0) {
                        r.vBlind.resize(32);
                        // Last to-be-blinded value: compute from all other blinding factors.
                        // sum of output blinding values must equal sum of input blinding values
                        if (!secp256k1_pedersen_blind_sum(secp256k1_ctx_blind, &r.vBlind[0], &vpBlinds[0], vpBlinds.size(), nBlindedInputs)) {
                            return wserrorN(1, sError, __func__, "secp256k1_pedersen_blind_sum failed.");
                        }
                    } else {
                        if (r.vBlind.size() != 32) {
                            r.vBlind.resize(32);
                            GetStrongRandBytes(&r.vBlind[0], 32);
                        } // else already prefilled
                        vpBlinds.push_back(&r.vBlind[0]);
                    }

                    assert(r.n < (int)txNew.vpout.size());
                    if (0 != AddCTData(coinControl, txNew.vpout[r.n].get(), r, sError)) {
                        return 1; // sError will be set
                    }
                }
            }

            // Fill in dummy signatures for fee calculation.
            int nIn = 0;
            for (const auto &coin : setCoins) {
                const CScript& scriptPubKey = coin.txout.scriptPubKey;
                SignatureData sigdata;

                std::map<COutPoint, CInputData>::const_iterator it = coinControl->m_inputData.find(coin.outpoint);
                if (it != coinControl->m_inputData.end()) {
                    sigdata.scriptWitness = it->second.scriptWitness;
                } else {
                    auto provider = GetLegacyScriptPubKeyMan();
                    if (!provider) {
                        return wserrorN(1, sError, __func__, "GetLegacyScriptPubKeyMan failed.");
                    }
                    if (!ProduceSignature(*provider, DUMMY_SIGNATURE_CREATOR_PARTICL, scriptPubKey, sigdata)) {
                        return wserrorN(1, sError, __func__, "Dummy signature failed.");
                    }
                }
                UpdateInput(txNew.vin[nIn], sigdata);
                nIn++;

                if (IsMine(coin.txout.scriptPubKey) & ISMINE_HARDWARE_DEVICE) {
                    coinControl->fNeedHardwareKey = true;
                }
            }

            nBytes = GetVirtualTransactionSize(CTransaction(txNew));

            // Remove scriptSigs to eliminate the fee calculation dummy signatures
            for (auto &vin : txNew.vin) {
                vin.scriptSig = CScript();
                vin.scriptWitness.SetNull();
            }

            nFeeNeeded = GetMinimumFee(*this, nBytes, *coinControl, &feeCalc);
            if (feeCalc.reason == FeeReason::FALLBACK && !m_allow_fallback_fee) {
                // eventually allow a fallback fee
                sError = _("Fee estimation failed. Fallbackfee is disabled. Wait a few blocks or enable -fallbackfee.").translated;
                return false;
            }

            if (nFeeRet >= nFeeNeeded) {
                // Reduce fee to only the needed amount if possible. This
                // prevents potential overpayment in fees if the coins
                // selected to meet nFeeNeeded result in a transaction that
                // requires less fee than the prior iteration.

                // If we have no change and a big enough excess fee, then
                // try to construct transaction again only without picking
                // new inputs. We now know we only need the smaller fee
                // (because of reduced tx size) and so we should add a
                // change output. Only try this once.
                if (nChangePosInOut == -1 && nSubtractFeeFromAmount == 0 && pick_new_inputs) {
                    CKeyID idNull;
                    CScript scriptChange = GetScriptForDestination(PKHash(idNull));
                    CTxOut change_prototype_txout(0, scriptChange);
                    size_t change_prototype_size = GetSerializeSize(change_prototype_txout);
                    unsigned int tx_size_with_change = nBytes + change_prototype_size + 2; // Add 2 as a buffer in case increasing # of outputs changes compact size
                    CAmount fee_needed_with_change = GetMinimumFee(*this, tx_size_with_change, *coinControl, nullptr);
                    CAmount minimum_value_for_change = GetDustThreshold(change_prototype_txout, coin_selection_params.m_discard_feerate);
                    if (nFeeRet >= fee_needed_with_change + minimum_value_for_change) {
                        pick_new_inputs = false;
                        nFeeRet = fee_needed_with_change;
                        continue;
                    }
                }

                // If we have change output already, just increase it
                if (nFeeRet > nFeeNeeded && nChangePosInOut != -1
                    && nSubtractFeeFromAmount == 0) {
                    auto &r = vecSend[nChangePosInOut];
                    CAmount extraFeePaid = nFeeRet - nFeeNeeded;
                    CTxOutBaseRef c = txNew.vpout[r.n];
                    c->SetValue(c->GetValue() + extraFeePaid);
                    r.nAmount = c->GetValue();

                    nFeeRet -= extraFeePaid;
                }
                break; // Done, enough fee included.
            } else
            if (!pick_new_inputs) {
                // This shouldn't happen, we should have had enough excess
                // fee to pay for the new output and still meet nFeeNeeded
                // Or we should have just subtracted fee from recipients and
                // nFeeNeeded should not have changed

                if (!nSubtractFeeFromAmount || !(--nSubFeeTries)) { // rangeproofs can change size per iteration
                    return wserrorN(1, sError, __func__, _("Transaction fee and change calculation failed.").translated);
                }
                LogPrint(BCLog::HDWALLET, "%s: nSubFeeTries %d\n", __func__, nSubFeeTries);
            }

            // Try to reduce change to include necessary fee
            if (nChangePosInOut != -1
                && nSubtractFeeFromAmount == 0) {
                auto &r = vecSend[nChangePosInOut];
                CAmount additionalFeeNeeded = nFeeNeeded - nFeeRet;

                CTxOutBaseRef c = txNew.vpout[r.n];
                // Only reduce change if remaining amount is still a large enough output.
                if (c->GetValue() >= MIN_FINAL_CHANGE + additionalFeeNeeded) {
                    c->SetValue(c->GetValue() - additionalFeeNeeded);
                    r.nAmount = c->GetValue();
                    nFeeRet += additionalFeeNeeded;
                    break; // Done, able to increase fee from change
                }
            }

            // If subtracting fee from recipients, we now know what fee we
            // need to subtract, we have no reason to reselect inputs
            if (nSubtractFeeFromAmount > 0) {
                pick_new_inputs = false;
            }

            // Include more fee and try again.
            nFeeRet = nFeeNeeded;
            continue;
        }
        coinControl->nChangePos = nChangePosInOut;

        if (!fOnlyStandardOutputs) {
            std::vector<uint8_t> &vData = *txNew.vpout[0]->GetPData();
            vData.resize(1);
            if (0 != part::PutVarInt(vData, nFeeRet)) {
                return werrorN(1, "%s: PutVarInt %d failed\n", __func__, nFeeRet);
            }
        }

        if (sign) {
            int nIn = 0;
            for (const auto &coin : setCoins) {
                const CScript& scriptPubKey = coin.txout.scriptPubKey;

                // TODO: ismine field on CInputCoin
                if (coinControl->fNeedHardwareKey && (IsMine(scriptPubKey) & ISMINE_HARDWARE_DEVICE)) {
                    nIn++;
                    continue;
                }

                std::vector<uint8_t> vchAmount(8);
                part::SetAmount(vchAmount, coin.txout.nValue);

                SignatureData sigdata;
                auto provider = GetLegacyScriptPubKeyMan();
                if (!provider) {
                    return wserrorN(1, sError, __func__, _("GetLegacyScriptPubKeyMan failed").translated);
                }
                if (!ProduceSignature(*provider, MutableTransactionSignatureCreator(&txNew, nIn, vchAmount, SIGHASH_ALL), scriptPubKey, sigdata)) {
                    return wserrorN(1, sError, __func__, _("Signing transaction failed").translated);
                }
                UpdateInput(txNew.vin[nIn], sigdata);

                nIn++;
            }

#if ENABLE_USBDEVICE
            if (coinControl->fNeedHardwareKey) {
                CCoinsView viewDummy;
                CCoinsViewCache view(&viewDummy);
                for (const auto &coin : setCoins) {
                    Coin newcoin;
                    newcoin.out.scriptPubKey = coin.txout.scriptPubKey;
                    newcoin.out.nValue = coin.GetValue();
                    newcoin.nHeight = 1;
                    view.AddCoin(coin.outpoint, std::move(newcoin), true);
                }
                std::vector<std::unique_ptr<usb_device::CUSBDevice> > vDevices;
                usb_device::CUSBDevice *pDevice = usb_device::SelectDevice(vDevices, sError);
                if (!pDevice) {
                    return 1; // sError is set
                }

                uiInterface.NotifyWaitingForDevice(false);

                auto spk_man = GetLegacyScriptPubKeyMan();
                if (!spk_man) {
                    pDevice->Cleanup();
                    uiInterface.NotifyWaitingForDevice(true);
                    return wserrorN(1, sError, __func__, _("GetLegacyScriptPubKeyMan failed.").translated);
                }

                int hw_change_pos = -1;
                std::vector<uint32_t> hw_change_path;
                if (nChangePosInOut > -1) {
                    auto &r = vecSend[nChangePosInOut];
                    if (GetChangePath(r.scriptPubKey, hw_change_path)) {
                        hw_change_pos = nChangePosInOut;
                    }
                }

                if (pDevice->RequirePrevTxns()) {
                    for (const auto &coin : setCoins) {
                        const auto &prevout = coin.outpoint;
                        if (pDevice->HavePrevTxn(prevout.hash)) {
                            continue;
                        }
                        CTransactionRef tx_prev;
                        if (GetTransaction(prevout.hash, tx_prev)) {
                            pDevice->AddPrevTxn(tx_prev);
                        } else {
                            WalletLogPrintf("%s: Could not find input txn %s\n", __func__, prevout.hash.ToString());
                        }
                    }
                }

                pDevice->PrepareTransaction(txNew, view, *spk_man, SIGHASH_ALL, hw_change_pos, hw_change_path);
                if (!pDevice->m_error.empty()) {
                    pDevice->Cleanup();
                    uiInterface.NotifyWaitingForDevice(true);
                    return wserrorN(1, sError, __func__, _("PrepareTransaction for device failed: %s").translated, pDevice->m_error);
                }

                int nIn = 0;
                for (const auto &coin : setCoins) {
                    const CScript& scriptPubKey = coin.txout.scriptPubKey;

                    if (!(IsMine(scriptPubKey) & ISMINE_HARDWARE_DEVICE)) {
                        nIn++;
                        continue;
                    }

                    std::vector<uint8_t> vchAmount(8);
                    part::SetAmount(vchAmount, coin.txout.nValue);

                    pDevice->m_error.clear();
                    SignatureData sigdata;
                    ProduceSignature(*spk_man, usb_device::DeviceSignatureCreator(pDevice, &txNew, nIn, vchAmount, SIGHASH_ALL), scriptPubKey, sigdata);

                    if (!pDevice->m_error.empty()) {
                        pDevice->Cleanup();
                        uiInterface.NotifyWaitingForDevice(true);
                        return wserrorN(1, sError, __func__, _("ProduceSignature from device failed: %s").translated, pDevice->m_error);
                    }
                    UpdateInput(txNew.vin[nIn], sigdata);

                    /*
                    ScriptError serror = SCRIPT_ERR_OK;
                    if (!VerifyScript(txin.scriptSig, prevPubKey, &txin.scriptWitness, STANDARD_SCRIPT_VERIFY_FLAGS, TransactionSignatureChecker(&txConst, i, vchAmount), &serror)) {
                        if (serror == SCRIPT_ERR_INVALID_STACK_OPERATION) {
                            // Unable to sign input and verification failed (possible attempt to partially sign).
                            TxInErrorToJSON(txin, vErrors, "Unable to sign input, invalid stack size (possibly missing key)");
                        } else {
                            TxInErrorToJSON(txin, vErrors, ScriptErrorString(serror));
                        }
                    }
                    */

                    nIn++;
                }

                pDevice->Cleanup();

                uiInterface.NotifyWaitingForDevice(true);
            }
#endif
        }

        rtx.nFee = nFeeRet;
        AddOutputRecordMetaData(rtx, vecSend);

        // Embed the constructed transaction data in wtxNew.
        wtx.SetTx(MakeTransactionRef(std::move(txNew)));
    }

    if (0 != PreAcceptMempoolTx(this, wtx, sError)) {
        return 1;
    }

    double all_est = feeCalc.est.pass.totalConfirmed + feeCalc.est.pass.inMempool + feeCalc.est.pass.leftMempool;
    if (all_est == 0.0) all_est = 1.0;
    WalletLogPrintf("Fee Calculation: Fee:%d Bytes:%u Needed:%d Tgt:%d (requested %d) Reason:\"%s\" Decay %.5f: Estimation: (%g - %g) %.2f%% %.1f/(%.1f %d mem %.1f out) Fail: (%g - %g) %.2f%% %.1f/(%.1f %d mem %.1f out)\n",
              nFeeRet, nBytes, nFeeNeeded, feeCalc.returnedTarget, feeCalc.desiredTarget, StringForFeeReason(feeCalc.reason), feeCalc.est.decay,
              feeCalc.est.pass.start, feeCalc.est.pass.end,
              100 * feeCalc.est.pass.withinTarget / all_est,
              feeCalc.est.pass.withinTarget, feeCalc.est.pass.totalConfirmed, feeCalc.est.pass.inMempool, feeCalc.est.pass.leftMempool,
              feeCalc.est.fail.start, feeCalc.est.fail.end,
              100 * feeCalc.est.fail.withinTarget / all_est,
              feeCalc.est.fail.withinTarget, feeCalc.est.fail.totalConfirmed, feeCalc.est.fail.inMempool, feeCalc.est.fail.leftMempool);
    return 0;
}

int CHDWallet::AddStandardInputs(CWalletTx &wtx, CTransactionRecord &rtx,
    std::vector<CTempRecipient> &vecSend, bool sign, CAmount &nFeeRet, const CCoinControl *coinControl, std::string &sError)
{
    ClearTxCreationState();

    if (vecSend.size() < 1) {
        return wserrorN(1, sError, __func__, _("Transaction must have at least one recipient.").translated);
    }

    CAmount nValue = 0;
    bool fCT = false;
    for (const auto &r : vecSend) {
        nValue += r.nAmount;
        if (nValue < 0 || r.nAmount < 0) {
            return wserrorN(1, sError, __func__, _("Transaction amounts must not be negative.").translated);
        }

        if (r.nType == OUTPUT_CT || r.nType == OUTPUT_RINGCT) {
            fCT = true;
        }
    }

    // No point hiding the amount in one output
    // If one of the outputs was always 0 it would be easy to track amounts,
    // the output that gets spent would be = plain input.
    if (fCT
        && vecSend.size() < 2) {
        CTempRecipient &r0 = vecSend[0];
        CTempRecipient rN;
        rN.nType = r0.nType;
        rN.nAmount = r0.nAmount * ((float)GetRandInt(100) / 100.0);
        rN.nAmountSelected = rN.nAmount;
        rN.address = r0.address;
        rN.fSubtractFeeFromAmount = r0.fSubtractFeeFromAmount;

        r0.nAmount -= rN.nAmount;
        r0.nAmountSelected = r0.nAmount;

        // Tag the smaller amount, might be too small to sub the fee from
        if (r0.nAmount < rN.nAmount) {
            r0.fSplitBlindOutput = true;
        } else {
            rN.fSplitBlindOutput = true;
        }

        vecSend.push_back(rN);
    }

    CExtKeyAccount *sea;
    CStoredExtKey *pcC = nullptr;
    if (0 != GetDefaultConfidentialChain(nullptr, sea, pcC)) {
        //return errorN(1, sError, __func__, _("Could not get confidential chain from account.").c_str());
    }

    uint32_t nLastHardened = pcC ? pcC->nHGenerated : 0;
    if (0 != AddStandardInputs(wtx, rtx, vecSend, sea, pcC, sign, nFeeRet, coinControl, sError)) {
        // sError will be set
        if (pcC) {
            pcC->nHGenerated = nLastHardened; // reset
        }
        return 1;
    }

    if (pcC) {
        LOCK(cs_wallet);
        CHDWalletDB wdb(*m_database);

        std::vector<uint8_t> vEphemPath;
        uint32_t idIndex;
        bool requireUpdateDB;
        if (0 == ExtKeyGetIndex(&wdb, sea, idIndex, requireUpdateDB)) {
            PushUInt32(vEphemPath, idIndex);

            if (0 == AppendChainPath(pcC, vEphemPath)) {
                uint32_t nChild = nLastHardened;
                PushUInt32(vEphemPath, SetHardenedBit(nChild));
                rtx.mapValue[RTXVT_EPHEM_PATH] = vEphemPath;
            } else {
                WalletLogPrintf("Warning: %s - missing path value.\n", __func__);
                vEphemPath.clear();
            }
        } else {
            WalletLogPrintf("Warning: %s - ExtKeyGetIndex failed %s.\n", __func__, pcC->GetIDString58());
        }

        CKeyID idChain = pcC->GetID();
        if (!wdb.WriteExtKey(idChain, *pcC)) {
            pcC->nHGenerated = nLastHardened;
            return wserrorN(1, sError, __func__, "WriteExtKey failed.");
        }
    }

    return 0;
};

int CHDWallet::AddBlindedInputs(CWalletTx &wtx, CTransactionRecord &rtx,
    std::vector<CTempRecipient> &vecSend,
    CExtKeyAccount *sea, CStoredExtKey *pc,
    bool sign, CAmount &nFeeRet, const CCoinControl *coinControl, std::string &sError)
{
    assert(coinControl);
    nFeeRet = 0;
    CAmount nValue;
    size_t nSubtractFeeFromAmount;
    bool fOnlyStandardOutputs;
    InspectOutputs(vecSend, nValue, nSubtractFeeFromAmount, fOnlyStandardOutputs);

    if (0 != ExpandTempRecipients(vecSend, pc, sError)) {
        return 1; // sError is set
    }

    wtx.fTimeReceivedIsTxTime = true;
    wtx.fFromMe = true;
    CMutableTransaction txNew;
    txNew.nVersion = PARTICL_TXN_VERSION;
    txNew.vout.clear();

    // Discourage fee sniping. See CWallet::CreateTransaction
    txNew.nLockTime = chain().getHeightInt();

    // 1/10 chance of random time further back to increase privacy
    if (GetRandInt(10) == 0) {
        txNew.nLockTime = std::max(0, (int)txNew.nLockTime - GetRandInt(100));
    }

    assert(txNew.nLockTime <= (unsigned int)chain().getHeightInt());
    assert(txNew.nLockTime < LOCKTIME_THRESHOLD);

    coinControl->fHaveAnonOutputs = HaveAnonOutputs(vecSend);
    FeeCalculation feeCalc;
    CAmount nFeeNeeded;
    unsigned int nBytes;
    {
        LOCK(cs_wallet);

        std::vector<std::pair<MapRecords_t::const_iterator, unsigned int> > setCoins;
        std::vector<COutputR> vAvailableCoins;
        AvailableBlindedCoins(vAvailableCoins, coinControl);

        CAmount nValueOutPlain = 0;
        int nChangePosInOut = -1;

        nFeeRet = 0;
        size_t nSubFeeTries = 100;
        bool pick_new_inputs = true;
        CAmount nValueIn = 0;
        // Start with no fee and loop until there is enough fee
        for (;;) {
            txNew.vin.clear();
            txNew.vpout.clear();
            wtx.fFromMe = true;

            CAmount nValueToSelect = nValue;
            if (nSubtractFeeFromAmount == 0) {
                nValueToSelect += nFeeRet;
            }

            // Choose coins to use
            if (pick_new_inputs) {
                nValueIn = 0;
                setCoins.clear();
                if (!SelectBlindedCoins(vAvailableCoins, nValueToSelect, setCoins, nValueIn, coinControl)) {
                    return wserrorN(1, sError, __func__, _("Insufficient funds.").translated);
                }
            }

            const CAmount nChange = nValueIn - nValueToSelect;

            // Remove fee outputs from last round
            for (int i = 0; i < (int) vecSend.size(); ++i) {
                if (vecSend[i].fChange) {
                    vecSend.erase(vecSend.begin() + i);
                    i--;
                }
            }

            if (coinControl->m_spend_frozen_blinded) {
                assert(!coinControl->m_addChangeOutput);
                if (nChange > DEFAULT_FALLBACK_FEE_PART) {
                    return wserrorN(1, sError, __func__, _("Change too high for frozen blinded spend.").translated);
                }
            }

            if (coinControl->m_addChangeOutput) {
                // Insert a sender-owned 0 value output which becomes the change output if needed
                CTempRecipient r;
                r.nType = OUTPUT_CT;

                CAmount value_change = nChange;
                if (!SetChangeDest(coinControl, r, sError)) {
                    return wserrorN(1, sError, __func__, ("SetChangeDest failed: " + sError));
                }

                if (fOnlyStandardOutputs) { // Need at least 2 blinded outputs
                    CTempRecipient r2;
                    r2.nType = OUTPUT_CT;
                    if (!SetChangeDest(coinControl, r2, sError)) {
                        return wserrorN(1, sError, __func__, ("SetChangeDest failed: " + sError));
                    }
                    CAmount value_split = value_change * ((float)GetRandInt(100) / 100.0);
                    value_change -= value_split;
                    r2.SetAmount(value_split);
                    InsertChangeAddress(r2, vecSend, nChangePosInOut);
                    r.SetAmount(value_change);
                } else
                {
                    if (value_change > ::minRelayTxFee.GetFee(2048)) { // TODO: better output size estimate
                        r.SetAmount(value_change);
                    } else {
                        r.SetAmount(0);
                        nFeeRet += value_change;
                    }
                }

                nChangePosInOut = coinControl->nChangePos;
                InsertChangeAddress(r, vecSend, nChangePosInOut);
            } else {
                nFeeRet += nChange;
            }

            // Fill vin
            //
            // Note how the sequence number is set to non-maxint so that
            // the nLockTime set above actually works.
            //
            // BIP125 defines opt-in RBF as any nSequence < maxint-1, so
            // we use the highest possible value in that range (maxint-2)
            // to avoid conflicting with other possible uses of nSequence,
            // and in the spirit of "smallest possible change from prior
            // behavior."
            for (const auto &coin : setCoins) {
                const uint256 &txhash = coin.first->first;
                const uint32_t nSequence = coinControl->m_signal_bip125_rbf.value_or(m_signal_rbf) ? MAX_BIP125_RBF_SEQUENCE : (CTxIn::SEQUENCE_FINAL - 1);
                txNew.vin.push_back(CTxIn(txhash, coin.second, CScript(), nSequence));
            }

            nValueOutPlain = 0;
            nChangePosInOut = -1;

            OUTPUT_PTR<CTxOutData> outFee = MAKE_OUTPUT<CTxOutData>();
            outFee->vData.push_back(DO_FEE);
            outFee->vData.resize(9); // More bytes than varint fee could use
            txNew.vpout.push_back(outFee);

            bool fFirst = true;
            for (size_t i = 0; i < vecSend.size(); ++i) {
                auto &r = vecSend[i];

                r.ApplySubFee(nFeeRet, nSubtractFeeFromAmount, fFirst);

                OUTPUT_PTR<CTxOutBase> txbout;
                if (0 != CreateOutput(txbout, r, sError)) {
                    return 1; // sError will be set
                }

                if (!CheckOutputValue(chain(), r, &*txbout, nFeeRet, sError)) {
                    return 1; // sError set
                }

                if (r.nType == OUTPUT_STANDARD) {
                    nValueOutPlain += r.nAmount;
                }

                if (r.fChange && r.nType == OUTPUT_CT) {
                    nChangePosInOut = i;
                }

                r.n = txNew.vpout.size();
                txNew.vpout.push_back(txbout);

                if (r.nType == OUTPUT_CT || r.nType == OUTPUT_RINGCT) {
                    // Need to know the fee before calculating the blind sum
                    if (r.vBlind.size() != 32) {
                        r.vBlind.resize(32);
                        GetStrongRandBytes(&r.vBlind[0], 32);
                    } // else already prefilled

                    if (0 != AddCTData(coinControl, txbout.get(), r, sError)) {
                        return 1; // sError will be set
                    }
                }
            }

            // Fill in dummy signatures for fee calculation.
            int nIn = 0;
            for (const auto &coin : setCoins) {
                const uint256 &txhash = coin.first->first;
                const COutputRecord *oR = coin.first->second.GetOutput(coin.second);
                const CScript &scriptPubKey = oR->scriptPubKey;
                SignatureData sigdata;

                // Use witness size estimate if set
                COutPoint prevout(txhash, coin.second);
                std::map<COutPoint, CInputData>::const_iterator it = coinControl->m_inputData.find(prevout);
                if (it != coinControl->m_inputData.end()) {
                    sigdata.scriptWitness = it->second.scriptWitness;
                } else {
                    std::unique_ptr<SigningProvider> provider = GetSolvingProvider(scriptPubKey);
                    if (!provider) {
                        return wserrorN(1, sError, __func__, "GetSolvingProvider failed.");
                    }
                    if (!ProduceSignature(*provider, DUMMY_SIGNATURE_CREATOR_PARTICL, scriptPubKey, sigdata)) {
                        return wserrorN(1, sError, __func__, "Dummy signature failed.");
                    }
                }
                UpdateInput(txNew.vin[nIn], sigdata);
                nIn++;
            }

            nBytes = GetVirtualTransactionSize(CTransaction(txNew));

            nFeeNeeded = GetMinimumFee(*this, nBytes, *coinControl, &feeCalc);
            if (feeCalc.reason == FeeReason::FALLBACK && !m_allow_fallback_fee) {
                // eventually allow a fallback fee
                sError = _("Fee estimation failed. Fallbackfee is disabled. Wait a few blocks or enable -fallbackfee.").translated;
                return false;
            }
            if (nFeeRet >= nFeeNeeded) {
                // Reduce fee to only the needed amount if possible. This
                // prevents potential overpayment in fees if the coins
                // selected to meet nFeeNeeded result in a transaction that
                // requires less fee than the prior iteration.
                if (nFeeRet > nFeeNeeded && nChangePosInOut != -1
                    && nSubtractFeeFromAmount == 0) {
                    auto &r = vecSend[nChangePosInOut];

                    CAmount extraFeePaid = nFeeRet - nFeeNeeded;

                    r.nAmount += extraFeePaid;
                    nFeeRet -= extraFeePaid;
                }

                if (nSubtractFeeFromAmount &&
                    !coinControl->m_spend_frozen_blinded &&
                    nValueOutPlain + nFeeRet == nValueIn) {
                    // blinded input value == plain output value
                    // blinding factor will be 0 for change (if spending all outputs from a tx)
                    // an observer could see sum blinded inputs must match plain outputs, avoid by forcing a 1sat change output

                    bool fFound = false;
                    for (auto &r : vecSend) {
                        if (r.nType == OUTPUT_STANDARD
                            && r.nAmountSelected > 0
                            && r.fSubtractFeeFromAmount
                            && !r.fChange) {
                            LogPrint(BCLog::HDWALLET, "%s: Reducing plain output %d by 1sat to force non 0 change.\n", __func__, r.n);
                            r.SetAmount(r.nAmountSelected-1);
                            fFound = true;
                            nValue -= 1;
                            break;
                        }
                    }

                    if (!fFound || !(--nSubFeeTries)) {
                        return wserrorN(1, sError, __func__, _("Unable to reduce plain output to add blind change.").translated);
                    }

                    pick_new_inputs = false;
                    continue;
                }

                break; // Done, enough fee included.
            } else
            if (!pick_new_inputs) {
                // This shouldn't happen, we should have had enough excess
                // fee to pay for the new output and still meet nFeeNeeded
                // Or we should have just subtracted fee from recipients and
                // nFeeNeeded should not have changed

                if (!nSubtractFeeFromAmount || !(--nSubFeeTries)) { // rangeproofs can change size per iteration
                    return wserrorN(1, sError, __func__, _("Transaction fee and change calculation failed.").translated);
                }
                LogPrint(BCLog::HDWALLET, "%s: nSubFeeTries %d\n", __func__, nSubFeeTries);
            }

            // Try to reduce change to include necessary fee
            if (nChangePosInOut != -1
                && nSubtractFeeFromAmount == 0) {
                auto &r = vecSend[nChangePosInOut];

                CAmount additionalFeeNeeded = nFeeNeeded - nFeeRet;

                if (r.nAmount >= MIN_FINAL_CHANGE + additionalFeeNeeded) {
                    r.nAmount -= additionalFeeNeeded;
                    nFeeRet += additionalFeeNeeded;
                    break; // Done, able to increase fee from change
                }
            }

            // If subtracting fee from recipients, we now know what fee we
            // need to subtract, we have no reason to reselect inputs
            if (nSubtractFeeFromAmount > 0) {
                pick_new_inputs = false;
            }

            // Include more fee and try again.
            nFeeRet = nFeeNeeded;
            continue;
        }
        coinControl->nChangePos = nChangePosInOut + 1; // Add one for the fee output


        nValueOutPlain += nFeeRet;

        std::vector<uint8_t> vInputBlinds(32 * setCoins.size());
        std::vector<uint8_t*> vpBlinds;

        int nIn = 0;
        for (const auto &coin : setCoins) {
            auto &txin = txNew.vin[nIn];
            const uint256 &txhash = coin.first->first;

            COutPoint prevout(txhash, coin.second);
            std::map<COutPoint, CInputData>::const_iterator it = coinControl->m_inputData.find(prevout);
            if (it != coinControl->m_inputData.end()) {
                memcpy(&vInputBlinds[nIn * 32], it->second.blind.begin(), 32);
            } else {
                CStoredTransaction stx;
                if (!CHDWalletDB(*m_database).ReadStoredTx(txhash, stx)) {
                    return werrorN(1, "%s: ReadStoredTx failed for %s.\n", __func__, txhash.ToString().c_str());
                }
                if (!stx.GetBlind(coin.second, &vInputBlinds[nIn * 32])) {
                    return werrorN(1, "%s: GetBlind failed for %s, %d.\n", __func__, txhash.ToString().c_str(), coin.second);
                }
            }
            vpBlinds.push_back(&vInputBlinds[nIn * 32]);

            // Remove scriptSigs to eliminate the fee calculation dummy signatures
            txin.scriptSig = CScript();
            txin.scriptWitness.SetNull();
            nIn++;
        }

        size_t nBlindedInputs = vpBlinds.size();

        uint8_t blind_plain[32] = {0};
        if (nValueOutPlain > 0) {
            vpBlinds.push_back(blind_plain);
        }

        // Update the change output commitment if it exists, else last blinded
        int nLastBlinded = -1;
        for (size_t i = 0; i < vecSend.size(); ++i) {
            auto &r = vecSend[i];

            if (r.nType == OUTPUT_CT || r.nType == OUTPUT_RINGCT) {
                if ((int)i != nChangePosInOut) {
                    vpBlinds.push_back(r.vBlind.data());
                }
                nLastBlinded = i;
            }
        }

        if (nChangePosInOut != -1) {
            nLastBlinded = nChangePosInOut; // Use the change output
        } else
        if (nLastBlinded != -1) {
            vpBlinds.pop_back();
        }

        if (nLastBlinded != -1) {
            auto &r = vecSend[nLastBlinded];
            if (r.nType != OUTPUT_CT) {
                return wserrorN(1, sError, __func__, "nLastBlinded not blind.");
            }

            CTxOutCT *pout = (CTxOutCT*)txNew.vpout[r.n].get();

            // Last to-be-blinded value: compute from all other blinding factors.
            // sum of output blinding values must equal sum of input blinding values
            if (!secp256k1_pedersen_blind_sum(secp256k1_ctx_blind, &r.vBlind[0], &vpBlinds[0], vpBlinds.size(), nBlindedInputs)) {
                return wserrorN(1, sError, __func__, "secp256k1_pedersen_blind_sum failed.");
            }

            size_t k = 0;
            for (k = 0; k < 32; k++) {
                if (r.vBlind[k] != 0) break;
            }
            if (k == 32) {
                // bulletproof_rangeproof checks for 0
                return wserrorN(1, sError, __func__, "Zero blind sum.");
            }
            if (0 != AddCTData(coinControl, pout, r, sError)) {
                return 1; // sError will be set
            }
        }


        std::vector<uint8_t> &vData = *txNew.vpout[0]->GetPData();
        vData.resize(1);
        if (0 != part::PutVarInt(vData, nFeeRet)) {
            return werrorN(1, "%s: PutVarInt %d failed\n", __func__, nFeeRet);
        }
        if (coinControl->m_spend_frozen_blinded) {
            // Embed the blinding factor in the change data output
            vData.push_back(DO_MASK);
            size_t start = vData.size();
            vData.resize(start + 32);
            if (!secp256k1_pedersen_blind_sum(secp256k1_ctx_blind, vData.data() + start, &vpBlinds[0], vpBlinds.size(), nBlindedInputs)) {
                return wserrorN(1, sError, __func__, "secp256k1_pedersen_blind_sum failed.");
            }
        }

        if (sign) {
            int nIn = 0;
            for (const auto &coin : setCoins) {
                const uint256 &txhash = coin.first->first;
                const COutputRecord *oR = coin.first->second.GetOutput(coin.second);
                if (!oR) {
                    return werrorN(1, "%s: GetOutput %s failed.\n", __func__, txhash.ToString().c_str());
                }

                const CScript &scriptPubKey = oR->scriptPubKey;

                CStoredTransaction stx;
                if (!CHDWalletDB(*m_database).ReadStoredTx(txhash, stx)) {
                    return werrorN(1, "%s: ReadStoredTx failed for %s.\n", __func__, txhash.ToString().c_str());
                }
                std::vector<uint8_t> vchAmount;
                stx.tx->vpout[coin.second]->PutValue(vchAmount);

                SignatureData sigdata;
                auto provider = GetLegacyScriptPubKeyMan();
                if (!provider) {
                    return wserrorN(1, sError, __func__, _("GetLegacyScriptPubKeyMan failed").translated);
                }
                if (!ProduceSignature(*provider, MutableTransactionSignatureCreator(&txNew, nIn, vchAmount, SIGHASH_ALL), scriptPubKey, sigdata)) {
                    return wserrorN(1, sError, __func__, _("Signing transaction failed").translated);
                }
                UpdateInput(txNew.vin[nIn], sigdata);

                nIn++;
            }
        }


        rtx.nFee = nFeeRet;
        AddOutputRecordMetaData(rtx, vecSend);

        // Embed the constructed transaction data in wtxNew.
        wtx.SetTx(MakeTransactionRef(std::move(txNew)));
    }

    if (0 != PreAcceptMempoolTx(this, wtx, sError)) {
        return 1;
    }

    double all_est = feeCalc.est.pass.totalConfirmed + feeCalc.est.pass.inMempool + feeCalc.est.pass.leftMempool;
    if (all_est == 0.0) all_est = 1.0;
    WalletLogPrintf("Fee Calculation: Fee:%d Bytes:%u Needed:%d Tgt:%d (requested %d) Reason:\"%s\" Decay %.5f: Estimation: (%g - %g) %.2f%% %.1f/(%.1f %d mem %.1f out) Fail: (%g - %g) %.2f%% %.1f/(%.1f %d mem %.1f out)\n",
              nFeeRet, nBytes, nFeeNeeded, feeCalc.returnedTarget, feeCalc.desiredTarget, StringForFeeReason(feeCalc.reason), feeCalc.est.decay,
              feeCalc.est.pass.start, feeCalc.est.pass.end,
              100 * feeCalc.est.pass.withinTarget / all_est,
              feeCalc.est.pass.withinTarget, feeCalc.est.pass.totalConfirmed, feeCalc.est.pass.inMempool, feeCalc.est.pass.leftMempool,
              feeCalc.est.fail.start, feeCalc.est.fail.end,
              100 * feeCalc.est.fail.withinTarget / all_est,
              feeCalc.est.fail.withinTarget, feeCalc.est.fail.totalConfirmed, feeCalc.est.fail.inMempool, feeCalc.est.fail.leftMempool);
    return 0;
};

int CHDWallet::AddBlindedInputs(CWalletTx &wtx, CTransactionRecord &rtx,
    std::vector<CTempRecipient> &vecSend, bool sign, CAmount &nFeeRet, const CCoinControl *coinControl, std::string &sError)
{
    ClearTxCreationState();

    if (vecSend.size() < 1) {
        return wserrorN(1, sError, __func__, _("Transaction must have at least one recipient.").translated);
    }

    CAmount nValue = 0;
    for (const auto &r : vecSend) {
        nValue += r.nAmount;
        if (nValue < 0 || r.nAmount < 0) {
            return wserrorN(1, sError, __func__, _("Transaction amounts must not be negative.").translated);
        }
    }

    CExtKeyAccount *sea;
    CStoredExtKey *pcC = nullptr;
    if (0 != GetDefaultConfidentialChain(nullptr, sea, pcC)) {
        //return errorN(1, sError, __func__, _("Could not get confidential chain from account.").c_str());
    }

    uint32_t nLastHardened = pcC ? pcC->nHGenerated : 0;
    if (0 != AddBlindedInputs(wtx, rtx, vecSend, sea, pcC, sign, nFeeRet, coinControl, sError)) {
        // sError will be set
        if (pcC) {
            pcC->nHGenerated = nLastHardened; // reset
        }
        return 1;
    }

    if (pcC) {
        LOCK(cs_wallet);
        CHDWalletDB wdb(*m_database);

        std::vector<uint8_t> vEphemPath;
        uint32_t idIndex;
        bool requireUpdateDB;
        if (0 == ExtKeyGetIndex(&wdb, sea, idIndex, requireUpdateDB)) {
            PushUInt32(vEphemPath, idIndex);

            if (0 == AppendChainPath(pcC, vEphemPath)) {
                uint32_t nChild = nLastHardened;
                PushUInt32(vEphemPath, SetHardenedBit(nChild));
                rtx.mapValue[RTXVT_EPHEM_PATH] = vEphemPath;
            } else {
                WalletLogPrintf("Warning: %s - missing path value.\n", __func__);
                vEphemPath.clear();
            }
        } else {
            WalletLogPrintf("Warning: %s - ExtKeyGetIndex failed %s.\n", __func__, pcC->GetIDString58());
        }

        CKeyID idChain = pcC->GetID();
        if (!wdb.WriteExtKey(idChain, *pcC)) {
            pcC->nHGenerated = nLastHardened;
            return wserrorN(1, sError, __func__, "WriteExtKey failed.");
        }
    }

    return 0;
};

int CHDWallet::PlaceRealOutputs(std::vector<std::vector<int64_t> > &vMI, size_t &nSecretColumn, size_t nRingSize, std::set<int64_t> &setHave,
    const std::vector<std::pair<MapRecords_t::const_iterator,unsigned int> > &vCoins, std::vector<uint8_t> &vInputBlinds, const CCoinControl *coinControl, std::string &sError)
{
    assert(coinControl);
    // Allow incorrect ring-size for testing
    size_t min_ringsize = Params().IsMockableChain() ? MIN_RINGSIZE : Params().GetConsensus().m_min_ringsize_post_hf2;
    if (nRingSize < MIN_RINGSIZE || nRingSize > MAX_RINGSIZE ||
        (!coinControl->m_spend_frozen_blinded && nRingSize < min_ringsize)) {
        return wserrorN(1, sError, __func__, _("Ring size out of range [%d, %d]").translated, MIN_RINGSIZE, MAX_RINGSIZE);
    }

    nSecretColumn = GetRandInt(nRingSize);

    CHDWalletDB wdb(*m_database);
    vMI.resize(vCoins.size());

    for (size_t k = 0; k < vCoins.size(); ++k) {
        vMI[k].resize(nRingSize);
        for (size_t i = 0; i < nRingSize; ++i) {
            if (i == nSecretColumn) {
                // TODO: Store pubkey on COutputRecord - in scriptPubKey?
                const auto &coin = vCoins[k];
                const uint256 &txhash = coin.first->first;
                COutPoint op(txhash, coin.second);
                const CCmpPubKey *pk = nullptr;
                CStoredTransaction stx;

                std::map<COutPoint, CInputData>::const_iterator it = coinControl->m_inputData.find(op);
                if (it != coinControl->m_inputData.end()) {
                    LogPrint(BCLog::HDWALLET, "%s: Using supplied data for input %s %d.\n", GetName(), txhash.ToString().c_str(), coin.second);
                    if (it->second.nType != OUTPUT_RINGCT) {
                        return wserrorN(1, sError, __func__, _("Not an anon output %s %d").translated, txhash.ToString().c_str(), coin.second);
                    }
                    pk = &it->second.pubkey;
                    if (it->second.blind.IsNull()) {
                        return wserrorN(1, sError, __func__, _("Blinding factor is null %s %d").translated, txhash.ToString().c_str(), coin.second);
                    }
                    memcpy(&vInputBlinds[k * 32], it->second.blind.data(), 32);
                } else {
                    if (!wdb.ReadStoredTx(txhash, stx)) {
                        return wserrorN(1, sError, __func__, "ReadStoredTx failed for %s", txhash.ToString().c_str());
                    }
                    if (!stx.tx->vpout[coin.second]->IsType(OUTPUT_RINGCT)) {
                        return wserrorN(1, sError, __func__, _("Not an anon output %s %d").translated, txhash.ToString().c_str(), coin.second);
                    }
                    pk = &(((CTxOutRingCT*)stx.tx->vpout[coin.second].get())->pk);
                    if (!stx.GetBlind(coin.second, &vInputBlinds[k * 32])) {
                        return werrorN(1, "%s: GetBlind failed for %s, %d.\n", __func__, txhash.ToString().c_str(), coin.second);
                    }
                }
                assert(pk);

                int64_t index;
                if (!pblocktree->ReadRCTOutputLink(*pk, index)) {
                    return wserrorN(1, sError, __func__, _("Anon pubkey not found in db, %s").translated, HexStr(*pk));
                }
                if (setHave.count(index)) {
                    return wserrorN(1, sError, __func__, _("Duplicate index found, %d").translated, index);
                }

                vMI[k][i] = index;
                setHave.insert(index);
                continue;
            }
        }
    }

    return 0;
};

int CHDWallet::PickHidingOutputs(std::vector<std::vector<int64_t> > &vMI,
    size_t nSecretColumn, size_t nRingSize, std::set<int64_t> &setHave, const CCoinControl *coinControl, std::string &sError)
{
    assert(coinControl);
    LOCK(cs_main);

    switch (coinControl->m_mixin_selection_mode) {
        case MIXIN_SEL_RECENT: // mostly recent
            break;
        case MIXIN_SEL_NEARBY: // nearby real outputs
            break;
        case MIXIN_SEL_FULL_RANGE:
            break;
        case MIXIN_SEL_DEBUG:
            break;
        default:
            return wserrorN(1, sError, __func__, _("Unknown mixin selection mode: %d").translated, coinControl->m_mixin_selection_mode);
    }

    const Consensus::Params &consensusParams = Params().GetConsensus();
    bool exploit_fix_2_active = GetTime() >= consensusParams.exploit_fix_2_time;
    size_t min_ringsize = Params().IsMockableChain() ? MIN_RINGSIZE : Params().GetConsensus().m_min_ringsize_post_hf2; // Allow incorrect size for testing
    if (nRingSize < min_ringsize || nRingSize > MAX_RINGSIZE) {
        return wserrorN(1, sError, __func__, _("Ring size out of range [%d, %d]").translated, MIN_RINGSIZE, MAX_RINGSIZE);
    }

    int nBestHeight = chain().getHeightInt();
    size_t nInputs = vMI.size();
    int64_t nLastRCTOutIndex = chain().getAnonOutputs();

    // Remove outputs without required depth
    while (nLastRCTOutIndex > 1) {
        CAnonOutput ao;
        if (!pblocktree->ReadRCTOutput(nLastRCTOutIndex, ao)) {
            return wserrorN(1, sError, __func__, _("Anon output not found in db, %d").translated, nLastRCTOutIndex);
        }
        if (nBestHeight - ao.nBlockHeight + 1 < consensusParams.nMinRCTOutputDepth) {
            nLastRCTOutIndex--;
            continue;
        }
        break;
    }

    if (LogAcceptCategory(BCLog::HDWALLET)) {
        WalletLogPrintf("%s: Last index %d, inputs %d, ring size %d, selection mode %d.\n", __func__, nLastRCTOutIndex, nInputs, nRingSize, coinControl->m_mixin_selection_mode);
    }
    int64_t min_anon_input = 1;
    int64_t available_outputs = nLastRCTOutIndex;
    if (exploit_fix_2_active) {
        available_outputs -= consensusParams.m_frozen_anon_index;
        min_anon_input = consensusParams.m_frozen_anon_index + 1;
        if (LogAcceptCategory(BCLog::HDWALLET)) {
            WalletLogPrintf("%s: Set min anon input to %d.\n", __func__, min_anon_input);
        }
    }
    if (coinControl->m_mixin_selection_mode != MIXIN_SEL_DEBUG &&
        available_outputs < (int64_t)(nInputs * nRingSize)) {
        return wserrorN(1, sError, __func__, _("Not enough anon outputs exist, last: %d, required: %d").translated, available_outputs, nInputs * nRingSize);
    }

    // Must add real outputs to setHave before adding the decoys.
    std::vector<int64_t> real_inputs;
    real_inputs.reserve(setHave.size());
    for (const auto &i : setHave) {
        real_inputs.push_back(i);
    }

    static const int max_groups = 4;
    static const double distribution[] = {0.6, 0.75, 0.85, 0.93};
    int64_t range_periods[] = {1, 7, 31, 365};
    int64_t expect_aos_per_period = 500;

    static const double range_blur = 0.3;
    int64_t ranges[max_groups];

    if (coinControl->m_mixin_selection_mode == MIXIN_SEL_RECENT) {
        for (int j = 0; j < max_groups; j++) {
            ranges[j] = expect_aos_per_period * range_periods[j];

            int64_t output_id = nLastRCTOutIndex - std::min(nLastRCTOutIndex-1, std::max(min_anon_input, ranges[j]));
            CAnonOutput ao;
            if (!pblocktree->ReadRCTOutput(output_id, ao)) {
                return wserrorN(1, sError, __func__, _("Anon output not found in db, %d").translated, output_id);
            }

            int num_blocks = nBestHeight - ao.nBlockHeight;
            if (num_blocks) {
                double ratio = ((double) range_periods[j] / ((double) num_blocks / 720.0));
                if (ratio > 1.0) {
                    if (LogAcceptCategory(BCLog::HDWALLET)) {
                        WalletLogPrintf("%s: Adjusting range, anon-outputs %d, blocks %d, ratio %f.\n", __func__, ranges[j], num_blocks, ratio);
                    }
                    ranges[j] *= ratio;
                }
            }
            ranges[j] += (int64_t) GetRand((uint64_t)((double)ranges[j] * range_blur));
        }
    }

    size_t used_presets = 0;
    for (size_t k = 0; k < nInputs; ++k)
    for (size_t i = 0; i < nRingSize; ++i) {
        if (i == nSecretColumn) {
            continue;
        }

        size_t j = 0;
        const static size_t nMaxTries = 1000;
        for (j = 0; j < nMaxTries; ++j) {
            if (used_presets < coinControl->m_use_mixins.size()) {
                int64_t nDecoy = coinControl->m_use_mixins[used_presets++];
                if (setHave.count(nDecoy) > 0) {
                    continue;
                }
                vMI[k][i] = nDecoy;
                setHave.insert(nDecoy);
                break;
                if (LogAcceptCategory(BCLog::HDWALLET)) {
                    WalletLogPrintf("Adding decoy %d, from presets.\n", nDecoy);
                }
            }

            int64_t select_min = min_anon_input;
            int64_t select_max = nLastRCTOutIndex;

            if (coinControl->m_mixin_selection_mode == MIXIN_SEL_RECENT) {
                static const int max_r = 1000;
                int g_r = GetRandInt(max_r);
                for (int j = 0; j < max_groups; j++) {
                    if (g_r <= max_r * distribution[j]) {
                        select_min = nLastRCTOutIndex - ranges[j];
                        break;
                    }
                    select_max -= ranges[j];
                }
                if (select_max <= 1) { // Select from entire range if too few mixins exist
                    select_max = nLastRCTOutIndex;
                }
                select_min = std::min(nLastRCTOutIndex, std::max(min_anon_input, select_min));
                select_max = std::min(nLastRCTOutIndex, std::max(min_anon_input, select_max));
            } else
            if (coinControl->m_mixin_selection_mode == MIXIN_SEL_NEARBY) {
                int64_t select_range = 0;
                int64_t select_near = 0;
                if (GetRandInt(100) < 50) { // 50% chance of selecting within 5000 places of a random input
                    select_range = nRCTOutSelectionGroup1;
                    select_near = real_inputs[GetRandInt(real_inputs.size())];
                } else
                if (GetRandInt(100) < 40) { // Further 40% chance of selecting within 50000 places of a random input
                    select_range = nRCTOutSelectionGroup2;
                    select_near = real_inputs[GetRandInt(real_inputs.size())];
                }

                if (select_near) {
                    // Randomly offset the range
                    select_near = std::max(min_anon_input, int64_t((select_near - select_range) + (select_range * 2.0) * GetRandDoubleUnit()));

                    select_min = std::min(nLastRCTOutIndex, std::max(min_anon_input, select_near - select_range));
                    select_max = std::min(nLastRCTOutIndex, select_near + select_range);

                    int64_t num_blocks, num_aos = select_max - select_min;
                    CAnonOutput ao_min, ao_max;
                    if (!pblocktree->ReadRCTOutput(select_min, ao_min)) {
                        return wserrorN(1, sError, __func__, _("Anon output not found in db, %d").translated, select_min);
                    }
                    if (!pblocktree->ReadRCTOutput(select_max, ao_max)) {
                        return wserrorN(1, sError, __func__, _("Anon output not found in db, %d").translated, select_max);
                    }
                    num_blocks = ao_max.nBlockHeight - ao_min.nBlockHeight;

                    if (num_blocks) {
                        double ratio = ((double) num_aos * 2.0) / ((double) num_blocks);
                        if (ratio > 1.0) {
                            if (LogAcceptCategory(BCLog::HDWALLET)) {
                                WalletLogPrintf("%s: Adjusting range, anon-outputs %d, blocks %d, ratio %f.\n", __func__, num_aos, num_blocks, ratio);
                            }
                            select_range *= ratio;
                            select_min = std::min(nLastRCTOutIndex, std::max(min_anon_input, select_near - select_range));
                            select_max = std::min(nLastRCTOutIndex, select_near + select_range);
                        }
                    }
                }
            }

            int64_t nDecoy = select_min;
            if (select_max - select_min > 0) {
                // GetRand(0) silently returns a value out of range
                nDecoy += GetRand(select_max - select_min);
            }
            if (setHave.count(nDecoy) > 0) {
                if (nDecoy == nLastRCTOutIndex) {
                    nLastRCTOutIndex--;
                }
                continue;
            }

            vMI[k][i] = nDecoy;
            setHave.insert(nDecoy);

            if (LogAcceptCategory(BCLog::HDWALLET)) {
                WalletLogPrintf("Adding decoy %d, from range (%d, %d).\n", nDecoy, select_min, select_max);
            }
            break;
        }

        if (j >= nMaxTries) {
            return wserrorN(1, sError, __func__, _("Hit nMaxTries limit, %d, %d, have %d, lastindex %d").translated, k, i, setHave.size(), nLastRCTOutIndex);
        }
    }

    return 0;
};

int CHDWallet::AddAnonInputs(CWalletTx &wtx, CTransactionRecord &rtx,
    std::vector<CTempRecipient> &vecSend,
    CExtKeyAccount *sea, CStoredExtKey *pc,
    bool sign, size_t nRingSize, size_t nInputsPerSig, CAmount &nFeeRet, const CCoinControl *coinControl, std::string &sError)
{
    assert(coinControl);
    size_t min_ringsize = Params().IsMockableChain() ? MIN_RINGSIZE : Params().GetConsensus().m_min_ringsize_post_hf2; // Allow incorrect size for testing
    if (nRingSize < MIN_RINGSIZE || nRingSize > MAX_RINGSIZE ||
        (!coinControl->m_spend_frozen_blinded && nRingSize < min_ringsize)) {
        return wserrorN(1, sError, __func__, _("Ring size out of range").translated);
    }
    if (nInputsPerSig < 1 || nInputsPerSig > MAX_ANON_INPUTS) {
        return wserrorN(1, sError, __func__, _("Num inputs per signature out of range").translated);
    }

    nFeeRet = 0;
    CAmount nValue;
    size_t nSubtractFeeFromAmount;
    bool fOnlyStandardOutputs;
    InspectOutputs(vecSend, nValue, nSubtractFeeFromAmount, fOnlyStandardOutputs);

    if (0 != ExpandTempRecipients(vecSend, pc, sError)) {
        return 1; // sError is set
    }

    wtx.fTimeReceivedIsTxTime = true;
    wtx.fFromMe = true;
    CMutableTransaction txNew;
    txNew.nVersion = PARTICL_TXN_VERSION;
    txNew.vout.clear();

    txNew.nLockTime = 0;

    coinControl->fHaveAnonOutputs = true;
    FeeCalculation feeCalc;
    CAmount nFeeNeeded;
    unsigned int nBytes;
    {
        LOCK(cs_wallet);

        std::vector<std::pair<MapRecords_t::const_iterator, unsigned int> > setCoins;
        std::vector<COutputR> vAvailableCoins;
        AvailableAnonCoins(vAvailableCoins, coinControl);

        CAmount nValueOutPlain = 0;
        int nChangePosInOut = -1;

        std::vector<std::vector<std::vector<int64_t> > > vMI;
        std::vector<std::vector<uint8_t> > vInputBlinds;
        std::vector<size_t> vSecretColumns;

        size_t nSubFeeTries = 100;
        bool pick_new_inputs = true;
        CAmount nValueIn = 0;
        // Start with no fee and loop until there is enough fee
        for (;;) {
            txNew.vin.clear();
            txNew.vpout.clear();
            wtx.fFromMe = true;

            CAmount nValueToSelect = nValue;
            if (nSubtractFeeFromAmount == 0) {
                nValueToSelect += nFeeRet;
            }

            // Choose coins to use
            if (pick_new_inputs) {
                nValueIn = 0;
                setCoins.clear();
                if (!SelectBlindedCoins(vAvailableCoins, nValueToSelect, setCoins, nValueIn, coinControl, true)) {
                    return wserrorN(1, sError, __func__, _("Insufficient funds.").translated);
                }
            }

            const CAmount nChange = nValueIn - nValueToSelect;

            // Remove fee outputs from last round
            for (int i = 0; i < (int) vecSend.size(); ++i) {
                if (vecSend[i].fChange) {
                    vecSend.erase(vecSend.begin() + i);
                    i--;
                }
            }

            if (coinControl->m_spend_frozen_blinded) {
                assert(!coinControl->m_addChangeOutput);
                if (nChange > DEFAULT_FALLBACK_FEE_PART) {
                    return wserrorN(1, sError, __func__, _("Change too high for frozen blinded spend.").translated);
                }
            }

            if (coinControl->m_addChangeOutput) {
                // Insert a sender-owned 0 value output that becomes the change output if needed
                CTempRecipient r;
                r.nType = OUTPUT_RINGCT;

                if (!SetChangeDest(coinControl, r, sError)) {
                    return wserrorN(1, sError, __func__, ("SetChangeDest failed: " + sError));
                }

                if (nChange > ::minRelayTxFee.GetFee(2048)) { // TODO: better output size estimate
                    r.SetAmount(nChange);
                } else {
                    r.SetAmount(0);
                    nFeeRet += nChange;
                }

                nChangePosInOut = coinControl->nChangePos;
                InsertChangeAddress(r, vecSend, nChangePosInOut);
            } else {
                nFeeRet += nChange;
            }

            int nSignSigs = 0;
            size_t nRemainingInputs = setCoins.size();
            while (nRemainingInputs > 0) {
                size_t nInputs = nRemainingInputs > nInputsPerSig ? nInputsPerSig : nRemainingInputs;
                CTxIn txin;
                txin.nSequence = CTxIn::SEQUENCE_FINAL;
                txin.prevout.n = COutPoint::ANON_MARKER;
                txin.SetAnonInfo(nInputs, nRingSize);
                txNew.vin.emplace_back(txin);

                nRemainingInputs -= nInputs;
                nSignSigs++;
            }

            vMI.resize(nSignSigs);
            vInputBlinds.resize(nSignSigs);
            vSecretColumns.resize(nSignSigs);

            nValueOutPlain = 0;
            nChangePosInOut = -1;

            OUTPUT_PTR<CTxOutData> outFee = MAKE_OUTPUT<CTxOutData>();
            outFee->vData.push_back(DO_FEE);
            outFee->vData.resize(9); // More bytes than varint fee could use
            if (coinControl->m_extra_data0.size() > 0) {
                outFee->vData.insert(outFee->vData.end(), coinControl->m_extra_data0.begin(), coinControl->m_extra_data0.end());
            }
            txNew.vpout.push_back(outFee);

            bool fFirst = true;
            for (size_t i = 0; i < vecSend.size(); ++i) {
                auto &r = vecSend[i];

                r.ApplySubFee(nFeeRet, nSubtractFeeFromAmount, fFirst);

                OUTPUT_PTR<CTxOutBase> txbout;

                if (0 != CreateOutput(txbout, r, sError)) {
                    return 1; // sError will be set
                }

                if (r.nType == OUTPUT_STANDARD) {
                    nValueOutPlain += r.nAmount;
                }

                if (r.fChange && r.nType == OUTPUT_RINGCT) {
                    nChangePosInOut = i;
                }

                r.n = txNew.vpout.size();
                txNew.vpout.push_back(txbout);

                if (r.nType == OUTPUT_CT || r.nType == OUTPUT_RINGCT) {
                    if (r.vBlind.size() != 32) {
                        r.vBlind.resize(32);
                        GetStrongRandBytes(&r.vBlind[0], 32);
                    } // else prefilled already

                    if (0 != AddCTData(coinControl, txbout.get(), r, sError)) {
                        return 1; // sError will be set
                    }
                }
            }

            std::set<int64_t> setHave; // Anon prev-outputs can only be used once per transaction.
            size_t nTotalInputs = 0;

            for (size_t l = 0; l < txNew.vin.size(); ++l) { // Must add real outputs to setHave before picking decoys
                auto &txin = txNew.vin[l];
                uint32_t nSigInputs, nSigRingSize;
                txin.GetAnonInfo(nSigInputs, nSigRingSize);

                vInputBlinds[l].resize(32 * nSigInputs);
                std::vector<std::pair<MapRecords_t::const_iterator, unsigned int> >
                    vCoins(setCoins.begin() + nTotalInputs, setCoins.begin() + nTotalInputs + nSigInputs);
                nTotalInputs += nSigInputs;

                if (0 != PlaceRealOutputs(vMI[l], vSecretColumns[l], nSigRingSize, setHave, vCoins, vInputBlinds[l], coinControl, sError)) {
                    return 1; // sError is set
                }
            }

            for (size_t l = 0; l < txNew.vin.size(); ++l) {
                auto &txin = txNew.vin[l];
                uint32_t nSigInputs, nSigRingSize;
                txin.GetAnonInfo(nSigInputs, nSigRingSize);

                if (nSigRingSize > 1 &&
                    0 != PickHidingOutputs(vMI[l], vSecretColumns[l], nSigRingSize, setHave, coinControl, sError)) {
                    return 1; // sError is set
                }

                std::vector<uint8_t> vPubkeyMatrixIndices;
                for (size_t k = 0; k < nSigInputs; ++k)
                for (size_t i = 0; i < nSigRingSize; ++i) {
                    part::PutVarInt(vPubkeyMatrixIndices, vMI[l][k][i]);
                }

                // Fill in dummy signatures for fee calculation.
                std::vector<uint8_t> vKeyImages(33 * nSigInputs);
                txin.scriptData.stack.emplace_back(vKeyImages);
                txin.scriptWitness.stack.emplace_back(vPubkeyMatrixIndices);

                std::vector<uint8_t> vDL((1 + (nSigInputs+1) * nSigRingSize) * 32 // extra element for C, extra row for commitment row
                    + (txNew.vin.size() > 1 ? 33 : 0)); // extra commitment for split value if multiple sigs
                txin.scriptWitness.stack.emplace_back(vDL);
            }

            nBytes = GetVirtualTransactionSize(CTransaction(txNew));

            nFeeNeeded = GetMinimumFee(*this, nBytes, *coinControl, &feeCalc);
            if (feeCalc.reason == FeeReason::FALLBACK && !m_allow_fallback_fee) {
                // eventually allow a fallback fee
                sError = _("Fee estimation failed. Fallbackfee is disabled. Wait a few blocks or enable -fallbackfee.").translated;
                return false;
            }

            if (nFeeRet >= nFeeNeeded) {
                // Reduce fee to only the needed amount if possible. This
                // prevents potential overpayment in fees if the coins
                // selected to meet nFeeNeeded result in a transaction that
                // requires less fee than the prior iteration.
                if (nFeeRet > nFeeNeeded && nChangePosInOut != -1
                    && nSubtractFeeFromAmount == 0) {
                    auto &r = vecSend[nChangePosInOut];

                    CAmount extraFeePaid = nFeeRet - nFeeNeeded;

                    r.nAmount += extraFeePaid;
                    nFeeRet -= extraFeePaid;
                }
                break; // Done, enough fee included.
            } else
            if (!pick_new_inputs) {
                // This shouldn't happen, we should have had enough excess
                // fee to pay for the new output and still meet nFeeNeeded
                // Or we should have just subtracted fee from recipients and
                // nFeeNeeded should not have changed

                if (!nSubtractFeeFromAmount || !(--nSubFeeTries)) { // rangeproofs can change size per iteration
                    return wserrorN(1, sError, __func__, _("Transaction fee and change calculation failed.").translated);
                }
                LogPrint(BCLog::HDWALLET, "%s: nSubFeeTries %d\n", __func__, nSubFeeTries);
            }

            // Try to reduce change to include necessary fee
            if (nChangePosInOut != -1
                && nSubtractFeeFromAmount == 0) {
                auto &r = vecSend[nChangePosInOut];

                CAmount additionalFeeNeeded = nFeeNeeded - nFeeRet;
                if (r.nAmount >= MIN_FINAL_CHANGE + additionalFeeNeeded) {
                    r.nAmount -= additionalFeeNeeded;
                    nFeeRet += additionalFeeNeeded;
                    break; // Done, able to increase fee from change
                }
            }

            // If subtracting fee from recipients, we now know what fee we
            // need to subtract, we have no reason to reselect inputs
            if (nSubtractFeeFromAmount > 0) {
                pick_new_inputs = false;
            }

            // Include more fee and try again.
            nFeeRet = nFeeNeeded;
            continue;
        }
        coinControl->nChangePos = nChangePosInOut + 1; // Add one for the fee output

        LogPrint(BCLog::HDWALLET, "%s: Using %d inputs, ringsize %d.\n", __func__, setCoins.size(), nRingSize);

        nValueOutPlain += nFeeRet;

        // Remove the fee calculation dummy signatures
        for (auto &txin : txNew.vin) {
            txin.scriptData.stack[0].resize(0);
            txin.scriptWitness.stack[1].resize(0);
        }

        // Add the plain commitment
        std::vector<const uint8_t*> vpOutCommits, vpOutBlinds;
        uint8_t blind_plain[32] = {0};
        secp256k1_pedersen_commitment plainCommitment;
        if (nValueOutPlain > 0) {
            if (!secp256k1_pedersen_commit(secp256k1_ctx_blind,
                &plainCommitment, blind_plain, (uint64_t) nValueOutPlain, &secp256k1_generator_const_h, &secp256k1_generator_const_g)) {
                return wserrorN(1, sError, __func__, "secp256k1_pedersen_commit failed for plain out.");
            }
            vpOutCommits.push_back(plainCommitment.data);
            vpOutBlinds.push_back(blind_plain);
        }

        // Update the change output commitment
        for (size_t i = 0; i < vecSend.size(); ++i) {
            auto &r = vecSend[i];

            if ((int)i == nChangePosInOut) {
                // Change amount may have changed

                if (r.nType != OUTPUT_RINGCT) {
                    return wserrorN(1, sError, __func__, "nChangePosInOut not anon.");
                }

                if (r.vBlind.size() != 32) {
                    r.vBlind.resize(32);
                    GetStrongRandBytes(&r.vBlind[0], 32);
                }

                if (0 != AddCTData(coinControl, txNew.vpout[r.n].get(), r, sError)) {
                    return 1; // sError will be set
                }
            }

            if (r.nType == OUTPUT_CT || r.nType == OUTPUT_RINGCT) {
                vpOutCommits.push_back(txNew.vpout[r.n]->GetPCommitment()->data);
                vpOutBlinds.push_back(&r.vBlind[0]);
            }
        }

        std::vector<uint8_t> &vData = *txNew.vpout[0]->GetPData();
        vData.resize(1);
        if (0 != part::PutVarInt(vData, nFeeRet)) {
            return werrorN(1, "%s: PutVarInt %d failed\n", __func__, nFeeRet);
        }
        if (coinControl->m_extra_data0.size() > 0) {
            vData.insert(vData.end(), coinControl->m_extra_data0.begin(), coinControl->m_extra_data0.end());
        }

        if (sign) {
            std::vector<CKey> &vSplitCommitBlindingKeys = coinControl->vSplitCommitBlindingKeys;
            vSplitCommitBlindingKeys.resize(txNew.vin.size());
            int rv;
            size_t nTotalInputs = 0;

            // All Keyimages must be set in advance, txn hash covers scriptData
            for (size_t l = 0; l < txNew.vin.size(); ++l) {
                auto &txin = txNew.vin[l];

                uint32_t nSigInputs, nSigRingSize;
                txin.GetAnonInfo(nSigInputs, nSigRingSize);

                std::vector<uint8_t> &vKeyImages = txin.scriptData.stack[0];
                vKeyImages.resize(33 * nSigInputs);

                for (size_t k = 0; k < nSigInputs; ++k) {
                    size_t i = vSecretColumns[l];
                    int64_t nIndex = vMI[l][k][i];

                    CAnonOutput ao;
                    if (!pblocktree->ReadRCTOutput(nIndex, ao)) {
                        return wserrorN(1, sError, __func__, _("Anon output not found in db, %d").translated, nIndex);
                    }

                    CKeyID idk = ao.pubkey.GetID();
                    CKey key;
                    if (!coinControl->SetKeyFromInputData(idk, key) && !GetKey(idk, key)) {
                        return wserrorN(1, sError, __func__, _("No key for anonoutput, %s").translated, HexStr(ao.pubkey));
                    }

                    // Keyimage is required for the tx hash
                    if (0 != (rv = secp256k1_get_keyimage(secp256k1_ctx_blind, &vKeyImages[k * 33], ao.pubkey.begin(), key.begin()))) {
                        return wserrorN(1, sError, __func__, "secp256k1_get_keyimage failed %d", rv);
                    }
                }
            }

            for (size_t l = 0; l < txNew.vin.size(); ++l) {
                auto &txin = txNew.vin[l];

                uint32_t nSigInputs, nSigRingSize;
                txin.GetAnonInfo(nSigInputs, nSigRingSize);

                size_t nCols = nSigRingSize;
                size_t nRows = nSigInputs + 1;

                uint8_t randSeed[32];
                GetStrongRandBytes(randSeed, 32);

                std::vector<CKey> vsk(nSigInputs);
                std::vector<const uint8_t*> vpsk(nRows), vpBlinds, vpInCommits(nCols * nSigInputs);
                std::vector<uint8_t> vm(nCols * nRows * 33);
                std::vector<uint8_t> &vKeyImages = txin.scriptData.stack[0];
                std::vector<uint8_t> &vDL = txin.scriptWitness.stack[1];
                std::vector<secp256k1_pedersen_commitment> vCommitments;
                vCommitments.reserve(nCols * nSigInputs);

                for (size_t k = 0; k < nSigInputs; ++k)
                for (size_t i = 0; i < nCols; ++i) {
                    int64_t nIndex = vMI[l][k][i];

                    CAnonOutput ao;
                    if (!pblocktree->ReadRCTOutput(nIndex, ao)) {
                        return wserrorN(1, sError, __func__, _("Anon output not found in db, %d").translated, nIndex);
                    }

                    memcpy(&vm[(i+k*nCols)*33], ao.pubkey.begin(), 33);
                    vCommitments.push_back(ao.commitment);
                    vpInCommits[i+k*nCols] = vCommitments.back().data;

                    if (i == vSecretColumns[l]) {
                        CKeyID idk = ao.pubkey.GetID();
                        if (!coinControl->SetKeyFromInputData(idk, vsk[k]) && !GetKey(idk, vsk[k])) {
                            return wserrorN(1, sError, __func__, _("No key for anonoutput, %s").translated, HexStr(ao.pubkey));
                        }
                        vpsk[k] = vsk[k].begin();
                        vpBlinds.push_back(&vInputBlinds[l][k * 32]);
                    }
                }

                uint8_t blindSum[32] = {0};
                vpsk[nRows-1] = blindSum;
                if (txNew.vin.size() == 1) {
                    vDL.resize((1 + (nSigInputs+1) * nSigRingSize) * 32); // extra element for C, extra row for commitment row
                    vpBlinds.insert(vpBlinds.end(), vpOutBlinds.begin(), vpOutBlinds.end());

                    if (0 != (rv = secp256k1_prepare_mlsag(&vm[0], blindSum,
                        vpOutCommits.size(), vpOutCommits.size(), nCols, nRows,
                        &vpInCommits[0], &vpOutCommits[0], &vpBlinds[0]))) {
                        return wserrorN(1, sError, __func__, "secp256k1_prepare_mlsag failed %d", rv);
                    }
                } else {
                    vDL.resize((1 + (nSigInputs+1) * nSigRingSize) * 32 + 33); // extra element for C extra, extra row for commitment row, split input commitment

                    if (l == txNew.vin.size()-1) {
                        std::vector<const uint8_t*> vpAllBlinds = vpOutBlinds;

                        for (size_t k = 0; k < l; ++k) {
                            vpAllBlinds.push_back(vSplitCommitBlindingKeys[k].begin());
                        }

                        if (!secp256k1_pedersen_blind_sum(secp256k1_ctx_blind,
                            vSplitCommitBlindingKeys[l].begin_nc(), &vpAllBlinds[0],
                            vpAllBlinds.size(), vpOutBlinds.size())) {
                            return wserrorN(1, sError, __func__, "secp256k1_pedersen_blind_sum failed.");
                        }
                    } else {
                        vSplitCommitBlindingKeys[l].MakeNewKey(true);
                    }

                    CAmount nCommitValue = 0;
                    for (size_t k = 0; k < nSigInputs; ++k) {
                        const auto &coin = setCoins[nTotalInputs+k];
                        const COutputRecord *oR = coin.first->second.GetOutput(coin.second);
                        nCommitValue += oR->nValue;
                    }

                    nTotalInputs += nSigInputs;

                    secp256k1_pedersen_commitment splitInputCommit;
                    if (!secp256k1_pedersen_commit(secp256k1_ctx_blind,
                        &splitInputCommit, (uint8_t*)vSplitCommitBlindingKeys[l].begin(),
                        nCommitValue, &secp256k1_generator_const_h, &secp256k1_generator_const_g)) {
                        return wserrorN(1, sError, __func__, "secp256k1_pedersen_commit failed.");
                    }

                    memcpy(&vDL[(1 + (nSigInputs+1) * nSigRingSize) * 32], splitInputCommit.data, 33);

                    vpBlinds.emplace_back(vSplitCommitBlindingKeys[l].begin());
                    const uint8_t *pSplitCommit = splitInputCommit.data;

                    if (0 != (rv = secp256k1_prepare_mlsag(&vm[0], blindSum,
                        1, 1, nCols, nRows,
                        &vpInCommits[0], &pSplitCommit, &vpBlinds[0]))) {
                        return wserrorN(1, sError, __func__, "secp256k1_prepare_mlsag failed %d", rv);
                    }

                    vpBlinds.pop_back();
                }

                uint256 txhash = txNew.GetHash();
                if (0 != (rv = secp256k1_generate_mlsag(secp256k1_ctx_blind, vKeyImages.data(), &vDL[0], &vDL[32],
                    randSeed, txhash.begin(), nCols, nRows, vSecretColumns[l],
                    &vpsk[0], &vm[0]))) {
                    return wserrorN(1, sError, __func__, "secp256k1_generate_mlsag failed %d", rv);
                }
            }
        }

        rtx.nFee = nFeeRet;
        AddOutputRecordMetaData(rtx, vecSend);

        // Embed the constructed transaction data in wtxNew.
        wtx.SetTx(MakeTransactionRef(std::move(txNew)));
    }

    if (0 != PreAcceptMempoolTx(this, wtx, sError)) {
        return 1;
    }

    double all_est = feeCalc.est.pass.totalConfirmed + feeCalc.est.pass.inMempool + feeCalc.est.pass.leftMempool;
    if (all_est == 0.0) all_est = 1.0;
    WalletLogPrintf("Fee Calculation: Fee:%d Bytes:%u Needed:%d Tgt:%d (requested %d) Reason:\"%s\" Decay %.5f: Estimation: (%g - %g) %.2f%% %.1f/(%.1f %d mem %.1f out) Fail: (%g - %g) %.2f%% %.1f/(%.1f %d mem %.1f out)\n",
              nFeeRet, nBytes, nFeeNeeded, feeCalc.returnedTarget, feeCalc.desiredTarget, StringForFeeReason(feeCalc.reason), feeCalc.est.decay,
              feeCalc.est.pass.start, feeCalc.est.pass.end,
              100 * feeCalc.est.pass.withinTarget / all_est,
              feeCalc.est.pass.withinTarget, feeCalc.est.pass.totalConfirmed, feeCalc.est.pass.inMempool, feeCalc.est.pass.leftMempool,
              feeCalc.est.fail.start, feeCalc.est.fail.end,
              100 * feeCalc.est.fail.withinTarget / all_est,
              feeCalc.est.fail.withinTarget, feeCalc.est.fail.totalConfirmed, feeCalc.est.fail.inMempool, feeCalc.est.fail.leftMempool);
    return 0;
};

int CHDWallet::AddAnonInputs(CWalletTx &wtx, CTransactionRecord &rtx,
    std::vector<CTempRecipient> &vecSend, bool sign, size_t nRingSize, size_t nSigs, CAmount &nFeeRet, const CCoinControl *coinControl, std::string &sError)
{
    ClearTxCreationState();

    if (vecSend.size() < 1 && (!coinControl || coinControl->m_extra_data0.size() < 1)) {
        return wserrorN(1, sError, __func__, _("Transaction must have at least one recipient.").translated);
    }

    CAmount nValue = 0;
    for (const auto &r : vecSend) {
        nValue += r.nAmount;
        if (nValue < 0 || r.nAmount < 0) {
            return wserrorN(1, sError, __func__, _("Transaction amounts must not be negative.").translated);
        }
    }

    CExtKeyAccount *sea;
    CStoredExtKey *pcC = nullptr;
    if (0 != GetDefaultConfidentialChain(nullptr, sea, pcC)) {
        //return errorN(1, sError, __func__, _("Could not get confidential chain from account.").c_str());
    }

    uint32_t nLastHardened = pcC ? pcC->nHGenerated : 0;
    if (0 != AddAnonInputs(wtx, rtx, vecSend, sea, pcC, sign, nRingSize, nSigs, nFeeRet, coinControl, sError)) {
        // sError will be set
        if (pcC) {
            pcC->nHGenerated = nLastHardened; // reset
        }
        return 1;
    }

    if (pcC) {
        LOCK(cs_wallet);
        CHDWalletDB wdb(*m_database);

        std::vector<uint8_t> vEphemPath;
        uint32_t idIndex;
        bool requireUpdateDB;
        if (0 == ExtKeyGetIndex(&wdb, sea, idIndex, requireUpdateDB)) {
            PushUInt32(vEphemPath, idIndex);

            if (0 == AppendChainPath(pcC, vEphemPath)) {
                uint32_t nChild = nLastHardened;
                PushUInt32(vEphemPath, SetHardenedBit(nChild));
                rtx.mapValue[RTXVT_EPHEM_PATH] = vEphemPath;
            } else {
                WalletLogPrintf("Warning: %s - missing path value.\n", __func__);
                vEphemPath.clear();
            }
        } else {
            WalletLogPrintf("Warning: %s - ExtKeyGetIndex failed %s.\n", __func__, pcC->GetIDString58());
        }

        CKeyID idChain = pcC->GetID();
        if (!wdb.WriteExtKey(idChain, *pcC)) {
            pcC->nHGenerated = nLastHardened;
            return wserrorN(1, sError, __func__, "WriteExtKey failed.");
        }
    }

    return 0;
};

void CHDWallet::ClearCachedBalances()
{
    // Clear cache when a new txn is added to the wallet or a block is added or removed from the chain.
    m_have_spendable_balance_cached = false;
    m_have_cached_stakeable_coins = false;
    return;
}

bool CHDWallet::LoadToWallet(const uint256& hash, const UpdateWalletTxFn& fill_wtx)
{
    CWallet::LoadToWallet(hash, fill_wtx);

    auto mi = mapWallet.find(hash);
    if (mi != mapWallet.end()) {
        CWalletTx &wtxIn = mi->second;
        int nBestHeight = chain().getHeightInt();
        if (wtxIn.IsCoinStake() && wtxIn.isAbandoned()) {
            int csHeight;
            if (wtxIn.tx->GetCoinStakeHeight(csHeight)
                && csHeight > nBestHeight - (particl::MAX_STAKE_SEEN_SIZE * 1.5)) {
                // Add to MapStakeSeen to prevent node submitting a block that would be rejected.
                LOCK(cs_main);
                const COutPoint &kernel = wtxIn.tx->vin[0].prevout;
                uint256 hash = wtxIn.GetHash();
                particl::AddToMapStakeSeen(kernel, hash);
            }
        }
    }

    return true;
};

void CHDWallet::LoadToWallet(const uint256 &hash, CTransactionRecord &rtx)
{
    std::optional<int> block_height = chain().getBlockHeight(rtx.blockHash);
    if (block_height) {
        rtx.block_height = *block_height;
    }

    std::pair<MapRecords_t::iterator, bool> ret = mapRecords.insert(std::make_pair(hash, rtx));

    MapRecords_t::iterator mri = ret.first;
    rtxOrdered.insert(std::make_pair(rtx.GetTxTime(), mri));

    // TODO: Spend only owned inputs?

    return;
};

void CHDWallet::blockConnected(const CBlock& block, int height)
{
    m_found_tx_in_block = false;
    CWallet::blockConnected(block, height);

    if (m_found_tx_in_block && !chain().isInitialBlockDownload()) {
        // Meant to wake the staking thread from a possible long sleep if the balance has changed.
        WakeThreadStakeMiner(this);
    }
}

void CHDWallet::leavingIBD()
{
}

void CHDWallet::RemoveFromTxSpends(const uint256 &hash, const CTransactionRef pt)
{
    for (const auto &txin : pt->vin) {
        std::pair<TxSpends::iterator, TxSpends::iterator> ip = mapTxSpends.equal_range(txin.prevout);
        for (auto it = ip.first; it != ip.second; ) {
            if (it->second == hash) {
                mapTxSpends.erase(it++);
                continue;
            }
            ++it;
        }
    }
    return;
};

int CHDWallet::UnloadTransaction(const uint256 &hash)
{
    // Remove txn from wallet, inc TxSpends
    if (LogAcceptCategory(BCLog::HDWALLET)) {
        WalletLogPrintf("%s: %s.\n", __func__, hash.ToString());
    }

    MapWallet_t::iterator itw;
    MapRecords_t::iterator itr;
    if ((itw = mapWallet.find(hash)) != mapWallet.end()) {
        CWalletTx *pcoin = &itw->second;

        RemoveFromTxSpends(hash, pcoin->tx);

        wtxOrdered.erase(pcoin->m_it_wtxOrdered);

        mapWallet.erase(itw);
    } else
    if ((itr = mapRecords.find(hash)) != mapRecords.end()) {
        CStoredTransaction stx;
        if (!CHDWalletDB(*m_database).ReadStoredTx(hash, stx)) { // TODO: cache / use mapTempWallet
            WalletLogPrintf("%s: ReadStoredTx failed for %s.\n", __func__, hash.ToString());
        } else {
            RemoveFromTxSpends(hash, stx.tx);
        }

        for (auto it = rtxOrdered.cbegin(); it != rtxOrdered.cend(); ) {
            //if (it->second->first == hash)
            if (it->second == itr) {
                rtxOrdered.erase(it++);
                break;
            }
            ++it;
        }

        mapRecords.erase(itr);
    } else {
        WalletLogPrintf("Warning: %s - tx not found in wallet! %s.\n", __func__, hash.ToString());
        return 1;
    }

    NotifyTransactionChanged(hash, CT_DELETED);
    return 0;
};

int CHDWallet::GetDefaultConfidentialChain(CHDWalletDB *pwdb, CExtKeyAccount *&sea, CStoredExtKey *&pc)
{
    pc = nullptr;
    LOCK(cs_wallet);

    ExtKeyAccountMap::iterator mi = mapExtAccounts.find(idDefaultAccount);
    if (mi == mapExtAccounts.end()) {
        return werrorN(1, "%s: %s.", __func__, "Default account not found");
    }

    sea = mi->second;
    mapEKValue_t::iterator mvi = sea->mapValue.find(EKVT_CONFIDENTIAL_CHAIN);
    if (mvi != sea->mapValue.end()) {
        uint64_t n;
        GetCompressedInt64(mvi->second, n);
        if ((pc = sea->GetChain(n))) {
            return 0;
        }

        return werrorN(1, "%s: %s.", __func__, "Confidential chain set but not found");
    }

    if (LogAcceptCategory(BCLog::HDWALLET)) {
        WalletLogPrintf("Adding confidential chain to account: %s.\n", sea->GetIDString58());
    }

    size_t nConfidential = sea->vExtKeys.size();

    CStoredExtKey *sekAccount = sea->ChainAccount();
    if (!sekAccount) {
        return werrorN(1, "%s: %s.", __func__, "Account chain not found");
    }

    std::vector<uint8_t> vAccountPath, vSubKeyPath, v;
    mvi = sekAccount->mapValue.find(EKVT_PATH);
    if (mvi != sekAccount->mapValue.end()) {
        vAccountPath = mvi->second;
    }

    CExtKey evConfidential;
    uint32_t nChild;
    if (0 != sekAccount->DeriveNextKey(evConfidential, nChild, true)) {
        return werrorN(1, "%s: %s.", __func__, "DeriveNextKey failed");
    }

    CStoredExtKey *sekConfidential = new CStoredExtKey();
    sekConfidential->kp = CExtKeyPair(evConfidential);
    vSubKeyPath = vAccountPath;
    SetHardenedBit(nChild);
    sekConfidential->mapValue[EKVT_PATH] = PushUInt32(vSubKeyPath, nChild);
    sekConfidential->nFlags |= EAF_ACTIVE | EAF_IN_ACCOUNT;
    sekConfidential->mapValue[EKVT_KEY_TYPE] = SetChar(v, EKT_CONFIDENTIAL);

    CKeyID idk = sekConfidential->GetID();
    sea->vExtKeyIDs.push_back(idk);
    sea->vExtKeys.push_back(sekConfidential);
    mapExtKeys[idk] = sekConfidential; // wallet destructor will delete

    sea->mapValue[EKVT_CONFIDENTIAL_CHAIN] = SetCompressedInt64(v, nConfidential);

    if (!pwdb) {
        CHDWalletDB wdb(*m_database);
        if (0 != ExtKeySaveAccountToDB(&wdb, idDefaultAccount, sea)) {
            return werrorN(1,"%s: %s.", __func__, "ExtKeySaveAccountToDB failed");
        }
    } else {
        if (0 != ExtKeySaveAccountToDB(pwdb, idDefaultAccount, sea)) {
            return werrorN(1, "%s: %s.", __func__, "ExtKeySaveAccountToDB failed");
        }
    }

    pc = sekConfidential;
    return 0;
};

int CHDWallet::MakeDefaultAccount()
{
    WalletLogPrintf("Generating initial master key and account from random data.\n");

    LOCK(cs_wallet);
    CHDWalletDB wdb(GetDatabase());
    if (!wdb.TxnBegin()) {
        return werrorN(1, "TxnBegin failed.");
    }

    std::string sLblMaster = "Master Key";
    std::string sLblAccount = "Default Account";
    int rv;
    CKeyID idNewMaster;
    CExtKeyAccount *sea;
    CExtKey ekMaster;

    if (0 != ExtKeyNew32(ekMaster)) {
        wdb.TxnAbort();
        return 1;
    }

    CStoredExtKey sek;
    sek.kp = CExtKeyPair(ekMaster);
    if (0 != (rv = ExtKeyImportLoose(&wdb, sek, idNewMaster, false, false))) {
        wdb.TxnAbort();
        return werrorN(1, "ExtKeyImportLoose failed, %s", ExtKeyGetString(rv));
    }

    idNewMaster = sek.GetID();
    if (0 != (rv = ExtKeySetMaster(&wdb, idNewMaster))) {
        wdb.TxnAbort();
        return werrorN(1, "ExtKeySetMaster failed, %s.", ExtKeyGetString(rv));
    }

    sea = new CExtKeyAccount();
    if (0 != (rv = ExtKeyDeriveNewAccount(&wdb, sea, sLblAccount))) {
        ExtKeyRemoveAccountFromMapsAndFree(sea);
        wdb.TxnAbort();
        return werrorN(1, "ExtKeyDeriveNewAccount failed, %s.", ExtKeyGetString(rv));
    }

    CKeyID idNewDefaultAccount = sea->GetID();
    CKeyID idOldDefault = idDefaultAccount;
    if (0 != (rv = ExtKeySetDefaultAccount(&wdb, idNewDefaultAccount))) {
        ExtKeyRemoveAccountFromMapsAndFree(sea);
        wdb.TxnAbort();
        return werrorN(1, "ExtKeySetDefaultAccount failed, %s.", ExtKeyGetString(rv));
    }

    if (!wdb.TxnCommit()) {
        idDefaultAccount = idOldDefault;
        ExtKeyRemoveAccountFromMapsAndFree(sea);
        return werrorN(1, "TxnCommit failed.");
    }
    return 0;
}

int CHDWallet::ExtKeyNew32(CExtKey &out)
{
    if (LogAcceptCategory(BCLog::HDWALLET)) {
        WalletLogPrintf("ExtKeyNew32 from random.\n");
    }

    uint8_t data[32];

    for (uint32_t i = 0; i < MAX_DERIVE_TRIES; ++i) {
        GetStrongRandBytes(data, 32);
        if (ExtKeyNew32(out, data, 32) == 0) {
            break;
        }
    }

    return out.IsValid() ? 0 : 1;
};

int CHDWallet::ExtKeyNew32(CExtKey &out, const char *sPassPhrase, int32_t nHash, const char *sSeed)
{
    // Match keys from http://bip32.org/
    LogPrint(BCLog::HDWALLET, "ExtKeyNew32 from pass phrase.\n");

    uint8_t data[64] = {0};
    int nPhraseLen = strlen(sPassPhrase);
    int nSeedLen = strlen(sSeed);

    CHMAC_SHA256 ctx256((const uint8_t*)sPassPhrase, nPhraseLen);
    for (int i = 0; i < nHash; ++i) {
        CHMAC_SHA256 tmp = ctx256;
        tmp.Write(data, 32).Finalize(data);
    }

    CHMAC_SHA512((const uint8_t*)sSeed, nSeedLen).Write(data, 32).Finalize(data);

    out.SetKeyCode(data, &data[32]);
    return out.IsValid() ? 0 : 1;
};

int CHDWallet::ExtKeyNew32(CExtKey &out, uint8_t *data, uint32_t lenData)
{
    LogPrint(BCLog::HDWALLET, "%s %s\n", GetDisplayName(), __func__);

    out.SetSeed(data, lenData);

    return out.IsValid() ? 0 : 1;
};

int CHDWallet::ExtKeyImportLoose(CHDWalletDB *pwdb, CStoredExtKey &sekIn, CKeyID &idDerived, bool fBip44, bool fSaveBip44)
{
    // If fBip44, the bip44 keyid is returned in idDerived

    LogPrint(BCLog::HDWALLET, "%s %s\n", GetDisplayName(), __func__);
    AssertLockHeld(cs_wallet);

    assert(pwdb);

    if (IsLocked()) {
        return werrorN(1, "Wallet must be unlocked.");
    }

    CKeyID id = sekIn.GetID();

    bool fsekInExist = true;
    // It's possible for a public ext key to be added first
    CStoredExtKey sekExist, sek = sekIn;
    if (pwdb->ReadExtKey(id, sekExist)) {
        if (IsCrypted()
            && 0 != ExtKeyUnlock(&sekExist)) {
            return werrorN(13, "%s: %s", __func__, ExtKeyGetString(13));
        }
        sek = sekExist;
        if (!sek.kp.IsValidV()
            && sekIn.kp.IsValidV()) {
            sek.kp = sekIn.kp;
            std::vector<uint8_t> v;
            sek.mapValue[EKVT_ADDED_SECRET_AT] = SetCompressedInt64(v, GetTime());
        }
    } else {
        // New key
        sek.nFlags |= EAF_ACTIVE;
        fsekInExist = false;
    }

    if (fBip44) {
        // Import key as bip44 root and derive a new master key
        // NOTE: can't know created at time of derived key here

        std::vector<uint8_t> v;
        sek.mapValue[EKVT_KEY_TYPE] = SetChar(v, EKT_BIP44_MASTER);

        CExtKey evDerivedKey, evPurposeKey;
        sek.kp.Derive(evPurposeKey, BIP44_PURPOSE);
        evPurposeKey.Derive(evDerivedKey, (uint32_t)Params().BIP44ID());

        v.resize(0);
        PushUInt32(v, BIP44_PURPOSE);
        PushUInt32(v, (uint32_t)Params().BIP44ID());

        CStoredExtKey sekDerived;
        sekDerived.nFlags |= EAF_ACTIVE;
        sekDerived.kp = CExtKeyPair(evDerivedKey);
        sekDerived.mapValue[EKVT_PATH] = v;
        sekDerived.mapValue[EKVT_ROOT_ID] = SetCKeyID(v, id);
        sekDerived.sLabel = sek.sLabel + " - bip44 derived.";

        idDerived = sekDerived.GetID();

        if (pwdb->ReadExtKey(idDerived, sekExist)) {
            if (fSaveBip44
                && !fsekInExist) {
                // Assume the user wants to save the bip44 key, drop down
            } else {
                return werrorN(12, "%s: %s", __func__, ExtKeyGetString(12));
            }
        } else {
            if (IsCrypted()
                && (ExtKeyEncrypt(&sekDerived, vMasterKey, false) != 0)) {
                return werrorN(1, "%s: ExtKeyEncrypt failed.", __func__);
            }

            if (!pwdb->WriteExtKey(idDerived, sekDerived)) {
                return werrorN(1, "%s: DB Write failed.", __func__);
            }
        }
    }

    if (!fBip44 || fSaveBip44) {
        if (IsCrypted() &&
            ExtKeyEncrypt(&sek, vMasterKey, false) != 0) {
            return werrorN(1, "%s: ExtKeyEncrypt failed.", __func__);
        }

        if (!pwdb->WriteExtKey(id, sek)) {
            return werrorN(1, "%s: DB Write failed.", __func__);
        }
    }
    if (!UnsetWalletFlagRV(pwdb, WALLET_FLAG_BLANK_WALLET)) {
        return werrorN(1, "%s: UnsetWalletFlag failed.", __func__);
    }
    return 0;
};

int CHDWallet::ExtKeyImportAccount(CHDWalletDB *pwdb, CStoredExtKey &sekIn, int64_t nCreatedAt, const std::string &sLabel)
{
    // rv: 0 success, 1 fail, 2 existing key, 3 updated key
    // It's not possible to import an account using only a public key as internal keys are derived hardened

    if (LogAcceptCategory(BCLog::HDWALLET)) {
        WalletLogPrintf("%s.\n", __func__);
        AssertLockHeld(cs_wallet);
    }

    assert(pwdb);

    if (IsLocked()) {
        return werrorN(1, "Wallet must be unlocked.");
    }

    CKeyID idAccount = sekIn.GetID();

    CStoredExtKey sekExist, *sek = new CStoredExtKey();
    *sek = sekIn;

    if (pwdb->ReadExtKey(idAccount, sekExist)) {
        // Add secret if exists in db
        *sek = sekExist;
        if (!sek->kp.IsValidV()
            && sekIn.kp.IsValidV()) {
            sek->kp = sekIn.kp;
            std::vector<uint8_t> v;
            sek->mapValue[EKVT_ADDED_SECRET_AT] = SetCompressedInt64(v, GetTime());
        }
    }

    CExtKeyAccount *sea = new CExtKeyAccount();
    if (pwdb->ReadExtAccount(idAccount, *sea)) {
        if (0 != ExtKeyUnlock(sea)) {
            delete sek;
            delete sea;
            return werrorN(1, "Error unlocking existing account.");
        }
        CStoredExtKey *sekAccount = sea->ChainAccount();
        if (!sekAccount) {
            delete sek;
            delete sea;
            return werrorN(1, "ChainAccount failed.");
        }
        // Account exists, update secret if necessary
        if (!sek->kp.IsValidV() &&
            sekAccount->kp.IsValidV()) {
            sekAccount->kp = sek->kp;
            std::vector<uint8_t> v;
            sekAccount->mapValue[EKVT_ADDED_SECRET_AT] = SetCompressedInt64(v, GetTime());

             if (IsCrypted() &&
                 ExtKeyEncrypt(sekAccount, vMasterKey, false) != 0) {
                delete sek;
                delete sea;
                return werrorN(1, "ExtKeyEncrypt failed.");
            }

            if (!pwdb->WriteExtKey(idAccount, *sekAccount)) {
                delete sek;
                delete sea;
                return werrorN(1, "WriteExtKey failed.");
            }

            delete sek;
            delete sea;
            return 3;
        }
        delete sek;
        delete sea;
        return 2;
    }

    CKeyID idMaster; // inits to 0
    if (0 != ExtKeyCreateAccount(sek, idMaster, *sea, sLabel)) {
        delete sek;
        delete sea;
        return werrorN(1, "ExtKeyCreateAccount failed.");
    }

    std::vector<uint8_t> v;
    sea->mapValue[EKVT_CREATED_AT] = SetCompressedInt64(v, nCreatedAt);

    if (0 != ExtKeySaveAccountToDB(pwdb, idAccount, sea)) {
        sea->FreeChains();
        delete sea;
        return werrorN(1, "DB Write failed.");
    }

    if (0 != ExtKeyAddAccountToMaps(idAccount, sea)) {
        sea->FreeChains();
        delete sea;
        return werrorN(1, "ExtKeyAddAccountToMap() failed.");
    }
    if (!UnsetWalletFlagRV(pwdb, WALLET_FLAG_BLANK_WALLET)) {
        return werrorN(1, "%s: UnsetWalletFlag failed.", __func__);
    }
    return 0;
};

int CHDWallet::ExtKeySetMaster(CHDWalletDB *pwdb, CKeyID &idNewMaster)
{
    if (LogAcceptCategory(BCLog::HDWALLET)) {
        CBitcoinAddress addr;
        addr.Set(idNewMaster, CChainParams::EXT_KEY_HASH);
        WalletLogPrintf("ExtKeySetMaster %s.\n", addr.ToString());
        AssertLockHeld(cs_wallet);
    }

    assert(pwdb);

    if (IsLocked()) {
        return werrorN(1, "Wallet must be unlocked.");
    }

    CKeyID idOldMaster;
    bool fOldMaster = pwdb->ReadNamedExtKeyId("master", idOldMaster);

    if (idNewMaster == idOldMaster) {
        return werrorN(11, ExtKeyGetString(11));
    }

    ExtKeyMap::iterator mi;
    CStoredExtKey ekOldMaster, *pEKOldMaster, *pEKNewMaster;
    bool fNew = false;
    mi = mapExtKeys.find(idNewMaster);
    if (mi != mapExtKeys.end()) {
        pEKNewMaster = mi->second;
    } else {
        pEKNewMaster = new CStoredExtKey();
        fNew = true;
        if (!pwdb->ReadExtKey(idNewMaster, *pEKNewMaster)) {
            delete pEKNewMaster;
            return werrorN(10, ExtKeyGetString(10));
        }
    }

    // Prevent setting bip44 root key as a master key.
    mapEKValue_t::iterator mvi = pEKNewMaster->mapValue.find(EKVT_KEY_TYPE);
    if (mvi != pEKNewMaster->mapValue.end()
        && mvi->second.size() == 1
        && mvi->second[0] == EKT_BIP44_MASTER) {
        if (fNew) delete pEKNewMaster;
        return werrorN(9, ExtKeyGetString(9));
    }

    if (ExtKeyUnlock(pEKNewMaster) != 0
        || !pEKNewMaster->kp.IsValidV()) {
        if (fNew) delete pEKNewMaster;
        return werrorN(1, "New master ext key has no secret.");
    }

    std::vector<uint8_t> v;
    pEKNewMaster->mapValue[EKVT_KEY_TYPE] = SetChar(v, EKT_MASTER);

    if (!pwdb->WriteExtKey(idNewMaster, *pEKNewMaster)
        || !pwdb->WriteNamedExtKeyId("master", idNewMaster)) {
        if (fNew) delete pEKNewMaster;
        return werrorN(1, "DB Write failed.");
    }

    // Unset old master ext key
    if (fOldMaster) {
        mi = mapExtKeys.find(idOldMaster);
        if (mi != mapExtKeys.end()) {
            pEKOldMaster = mi->second;
        } else {
            if (!pwdb->ReadExtKey(idOldMaster, ekOldMaster)) {
                if (fNew) delete pEKNewMaster;
                return werrorN(1, "ReadExtKey failed.");
            }

            pEKOldMaster = &ekOldMaster;
        }

        mapEKValue_t::iterator it = pEKOldMaster->mapValue.find(EKVT_KEY_TYPE);
        if (it != pEKOldMaster->mapValue.end()) {
            if (LogAcceptCategory(BCLog::HDWALLET))
                WalletLogPrintf("Removing tag from old master key %s.\n", pEKOldMaster->GetIDString58());
            pEKOldMaster->mapValue.erase(it);
            if (!pwdb->WriteExtKey(idOldMaster, *pEKOldMaster)) {
                if (fNew) delete pEKNewMaster;
                return werrorN(1, "WriteExtKey failed.");
            }
        }
    }

    mapExtKeys[idNewMaster] = pEKNewMaster;
    pEKMaster = pEKNewMaster;

    return 0;
};

int CHDWallet::ExtKeyNewMaster(CHDWalletDB *pwdb, CKeyID &idMaster, bool fAutoGenerated)
{
    // Must pair with ExtKeySetMaster

    //  This creates two keys, a root key and a master key derived according
    //  to BIP44 (path 44'/44'), The root (bip44) key only stored in the system
    //  and the derived key is set as the system master key.

    WalletLogPrintf("ExtKeyNewMaster.\n");
    AssertLockHeld(cs_wallet);
    assert(pwdb);

    if (IsLocked()) {
        return werrorN(1, "Wallet must be unlocked.");
    }

    CExtKey evRootKey;
    CStoredExtKey sekRoot;
    if (ExtKeyNew32(evRootKey) != 0) {
        return werrorN(1, "ExtKeyNew32 failed.");
    }

    std::vector<uint8_t> v;
    sekRoot.nFlags |= EAF_ACTIVE;
    sekRoot.mapValue[EKVT_KEY_TYPE] = SetChar(v, EKT_BIP44_MASTER);
    sekRoot.kp = CExtKeyPair(evRootKey);
    sekRoot.mapValue[EKVT_CREATED_AT] = SetCompressedInt64(v, GetTime());
    sekRoot.sLabel = "Initial BIP44 Master";
    CKeyID idRoot = sekRoot.GetID();

    CExtKey evMasterKey;
    evRootKey.Derive(evMasterKey, BIP44_PURPOSE);
    evMasterKey.Derive(evMasterKey, Params().BIP44ID());

    std::vector<uint8_t> vPath;
    PushUInt32(vPath, BIP44_PURPOSE);
    PushUInt32(vPath, Params().BIP44ID());

    CStoredExtKey sekMaster;
    sekMaster.nFlags |= EAF_ACTIVE;
    sekMaster.kp = CExtKeyPair(evMasterKey);
    sekMaster.mapValue[EKVT_PATH] = vPath;
    sekMaster.mapValue[EKVT_ROOT_ID] = SetCKeyID(v, idRoot);
    sekMaster.mapValue[EKVT_CREATED_AT] = SetCompressedInt64(v, GetTime());
    sekMaster.sLabel = "Initial Master";

    idMaster = sekMaster.GetID();

    if (IsCrypted() &&
        (ExtKeyEncrypt(&sekRoot, vMasterKey, false) != 0 ||
         ExtKeyEncrypt(&sekMaster, vMasterKey, false) != 0)) {
        return werrorN(1, "ExtKeyEncrypt failed.");
    }

    if (!pwdb->WriteExtKey(idRoot, sekRoot) ||
        !pwdb->WriteExtKey(idMaster, sekMaster) ||
        (fAutoGenerated && !pwdb->WriteFlag("madeDefaultEKey", 1))) {
        return werrorN(1, "DB Write failed.");
    }

    return 0;
};

int CHDWallet::ExtKeyCreateAccount(CStoredExtKey *sekAccount, CKeyID &idMaster, CExtKeyAccount &ekaOut, const std::string &sLabel)
{
    LogPrint(BCLog::HDWALLET, "%s %s\n", GetDisplayName(), __func__);
    AssertLockHeld(cs_wallet);

    std::vector<uint8_t> vAccountPath, vSubKeyPath, v;
    mapEKValue_t::iterator mi = sekAccount->mapValue.find(EKVT_PATH);

    if (mi != sekAccount->mapValue.end()) {
        vAccountPath = mi->second;
    }

    ekaOut.idMaster = idMaster;
    ekaOut.sLabel = sLabel;
    ekaOut.nFlags |= EAF_ACTIVE;
    ekaOut.mapValue[EKVT_CREATED_AT] = SetCompressedInt64(v, GetTime());

    if (sekAccount->kp.IsValidV()) {
        ekaOut.nFlags |= EAF_HAVE_SECRET;
    }

    uint32_t nExternal = 0, nInternal = 0, nStealth = 0;
    CStoredExtKey *sekExternal = new CStoredExtKey(), *sekInternal = new CStoredExtKey(), *sekStealth = nullptr;

    if (sekAccount->kp.IsValidV()) {
        CExtKey evExternal, evInternal, evStealth;
        if (sekAccount->DeriveNextKey(evExternal, nExternal, false) != 0
            || sekAccount->DeriveNextKey(evInternal, nInternal, false) != 0
            || sekAccount->DeriveNextKey(evStealth, nStealth, true) != 0) {
            return werrorN(1, "Could not derive account chain keys.");
        }

        sekExternal->kp = CExtKeyPair(evExternal);
        sekInternal->kp = CExtKeyPair(evInternal);

        sekStealth = new CStoredExtKey();
        sekStealth->kp = CExtKeyPair(evStealth);
    } else {
        CExtPubKey epExternal, epInternal;
        if (sekAccount->DeriveNextKey(epExternal, nExternal, false) != 0
            || sekAccount->DeriveNextKey(epInternal, nInternal, false) != 0) {
            return werrorN(1, "Could not derive account chain keys.");
        }
        sekExternal->kp = CExtKeyPair(epExternal);
        sekInternal->kp = CExtKeyPair(epInternal);
    }

    vSubKeyPath = vAccountPath;
    sekExternal->mapValue[EKVT_PATH] = PushUInt32(vSubKeyPath, nExternal);
    sekExternal->nFlags |= EAF_ACTIVE | EAF_RECEIVE_ON | EAF_IN_ACCOUNT;

    vSubKeyPath = vAccountPath;
    sekInternal->mapValue[EKVT_PATH] = PushUInt32(vSubKeyPath, nInternal);
    sekInternal->nFlags |= EAF_ACTIVE | EAF_RECEIVE_ON | EAF_IN_ACCOUNT;

    ekaOut.vExtKeyIDs.push_back(sekAccount->GetID());
    ekaOut.vExtKeyIDs.push_back(sekExternal->GetID());
    ekaOut.vExtKeyIDs.push_back(sekInternal->GetID());

    ekaOut.vExtKeys.push_back(sekAccount);
    ekaOut.vExtKeys.push_back(sekExternal);
    ekaOut.vExtKeys.push_back(sekInternal);

    sekExternal->mapValue[EKVT_KEY_TYPE] = SetChar(v, EKT_EXTERNAL);
    sekInternal->mapValue[EKVT_KEY_TYPE] = SetChar(v, EKT_INTERNAL);

    ekaOut.nActiveExternal = 1;
    ekaOut.nActiveInternal = 2;

    if (sekAccount->kp.IsValidV()) {
        vSubKeyPath = vAccountPath;
        if (sekStealth) { // Silence compiler warning
            sekStealth->mapValue[EKVT_PATH] = PushUInt32(vSubKeyPath, nStealth);
            sekStealth->nFlags |= EAF_ACTIVE | EAF_IN_ACCOUNT;
            sekStealth->mapValue[EKVT_KEY_TYPE] = SetChar(v, EKT_STEALTH);
        }

        ekaOut.vExtKeyIDs.push_back(sekStealth->GetID());
        ekaOut.vExtKeys.push_back(sekStealth);
        ekaOut.nActiveStealth = 3;
    }

    if (IsCrypted() &&
        ExtKeyEncrypt(&ekaOut, vMasterKey, false) != 0) {
        delete sekExternal;
        delete sekInternal;
        if (sekStealth) {
            delete sekStealth;
        }
        // sekAccount should be freed in calling function
        return werrorN(1, "ExtKeyEncrypt failed.");
    }

    return 0;
};

int CHDWallet::ExtKeyDeriveNewAccount(CHDWalletDB *pwdb, CExtKeyAccount *sea, const std::string &sLabel, const std::string &sPath)
{
    // Derive a new account from the master extkey and save to wallet
    WalletLogPrintf("%s\n", __func__);
    AssertLockHeld(cs_wallet);
    assert(pwdb);
    assert(sea);

    if (IsLocked()) {
        return werrorN(1, "%s: Wallet must be unlocked.", __func__);
    }

    if (!pEKMaster || !pEKMaster->kp.IsValidV()) {
        return werrorN(1, "%s: Master ext key is invalid.", __func__);
    }

    CKeyID idMaster = pEKMaster->GetID();

    CStoredExtKey *sekAccount = new CStoredExtKey();
    CExtKey evAccountKey;
    uint32_t nOldHGen = pEKMaster->GetCounter(true);
    uint32_t nAccount;
    std::vector<uint8_t> vAccountPath, vSubKeyPath;

    if (sPath.length() == 0) {
        if (pEKMaster->DeriveNextKey(evAccountKey, nAccount, true, true) != 0) {
            delete sekAccount;
            return werrorN(1, "%s: Could not derive account key from master.", __func__);
        }
        sekAccount->kp = CExtKeyPair(evAccountKey);
        sekAccount->mapValue[EKVT_PATH] = PushUInt32(vAccountPath, nAccount);
    } else {
        std::vector<uint32_t> vPath;
        int rv;
        if ((rv = ExtractExtKeyPath(sPath, vPath)) != 0) {
            delete sekAccount;
            return werrorN(1, "%s: ExtractExtKeyPath failed %s.", __func__, ExtKeyGetString(rv));
        }

        CExtKey vkOut;
        CExtKey vkWork = pEKMaster->kp.GetExtKey();
        for (std::vector<uint32_t>::iterator it = vPath.begin(); it != vPath.end(); ++it) {
            if (!vkWork.Derive(vkOut, *it)) {
                delete sekAccount;
                return werrorN(1, "%s: CExtKey Derive failed %s, %d.", __func__, sPath.c_str(), *it);
            }
            PushUInt32(vAccountPath, *it);

            vkWork = vkOut;
        }

        sekAccount->kp = CExtKeyPair(vkOut);
        sekAccount->mapValue[EKVT_PATH] = vAccountPath;
    }

    if (!sekAccount->kp.IsValidV()
        || !sekAccount->kp.IsValidP()) {
        delete sekAccount;
        pEKMaster->SetCounter(nOldHGen, true);
        return werrorN(1, "%s: Invalid key.", __func__);
    }

    sekAccount->nFlags |= EAF_ACTIVE | EAF_IN_ACCOUNT;
    if (0 != ExtKeyCreateAccount(sekAccount, idMaster, *sea, sLabel)) {
        delete sekAccount;
        pEKMaster->SetCounter(nOldHGen, true);
        return werrorN(1, "%s: ExtKeyCreateAccount failed.", __func__);
    }

    CKeyID idAccount = sea->GetID();

    CStoredExtKey checkSEA;
    if (pwdb->ReadExtKey(idAccount, checkSEA)) {
        sea->FreeChains();
        pEKMaster->SetCounter(nOldHGen, true);
        return werrorN(14, "%s: Account already exists in db.", __func__);
    }

    if (!pwdb->WriteExtKey(idMaster, *pEKMaster)
        || 0 != ExtKeySaveAccountToDB(pwdb, idAccount, sea)) {
        sea->FreeChains();
        pEKMaster->SetCounter(nOldHGen, true);
        return werrorN(1, "%s: DB Write failed.", __func__);
    }

    if (0 != ExtKeyAddAccountToMaps(idAccount, sea)) {
        sea->FreeChains();
        return werrorN(1, "%s: ExtKeyAddAccountToMaps() failed.", __func__);
    }

    return 0;
};

int CHDWallet::ExtKeySetDefaultAccount(CHDWalletDB *pwdb, CKeyID &idNewDefault)
{
    // Set an existing account as the new master, ensure EAF_ACTIVE is set
    // add account to maps if not already there
    // run in a db transaction

    LogPrint(BCLog::HDWALLET, "%s %s\n", GetDisplayName(), __func__);
    AssertLockHeld(cs_wallet);
    assert(pwdb);

    CExtKeyAccount *sea = new CExtKeyAccount();

    // Read account from db, inactive accounts are not loaded into maps
    if (!pwdb->ReadExtAccount(idNewDefault, *sea)) {
        delete sea;
        return werrorN(15, "%s: Account not in wallet.", __func__);
    }

    // If !EAF_ACTIVE, rewrite with EAF_ACTIVE set
    if (!(sea->nFlags & EAF_ACTIVE)) {
        sea->nFlags |= EAF_ACTIVE;
        if (!pwdb->WriteExtAccount(idNewDefault, *sea)) {
            delete sea;
            return werrorN(1, "%s: WriteExtAccount() failed.", __func__);
        }
    }

    if (!pwdb->WriteNamedExtKeyId("defaultAccount", idNewDefault)) {
        delete sea;
        return werrorN(1, "%s: WriteNamedExtKeyId() failed.", __func__);
    }

    ExtKeyAccountMap::iterator mi = mapExtAccounts.find(idNewDefault);
    if (mi == mapExtAccounts.end()) {
        if (0 != ExtKeyAddAccountToMaps(idNewDefault, sea)) {
            delete sea;
            return werrorN(1, "%s: ExtKeyAddAccountToMaps() failed.", __func__);
        }
        // sea will be freed in FreeExtKeyMaps
    } else {
        delete sea;
    }

    // Set idDefaultAccount last, in case something fails.
    idDefaultAccount = idNewDefault;

    NotifyCanGetAddressesChanged();

    return 0;
};

int CHDWallet::ExtKeyEncrypt(CStoredExtKey *sek, const CKeyingMaterial &vMKey, bool fLockKey)
{
    if (!sek->kp.IsValidV()) {
        if (LogAcceptCategory(BCLog::HDWALLET)) {
            WalletLogPrintf("%s: sek %s has no secret, encryption skipped.\n", __func__, sek->GetIDString58());
        }
        return 0;
    }

    std::vector<uint8_t> vchCryptedSecret;
    CPubKey pubkey = sek->kp.pubkey;
    CKeyingMaterial vchSecret(sek->kp.key.begin(), sek->kp.key.end());
    if (!EncryptSecret(vMKey, vchSecret, pubkey.GetHash(), vchCryptedSecret)) {
        return werrorN(1, "EncryptSecret failed.");
    }

    sek->nFlags |= EAF_IS_CRYPTED;

    sek->vchCryptedSecret = vchCryptedSecret;

    // CStoredExtKey serialise will never save key when vchCryptedSecret is set
    // thus key can be left intact here
    if (fLockKey) {
        sek->fLocked = 1;
        sek->kp.key.Clear();
    } else {
        sek->fLocked = 0;
    }

    CKeyID sek_id = sek->GetID();
    auto mi = mapExtKeys.find(sek_id);
    if (mi != mapExtKeys.end() && sek != mi->second) {
        auto sek_in_memory = mi->second;
        sek_in_memory->nFlags = sek->nFlags;
        sek_in_memory->vchCryptedSecret = vchCryptedSecret;
        sek_in_memory->fLocked = sek->fLocked;
        if (fLockKey) {
            sek_in_memory->kp.key.Clear();
        }
    }

    return 0;
};

int CHDWallet::ExtKeyEncrypt(CExtKeyAccount *sea, const CKeyingMaterial &vMKey, bool fLockKey)
{
    assert(sea);

    std::vector<CStoredExtKey*>::iterator it;
    for (it = sea->vExtKeys.begin(); it != sea->vExtKeys.end(); ++it) {
        CStoredExtKey *sek = *it;
        if (sek->IsEncrypted()) {
            continue;
        }

        if (!sek->kp.IsValidV() &&
            LogAcceptCategory(BCLog::HDWALLET)) {
            WalletLogPrintf("%s : Skipping account %s chain, no secret.\n", __func__, sea->GetIDString58());
            continue;
        }

        if (sek->kp.IsValidV() &&
            ExtKeyEncrypt(sek, vMKey, fLockKey) != 0) {
            return 1;
        }
    }

    return 0;
};

int CHDWallet::ExtKeyEncryptAll(CHDWalletDB *pwdb, const CKeyingMaterial &vMKey)
{
    WalletLogPrintf("%s\n", __func__);

    // Encrypt loose and account extkeys stored in wallet
    // skip invalid private keys

    Dbc *pcursor = pwdb->GetTxnCursor();

    if (!pcursor) {
        return werrorN(1, "%s : cannot create DB cursor.", __func__);
    }

    CDataStream ssKey(SER_DISK, CLIENT_VERSION);
    CDataStream ssValue(SER_DISK, CLIENT_VERSION);

    CKeyID ckeyId;
    CBitcoinAddress addr;
    CStoredExtKey sek;
    CExtKey58 eKey58;
    std::string strType;

    size_t nKeys = 0;

    uint32_t fFlags = DB_SET_RANGE;
    ssKey << std::string(DBKeys::PART_EXTKEY);
    while (pwdb->ReadAtCursor(pcursor, ssKey, ssValue, fFlags) == 0) {
        fFlags = DB_NEXT;

        ssKey >> strType;
        if (strType != DBKeys::PART_EXTKEY) {
            break;
        }

        ssKey >> ckeyId;
        ssValue >> sek;

        if (!sek.kp.IsValidV()) {
            if (LogAcceptCategory(BCLog::HDWALLET)) {
                addr.Set(ckeyId, CChainParams::EXT_KEY_HASH);
                WalletLogPrintf("%s: Skipping key %s, no secret.\n", __func__, sek.GetIDString58());
            }
            continue;
        }

        if (ExtKeyEncrypt(&sek, vMKey, true) != 0) {
            return werrorN(1, "%s: ExtKeyEncrypt failed.", __func__);
        }

        nKeys++;

        if (!pwdb->Replace(pcursor, sek)) {
            return werrorN(1, "%s: Replace failed.", __func__);
        }
    }

    pcursor->close();

    LogPrint(BCLog::HDWALLET, "%s : Encrypted %u keys.\n", __func__, nKeys);

    return 0;
};

int CHDWallet::ExtKeyLock()
{
    LogPrint(BCLog::HDWALLET, "ExtKeyLock.\n");

    if (pEKMaster) {
        pEKMaster->kp.key.Clear();
        pEKMaster->fLocked = 1;
    }

    for (auto &mi : mapExtKeys) {
        CStoredExtKey *sek = mi.second;
        if (!(sek->IsEncrypted())) {
            continue;
        }
        sek->kp.key.Clear();
        sek->fLocked = 1;
    }

    return 0;
};

int CHDWallet::ExtKeyUnlock(CExtKeyAccount *sea)
{
    return ExtKeyUnlock(sea, vMasterKey);
};

int CHDWallet::ExtKeyUnlock(CExtKeyAccount *sea, const CKeyingMaterial &vMKey)
{
    for (auto it = sea->vExtKeys.begin(); it != sea->vExtKeys.end(); ++it) {
        CStoredExtKey *sek = *it;
        if (!(sek->nFlags & EAF_IS_CRYPTED)) {
            continue;
        }
        if (ExtKeyUnlock(sek, vMKey) != 0) {
            return 1;
        }
    }

    return 0;
};

int CHDWallet::ExtKeyUnlock(CStoredExtKey *sek)
{
    return ExtKeyUnlock(sek, vMasterKey);
};

int CHDWallet::ExtKeyUnlock(CStoredExtKey *sek, const CKeyingMaterial &vMKey)
{
    if (!(sek->nFlags & EAF_IS_CRYPTED)) { // not necessary to unlock
        return 0;
    }

    CKeyingMaterial vchSecret;
    uint256 iv = Hash(sek->kp.pubkey);
    if (!DecryptSecret(vMKey, sek->vchCryptedSecret, iv, vchSecret)
        || vchSecret.size() != 32) {
        return werrorN(1, "%s Failed decrypting ext key %s", __func__, sek->GetIDString58().c_str());
    }

    CKey key;
    key.Set(vchSecret.begin(), vchSecret.end(), true);

    if (!key.IsValid()) {
        return werrorN(1, "%s Failed decrypting ext key %s", __func__, sek->GetIDString58().c_str());
    }

    if (key.GetPubKey() != sek->kp.pubkey) {
        return werrorN(1, "%s Decrypted ext key mismatch %s", __func__, sek->GetIDString58().c_str());
    }

    sek->kp.key = key;
    sek->fLocked = 0;
    return 0;
};

int CHDWallet::ExtKeyUnlock(const CKeyingMaterial &vMKey)
{
    LogPrint(BCLog::HDWALLET, "ExtKeyUnlock.\n");

    if (pEKMaster
        && pEKMaster->nFlags & EAF_IS_CRYPTED) {
        if (ExtKeyUnlock(pEKMaster, vMKey) != 0) {
            return 1;
        }
    }

    for (auto &mi : mapExtKeys) {
        CStoredExtKey *sek = mi.second;
        if (0 != ExtKeyUnlock(sek, vMKey)) {
            return werrorN(1, "ExtKeyUnlock failed.");
        }
    }

    return 0;
};

int CHDWallet::ExtKeyLoadMaster()
{
    WalletLogPrintf("Loading master ext key.\n");

    LOCK(cs_wallet);
    CKeyID idMaster;

    CHDWalletDB wdb(*m_database);
    if (!wdb.ReadNamedExtKeyId("master", idMaster)) {
        WalletLogPrintf("Warning: No master ext key has been set.\n");
        return 1;
    }

    pEKMaster = new CStoredExtKey();
    if (!wdb.ReadExtKey(idMaster, *pEKMaster)) {
        delete pEKMaster;
        pEKMaster = nullptr;
        return werrorN(1, "%s ReadExtKey failed to read master ext key.", __func__);
    }

    if (!pEKMaster->kp.IsValidP()) { // wallet could be locked, check pk
        delete pEKMaster;
        pEKMaster = nullptr;
        return werrorN(1, "%s Master ext key is invalid: %s.", __func__, HDKeyIDToString(idMaster));
    }

    if (pEKMaster->nFlags & EAF_IS_CRYPTED) {
        pEKMaster->fLocked = 1;
    }

    // Add to key map
    mapExtKeys[idMaster] = pEKMaster;

    // Find earliest key creation time, as wallet birthday
    int64_t nCreatedAt = 0;
    GetCompressedInt64(pEKMaster->mapValue[EKVT_CREATED_AT], (uint64_t&)nCreatedAt);

    auto spk_man = GetLegacyScriptPubKeyMan();
    if (spk_man) {
        LOCK(spk_man->cs_KeyStore);
        // TODO: Split CHDWallet into a new ScriptPubKeyMan
        spk_man->UpdateTimeFirstKey(nCreatedAt);
    }

    return 0;
};

int CHDWallet::ExtKeyLoadAccountKeys(CHDWalletDB *pwdb, CExtKeyAccount *sea)
{
    sea->vExtKeys.resize(sea->vExtKeyIDs.size());
    for (size_t i = 0; i < sea->vExtKeyIDs.size(); ++i) {
        CKeyID &id = sea->vExtKeyIDs[i];

        CStoredExtKey *sek = new CStoredExtKey();
        if (pwdb->ReadExtKey(id, *sek)) {
            sea->vExtKeys[i] = sek;
        } else {
            WalletLogPrintf("WARNING: Could not read key %d of account %s\n", i, sea->GetIDString58());
            sea->vExtKeys[i] = nullptr;
            delete sek;
        }
    }
    return 0;
};

int CHDWallet::ExtKeyLoadAccount(CHDWalletDB *pwdb, const CKeyID &idAccount)
{
    CExtKeyAccount *sea = new CExtKeyAccount();
    if (!pwdb->ReadExtAccount(idAccount, *sea)) {
        return werrorN(1, "%s: ReadExtAccount failed.", __func__);
    }

    ExtKeyLoadAccountKeys(pwdb, sea);

    if (0 != ExtKeyAddAccountToMaps(idAccount, sea, true)) {
        sea->FreeChains();
        delete sea;
        return werrorN(1, "%s: ExtKeyAddAccountToMaps failed: %s.",  __func__, HDAccIDToString(idAccount));
    }

    return 0;
};

int CHDWallet::ExtKeyLoadAccounts()
{
    WalletLogPrintf("Loading extkey accounts.\n");

    LOCK(cs_wallet);

    CHDWalletDB wdb(*m_database);

    if (!wdb.ReadNamedExtKeyId("defaultAccount", idDefaultAccount)) {
        WalletLogPrintf("Warning: No default ext account set.\n");
    }

    Dbc *pcursor;
    if (!(pcursor = wdb.GetCursor())) {
        return werrorN(1, "%s: cannot create DB cursor", __func__);
    }

    CDataStream ssKey(SER_DISK, CLIENT_VERSION);
    CDataStream ssValue(SER_DISK, CLIENT_VERSION);

    CKeyID idAccount;
    std::string strType;

    unsigned int fFlags = DB_SET_RANGE;
    ssKey << std::string(DBKeys::PART_EXTACC);
    while (wdb.ReadAtCursor(pcursor, ssKey, ssValue, fFlags) == 0) {
        fFlags = DB_NEXT;

        ssKey >> strType;
        if (strType != DBKeys::PART_EXTACC) {
            break;
        }

        ssKey >> idAccount;

        if (LogAcceptCategory(BCLog::HDWALLET)) {
            WalletLogPrintf("Loading account %s\n", HDAccIDToString(idAccount));
        }

        CExtKeyAccount *sea = new CExtKeyAccount();
        ssValue >> *sea;

        ExtKeyAccountMap::iterator mi = mapExtAccounts.find(idAccount);
        if (mi != mapExtAccounts.end()) {
            // Account already loaded, skip
            if (LogAcceptCategory(BCLog::HDWALLET)) {
                WalletLogPrintf("Account already loaded.\n");
            }
            continue;
        }

        if (!(sea->nFlags & EAF_ACTIVE)) {
            if (LogAcceptCategory(BCLog::HDWALLET)) {
                WalletLogPrintf("Skipping inactive %s\n", HDAccIDToString(idAccount));
            }
            delete sea;
            continue;
        }

        // Find earliest key creation time, as wallet birthday
        int64_t nCreatedAt;
        GetCompressedInt64(sea->mapValue[EKVT_CREATED_AT], (uint64_t&)nCreatedAt);

        auto spk_man = GetLegacyScriptPubKeyMan();
        if (spk_man) {
            LOCK(spk_man->cs_KeyStore);
            // TODO: Split CHDWallet into a new ScriptPubKeyMan
            spk_man->UpdateTimeFirstKey(nCreatedAt);
        }

        ExtKeyLoadAccountKeys(&wdb, sea);

        if (0 != ExtKeyAddAccountToMaps(idAccount, sea, false)) {
            WalletLogPrintf("%s: ExtKeyAddAccountToMaps failed: %s\n", __func__, HDAccIDToString(idAccount));
            sea->FreeChains();
            delete sea;
        }
    }

    pcursor->close();

    return 0;
};

int CHDWallet::ExtKeyLoadLoose()
{
    WalletLogPrintf("Loading loose extkeys.\n");

    LOCK(cs_wallet);

    CHDWalletDB wdb(GetDatabase());

    Dbc *pcursor;
    if (!(pcursor = wdb.GetCursor())) {
        throw std::runtime_error(strprintf("%s : cannot create DB cursor", __func__).c_str());
    }

    CDataStream ssKey(SER_DISK, CLIENT_VERSION);
    CDataStream ssValue(SER_DISK, CLIENT_VERSION);

    CKeyID ckeyId;
    CStoredExtKey sek;
    std::string strType;

    uint32_t fFlags = DB_SET_RANGE;
    ssKey << std::string(DBKeys::PART_EXTKEY);

    while (wdb.ReadAtCursor(pcursor, ssKey, ssValue, fFlags) == 0) {
        fFlags = DB_NEXT;

        ssKey >> strType;
        if (strType != DBKeys::PART_EXTKEY) {
            break;
        }

        ssKey >> ckeyId;
        ssValue >> sek;
        if (sek.IsInAccount() ||
            !sek.IsActive() ||
            !sek.IsReceiveEnabled()) {
            continue;
        }
        CStoredExtKey *psek = nullptr;
        // Don't overwrite existing keys.
        if (mapExtKeys.count(ckeyId) == 0) {
            psek = new CStoredExtKey();
            *psek = sek;
            mapExtKeys[ckeyId] = psek;
        } else {
            psek = mapExtKeys[ckeyId];
        }
        if (psek->IsReceiveEnabled()) {
            ExtKeyAddLookAhead(psek);
        }
    }
    pcursor->close();
    WalletLogPrintf("Active extkey chains: %d.\n", mapExtKeys.size());

    {
        WalletLogPrintf("Loading loose extkey child keys.\n");
        Dbc *pcursor;
        if (!(pcursor = wdb.GetCursor())) {
            throw std::runtime_error(strprintf("%s : cannot create DB cursor", __func__).c_str());
        }
        CEKLKey ekl;
        fFlags = DB_SET_RANGE;
        ssKey.clear();
        ssKey << std::string(DBKeys::PART_LEXTKEYCK);
        while (wdb.ReadAtCursor(pcursor, ssKey, ssValue, fFlags) == 0) {
            fFlags = DB_NEXT;

            ssKey >> strType;
            if (strType != DBKeys::PART_LEXTKEYCK) {
                break;
            }

            ssKey >> ckeyId;
            ssValue >> ekl;
            mapLooseKeys[ckeyId] = ekl;
        }
        pcursor->close();
        WalletLogPrintf("Loaded %d loose extkey derived keys.\n", mapLooseKeys.size());
    }

    return 0;
}

int CHDWallet::ExtKeyReload(const CStoredExtKey *sek)
{
    CKeyID idk = sek->GetID();

    bool is_master = idk == idDefaultAccount;

    if (sek->IsInAccount()) {
        return werrorN(1, "%s: TODO: Can only reload loose keys.", __func__);
    }

    // Remove temporary keys from lookahead
    for (auto it = mapLooseLookAhead.cbegin(); it != mapLooseLookAhead.cend();) {
        if (it->second.chain_id == idk) {
            it = mapLooseLookAhead.erase(it);
        } else {
            ++it;
        }
    }

    auto it = mapExtKeys.find(idk);
    if (!sek->IsActive() ||
        (!sek->IsReceiveEnabled() && !is_master)) {
        // Remove if exists
        if (it != mapExtKeys.end()) {
            WalletLogPrintf("Unloading extkey %s.\n", HDKeyIDToString(idk));
            delete it->second;
            mapExtKeys.erase(it);
        }
        return 0;
    }
    WalletLogPrintf("Reloading extkey %s.\n", HDKeyIDToString(idk));

    CStoredExtKey *psek = nullptr;
    if (it != mapExtKeys.end()) {
        *it->second = *sek;
        psek = it->second;
    } else {
        psek = new CStoredExtKey();
        *psek = *sek;
        mapExtKeys[idk] = psek;
    }
    psek->nLastLookAhead = 0;
    if (psek->IsReceiveEnabled()) {
        ExtKeyAddLookAhead(psek);
    }

    return 0;
}

int CHDWallet::ExtKeyAddLookAhead(CStoredExtKey *sek) const
{
    CKeyID derivedId, idk = sek->GetID();
    CPubKey pk;
    LooseKeyMap::const_iterator mi;

    uint64_t nLookAhead = m_default_lookahead;
    auto itV = sek->mapValue.find(EKVT_N_LOOKAHEAD);
    if (itV != sek->mapValue.end()) {
        nLookAhead = GetCompressedInt64(itV->second, nLookAhead);
    }

    // nGenerated counts number of keys generated, last used offset will be nGenerated-1
    uint32_t nChild = std::max(sek->nGenerated, sek->nLastLookAhead > 0 ? sek->nLastLookAhead + 1 : 0);
    uint32_t nChildOut = nChild;
    uint32_t nStart = nChild - sek->nGenerated;

    WalletLogPrintf("Adding %d keys to lookahead for loose chain %s from %d.\n", nLookAhead - nStart, HDKeyIDToString(idk), nChild);

    for (uint32_t k = nStart; k < (uint32_t)nLookAhead; ++k) {
        bool fGotKey = false;

        uint32_t nMaxTries = 1000; // TODO: link to lookahead size
        for (uint32_t i = 0; i < nMaxTries; ++i) { // nMaxTries > lookahead pool
            if (sek->DeriveKey(pk, nChild, nChildOut, false) != 0) {
                WalletLogPrintf("Warning: %s - DeriveKey failed, chain %s, child %d.\n", __func__, HDKeyIDToString(idk), nChild);
                nChild = nChildOut + 1;
                continue;
            }
            nChild = nChildOut + 1;

            derivedId = pk.GetID();
            if ((mi = mapLooseKeys.find(derivedId)) != mapLooseKeys.end()) {
                if (LogAcceptCategory(BCLog::HDWALLET)) {
                    WalletLogPrintf("%s: key exists in map skipping %s.\n", __func__, EncodeDestination(PKHash(derivedId)));
                }
                continue;
            }

            if ((mi = mapLooseLookAhead.find(derivedId)) != mapLooseLookAhead.end()) {
                continue;
            }

            fGotKey = true;
            break;
        }

        if (!fGotKey) {
            WalletLogPrintf("Error: %s - DeriveKey loop failed, chain %s, child %d.\n", __func__, HDKeyIDToString(idk), nChild);
            continue;
        }

        mapLooseLookAhead[derivedId] = CEKLKey(idk, nChildOut);
        sek->nLastLookAhead = nChildOut;

        if (LogAcceptCategory(BCLog::HDWALLET)) {
            WalletLogPrintf("Added %d %s to loose-extkey look-ahead size %u.\n", nChildOut, EncodeDestination(PKHash(derivedId)), mapLooseLookAhead.size());
        }
    }

    return 0;
}

int CHDWallet::ExtKeyPromoteKey(CStoredExtKey *sek, uint32_t nChildKey) const
{
    CKeyID idk = sek->GetID();
    // sek must be a pointer to entry in mapExtKeys
    AssertLockHeld(cs_wallet);

    CHDWalletDB wdb(*m_database);

    if (!sek->IsTrackOnly() && !wdb.TxnBegin()) {
        return werrorN(1, "%s TxnBegin failed.", __func__);
    }

    for (auto it = mapLooseLookAhead.cbegin(); it != mapLooseLookAhead.cend();) {
        if (it->second.chain_id == idk && it->second.nKey <= nChildKey) {
            if (!sek->IsTrackOnly()) {
                WalletLogPrintf("Promoting child key %d %s from loose extkey %s lookahead.\n",
                                it->second.nKey, EncodeDestination(PKHash(it->first)), sek->GetIDString58());
                mapLooseKeys[it->first] = it->second;
                wdb.WriteEKLKey(it->first, it->second);
            }
            it = mapLooseLookAhead.erase(it);
        } else {
            ++it;
        }
    }

    sek->nGenerated = nChildKey + 1;
    if (!wdb.WriteExtKey(idk, *sek)) {
        return werrorN(1, "%s: WriteExtKey failed.", __func__);
    }
    ExtKeyAddLookAhead(sek);

    if (!sek->IsTrackOnly() && !wdb.TxnCommit()) {
        return werrorN(1, "%s TxnCommit failed.", __func__);
    }
    return 0;
};

int CHDWallet::ExtKeySaveAccountToDB(CHDWalletDB *pwdb, const CKeyID &idAccount, CExtKeyAccount *sea)
{
    LogPrint(BCLog::HDWALLET, "%s %s\n", GetDisplayName(), __func__);
    AssertLockHeld(cs_wallet);
    assert(sea);

    for (size_t i = 0; i < sea->vExtKeys.size(); ++i) {
        CStoredExtKey *sek = sea->vExtKeys[i];
        if (!pwdb->WriteExtKey(sea->vExtKeyIDs[i], *sek)) {
            return werrorN(1, "%s: WriteExtKey failed.", __func__);
        }
    }

    if (!pwdb->WriteExtAccount(idAccount, *sea)) {
        return werrorN(1, "%s: WriteExtAccount failed.", __func__);
    }

    return 0;
};

int CHDWallet::ExtKeyAddAccountToMaps(const CKeyID &idAccount, CExtKeyAccount *sea, bool fAddToLookAhead)
{
    LogPrint(BCLog::HDWALLET, "%s %s\n", GetDisplayName(), __func__);
    AssertLockHeld(cs_wallet);
    assert(sea);

    for (size_t i = 0; i < sea->vExtKeys.size(); ++i) {
        CStoredExtKey *sek = sea->vExtKeys[i];

        if (IsLocked() && sek->IsEncrypted()) {
            sek->fLocked = 1;
        }

        if (sek->IsActive()
            && sek->IsReceiveEnabled()) {
            uint64_t nLookAhead = m_default_lookahead;
            mapEKValue_t::iterator itV = sek->mapValue.find(EKVT_N_LOOKAHEAD);
            if (itV != sek->mapValue.end()) {
                nLookAhead = GetCompressedInt64(itV->second, nLookAhead);
            }

            if (fAddToLookAhead) {
                sea->AddLookAhead(i, (uint32_t)nLookAhead);
            }
        }

        mapExtKeys[sea->vExtKeyIDs[i]] = sek;
    }

    mapExtAccounts[idAccount] = sea;
    return 0;
};

int CHDWallet::ExtKeyRemoveAccountFromMapsAndFree(CExtKeyAccount *sea)
{
    // Remove account keys from wallet maps and free
    if (!sea) {
        return 0;
    }

    CKeyID idAccount = sea->GetID();

    for (size_t i = 0; i < sea->vExtKeys.size(); ++i) {
        mapExtKeys.erase(sea->vExtKeyIDs[i]);
    }

    mapExtAccounts.erase(idAccount);
    sea->FreeChains();
    delete sea;
    return 0;
};

int CHDWallet::ExtKeyRemoveAccountFromMapsAndFree(const CKeyID &idAccount)
{
    ExtKeyAccountMap::iterator mi = mapExtAccounts.find(idAccount);
    if (mi == mapExtAccounts.end()) {
        return werrorN(1, "%s: Account %s not found.", __func__, HDAccIDToString(idAccount));
    }

    return ExtKeyRemoveAccountFromMapsAndFree(mi->second);
};

int CHDWallet::ExtKeyLoadAccountPacks()
{
    WalletLogPrintf("Loading ext account packs.\n");

    LOCK(cs_wallet);

    CHDWalletDB wdb(*m_database);

    Dbc *pcursor;
    if (!(pcursor = wdb.GetCursor())) {
        return werrorN(1, "%s: cannot create DB cursor", __func__);
    }

    CDataStream ssKey(SER_DISK, CLIENT_VERSION);
    CDataStream ssValue(SER_DISK, CLIENT_VERSION);

    CKeyID idAccount;
    uint32_t nPack;
    size_t nKeys = 0, nStealthKeys = 0, nStealthChildKeys = 0;
    std::string strType;
    std::vector<CEKAKeyPack> ekPak;
    std::vector<CEKAStealthKeyPack> aksPak;
    std::vector<CEKASCKeyPack> asckPak;

    unsigned int fFlags = DB_SET_RANGE;
    ssKey << std::string("epak");
    while (wdb.ReadAtCursor(pcursor, ssKey, ssValue, fFlags) == 0) {
        ekPak.clear();
        fFlags = DB_NEXT;

        ssKey >> strType;
        if (strType != "epak") {
            break;
        }

        ssKey >> idAccount;
        ssKey >> nPack;

        if (LogAcceptCategory(BCLog::HDWALLET)) {
            WalletLogPrintf("Loading account key pack %s %u\n", HDAccIDToString(idAccount), nPack);
        }

        ExtKeyAccountMap::iterator mi = mapExtAccounts.find(idAccount);
        if (mi == mapExtAccounts.end()) {
            WalletLogPrintf("Warning: Unknown account %s.\n", HDAccIDToString(idAccount));
            continue;
        }

        CExtKeyAccount *sea = mi->second;

        ssValue >> ekPak;

        std::vector<CEKAKeyPack>::iterator it;
        for (it = ekPak.begin(); it != ekPak.end(); ++it) {
            nKeys++;
            sea->mapKeys[it->id] = it->ak;
        }
    }

    if (LogAcceptCategory(BCLog::HDWALLET)) {
        WalletLogPrintf("Loaded %d keys\n", nKeys);
    }

    ssKey.clear();
    ssKey << std::string(DBKeys::PART_SXADDRKEYPACK);
    fFlags = DB_SET_RANGE;
    while (wdb.ReadAtCursor(pcursor, ssKey, ssValue, fFlags) == 0) {
        aksPak.clear();
        fFlags = DB_NEXT;

        ssKey >> strType;
        if (strType != DBKeys::PART_SXADDRKEYPACK) {
            break;
        }

        ssKey >> idAccount;
        ssKey >> nPack;

        if (LogAcceptCategory(BCLog::HDWALLET)) {
            WalletLogPrintf("Loading account stealth key pack %s %u\n", idAccount.ToString(), nPack);
        }

        ExtKeyAccountMap::iterator mi = mapExtAccounts.find(idAccount);
        if (mi == mapExtAccounts.end()) {
            WalletLogPrintf("Warning: Unknown account %s.\n", HDAccIDToString(idAccount));
            continue;
        }
        CExtKeyAccount *sea = mi->second;

        ssValue >> aksPak;

        for (auto it = aksPak.begin(); it != aksPak.end(); ++it) {
            nStealthKeys++;
            sea->mapStealthKeys[it->id] = it->aks;
        }
    }

    if (LogAcceptCategory(BCLog::HDWALLET)) {
        WalletLogPrintf("Loaded %d stealthkey%s.\n", nStealthKeys, nStealthKeys == 1 ? "" : "s");
    }

    ssKey.clear();
    ssKey << std::string("ecpk");
    fFlags = DB_SET_RANGE;
    while (wdb.ReadAtCursor(pcursor, ssKey, ssValue, fFlags) == 0) {
        aksPak.clear();
        fFlags = DB_NEXT;

        ssKey >> strType;
        if (strType != "ecpk") {
            break;
        }

        ssKey >> idAccount;
        ssKey >> nPack;

        if (LogAcceptCategory(BCLog::HDWALLET)) {
            WalletLogPrintf("Loading account stealth child key pack %s %u\n", idAccount.ToString(), nPack);
        }

        ExtKeyAccountMap::iterator mi = mapExtAccounts.find(idAccount);
        if (mi == mapExtAccounts.end()) {
            CBitcoinAddress addr;
            addr.Set(idAccount, CChainParams::EXT_ACC_HASH);
            WalletLogPrintf("Warning: Unknown account %s.\n", addr.ToString());
            continue;
        }
        CExtKeyAccount *sea = mi->second;

        ssValue >> asckPak;

        for (auto it = asckPak.begin(); it != asckPak.end(); ++it) {
            nStealthChildKeys++;
            sea->mapStealthChildKeys[it->id] = it->asck;
        }
    }

    if (LogAcceptCategory(BCLog::HDWALLET)) {
        WalletLogPrintf("Loaded %d stealth child keys\n", nStealthChildKeys);
    }

    pcursor->close();

    return 0;
};

int CHDWallet::PrepareLookahead()
{
    WalletLogPrintf("Preparing Lookahead pools.\n");

    for (auto it = mapExtAccounts.cbegin(); it != mapExtAccounts.cend(); ++it) {
        CExtKeyAccount *sea = it->second;
        sea->ClearLookAhead();
        for (size_t i = 0; i < sea->vExtKeys.size(); ++i) {
            CStoredExtKey *sek = sea->vExtKeys[i];

            if (sek->IsActive()
                && sek->IsReceiveEnabled()) {
                uint64_t nLookAhead = m_default_lookahead;
                mapEKValue_t::iterator itV = sek->mapValue.find(EKVT_N_LOOKAHEAD);
                if (itV != sek->mapValue.end()) {
                    nLookAhead = GetCompressedInt64(itV->second, nLookAhead);
                }

                sea->AddLookAhead(i, (uint32_t)nLookAhead);
            }
        }
    }

    return 0;
};

int CHDWallet::ExtKeyAppendToPack(CHDWalletDB *pwdb, CExtKeyAccount *sea, const CKeyID &idKey, const CEKAKey &ak, bool &fUpdateAcc) const
{
    // Must call WriteExtAccount after

    CKeyID idAccount = sea->GetID();
    std::vector<CEKAKeyPack> ekPak;
    if (!pwdb->ReadExtKeyPack(idAccount, sea->nPack, ekPak)) {
        // New pack
        ekPak.clear();
        if (LogAcceptCategory(BCLog::HDWALLET)) {
            WalletLogPrintf("Account %s, starting new keypack %u.\n", idAccount.ToString(), sea->nPack);
        }
    }

    try { ekPak.push_back(CEKAKeyPack(idKey, ak)); } catch (std::exception& e) {
        return werrorN(1, "%s push_back failed.", __func__);
    }

    if (!pwdb->WriteExtKeyPack(idAccount, sea->nPack, ekPak)) {
        return werrorN(1, "%s Save key pack %u failed.", __func__, sea->nPack);
    }

    fUpdateAcc = false;
    if ((uint32_t)ekPak.size() >= MAX_KEY_PACK_SIZE-1) {
        fUpdateAcc = true;
        sea->nPack++;
    }
    return 0;
};

int CHDWallet::ExtKeyAppendToPack(CHDWalletDB *pwdb, CExtKeyAccount *sea, const CKeyID &idKey, const CEKASCKey &asck, bool &fUpdateAcc) const
{
    // Must call WriteExtAccount after

    CKeyID idAccount = sea->GetID();
    std::vector<CEKASCKeyPack> asckPak;
    if (!pwdb->ReadExtStealthKeyChildPack(idAccount, sea->nPackStealthKeys, asckPak)) {
        // New pack
        asckPak.clear();
        if (LogAcceptCategory(BCLog::HDWALLET)) {
            WalletLogPrintf("Account %s, starting new stealth child keypack %u.\n", idAccount.ToString(), sea->nPackStealthKeys);
        }
    }

    try { asckPak.push_back(CEKASCKeyPack(idKey, asck)); } catch (std::exception& e) {
        return werrorN(1, "%s push_back failed.", __func__);
    }

    if (!pwdb->WriteExtStealthKeyChildPack(idAccount, sea->nPackStealthKeys, asckPak)) {
        return werrorN(1, "%s Save key pack %u failed.", __func__, sea->nPackStealthKeys);
    }

    fUpdateAcc = false;
    if ((uint32_t)asckPak.size() >= MAX_KEY_PACK_SIZE-1) {
        sea->nPackStealthKeys++;
        fUpdateAcc = true;
    }

    return 0;
};

int CHDWallet::ExtKeySaveKey(CHDWalletDB *pwdb, CExtKeyAccount *sea, const CKeyID &keyId, const CEKAKey &ak) const
{
    LogPrint(BCLog::HDWALLET, "%s %s %s.\n", __func__, sea->GetIDString58(), EncodeDestination(PKHash(keyId)));

    size_t nChain = ak.nParent;
    bool fUpdateAccTmp, fUpdateAcc = false;
    if (gArgs.GetBoolArg("-extkeysaveancestors", true)) {
        LOCK(sea->cs_account);
        AccKeyMap::const_iterator mi = sea->mapKeys.find(keyId);
        if (mi != sea->mapKeys.end()) {
            return false; // already saved
        }

        if (sea->mapLookAhead.erase(keyId) != 1) {
            WalletLogPrintf("Warning: SaveKey %s key not found in look ahead %s.\n", sea->GetIDString58(), EncodeDestination(PKHash(keyId)));
        }

        sea->mapKeys[keyId] = ak;
        if (0 != ExtKeyAppendToPack(pwdb, sea, keyId, ak, fUpdateAccTmp)) {
            return werrorN(1, "%s ExtKeyAppendToPack failed.", __func__);
        }
        fUpdateAcc = fUpdateAccTmp ? true : fUpdateAcc;

        CStoredExtKey *pc;
        if (!IsHardened(ak.nKey)
            && (pc = sea->GetChain(nChain)) != nullptr) {
            if (ak.nKey == pc->nGenerated) {
                pc->nGenerated++;
            } else
            if (pc->nGenerated < ak.nKey) {
                uint32_t nOldGenerated = pc->nGenerated;
                pc->nGenerated = ak.nKey + 1;

                for (uint32_t i = nOldGenerated; i < ak.nKey; ++i) {
                    uint32_t nChildOut = 0;
                    CPubKey pk;
                    if (0 != pc->DeriveKey(pk, i, nChildOut, false)) {
                        WalletLogPrintf("%s DeriveKey failed %d.\n", __func__, i);
                        break;
                    }

                    CKeyID idkExtra = pk.GetID();
                    if (sea->mapLookAhead.erase(idkExtra) != 1) {
                        WalletLogPrintf("Warning: SaveKey %s key not found in look ahead %s.\n", sea->GetIDString58(), EncodeDestination(PKHash(idkExtra)));
                    }

                    CEKAKey akExtra(nChain, nChildOut);
                    sea->mapKeys[idkExtra] = akExtra;
                    if (0 != ExtKeyAppendToPack(pwdb, sea, idkExtra, akExtra, fUpdateAccTmp)) {
                        return werrorN(1, "%s ExtKeyAppendToPack failed.", __func__);
                    }
                    fUpdateAcc = fUpdateAccTmp ? true : fUpdateAcc;

                    if (pc->IsActive()
                        && pc->IsReceiveEnabled()) {
                        sea->AddLookAhead(nChain, 1);
                    }

                    if (LogAcceptCategory(BCLog::HDWALLET)) {
                        WalletLogPrintf("Saved key %s %d, %s.\n", sea->GetIDString58(), nChain, EncodeDestination(PKHash(idkExtra)));
                    }
                }
            }
            if (pc->IsActive()
                && pc->IsReceiveEnabled()) {
                sea->AddLookAhead(nChain, 1);
            }
            if (LogAcceptCategory(BCLog::HDWALLET)) {
                WalletLogPrintf("Saved key %s %d, %s.\n", sea->GetIDString58(), nChain, EncodeDestination(PKHash(keyId)));
            }
        }
    } else {
        if (!sea->SaveKey(keyId, ak)) {
            return werrorN(1, "%s SaveKey failed.", __func__);
        }

        if (0 != ExtKeyAppendToPack(pwdb, sea, keyId, ak, fUpdateAcc)) {
            return werrorN(1, "%s ExtKeyAppendToPack failed.", __func__);
        }
    }


    // Save chain, nGenerated changed
    CStoredExtKey *pc = sea->GetChain(nChain);
    if (!pc) {
        return werrorN(1, "%s GetChain failed.", __func__);
    }

    CKeyID idChain = sea->vExtKeyIDs[nChain];
    if (!pwdb->WriteExtKey(idChain, *pc)) {
        return werrorN(1, "%s WriteExtKey failed.", __func__);
    }

    if (fUpdateAcc) { // only necessary if nPack has changed
        CKeyID idAccount = sea->GetID();
        if (!pwdb->WriteExtAccount(idAccount, *sea)) {
            return werrorN(1, "%s WriteExtAccount failed.", __func__);
        }
    }

    return 0;
};

int CHDWallet::ExtKeySaveKey(CExtKeyAccount *sea, const CKeyID &keyId, const CEKAKey &ak) const
{
    AssertLockHeld(cs_wallet);

    CHDWalletDB wdb(*m_database, true); // FlushOnClose

    if (!wdb.TxnBegin()) {
        return werrorN(1, "%s TxnBegin failed.", __func__);
    }

    if (0 != ExtKeySaveKey(&wdb, sea, keyId, ak)) {
        wdb.TxnAbort();
        return 1;
    }

    if (!wdb.TxnCommit()) {
        return werrorN(1, "%s TxnCommit failed.", __func__);
    }
    return 0;
};

int CHDWallet::ExtKeySaveKey(CHDWalletDB *pwdb, CExtKeyAccount *sea, const CKeyID &keyId, const CEKASCKey &asck) const
{
    LogPrint(BCLog::HDWALLET, "%s: %s %s.\n", __func__, sea->GetIDString58(), EncodeDestination(PKHash(keyId)));
    AssertLockHeld(cs_wallet);

    if (!sea->SaveKey(keyId, asck)) {
        return werrorN(1, "%s SaveKey failed.", __func__);
    }

    bool fUpdateAcc;
    if (0 != ExtKeyAppendToPack(pwdb, sea, keyId, asck, fUpdateAcc)) {
        return werrorN(1, "%s ExtKeyAppendToPack failed.", __func__);
    }

    if (fUpdateAcc) { // only necessary if nPackStealth has changed
        CKeyID idAccount = sea->GetID();
        if (!pwdb->WriteExtAccount(idAccount, *sea)) {
            return werrorN(1, "%s WriteExtAccount failed.", __func__);
        }
    }

    return 0;
};

int CHDWallet::ExtKeySaveKey(CExtKeyAccount *sea, const CKeyID &keyId, const CEKASCKey &asck) const
{
    AssertLockHeld(cs_wallet);

    CHDWalletDB wdb(*m_database);

    if (!wdb.TxnBegin()) {
        return werrorN(1, "%s TxnBegin failed.", __func__);
    }

    if (0 != ExtKeySaveKey(&wdb, sea, keyId, asck)) {
        wdb.TxnAbort();
        return 1;
    }

    if (!wdb.TxnCommit()) {
        return werrorN(1, "%s TxnCommit failed.", __func__);
    }
    return 0;
};

int CHDWallet::ExtKeyUpdateStealthAddress(CHDWalletDB *pwdb, CExtKeyAccount *sea, CKeyID &sxId, std::string &sLabel)
{
    AssertLockHeld(cs_wallet);
    LogPrint(BCLog::HDWALLET, "%s %s\n", GetDisplayName(), __func__);

    AccStealthKeyMap::iterator it = sea->mapStealthKeys.find(sxId);
    if (it == sea->mapStealthKeys.end()) {
        return werrorN(1, "%s: Stealth key not in account.", __func__);
    }

    if (it->second.sLabel == sLabel) {
        return 0; // no change
    }

    CKeyID accId = sea->GetID();
    std::vector<CEKAStealthKeyPack> aksPak;
    for (uint32_t i = 0; i <= sea->nPackStealth; ++i) {
        if (!pwdb->ReadExtStealthKeyPack(accId, i, aksPak)) {
            return werrorN(1, "%s: ReadExtStealthKeyPack %d failed.", __func__, i);
        }

        std::vector<CEKAStealthKeyPack>::iterator itp;
        for (itp = aksPak.begin(); itp != aksPak.end(); ++itp) {
            if (itp->id == sxId) {
                itp->aks.sLabel = sLabel;
                if (!pwdb->WriteExtStealthKeyPack(accId, i, aksPak)) {
                    return werrorN(1, "%s: WriteExtStealthKeyPack %d failed.", __func__, i);
                }

                it->second.sLabel = sLabel;
                return 0;
            }
        }
    }

    return werrorN(1, "%s: Stealth key not in db.", __func__);
};

int CHDWallet::ExtKeyNewIndex(CHDWalletDB *pwdb, const CKeyID &idKey, uint32_t &index)
{
    if (LogAcceptCategory(BCLog::HDWALLET)) {
        CBitcoinAddress addr;
        addr.Set(idKey, CChainParams::EXT_ACC_HASH); // could be a loose key also
        WalletLogPrintf("%s %s.\n", __func__, addr.ToString());
        AssertLockHeld(cs_wallet);
    }

    std::string sPrefix = "ine";
    uint32_t lastId = 0xFFFFFFFF;
    index = 0;

    if (!pwdb->ReadFlag("ekLastI", (int32_t&)index)) {
        LogPrint(BCLog::HDWALLET, "%s Warning: %s - ReadFlag ekLastI failed.\n", GetDisplayName(), __func__);
    }

    index++;

    if (index == lastId) {
        return werrorN(1, "%s: Wallet extkey index is full!\n", __func__); // expect multiple wallets per node before anyone hits this
    }

    LogPrint(BCLog::HDWALLET, "%s: New index %u.\n", __func__, index);
    if (!pwdb->WriteExtKeyIndex(index, idKey)
        || !pwdb->WriteFlag("ekLastI", (int32_t&)index)) {
        return werrorN(1, "%s: WriteExtKeyIndex failed.\n", __func__);
    }

    return 0;
};

int CHDWallet::ExtKeyGetIndex(CHDWalletDB *pwdb, CExtKeyAccount *sea, uint32_t &index, bool &fUpdate)
{
    mapEKValue_t::iterator mi = sea->mapValue.find(EKVT_INDEX);
    if (mi != sea->mapValue.end()) {
        fUpdate = false;
        assert(mi->second.size() == 4);
        memcpy(&index, &mi->second[0], 4);
        return 0;
    }

    CKeyID idAccount = sea->GetID();
    if (0 != ExtKeyNewIndex(pwdb, idAccount, index)) {
        return werrorN(1, "%s ExtKeyNewIndex failed.", __func__);
    }
    std::vector<uint8_t> vTmp;
    sea->mapValue[EKVT_INDEX] = PushUInt32(vTmp, index);
    fUpdate = true;

    return 0;
};

int CHDWallet::ExtKeyGetIndex(CExtKeyAccount *sea, uint32_t &index)
{
    LOCK(cs_wallet);

    CHDWalletDB wdb(*m_database);
    bool requireUpdateDB;
    if (0 != ExtKeyGetIndex(&wdb, sea, index, requireUpdateDB)) {
        return werrorN(1, "ExtKeyGetIndex failed.");
    }

    if (requireUpdateDB) {
        CKeyID idAccount = sea->GetID();
        if (!wdb.WriteExtAccount(idAccount, *sea)) {
            return werrorN(7, "%s Save account chain failed.", __func__);
        }
    }

    return 0;
};

int CHDWallet::NewKeyFromAccount(CHDWalletDB *pwdb, const CKeyID &idAccount, CPubKey &pkOut,
    bool fInternal, bool fHardened, bool f256bit, bool fBech32, const char *plabel, OutputType output_type)
{
    // If plabel is not null, add to m_address_book

    if (LogAcceptCategory(BCLog::HDWALLET)) {
        WalletLogPrintf("%s %s.\n", __func__, HDAccIDToString(idAccount));
        AssertLockHeld(cs_wallet);
    }

    assert(pwdb);

    if (fHardened && IsLocked()) {
        return werrorN(1, "%s Wallet must be unlocked to derive hardened keys.", __func__);
    }

    ExtKeyAccountMap::iterator mi = mapExtAccounts.find(idAccount);
    if (mi == mapExtAccounts.end()) {
        return werrorN(2, "%s Unknown account.", __func__);
    }

    CExtKeyAccount *sea = mi->second;
    CStoredExtKey *sek = nullptr;

    uint32_t nExtKey = fInternal ? sea->nActiveInternal : sea->nActiveExternal;

    if (nExtKey < sea->vExtKeys.size()) {
        sek = sea->vExtKeys[nExtKey];
    }

    if (!sek) {
        return werrorN(3, "%s Unknown chain.", __func__);
    }

    uint32_t nChildBkp = fHardened ? sek->nHGenerated : sek->nGenerated;
    uint32_t nChildOut;
    if (0 != sek->DeriveNextKey(pkOut, nChildOut, fHardened)) {
        return werrorN(4, "%s Derive failed.", __func__);
    }

    CEKAKey ks(nExtKey, nChildOut);
    CKeyID idKey = pkOut.GetID();

    bool fUpdateAcc;
    if (0 != ExtKeyAppendToPack(pwdb, sea, idKey, ks, fUpdateAcc)) {
        sek->SetCounter(nChildBkp, fHardened);
        return werrorN(5, "%s ExtKeyAppendToPack failed.", __func__);
    }

    if (!pwdb->WriteExtKey(sea->vExtKeyIDs[nExtKey], *sek)) {
        sek->SetCounter(nChildBkp, fHardened);
        return werrorN(6, "%s Save account chain failed.", __func__);
    }

    std::vector<uint32_t> vPath;
    uint32_t idIndex;
    if (plabel) {
        bool requireUpdateDB;
        if (0 == ExtKeyGetIndex(pwdb, sea, idIndex, requireUpdateDB)) {
            vPath.push_back(idIndex); // First entry is the index to the account / master key
        }
        fUpdateAcc = requireUpdateDB ? true : fUpdateAcc;
    }

    if (fUpdateAcc) {
        CKeyID idAccount = sea->GetID();
        if (!pwdb->WriteExtAccount(idAccount, *sea)) {
            sek->SetCounter(nChildBkp, fHardened);
            return werrorN(7, "%s Save account chain failed.", __func__);
        }
    }

    sea->SaveKey(idKey, ks); // remove from lookahead, add to pool, add new lookahead

    if (plabel) {
        if (0 == AppendChainPath(sek, vPath)) {
            vPath.push_back(ks.nKey);
        } else {
            WalletLogPrintf("Warning: %s - missing path value.\n", __func__);
            vPath.clear();
        }

        if (output_type == OutputType::BECH32) {
            SetAddressBook(pwdb, WitnessV0KeyHash(pkOut), plabel, "receive", vPath, false);
        } else
        if (f256bit) {
            CKeyID256 idKey256 = pkOut.GetID256();
            SetAddressBook(pwdb, idKey256, plabel, "receive", vPath, false, fBech32);
        } else {
            SetAddressBook(pwdb, PKHash(idKey), plabel, "receive", vPath, false, fBech32);
        }
    }

    return 0;
};

int CHDWallet::NewKeyFromAccount(CPubKey &pkOut, bool fInternal, bool fHardened, bool f256bit, bool fBech32, const char *plabel, OutputType output_type)
{
    {
        LOCK(cs_wallet);
        CHDWalletDB wdb(*m_database);

        if (!wdb.TxnBegin()) {
            return werrorN(1, "%s TxnBegin failed.", __func__);
        }

        if (0 != NewKeyFromAccount(&wdb, idDefaultAccount, pkOut, fInternal, fHardened, f256bit, fBech32, plabel, output_type)) {
            wdb.TxnAbort();
            return 1;
        }

        if (!wdb.TxnCommit()) {
            return werrorN(1, "%s TxnCommit failed.", __func__);
        }
    }

    if (f256bit) {
        AddressBookChangedNotify(pkOut.GetID256(), CT_NEW);
    } else {
        AddressBookChangedNotify(PKHash(pkOut), CT_NEW);
    }
    return 0;
};

int CHDWallet::NewStealthKeyFromAccount(
    CHDWalletDB *pwdb, const CKeyID &idAccount, const std::string &sLabel,
    CEKAStealthKey &akStealthOut, uint32_t nPrefixBits, const char *pPrefix, bool fBech32, uint32_t *pscankey_num, bool add_to_lookahead)
{
    // Scan secrets must be stored uncrypted - always derive hardened keys

    if (LogAcceptCategory(BCLog::HDWALLET)) {
        WalletLogPrintf("%s %s%s.\n", __func__, HDAccIDToString(idAccount), pscankey_num ? " for lookahead" : "");
        AssertLockHeld(cs_wallet);
    }

    assert(pwdb || pscankey_num);

    if (IsLocked()) {
        return werrorN(1, "%s Wallet must be unlocked to derive hardened keys.", __func__);
    }

    ExtKeyAccountMap::iterator mi = mapExtAccounts.find(idAccount);
    if (mi == mapExtAccounts.end()) {
        return werrorN(1, "%s Unknown account.", __func__);
    }

    CExtKeyAccount *sea = mi->second;
    uint32_t nChain = sea->nActiveStealth;
    CStoredExtKey *sek = sea->GetChain(nChain);
    if (!sek) {
        return werrorN(1, "%s Stealth chain unknown %d.", __func__, nChain);
    }

    uint32_t nChildBkp = sek->nHGenerated;

    CKey kScan, kSpend;
    uint32_t nScanOut = 0, nSpendOut = 0;
    if (pscankey_num) {
        if (0 != sek->DeriveKey(kScan, *pscankey_num, nScanOut, true)) {
            return werrorN(1, "%s Derive failed.", __func__);
        }
        if (0 != sek->DeriveKey(kSpend, WithoutHardenedBit(nScanOut) + 1, nSpendOut, true)) {
            return werrorN(1, "%s Derive failed.", __func__);
        }
        *pscankey_num = WithoutHardenedBit(nSpendOut);
    } else {
        if (0 != sek->DeriveNextKey(kScan, nScanOut, true)) {
            return werrorN(1, "%s Derive failed.", __func__);
        }
        if (0 != sek->DeriveNextKey(kSpend, nSpendOut, true)) {
            sek->SetCounter(nChildBkp, true);
            return werrorN(1, "%s Derive failed.", __func__);
        }
    }

    uint32_t nPrefix = 0;
    if (pPrefix) {
        if (!ExtractStealthPrefix(pPrefix, nPrefix)) {
            return werrorN(1, "%s ExtractStealthPrefix.", __func__);
        }
    } else
    if (nPrefixBits > 0) {
        // If pPrefix is null, set nPrefix from the hash of kSpend
        uint8_t tmp32[32];
        CSHA256().Write(kSpend.begin(), 32).Finalize(tmp32);
        memcpy(&nPrefix, tmp32, 4);
        nPrefix = le32toh(nPrefix);
    }

    uint32_t nMask = SetStealthMask(nPrefixBits);
    nPrefix = nPrefix & nMask;

    CPubKey pkSpend = kSpend.GetPubKey();
    akStealthOut = CEKAStealthKey(nChain, nScanOut, kScan, nChain, nSpendOut, pkSpend, nPrefixBits, nPrefix);
    akStealthOut.sLabel = sLabel;
    if (pscankey_num) {
        if (add_to_lookahead) {
            CKeyID idKey = akStealthOut.GetID();
            auto insert = sea->mapStealthKeys.insert(std::pair<CKeyID, CEKAStealthKey>(idKey, akStealthOut));
            sea->setLookAheadStealth.insert(&insert.first->second);
        }
    } else
    if (0 != SaveStealthAddress(pwdb, sea, akStealthOut, fBech32)) {
        return werrorN(1, "SaveStealthAddress failed.");
    }

    return 0;
};

int CHDWallet::NewStealthKeyFromAccount(const std::string &sLabel, CEKAStealthKey &akStealthOut, uint32_t nPrefixBits, const char *pPrefix, bool fBech32)
{
    {
        LOCK(cs_wallet);
        CHDWalletDB wdb(*m_database);

        if (!wdb.TxnBegin()) {
            return werrorN(1, "%s TxnBegin failed.", __func__);
        }

        if (0 != NewStealthKeyFromAccount(&wdb, idDefaultAccount, sLabel, akStealthOut, nPrefixBits, pPrefix, fBech32)) {
            wdb.TxnAbort();
            return 1;
        }

        if (!wdb.TxnCommit()) {
            return werrorN(1, "%s TxnCommit failed.", __func__);
        }
    }

    CStealthAddress sxAddr;
    akStealthOut.SetSxAddr(sxAddr);
    AddressBookChangedNotify(sxAddr, CT_NEW);
    return 0;
};

int CHDWallet::InitAccountStealthV2Chains(CHDWalletDB *pwdb, CExtKeyAccount *sea)
{
    AssertLockHeld(cs_wallet);
    LogPrint(BCLog::HDWALLET, "%s: %s %s.\n", GetDisplayName(), __func__, sea->GetIDString58());

    CStoredExtKey *sekAccount = sea->GetChain(0);
    if (!sekAccount) {
        return 1;
    }

    CExtKey vkAcc0, vkAcc0_0, vkAccount = sekAccount->kp.GetExtKey();
    if (!vkAccount.Derive(vkAcc0, 0)
        || !vkAcc0.Derive(vkAcc0_0, 0)) {
        return werrorN(1, "%s: Derive failed.", __func__);
    }

    std::string msg = "Scan chain secret seed";
    std::vector<uint8_t> vData, vchSig;

    CHashWriter ss(SER_GETHASH, 0);
    ss << MESSAGE_MAGIC;
    ss << msg;
    if (!vkAcc0_0.key.SignCompact(ss.GetHash(), vchSig)) {
        return werrorN(1, "%s: Sign failed.", __func__);
    }

    CPubKey pk = vkAcc0.key.GetPubKey();
    vchSig.insert(vchSig.end(), pk.begin(), pk.end());

    CExtKey evStealthScan;
    evStealthScan.SetSeed(vchSig.data(), vchSig.size());

    CStoredExtKey *sekStealthScan = new CStoredExtKey();
    sekStealthScan->kp = CExtKeyPair(evStealthScan);
    std::vector<uint32_t> vPath;
    //sekStealthScan->SetPath(vPath);
    sekStealthScan->nFlags |= EAF_ACTIVE | EAF_IN_ACCOUNT;
    sekStealthScan->mapValue[EKVT_KEY_TYPE] = SetChar(vData, EKT_STEALTH_SCAN);
    sea->InsertChain(sekStealthScan);
    CKeyID id_scan = sekStealthScan->GetID();
    mapExtKeys[id_scan] = sekStealthScan;
    uint32_t nStealthScanChain = sea->NumChains();

    CExtKey evStealthSpend;
    uint32_t nStealthSpend;
    if (0 != sekAccount->DeriveKey(evStealthSpend, CHAIN_NO_STEALTH_SPEND, nStealthSpend, true)) {
        return werrorN(1, "%s: Could not derive account chain keys.", __func__);
    }

    vPath.clear();
    AppendPath(sekAccount, vPath);

    CStoredExtKey *sekStealthSpend = new CStoredExtKey();
    sekStealthSpend->kp = CExtKeyPair(evStealthSpend);
    vPath.push_back(nStealthSpend);
    sekStealthSpend->SetPath(vPath);
    sekStealthSpend->nFlags |= EAF_ACTIVE | EAF_IN_ACCOUNT;
    sekStealthSpend->mapValue[EKVT_KEY_TYPE] = SetChar(vData, EKT_STEALTH_SPEND);
    sea->InsertChain(sekStealthSpend);
    CKeyID id_spend = sekStealthSpend->GetID();
    mapExtKeys[id_spend] = sekStealthSpend;
    uint32_t nStealthSpendChain = sea->NumChains();

    sea->mapValue[EKVT_STEALTH_SCAN_CHAIN] = SetCompressedInt64(vData, nStealthScanChain);
    sea->mapValue[EKVT_STEALTH_SPEND_CHAIN] = SetCompressedInt64(vData, nStealthSpendChain);

    if (IsCrypted() &&
        (ExtKeyEncrypt(sekStealthScan, vMasterKey, false) != 0 ||
         ExtKeyEncrypt(sekStealthSpend, vMasterKey, false) != 0)) {
        return werrorN(1, "%s: ExtKeyEncrypt failed.", __func__);
    }

    if (!pwdb->WriteExtKey(id_scan, *sekStealthScan) ||
        !pwdb->WriteExtKey(id_spend, *sekStealthSpend)) {
        return werrorN(1, "%s WriteExtKey failed.", __func__);
    }

    CKeyID idAccount = sea->GetID();
    if (!pwdb->WriteExtAccount(idAccount, *sea)) {
        return werrorN(1, "%s WriteExtAccount failed.", __func__);
    }

    return 0;
};

int CHDWallet::SaveStealthAddress(CHDWalletDB *pwdb, CExtKeyAccount *sea, const CEKAStealthKey &akStealth, bool fBech32)
{
    LogPrint(BCLog::HDWALLET, "%s %s\n", GetDisplayName(), __func__);
    assert(sea);

    std::vector<CEKAStealthKeyPack> aksPak;
    CKeyID idKey = akStealth.GetID();
    CKeyID idAccount = sea->GetID();

    uint32_t nScanChain = akStealth.nScanParent;
    uint32_t nSpendChain = akStealth.akSpend.nParent;

    bool is_v1_key = nScanChain == nSpendChain; // v2 stealth addresses use two chains.

    CStoredExtKey *sekScan, *sekSpend;
    if (!(sekScan = sea->GetChain(nScanChain))) {
        return werrorN(1, "Unknown scan chain.");
    }
    if (!(sekSpend = sea->GetChain(nSpendChain))) {
        return werrorN(1, "Unknown spend chain.");
    }

    // Update counters, necessary if stealthkey was lookahead
    if (sekScan->nHGenerated <= WithoutHardenedBit(akStealth.nScanKey)) {
        sekScan->nHGenerated = WithoutHardenedBit(akStealth.nScanKey) + 1;
    }
    if (sekSpend->nHGenerated <= WithoutHardenedBit(akStealth.akSpend.nKey)) {
        sekSpend->nHGenerated = WithoutHardenedBit(akStealth.akSpend.nKey) + 1;
    }

    sea->mapStealthKeys[idKey] = akStealth;

    if (!pwdb->ReadExtStealthKeyPack(idAccount, sea->nPackStealth, aksPak)) {
        // New pack
        aksPak.clear();
        if (LogAcceptCategory(BCLog::HDWALLET)) {
            WalletLogPrintf("Account %s, starting new stealth keypack %u.\n", HDAccIDToString(idAccount), sea->nPackStealth);
        }
    }

    aksPak.push_back(CEKAStealthKeyPack(idKey, akStealth));
    if (!pwdb->WriteExtStealthKeyPack(idAccount, sea->nPackStealth, aksPak)) {
        sea->mapStealthKeys.erase(idKey);
        return werrorN(1, "WriteExtStealthKeyPack failed.");
    }

    if (!pwdb->WriteExtKey(sea->vExtKeyIDs[nScanChain], *sekScan)
        || (!is_v1_key && !pwdb->WriteExtKey(sea->vExtKeyIDs[nSpendChain], *sekSpend))) {
        sea->mapStealthKeys.erase(idKey);
        return werrorN(1, "WriteExtKey failed.");
    }

    std::vector<uint32_t> vPath;
    uint32_t idIndex;
    bool requireUpdateDB;
    if (0 == ExtKeyGetIndex(pwdb, sea, idIndex, requireUpdateDB)) {
        vPath.push_back(idIndex); // first entry is the index to the account / master key
    }

    // V1 stealth addrs use the path of the scan secret
    bool have_path = false;
    if (is_v1_key) {
        if (0 == AppendChainPath(sekScan, vPath)) {
            uint32_t nChild = akStealth.nScanKey;
            vPath.push_back(SetHardenedBit(nChild));
            have_path = true;
        }
    } else
    if (0 == AppendChainPath(sekSpend, vPath)) {
        vPath.push_back(akStealth.akSpend.nKey);
        have_path = true;
    }

    if (!have_path) {
        WalletLogPrintf("Warning: %s - missing path value.\n", __func__);
        vPath.clear();
    }

    if ((uint32_t)aksPak.size() >= MAX_KEY_PACK_SIZE-1) {
        sea->nPackStealth++;
    }
    if (((uint32_t)aksPak.size() >= MAX_KEY_PACK_SIZE-1 || requireUpdateDB)
        && !pwdb->WriteExtAccount(idAccount, *sea)) {
        return werrorN(1, "WriteExtAccount failed.");
    }

    CStealthAddress sxAddr;
    if (0 != akStealth.SetSxAddr(sxAddr)) {
        return werrorN(1, "SetSxAddr failed.");
    }

    SetAddressBook(pwdb, sxAddr, akStealth.sLabel, "receive", vPath, false, fBech32);

    return 0;
};

int CHDWallet::NewStealthKeyV2FromAccount(
    CHDWalletDB *pwdb, const CKeyID &idAccount, const std::string &sLabel,
    CEKAStealthKey &akStealthOut, uint32_t nPrefixBits, const char *pPrefix, bool fBech32, uint32_t *pscankey_num, uint32_t *pspendkey_num, bool add_to_lookahead)
{
    // Scan secrets must be stored uncrypted - always derive hardened keys

    if (LogAcceptCategory(BCLog::HDWALLET)) {
        WalletLogPrintf("%s %s%s.\n", __func__, HDAccIDToString(idAccount), pscankey_num ? " for lookahead" : "");
        AssertLockHeld(cs_wallet);
    }

    assert(pwdb || pscankey_num);

    if (IsLocked()) {
        return werrorN(1, "%s Wallet must be unlocked to derive hardened keys.", __func__);
    }

    ExtKeyAccountMap::iterator mi = mapExtAccounts.find(idAccount);
    if (mi == mapExtAccounts.end()) {
        return werrorN(1, "%s Unknown account.", __func__);
    }

    CExtKeyAccount *sea = mi->second;
    uint64_t nScanChain = 0, nSpendChain = 0;
    CStoredExtKey *sekScan = nullptr, *sekSpend = nullptr;
    mapEKValue_t::iterator mvi = sea->mapValue.find(EKVT_STEALTH_SCAN_CHAIN);
    if (mvi == sea->mapValue.end()) {
        if (0 != InitAccountStealthV2Chains(pwdb, sea)) {
            return werrorN(1, "%s InitAccountStealthV2Chains failed.", __func__);
        }
        mvi = sea->mapValue.find(EKVT_STEALTH_SCAN_CHAIN);
    }

    if (mvi != sea->mapValue.end()) {
        GetCompressedInt64(mvi->second, nScanChain);
        sekScan = sea->GetChain(nScanChain);
    }
    if (!sekScan) {
        return werrorN(1, "%s Unknown stealth scan chain.", __func__);
    }

    mvi = sea->mapValue.find(EKVT_STEALTH_SPEND_CHAIN);
    if (mvi != sea->mapValue.end()) {
        GetCompressedInt64(mvi->second, nSpendChain);
        sekSpend = sea->GetChain(nSpendChain);
    }
    if (!sekSpend) {
        return werrorN(1, "%s Unknown stealth spend chain.", __func__);
    }

    CKey kScan;
    CPubKey pkSpend;
    uint32_t nScanOut = 0, nSpendGenerated = 0;
    if (pscankey_num) {
        assert(pspendkey_num);
        if (0 != sekScan->DeriveKey(kScan, *pscankey_num, nScanOut, true)) {
            return werrorN(1, "Derive failed.");
        }
        *pscankey_num = WithoutHardenedBit(nScanOut);
        if (0 != sekSpend->DeriveKey(pkSpend, *pspendkey_num, nSpendGenerated, true)) {
            return werrorN(1, "Derive failed.");
        }
        *pspendkey_num = WithoutHardenedBit(nSpendGenerated);
    } else {
        if (0 != sekScan->DeriveNextKey(kScan, nScanOut, true)) {
            return werrorN(1, "Derive failed.");
        }
        if (0 != sekSpend->DeriveNextKey(pkSpend, nSpendGenerated, true)) {
            return werrorN(1, "Derive failed.");
        }
    }

    uint32_t nPrefix = 0;
    if (pPrefix) {
        if (!ExtractStealthPrefix(pPrefix, nPrefix))
            return werrorN(1, "ExtractStealthPrefix failed.");
    } else
    if (nPrefixBits > 0) {
        // If pPrefix is null, set nPrefix from the hash of kScan
        uint8_t tmp32[32];
        CSHA256().Write(kScan.begin(), 32).Finalize(tmp32);
        memcpy(&nPrefix, tmp32, 4);
        nPrefix = le32toh(nPrefix);
    }

    uint32_t nMask = SetStealthMask(nPrefixBits);
    nPrefix = nPrefix & nMask;
    akStealthOut = CEKAStealthKey(nScanChain, nScanOut, kScan, nSpendChain, WithHardenedBit(nSpendGenerated), pkSpend, nPrefixBits, nPrefix);
    akStealthOut.sLabel = sLabel;

    if (pscankey_num) {
        if (add_to_lookahead) {
            CKeyID idKey = akStealthOut.GetID();
            auto insert = sea->mapStealthKeys.insert(std::pair<CKeyID, CEKAStealthKey>(idKey, akStealthOut));
            sea->setLookAheadStealthV2.insert(&insert.first->second);
        }
    } else
    if (0 != SaveStealthAddress(pwdb, sea, akStealthOut, fBech32)) {
        return werrorN(1, "SaveStealthAddress failed.");
    }

    return 0;
};

int CHDWallet::NewStealthKeyV2FromAccount(const std::string &sLabel, CEKAStealthKey &akStealthOut, uint32_t nPrefixBits, const char *pPrefix, bool fBech32)
{
    {
        LOCK(cs_wallet);
        CHDWalletDB wdb(*m_database);

        if (!wdb.TxnBegin()) {
            return werrorN(1, "%s TxnBegin failed.", __func__);
        }

        if (0 != NewStealthKeyV2FromAccount(&wdb, idDefaultAccount, sLabel, akStealthOut, nPrefixBits, pPrefix, fBech32)) {
            wdb.TxnAbort();
            ExtKeyRemoveAccountFromMapsAndFree(idDefaultAccount);
            ExtKeyLoadAccount(&wdb, idDefaultAccount);
            return 1;
        }

        if (!wdb.TxnCommit()) {
            ExtKeyRemoveAccountFromMapsAndFree(idDefaultAccount);
            ExtKeyLoadAccount(&wdb, idDefaultAccount);
            return werrorN(1, "%s TxnCommit failed.", __func__);
        }
    }

    CStealthAddress sxAddr;
    akStealthOut.SetSxAddr(sxAddr);
    AddressBookChangedNotify(sxAddr, CT_NEW);
    return 0;
};

int CHDWallet::NewExtKeyFromAccount(CHDWalletDB *pwdb, const CKeyID &idAccount,
    std::string &sLabel, CStoredExtKey *sekOut, const char *plabel, const uint32_t *childNo, bool fHardened, bool fBech32)
{
    if (LogAcceptCategory(BCLog::HDWALLET)) {
        WalletLogPrintf("%s %s.\n", __func__, HDAccIDToString(idAccount));
        AssertLockHeld(cs_wallet);
    }

    assert(pwdb);

    if (fHardened && IsLocked()) {
        return werrorN(1, "%s Wallet must be unlocked to derive hardened keys.", __func__);
    }

    ExtKeyAccountMap::iterator mi = mapExtAccounts.find(idAccount);
    if (mi == mapExtAccounts.end()) {
        return werrorN(1, "%s Unknown account.", __func__);
    }

    CExtKeyAccount *sea = mi->second;

    CStoredExtKey *sekAccount = sea->ChainAccount();
    if (!sekAccount) {
        return werrorN(1, "%s Unknown chain.", __func__);
    }

    std::vector<uint8_t> vAccountPath, v;
    mapEKValue_t::iterator mvi = sekAccount->mapValue.find(EKVT_PATH);
    if (mvi != sekAccount->mapValue.end()) {
        vAccountPath = mvi->second;
    }

    uint32_t nOldGen = sekAccount->GetCounter(fHardened);
    uint32_t nNewChildNo;

    if (sekAccount->nFlags & EAF_HARDWARE_DEVICE) {
        if (vAccountPath.size() > 8) {
            // Trim the 44h/44h appended to hardware accounts
            std::vector<uint32_t> vAccountPathTest;
            if (0 == ConvertPath(vAccountPath, vAccountPathTest) &&
                vAccountPathTest.size() > 1 &&
                vAccountPathTest[0] == WithHardenedBit(44)) {
                vAccountPath.erase(vAccountPath.begin(), vAccountPath.begin() + 8);
            }
        }
        CExtPubKey epNewKey;
        if (childNo) {
            if ((0 != sekAccount->DeriveKey(epNewKey, *childNo, nNewChildNo, fHardened)) != 0) {
                return werrorN(1, "DeriveKey failed.");
            }
        } else {
            if (sekAccount->DeriveNextKey(epNewKey, nNewChildNo, fHardened) != 0) {
                return werrorN(1, "DeriveNextKey failed.");
            }
        }

        sekOut->nFlags |= EAF_HARDWARE_DEVICE;
        sekOut->kp = CExtKeyPair(epNewKey);
    } else {
        CExtKey evNewKey;
        if (childNo) {
            if ((0 != sekAccount->DeriveKey(evNewKey, *childNo, nNewChildNo, fHardened)) != 0) {
                return werrorN(1, "DeriveKey failed.");
            }
        } else {
            if (sekAccount->DeriveNextKey(evNewKey, nNewChildNo, fHardened) != 0) {
                return werrorN(1, "DeriveNextKey failed.");
            }
        }
        sekOut->kp = CExtKeyPair(evNewKey);
    }

    sekOut->nFlags |= EAF_ACTIVE | EAF_RECEIVE_ON | EAF_IN_ACCOUNT;
    sekOut->mapValue[EKVT_PATH] = PushUInt32(vAccountPath, nNewChildNo);
    sekOut->mapValue[EKVT_CREATED_AT] = SetCompressedInt64(v, GetTime());
    sekOut->sLabel = sLabel;

    if (IsCrypted() &&
        ExtKeyEncrypt(sekOut, vMasterKey, false) != 0) {
        sekAccount->SetCounter(nOldGen, fHardened);
        return werrorN(1, "ExtKeyEncrypt failed.");
    }

    size_t chainNo = sea->vExtKeyIDs.size();
    CKeyID idNewChain = sekOut->GetID();
    sea->vExtKeyIDs.push_back(idNewChain);
    sea->vExtKeys.push_back(sekOut);

    if (plabel) {
        std::vector<uint32_t> vPath;
        uint32_t idIndex;
        bool requireUpdateDB;
        if (0 == ExtKeyGetIndex(pwdb, sea, idIndex, requireUpdateDB)) {
            vPath.push_back(idIndex); // first entry is the index to the account / master key
        }

        vPath.push_back(nNewChildNo);
        SetAddressBook(pwdb, MakeExtPubKey(sekOut->kp), plabel, "receive", vPath, false, fBech32);
    }

    if (!pwdb->WriteExtAccount(idAccount, *sea) ||
        !pwdb->WriteExtKey(idAccount, *sekAccount) ||
        !pwdb->WriteExtKey(idNewChain, *sekOut)) {
        sekAccount->SetCounter(nOldGen, fHardened);
        return werrorN(1, "DB Write failed.");
    }

    uint64_t nLookAhead = m_default_lookahead;
    mvi = sekOut->mapValue.find(EKVT_N_LOOKAHEAD);
    if (mvi != sekOut->mapValue.end()) {
        nLookAhead = GetCompressedInt64(mvi->second, nLookAhead);
    }
    sea->AddLookAhead(chainNo, nLookAhead);

    mapExtKeys[idNewChain] = sekOut;

    return 0;
};

int CHDWallet::NewExtKeyFromAccount(std::string &sLabel, CStoredExtKey *sekOut,
    const char *plabel, const uint32_t *childNo, bool fHardened, bool fBech32)
{
    {
        LOCK(cs_wallet);
        CHDWalletDB wdb(*m_database);

        if (!wdb.TxnBegin()) {
            return werrorN(1, "%s TxnBegin failed.", __func__);
        }

        if (0 != NewExtKeyFromAccount(&wdb, idDefaultAccount, sLabel, sekOut, plabel, childNo, fHardened, fBech32)) {
            wdb.TxnAbort();
            return 1;
        }

        if (!wdb.TxnCommit()) {
            return werrorN(1, "%s TxnCommit failed.", __func__);
        }
    }
    AddressBookChangedNotify(MakeExtPubKey(sekOut->kp), CT_NEW);
    return 0;
};

int CHDWallet::ExtKeyGetDestination(const CExtKeyPair &ek, CPubKey &pkDest, uint32_t &nKey)
{
    if (LogAcceptCategory(BCLog::HDWALLET)) {
        CExtKey58 ek58;
        ek58.SetKeyP(ek);
        WalletLogPrintf("%s: %s.\n", __func__, ek58.ToString());
        AssertLockHeld(cs_wallet);
    }

    /*
    Get the next destination,
    if key is not saved yet, return 1st key
    don't save key here, save after derived key has been successfully used
    */

    CKeyID keyId = ek.GetID();

    CHDWalletDB wdb(*m_database);

    CStoredExtKey sek;
    if (wdb.ReadExtKey(keyId, sek)) {
        if (m_derived_keys.count(keyId)) {
            uint32_t nKeyIn = m_derived_keys[keyId] + 1;
            if (0 != sek.DeriveKey(pkDest, nKeyIn, nKey)) {
                return werrorN(1, "%s: DeriveKey failed.", __func__);
            }
        } else
        if (0 != sek.DeriveNextKey(pkDest, nKey)) {
            return werrorN(1, "%s: DeriveNextKey failed.", __func__);
        }
        m_derived_keys[keyId] = nKey;
        return 0;
    } else {
        nKey = 0; // AddLookAhead starts from 0
        for (uint32_t i = 0; i < MAX_DERIVE_TRIES; ++i) {
            if (ek.Derive(pkDest, nKey)) {
                return 0;
            }
            nKey++;
        }
    }

    return werrorN(1, "%s: Could not derive key.", __func__);
};

int CHDWallet::ExtKeyUpdateLooseKey(const CExtKeyPair &ek, uint32_t nKey, bool fAddToAddressBook)
{
    if (LogAcceptCategory(BCLog::HDWALLET)) {
        CExtKey58 ek58;
        ek58.SetKeyP(ek);
        WalletLogPrintf("%s %s, nKey %d.\n", __func__, ek58.ToString(), nKey);
        AssertLockHeld(cs_wallet);
    }

    CKeyID keyId = ek.GetID();
    auto mi = m_derived_keys.find(keyId);
    if (mi != m_derived_keys.end()) {
        if (nKey < mi->second + 1) {
            nKey = mi->second + 1;
        }
    }

    CHDWalletDB wdb(*m_database);
    CStoredExtKey sek;
    if (wdb.ReadExtKey(keyId, sek)) {
        sek.nGenerated = nKey;
        if (!wdb.WriteExtKey(keyId, sek)) {
            return werrorN(1, "%s: WriteExtKey failed.", __func__);
        }
    } else {
        sek.kp = CExtKeyPair(ek);
        sek.nGenerated = nKey;
        CKeyID idDerived;
        if (0 != ExtKeyImportLoose(&wdb, sek, idDerived, false, false)) {
            return werrorN(1, "%s: ExtKeyImportLoose failed.", __func__);
        }
    }

    auto epk = MakeExtPubKey(ek);
    if (fAddToAddressBook
        && !m_address_book.count(CTxDestination(epk))) {
        SetAddressBook(epk, "", "");
    }
    return 0;
};

bool CHDWallet::GetFullChainPath(const CExtKeyAccount *pa, size_t nChain, std::vector<uint32_t> &vPath) const
{
    vPath.clear();
    if (!pa->idMaster.IsNull()) {
        ExtKeyMap::const_iterator it = mapExtKeys.find(pa->idMaster);
        if (it == mapExtKeys.end()) {
            CBitcoinAddress addr;
            addr.Set(pa->idMaster, CChainParams::EXT_KEY_HASH);
            return werror("%s: Unknown master key %s.", __func__, addr.ToString());
        }
        const CStoredExtKey *pSek = it->second;
        if (0 != AppendPath(pSek, vPath)) {
            return werror("%s: AppendPath failed.", __func__);
        }
    } else {
        // This account has a path relative to the root, key0 is the account key
        const CStoredExtKey *sek = pa->GetChain(0);
        if (sek && 0 != AppendPath(sek, vPath)) {
            return werror("%s: AppendPath failed.", __func__);
        }
        vPath.pop_back();
    }

    const CStoredExtKey *sekChain = pa->GetChain(nChain);
    if (!sekChain) {
        return werror("%s: Unknown chain %d.", __func__, nChain);
    }

    if (0 != AppendPath(sekChain, vPath)) {
        return werror("%s: AppendPath failed.", __func__);
    }
    return true;
};

bool CHDWallet::FundTransaction(CMutableTransaction& tx, CAmount& nFeeRet, int& nChangePosInOut, bilingual_str& error, bool lockUnspents, const std::set<int>& setSubtractFeeFromOutputs, CCoinControl coinControl)
{
    std::vector<CTempRecipient> vecSend;

    // Turn the txout set into a CRecipient vector
    for (size_t idx = 0; idx < tx.vpout.size(); idx++) {
        const auto &txOut = tx.vpout[idx];

        if (txOut->IsType(OUTPUT_STANDARD)) {
            CTempRecipient tr;
            tr.nType = OUTPUT_STANDARD;
            tr.SetAmount(txOut->GetValue());
            tr.fSubtractFeeFromAmount = setSubtractFeeFromOutputs.count(idx);
            tr.fScriptSet = true;
            tr.scriptPubKey = *txOut->GetPScriptPubKey();

            vecSend.emplace_back(tr);
        } else
        if (txOut->IsType(OUTPUT_DATA)) {
            CTempRecipient tr;
            tr.nType = OUTPUT_DATA;
            tr.vData = ((CTxOutData*)txOut.get())->vData;

            vecSend.emplace_back(tr);
        } else {
            error = _("Output isn't standard.");
            return false;
        }
    }

    coinControl.fAllowOtherInputs = true;

    for (const auto &txin : tx.vin) {
        coinControl.Select(txin.prevout);
        if (txin.scriptWitness.stack.size() > 0) { // Keep existing signatures
            CInputData im;
            im.scriptWitness.stack = txin.scriptWitness.stack;
            coinControl.m_inputData[txin.prevout] = im;
        }
    }

    if (nChangePosInOut != -1) {
        coinControl.nChangePos = nChangePosInOut;
    }

    // Acquire the locks to prevent races to the new locked unspents between the
    // CreateTransaction call and LockCoin calls (when lockUnspents is true).
    LOCK(cs_wallet);

    FeeCalculation fee_calc;
    CTransactionRef tx_new;
    if (!CreateTransaction(vecSend, tx_new, nFeeRet, nChangePosInOut, error, coinControl, fee_calc, false)) {
        return false;
    }

    if (nChangePosInOut != -1) {
        tx.vpout.insert(tx.vpout.begin() + nChangePosInOut, tx_new->vpout[nChangePosInOut]);
    }

    // Copy output sizes from new transaction; they may have had the fee subtracted from them
    for (unsigned int idx = 0; idx < tx.vpout.size(); idx++) {
        if (tx.vpout[idx]->IsType(OUTPUT_STANDARD)) {
            tx.vpout[idx]->SetValue(tx_new->vpout[idx]->GetValue());
        }
    }

    // Add new txins (keeping original txin scriptSig/order)
    for (const auto &txin : tx_new->vin) {
        if (!coinControl.IsSelected(txin.prevout)) {
            tx.vin.push_back(txin);

            if (lockUnspents) {
                LockCoin(txin.prevout);
            }
        }
    }

    if (nFeeRet > this->m_default_max_tx_fee) {
        error = Untranslated(TransactionErrorString(TransactionError::MAX_FEE_EXCEEDED).original);
        return false;
    }

    return true;
};

void CHDWallet::ClearTxCreationState()
{
    m_derived_keys.clear();
}

bool CHDWallet::SignTransaction(CMutableTransaction &tx) const
{
    AssertLockHeld(cs_wallet); // mapWallet

    // sign the new tx
    int nIn = 0;
    for (auto& input : tx.vin) {
        CScript scriptPubKey;
        CAmount amount;

        MapWallet_t::const_iterator mi = mapWallet.find(input.prevout.hash);
        if (mi != mapWallet.end())  {
            if (input.prevout.n >= mi->second.tx->vpout.size()) {
                return false;
            }

            const auto &txOut = mi->second.tx->vpout[input.prevout.n];

            if (!txOut->GetPScriptPubKey()) {
                return werror("%s: No script on output type %d.", __func__, txOut->GetType());
            }

            txOut->GetScriptPubKey(scriptPubKey);
            amount = txOut->GetValue();
        } else {
            MapRecords_t::const_iterator mir = mapRecords.find(input.prevout.hash);
            if (mir == mapRecords.end()) {
                return false;
            }

            const COutputRecord *oR = mir->second.GetOutput(input.prevout.n);
            if (!oR) {
                return false;
            }

            if (oR->nType == OUTPUT_RINGCT) {
                return werror("%s: Can't sign for anon input.", __func__);
            }

            scriptPubKey = oR->scriptPubKey;
            amount = oR->nValue;
        }

        SignatureData sigdata;

        std::vector<uint8_t> vchAmount(8);
        part::SetAmount(vchAmount, amount);
        auto provider = GetLegacyScriptPubKeyMan();
        if (!provider) {
            return false;
        }
        if (!ProduceSignature(*provider, MutableTransactionSignatureCreator(&tx, nIn, vchAmount, SIGHASH_ALL), scriptPubKey, sigdata)) {
            return false;
        }
        UpdateInput(input, sigdata);
        nIn++;
    }
    return true;
}

bool CHDWallet::CreateTransaction(const std::vector<CRecipient>& vecSend, CTransactionRef& tx, CAmount& nFeeRet,
                                int& nChangePosInOut, bilingual_str& error, const CCoinControl& coin_control, FeeCalculation& fee_calc_out, bool sign)
{
    WalletLogPrintf("CHDWallet %s\n", __func__);

    std::vector<CTempRecipient> vecSendB;
    for (const auto &rec : vecSend) {
        CTempRecipient tr;

        tr.nType = OUTPUT_STANDARD;
        tr.SetAmount(rec.nAmount);
        tr.fSubtractFeeFromAmount = rec.fSubtractFeeFromAmount;

        tr.fScriptSet = true;
        tr.scriptPubKey = rec.scriptPubKey;
        //tr.address = rec.address;
        //tr.sNarration = rec.sNarr;

        vecSendB.emplace_back(tr);
    }

    return CreateTransaction(vecSendB, tx, nFeeRet, nChangePosInOut, error, coin_control, fee_calc_out, sign);
};

bool CHDWallet::CreateTransaction(std::vector<CTempRecipient>& vecSend, CTransactionRef& tx, CAmount& nFeeRet,
                                int& nChangePosInOut, bilingual_str& error, const CCoinControl& coin_control, FeeCalculation& fee_calc_out, bool sign)
{
    WalletLogPrintf("CHDWallet %s\n", __func__);

    CTransactionRecord rtxTemp;
    CWalletTx wtxNew(this, tx);
    std::string str_error;
    if (0 != AddStandardInputs(wtxNew, rtxTemp, vecSend, sign, nFeeRet, &coin_control, str_error)) {
        if (!str_error.empty()) {
            error = Untranslated(str_error);
        }
        return false;
    }

    for (const auto &r : vecSend) {
        if (r.fChange) {
            nChangePosInOut = r.n;
            break;
        }
    }

    tx = wtxNew.tx;
    return true;
};

bool CHDWallet::TestMempoolAccept(const CTransactionRef &tx, std::string &sError, CAmount override_max_fee) const {
    if (!GetBroadcastTransactions()) {
        sError = "Wallet broadcast is disabled";
        return false;
    }
    if (!HaveChain()) {
        sError = "Unable to get chain";
        return false;
    }
    if (!chain().isReadyToBroadcast()) {
        //sError = "Node is not ready to broadcast";
        //return false;
    }
    ChainstateManager *pchainman = chain().getChainman();
    if (!pchainman) {
        sError = "Chainstate manager not found";
        return false;
    }
    CTxMemPool *mempool = chain().getMempool();
    if (!mempool) {
        sError = "Unable to get mempool";
        return false;
    }
    const MempoolAcceptResult accept_result = WITH_LOCK(cs_main, return AcceptToMemoryPool(pchainman->ActiveChainstate(), *mempool, tx,
                                                        false /* bypass_limits */, /* test_accept */ true, /* ignore_locks */ false));
    if (accept_result.m_result_type != MempoolAcceptResult::ResultType::VALID) {
        const TxValidationState state = accept_result.m_state;
        sError = state.GetRejectReason();
        return false;
    }
    CAmount max_fee = override_max_fee >= 0 ? override_max_fee : m_default_max_tx_fee;
    if (max_fee > 0 && accept_result.m_base_fees.value() > max_fee) {
        sError = "Exceeds max fee";
        return false;
    }
    return true;
}

void CHDWallet::CommitTransaction(CTransactionRef tx, mapValue_t mapValue, std::vector<std::pair<std::string, std::string>> orderForm)
{
    CTransactionRecord rtx_unused;
    CWalletTx wtx_temp(this, tx);
    TxValidationState state;

    CommitTransaction(wtx_temp, rtx_unused, state, mapValue, orderForm, false);
}

bool CHDWallet::CommitTransaction(CWalletTx &wtxNew, CTransactionRecord &rtx, TxValidationState &state,
                                  mapValue_t mapValue, std::vector<std::pair<std::string, std::string>> orderForm,
                                  bool is_record, bool broadcast_tx, CAmount override_max_fee)
{
    LOCK(cs_wallet);
    WalletLogPrintf("CommitTransaction:\n%s", wtxNew.tx->ToString()); /* Continued */

    CWalletTx *wtx_broadcast = nullptr;
    CWalletTx::Confirmation confirm;
    if (is_record) {
        rtx.nFlags |= ORF_FROM;
        AddToRecord(rtx, *wtxNew.tx, confirm);
        wtx_broadcast = &wtxNew;
    } else {
        CTransactionRef tx = wtxNew.tx;
        mapValue_t mapNarr;
        FindStealthTransactions(*tx, mapNarr);

        if (!mapNarr.empty()) {
            for (const auto &item : mapNarr) {
                mapValue[item.first] = item.second;
            }
        }

        // Add tx to wallet, because if it has change it's also ours,
        // otherwise just for transaction history.
        AddToWallet(tx, {}, [&](CWalletTx& wtx, bool new_tx) {
            CHECK_NONFATAL(wtx.mapValue.empty());
            CHECK_NONFATAL(wtx.vOrderForm.empty());
            wtx.mapValue = std::move(mapValue);
            wtx.vOrderForm = std::move(orderForm);
            wtx.fTimeReceivedIsTxTime = true;
            wtx.fFromMe = true;
            return true;
        });

        // Notify that old coins are spent
        for (const auto &txin : tx->vin) {
            const uint256 &txhash = txin.prevout.hash;
            auto it = mapWallet.find(txin.prevout.hash);
            if (it != mapWallet.end()) {
                it->second.MarkDirty();
            }
            NotifyTransactionChanged(txhash, CT_UPDATED);
        }

        // Get the inserted-CWalletTx from mapWallet so that the
        // fInMempool flag is cached properly
        wtx_broadcast = &mapWallet.at(tx->GetHash());
    }

    if (fBroadcastTransactions && broadcast_tx) {
        std::string err_string;
        assert(wtx_broadcast);
        if (!wtx_broadcast->SubmitMemoryPoolAndRelay(err_string, true, override_max_fee)) {
            WalletLogPrintf("CommitTransaction(): Transaction cannot be broadcast immediately, %s\n", err_string);
            // TODO: if we expect the failure to be long term or permanent, instead delete wtx from the wallet and return failure.
        }
    }
    return true;
};

// Helper for producing a max-sized low-S signature (eg 72 bytes)
bool CHDWallet::DummySignInput(CTxIn &tx_in, const CTxOut &txout, bool use_max_sig) const
{
    // Fill in dummy signatures for fee calculation.
    const CScript &scriptPubKey = txout.scriptPubKey;
    std::unique_ptr<SigningProvider> provider = GetSolvingProvider(scriptPubKey);
    SignatureData sigdata;

    if (!ProduceSignature(*provider, DUMMY_SIGNATURE_CREATOR_PARTICL, scriptPubKey, sigdata)) {
        return false;
    } else {
        UpdateInput(tx_in, sigdata);
    }
    return true;
}

bool CHDWallet::DummySignInput(CTxIn &tx_in, const CTxOutBaseRef &txout) const
{
    // Fill in dummy signatures for fee calculation.
    if (!txout->GetPScriptPubKey()) {
        return werror("%s: Bad output type\n", __func__);
    }
    const CScript &scriptPubKey = *txout->GetPScriptPubKey();
    std::unique_ptr<SigningProvider> provider = GetSolvingProvider(scriptPubKey);
    SignatureData sigdata;

    if (!ProduceSignature(*provider, DUMMY_SIGNATURE_CREATOR_PARTICL, scriptPubKey, sigdata)) {
        return false;
    } else {
        UpdateInput(tx_in, sigdata);
    }
    return true;
}

bool CHDWallet::DummySignTx(CMutableTransaction &txNew, const std::vector<CTxOutBaseRef> &txouts) const
{
    // Fill in dummy signatures for fee calculation.
    int nIn = 0;
    for (const auto& txout : txouts)
    {
        if (!DummySignInput(txNew.vin[nIn], txout)) {
            return false;
        }

        nIn++;
    }
    return true;
};

int CHDWallet::LoadStealthAddresses()
{
    LogPrint(BCLog::HDWALLET, "%s %s\n", GetDisplayName(), __func__);

    LOCK(cs_wallet);

    CHDWalletDB wdb(*m_database);

    Dbc *pcursor;
    if (!(pcursor = wdb.GetCursor())) {
        return werrorN(1, "%s: cannot create DB cursor", __func__);
    }

    CDataStream ssKey(SER_DISK, CLIENT_VERSION);
    CDataStream ssValue(SER_DISK, CLIENT_VERSION);

    CBitcoinAddress addr;
    CStealthAddress sx;
    std::string strType;

    unsigned int fFlags = DB_SET_RANGE;
    ssKey << std::string(DBKeys::PART_SXADDR);
    while (wdb.ReadAtCursor(pcursor, ssKey, ssValue, fFlags) == 0) {
        fFlags = DB_NEXT;

        ssKey >> strType;
        if (strType != DBKeys::PART_SXADDR) {
            break;
        }

        ssValue >> sx;
        if (LogAcceptCategory(BCLog::HDWALLET)) {
            WalletLogPrintf("Loading stealth address %s\n", sx.Encoded());
        }

        stealthAddresses.insert(sx);
    }
    pcursor->close();

    LogPrint(BCLog::HDWALLET, "Loaded %u stealth address.\n", stealthAddresses.size());

    return 0;
};

int CHDWallet::LoadMasterKeys()
{
    LogPrint(BCLog::HDWALLET, "%s %s\n", GetDisplayName(), __func__);

    LOCK(cs_wallet);

    CHDWalletDB wdb(*m_database);

    Dbc *pcursor;
    if (!(pcursor = wdb.GetCursor())) {
        return werrorN(1, "%s: cannot create DB cursor", __func__);
    }

    CDataStream ssKey(SER_DISK, CLIENT_VERSION), ssValue(SER_DISK, CLIENT_VERSION);

    unsigned int fFlags = DB_SET_RANGE;
    std::string strType;
    ssKey << std::string("mkey");
    while (wdb.ReadAtCursor(pcursor, ssKey, ssValue, fFlags) == 0) {
        fFlags = DB_NEXT;

        ssKey >> strType;
        if (strType != "mkey") {
            break;
        }

        unsigned int nID;
        CMasterKey kMasterKey;

        ssKey >> nID;
        ssValue >> kMasterKey;

        if (mapMasterKeys.count(nID) != 0)  {
            return werrorN(1, "%s: reading wallet database: duplicate CMasterKey id %u", __func__, nID);
        }
        mapMasterKeys[nID] = kMasterKey;
        if (nMasterKeyMaxID < nID) {
            nMasterKeyMaxID = nID;
        }
    }
    pcursor->close();

    return 0;
};

bool CHDWallet::IndexStealthKey(CHDWalletDB *pwdb, uint160 &hash, const CStealthAddressIndexed &sxi, uint32_t &id)
{
    AssertLockHeld(cs_wallet);
    LogPrint(BCLog::HDWALLET, "%s: Indexing new stealth key.\n", __func__);

    uint32_t lastId = 0xFFFFFFFF;
    id = 0;

    if (!pwdb->ReadFlag("sxLastI", (int32_t&)id)) {
        if (LogAcceptCategory(BCLog::HDWALLET)) {
            WalletLogPrintf("Warning: %s - ReadFlag sxLastI failed.\n", __func__);
        }
    }

    id++;

    if (id == lastId) {
        return werror("%s: Wallet stealth index is full!", __func__); // expect multiple wallets per node before anyone hits this
    }

    if (LogAcceptCategory(BCLog::HDWALLET)) {
        WalletLogPrintf("%s: New index %u.\n", __func__, id);
    }

    if (!pwdb->WriteStealthAddressIndex(id, sxi)
        || !pwdb->WriteStealthAddressIndexReverse(hash, id)
        || !pwdb->WriteFlag("sxLastI", (int32_t&)id)) {
        return werror("%s: Write failed.", __func__);
    }

    return true;
};

bool CHDWallet::GetStealthKeyIndex(CHDWalletDB *pwdb, const CStealthAddressIndexed &sxi, uint32_t &id)
{
    AssertLockHeld(cs_wallet);

    uint160 hash = Hash160(sxi.addrRaw);
    if (pwdb->ReadStealthAddressIndexReverse(hash, id)) {
        return true;
    }

    return IndexStealthKey(pwdb, hash, sxi, id);
};

bool CHDWallet::GetStealthKeyIndex(const CStealthAddressIndexed &sxi, uint32_t &id)
{
    LOCK(cs_wallet);
    CHDWalletDB wdb(*m_database);

    return GetStealthKeyIndex(&wdb, sxi, id);
};

bool CHDWallet::UpdateStealthAddressIndex(const CKeyID &idK, const CStealthAddressIndexed &sxi, uint32_t &id)
{
    LOCK(cs_wallet);

    uint160 hash = Hash160(sxi.addrRaw);

    CHDWalletDB wdb(*m_database);

    if (wdb.ReadStealthAddressIndexReverse(hash, id)) {
        if (!wdb.WriteStealthAddressLink(idK, id)) {
            return werror("%s: WriteStealthAddressLink failed.\n", __func__);
        }
        return true;
    }

    if (!IndexStealthKey(&wdb, hash, sxi, id)) {
        return werror("%s: IndexStealthKey failed.\n", __func__);
    }

    if (!wdb.WriteStealthAddressLink(idK, id)) {
        return werror("%s: Write failed.\n", __func__);
    }

    return true;
};

bool CHDWallet::GetStealthByIndex(uint32_t sxId, CStealthAddress &sx) const
{
    LOCK(cs_wallet);

    // TODO: cache stealth addresses

    CHDWalletDB wdb(*m_database);

    CStealthAddressIndexed sxi;
    if (!wdb.ReadStealthAddressIndex(sxId, sxi)) {
        return false;
    }
    if (sxi.addrRaw.size() < MIN_STEALTH_RAW_SIZE) {
        return werror("%s: Incorrect size for stealthId: %u", __func__, sxId);
    }
    if (0 != sx.FromRaw(&sxi.addrRaw[0], sxi.addrRaw.size())) {
        return werror("%s: FromRaw failed for stealthId: %u", __func__, sxId);
    }

    return true;
};

bool CHDWallet::GetStealthLinked(CHDWalletDB *pwdb, const CKeyID &idK, CStealthAddress &sx) const
{
    assert(pwdb);
    AssertLockHeld(cs_wallet);

    uint32_t sxId;
    if (!pwdb->ReadStealthAddressLink(idK, sxId)) {
        return false;
    }
    CStealthAddressIndexed sxi;
    if (!pwdb->ReadStealthAddressIndex(sxId, sxi)) {
        return false;
    }
    if (sxi.addrRaw.size() < MIN_STEALTH_RAW_SIZE) {
        return werror("%s: Incorrect size for stealthId: %u", __func__, sxId);
    }
    if (0 != sx.FromRaw(&sxi.addrRaw[0], sxi.addrRaw.size())) {
        return werror("%s: FromRaw failed for stealthId: %u", __func__, sxId);
    }

    return true;
};

bool CHDWallet::GetStealthLinked(const CKeyID &idK, CStealthAddress &sx) const
{
    LOCK(cs_wallet);
    CHDWalletDB wdb(*m_database);

    return GetStealthLinked(&wdb, idK, sx);
};

bool CHDWallet::GetStealthSecret(const CStealthAddress &sx, CKey &key_out) const
{
    if (sx.scan_pubkey.size() != 33) {
        return false;
    }
    for (auto mi = mapExtAccounts.cbegin(); mi != mapExtAccounts.cend(); ++mi) {
        CExtKeyAccount *ea = mi->second;
        for (auto it = ea->mapStealthKeys.cbegin(); it != ea->mapStealthKeys.cend(); ++it) {
            const CEKAStealthKey &aks = it->second;
            if (aks.pkScan.size() == 33 &&
                memcmp(aks.pkScan.data(), sx.scan_pubkey.data(), 33) == 0) {
                key_out = aks.skScan;
                return true;
            }
        }
    }
    for (auto it = stealthAddresses.cbegin(); it != stealthAddresses.cend(); ++it) {
        if (it->scan_pubkey.size() == 33 &&
            memcmp(it->scan_pubkey.data(), sx.scan_pubkey.data(), 33) == 0) {
            key_out = it->scan_secret;
            return true;
        }
    }
    return false;
};

bool CHDWallet::ProcessLockedStealthOutputs()
{
    LogPrint(BCLog::HDWALLET, "%s %s\n", GetDisplayName(), __func__);
    AssertLockHeld(cs_wallet);

    CHDWalletDB wdb(*m_database);

    if (!wdb.TxnBegin()) {
        return werror("%s: TxnBegin failed.", __func__);
    }

    Dbc *pcursor;
    if (!(pcursor = wdb.GetTxnCursor())) {
        return werror("%s: Cannot create DB cursor.", __func__);
    }

    CDataStream ssKey(SER_DISK, CLIENT_VERSION);
    CDataStream ssValue(SER_DISK, CLIENT_VERSION);

    CPubKey pk;

    std::string strType;
    CKeyID idk;
    CStealthKeyMetadata sxKeyMeta;

    size_t nProcessed = 0; // incl any failed attempts
    size_t nExpanded = 0;
    unsigned int fFlags = DB_SET_RANGE;
    ssKey << std::string("sxkm");
    while (wdb.ReadAtCursor(pcursor, ssKey, ssValue, fFlags) == 0) {
        fFlags = DB_NEXT;
        ssKey >> strType;
        if (strType != "sxkm") {
            break;
        }

        nProcessed++;

        ssKey >> idk;
        ssValue >> sxKeyMeta;

        if (!GetPubKey(idk, pk)) {
            WalletLogPrintf("%s Error: GetPubKey failed %s.\n", __func__, EncodeDestination(PKHash(idk)));
            continue;
        }

        CStealthAddress sxFind;
        sxFind.SetScanPubKey(sxKeyMeta.pkScan);

        std::set<CStealthAddress>::iterator si = stealthAddresses.find(sxFind);
        if (si == stealthAddresses.end()) {
            WalletLogPrintf("%s Error: No stealth key found to add secret for %s.\n", __func__, EncodeDestination(PKHash(idk)));
            continue;
        }

        if (LogAcceptCategory(BCLog::HDWALLET)) {
            WalletLogPrintf("Expanding secret for %s\n", EncodeDestination(PKHash(idk)));
        }

        CKey sSpendR, sSpend;

        if (!GetKey(si->spend_secret_id, sSpend)) {
            WalletLogPrintf("%s Error: Stealth address has no spend_secret_id key for %s\n", __func__, EncodeDestination(PKHash(idk)));
            continue;
        }

        if (si->scan_secret.size() != EC_SECRET_SIZE) {
            WalletLogPrintf("%s Error: Stealth address has no scan_secret key for %s\n", __func__, EncodeDestination(PKHash(idk)));
            continue;
        }

        if (sxKeyMeta.pkEphem.size() != EC_COMPRESSED_SIZE) {
            WalletLogPrintf("%s Error: Incorrect Ephemeral point size (%d) for %s\n", __func__, sxKeyMeta.pkEphem.size(), EncodeDestination(PKHash(idk)));
            continue;
        }

        ec_point pkEphem;
        pkEphem.resize(EC_COMPRESSED_SIZE);
        memcpy(&pkEphem[0], sxKeyMeta.pkEphem.begin(), sxKeyMeta.pkEphem.size());

        if (StealthSecretSpend(si->scan_secret, pkEphem, sSpend, sSpendR) != 0) {
            WalletLogPrintf("%s Error: StealthSecretSpend() failed for %s\n", __func__, EncodeDestination(PKHash(idk)));
            continue;
        }

        if (!sSpendR.IsValid()) {
            WalletLogPrintf("%s Error: Reconstructed key is invalid for %s\n", __func__, EncodeDestination(PKHash(idk)));
            continue;
        }

        CPubKey cpkT = sSpendR.GetPubKey();
        if (cpkT != pk) {
            WalletLogPrintf("%s: Error: Generated secret does not match.\n", __func__);
            if (LogAcceptCategory(BCLog::HDWALLET)) {
                LogPrintf("cpkT   %s\n", HexStr(cpkT));
                LogPrintf("pubKey %s\n", HexStr(pk));
            }
            continue;
        }

        if (LogAcceptCategory(BCLog::HDWALLET)) {
            WalletLogPrintf("%s: Adding secret to key %s.\n", __func__, EncodeDestination(PKHash(idk)));
        }


        WalletBatch *batch = &wdb;
        auto spk_man = GetLegacyScriptPubKeyMan();
        if (spk_man) {
            LOCK(spk_man->cs_KeyStore);
            if (!spk_man->AddKeyPubKeyWithDB(*batch, sSpendR, pk)) {
                WalletLogPrintf("%s: Error: AddKeyPubKey failed.\n", __func__);
                continue;
            }
        } else {
            WalletLogPrintf("%s: Error: GetLegacyScriptPubKeyMan failed.\n", __func__);
            continue;
        }

        nExpanded++;

        int rv = pcursor->del(0);
        if (rv != 0) {
            WalletLogPrintf("%s: Error: EraseStealthKeyMeta failed for %s, %d\n", __func__, EncodeDestination(PKHash(idk)), rv);
        }
    }

    pcursor->close();

    wdb.TxnCommit();

    LogPrint(BCLog::HDWALLET, "%s: Expanded %u/%u key%s.\n", __func__, nExpanded, nProcessed, nProcessed == 1 ? "" : "s");

    return true;
};

bool CHDWallet::ProcessLockedBlindedOutputs()
{
    LogPrint(BCLog::HDWALLET, "%s %s\n", GetDisplayName(), __func__);
    AssertLockHeld(cs_wallet);

    size_t nProcessed = 0; // incl any failed attempts
    size_t nExpanded = 0;
    std::set<uint256> setChanged;
    int64_t earliest_anon_out_time = std::numeric_limits<int64_t>::max();

    {
    CHDWalletDB wdb(*m_database);

    if (!wdb.TxnBegin()) {
        return werror("%s: TxnBegin failed.", __func__);
    }

    Dbc *pcursor;
    if (!(pcursor = wdb.GetTxnCursor())) {
        return werror("%s: Cannot create DB cursor.", __func__);
    }

    CDataStream ssKey(SER_DISK, CLIENT_VERSION);

    COutPoint op;
    std::string strType;

    CStoredTransaction stx;
    unsigned int fFlags = DB_SET_RANGE;
    ssKey << std::string("lao");
    while (wdb.ReadKeyAtCursor(pcursor, ssKey, fFlags) == 0) {
        fFlags = DB_NEXT;
        ssKey >> strType;
        if (strType != "lao") {
            break;
        }

        nProcessed++;
        ssKey >> op;

        int rv = pcursor->del(0);
        if (rv != 0) {
            WalletLogPrintf("%s: Error: pcursor->del failed for %s, %d.\n", __func__, op.ToString(), rv);
        }

        MapRecords_t::iterator mir;
        mir = mapRecords.find(op.hash);
        if (mir == mapRecords.end() ||
            !wdb.ReadStoredTx(op.hash, stx)) {
            WalletLogPrintf("%s: Error: mapRecord not found for %s.\n", __func__, op.ToString());
            continue;
        }
        CTransactionRecord &rtx = mir->second;

        if (stx.tx->vpout.size() < op.n) {
            WalletLogPrintf("%s: Error: Outpoint doesn't exist %s.\n", __func__, op.ToString());
            continue;
        }

        const auto &txout = stx.tx->vpout[op.n];

        COutputRecord rout, *pout = rtx.GetOutput(op.n);

        bool fHave = false;
        if (pout) { // Have output recorded already, still need to check if owned
            fHave = true;
        } else {
            pout = &rout;
        }

        uint32_t n = 0;
        bool fUpdated = false;
        bool is_from_me = rtx.FlagSet(ORF_FROM);
        pout->n = op.n;
        switch (txout->nVersion) {
            case OUTPUT_CT:
                if (OwnBlindOut(&wdb, op.hash, (CTxOutCT*)txout.get(), nullptr, n, *pout, stx, fUpdated, is_from_me) &&
                    !fHave) {
                    fUpdated = true;
                    rtx.InsertOutput(*pout);
                }
                break;
            case OUTPUT_RINGCT:
                if (OwnAnonOut(&wdb, op.hash, (CTxOutRingCT*)txout.get(), nullptr, n, *pout, stx, fUpdated, is_from_me) &&
                    !fHave) {
                    fUpdated = true;
                    rtx.InsertOutput(*pout);
                }
                if (earliest_anon_out_time > rtx.GetTxTime()) {
                    earliest_anon_out_time = rtx.GetTxTime();
                }
                break;
            default:
                WalletLogPrintf("%s: Error: Output is unexpected type %d %s.\n", __func__, txout->nVersion, op.ToString());
                continue;
        }

        if (fUpdated) {
            // If txn has change, it must have been sent by this wallet
            if (is_from_me || rtx.HaveChange()) {
                ProcessPlaceholder(*stx.tx.get(), rtx);
            }

            if (!wdb.WriteTxRecord(op.hash, rtx) ||
                !wdb.WriteStoredTx(op.hash, stx)) {
                return false;
            }

            setChanged.insert(op.hash);
        }

        nExpanded++;
    }

    pcursor->close();

    wdb.TxnCommit();
    }

    // Trigger a rescan from the deepest anon out, spend info may need to be updated
    // Only possible if outputs were spent from a different wallet.
    if (!m_is_only_instance &&
        earliest_anon_out_time != std::numeric_limits<int64_t>::max()) {
        WalletRescanReserver reserver(*this);
        if (!reserver.reserve()) {
            WalletLogPrintf("%s: Wallet is currently rescanning.\n", __func__);
        } else {
            RescanFromTime(earliest_anon_out_time, reserver, true);
        }
    }

    // Notify UI of updated transaction
    for (const auto &hash : setChanged) {
        NotifyTransactionChanged(hash, CT_REPLACE);
    }

    LogPrint(BCLog::HDWALLET, "%s %s: Expanded %u/%u output%s.\n", GetDisplayName(), __func__, nExpanded, nProcessed, nProcessed == 1 ? "" : "s");

    return true;
};

bool CHDWallet::CountRecords(std::string sPrefix, int64_t rv)
{
    rv = 0;
    LOCK(cs_wallet);
    CHDWalletDB wdb(*m_database);

    if (!wdb.TxnBegin()) {
        return werror("%s: TxnBegin failed.", __func__);
    }

    Dbc *pcursor;
    if (!(pcursor = wdb.GetTxnCursor())) {
        return werror("%s: Cannot create DB cursor.", __func__);
    }

    CDataStream ssKey(SER_DISK, CLIENT_VERSION);
    ssKey << sPrefix;
    std::string strType;
    unsigned int fFlags = DB_SET_RANGE;
    while (wdb.ReadKeyAtCursor(pcursor, ssKey, fFlags) == 0) {
        fFlags = DB_NEXT;
        ssKey >> strType;
        if (strType != sPrefix) {
            break;
        }

        rv++;
    }

    pcursor->close();

    wdb.TxnAbort();

    return true;
};

inline bool MatchPrefix(uint32_t nAddrBits, uint32_t addrPrefix, uint32_t outputPrefix, bool fHavePrefix)
{
    if (nAddrBits < 1) { // addresses without prefixes scan all incoming stealth outputs
        return true;
    }
    if (!fHavePrefix) { // don't check when address has a prefix and no prefix on output
        return false;
    }

    uint32_t mask = SetStealthMask(nAddrBits);

    return (addrPrefix & mask) == (outputPrefix & mask);
};

void CHDWallet::ProcessStealthLookahead(CExtKeyAccount *ea, const CEKAStealthKey &aks, bool v2)
{
    auto &use_set = v2 ? ea->setLookAheadStealthV2 : ea->setLookAheadStealth;
    size_t rescan_stealth_lookahead = v2 ? m_rescan_stealth_v2_lookahead : m_rescan_stealth_v1_lookahead;

    auto it = use_set.find(&aks);
    if (it != use_set.end()) {
        const CEKAStealthKey *psx = *it;
        CHDWalletDB wdb(*m_database);
        if (!wdb.TxnBegin()) {
            WalletLogPrintf("%s TxnBegin failed.\n", __func__);
            return;
        }

        uint32_t greatestScanKey = 0;
        uint32_t greatestSpendKey = 0;
        for (auto itd = use_set.begin(); itd != use_set.end();) {
            const CEKAStealthKey *psx_test = *itd;
            if (psx_test->nScanKey > greatestScanKey) {
                greatestScanKey = psx_test->nScanKey;
            }
            if (psx_test->akSpend.nKey > greatestSpendKey) {
                greatestSpendKey = psx_test->akSpend.nKey;
            }
            if (psx_test->nScanKey <= psx->nScanKey) {
                CStealthAddress sxAddr;
                if (0 != psx_test->SetSxAddr(sxAddr)) {
                    WalletLogPrintf("%s: Warning SetSxAddr failed.\n", __func__);
                }
                WalletLogPrintf("Promoting stealth address %s from lookahead.\n", sxAddr.ToString());

                if (0 != SaveStealthAddress(&wdb, ea, *psx_test, v2)) {
                    WalletLogPrintf("%s: Warning SaveStealthAddress failed.\n", __func__);
                }
                itd = use_set.erase(itd);
            } else {
                itd++;
            }
        }

        if (!wdb.TxnCommit()) {
            WalletLogPrintf("%s TxnCommit failed.\n", __func__);
            return;
        }

        uint32_t nScanKey = WithoutHardenedBit(greatestScanKey);
        uint32_t nSpendKey = WithoutHardenedBit(greatestSpendKey);

        if (v2) {
            nScanKey += 1;
            nSpendKey += 1;
        } else {
            nScanKey = nSpendKey + 1;  // Step over spend key
        }
        size_t num_loops = 0;
        while (use_set.size() < rescan_stealth_lookahead) {
            CEKAStealthKey akStealth;
            if (v2) {
                if (0 != NewStealthKeyV2FromAccount(nullptr, idDefaultAccount, "", akStealth, 0, nullptr, true, &nScanKey, &nSpendKey)) {
                    WalletLogPrintf("%s NewStealthKeyV2FromAccount failed.\n", __func__);
                    return;
                }
                nScanKey += 1;
                nSpendKey += 1;
            } else {
                if (0 != NewStealthKeyFromAccount(nullptr, idDefaultAccount, "", akStealth, 0, nullptr, false, &nScanKey)) {
                    WalletLogPrintf("%s NewStealthKeyFromAccount failed.\n", __func__);
                    return;
                }
                nScanKey += 1;
            }
            if (LogAcceptCategory(BCLog::HDWALLET)) {
                CStealthAddress sxAddr;
                if (0 == akStealth.SetSxAddr(sxAddr)) {
                    WalletLogPrintf("Adding stealth address %s to lookahead.\n", sxAddr.ToString());
                }
            }

            if (++num_loops > rescan_stealth_lookahead) {
                WalletLogPrintf("%s Loop stuck.\n", __func__);
                return;
            }
        }
    }
};

bool CHDWallet::ProcessStealthOutput(const CTxDestination &address,
    std::vector<uint8_t> &vchEphemPK, uint32_t prefix, bool fHavePrefix, CKey &sShared, bool fNeedShared)
{
    LOCK(cs_wallet);
    ec_point pkExtracted;
    CKey sSpend;

    CKeyID ckidMatch = ToKeyID(std::get<PKHash>(address));
    if (HaveKey(ckidMatch)) {
        CStealthAddress sx;
        if (fNeedShared &&
            GetStealthLinked(ckidMatch, sx) &&
            GetStealthAddressScanKey(sx)) {
            if (StealthShared(sx.scan_secret, vchEphemPK, sShared) != 0) {
                WalletLogPrintf("%s: StealthShared failed.\n", __func__);
                //continue;
            }
        }
        return true;
    }

    std::set<CStealthAddress>::iterator it;
    for (it = stealthAddresses.begin(); it != stealthAddresses.end(); ++it) {
        if (!MatchPrefix(it->prefix.number_bits, it->prefix.bitfield, prefix, fHavePrefix)) {
            continue;
        }

        if (!it->scan_secret.IsValid()) {
            continue; // stealth address is not owned
        }

        if (StealthSecret(it->scan_secret, vchEphemPK, it->spend_pubkey, sShared, pkExtracted) != 0) {
            WalletLogPrintf("%s: StealthSecret failed.\n", __func__);
            continue;
        }

        CPubKey pkE(pkExtracted);
        if (!pkE.IsValid()) {
            continue;
        }

        CKeyID idExtracted = pkE.GetID();
        if (ckidMatch != idExtracted) {
            continue;
        }

        if (LogAcceptCategory(BCLog::HDWALLET)) {
            WalletLogPrintf("Found stealth txn to address %s\n", it->Encoded());
        }

        CStealthAddressIndexed sxi;
        it->ToRaw(sxi.addrRaw);
        uint32_t sxId;
        if (!UpdateStealthAddressIndex(ckidMatch, sxi, sxId)) {
            return werror("%s: UpdateStealthAddressIndex failed.\n", __func__);
        }

        if (!HaveKey(it->spend_secret_id)) {
            const auto script = GetScriptForDestination(address);
            const auto pk_script = GetScriptForRawPubKey(pkE);  // LegacyScriptPubKeyMan::AddWatchOnlyInMem needs a pubkey to affect mapWatchKeys
            auto spk_man = GetLegacyScriptPubKeyMan();
            if (spk_man) {
                LOCK(spk_man->cs_KeyStore);
                spk_man->AddWatchOnly(script, 0 /* nCreateTime */);
                spk_man->AddWatchOnly(pk_script, 0 /* nCreateTime */);
            }
            nFoundStealth++;
            return true;
        }

        if (IsLocked()) {
            if (LogAcceptCategory(BCLog::HDWALLET)) {
                WalletLogPrintf("Wallet locked, adding key without secret.\n");
            }

            // Add key without secret
            std::vector<uint8_t> vchEmpty;
            auto spk_man = GetLegacyScriptPubKeyMan();
            if (spk_man) {
                spk_man->AddCryptedKey(pkE, vchEmpty);
            }

            CPubKey cpkEphem(vchEphemPK);
            CPubKey cpkScan(it->scan_pubkey);
            CStealthKeyMetadata lockedSkMeta(cpkEphem, cpkScan);

            if (!CHDWalletDB(*m_database).WriteStealthKeyMeta(idExtracted, lockedSkMeta)) {
                WalletLogPrintf("WriteStealthKeyMeta failed for %s.\n", EncodeDestination(PKHash(idExtracted)));
            }

            nFoundStealth++;
            return true;
        }

        if (!GetKey(it->spend_secret_id, sSpend)) {
            // silently fail?
            if (LogAcceptCategory(BCLog::HDWALLET))
                WalletLogPrintf("GetKey() stealth spend failed.\n");
            continue;
        }

        CKey sSpendR;
        if (StealthSharedToSecretSpend(sShared, sSpend, sSpendR) != 0) {
            WalletLogPrintf("%s: StealthSharedToSecretSpend() failed.\n", __func__);
            continue;
        }

        CPubKey pkT = sSpendR.GetPubKey();
        if (!pkT.IsValid()) {
            WalletLogPrintf("%s: pkT is invalid.\n", __func__);
            continue;
        }

        CKeyID keyID = pkT.GetID();
        if (keyID != ckidMatch) {
            WalletLogPrintf("%s: Spend key mismatch!\n", __func__);
            continue;
        }

        if (LogAcceptCategory(BCLog::HDWALLET)) {
            WalletLogPrintf("%s: Adding key %s.\n", __func__, EncodeDestination(PKHash(keyID)));
        }

        auto spk_man = GetLegacyScriptPubKeyMan();
        if (spk_man) {
            LOCK(spk_man->cs_KeyStore);
            if (!spk_man->AddKeyPubKey(sSpendR, pkT)) {
                WalletLogPrintf("%s: AddKeyPubKey failed.\n", __func__);
                continue;
            }
        } else {
            WalletLogPrintf("%s: GetLegacyScriptPubKeyMan failed.\n", __func__);
        }

        nFoundStealth++;
        return true;
    }

    // ext account stealth keys
    for (auto mi = mapExtAccounts.cbegin(); mi != mapExtAccounts.cend(); ++mi) {
        CExtKeyAccount *ea = mi->second;

        for (auto it = ea->mapStealthKeys.cbegin(); it != ea->mapStealthKeys.cend(); ++it) {
            const CEKAStealthKey &aks = it->second;

            if (!MatchPrefix(aks.nPrefixBits, aks.nPrefix, prefix, fHavePrefix)) {
                continue;
            }
            if (!aks.skScan.IsValid()) {
                continue;
            }
            if (StealthSecret(aks.skScan, vchEphemPK, aks.pkSpend, sShared, pkExtracted) != 0) {
                WalletLogPrintf("%s: StealthSecret failed.\n", __func__);
                continue;
            }
            CPubKey pkE(pkExtracted);
            if (!pkE.IsValid()) {
                continue;
            }
            CKeyID idExtracted = pkE.GetID();
            if (ckidMatch != idExtracted) {
                continue;
            }

            if (LogAcceptCategory(BCLog::HDWALLET)) {
                WalletLogPrintf("Found stealth txn to address %s\n", aks.ToStealthAddress());

                // Check key if not locked
                if (!IsLocked() && !(ea->nFlags & EAF_HARDWARE_DEVICE)) {
                    CKey kTest;
                    if (0 != ea->ExpandStealthChildKey(&aks, sShared, kTest)) {
                        WalletLogPrintf("%s: Error: ExpandStealthChildKey failed! %s.\n", __func__, aks.ToStealthAddress());
                        continue;
                    }

                    CKeyID kTestId = kTest.GetPubKey().GetID();
                    if (kTestId != ckidMatch) {
                        WalletLogPrintf("%s: Error: Spend key mismatch!\n", __func__);
                        continue;
                    }
                    WalletLogPrintf("Debug: ExpandStealthChildKey matches! %s, %s.\n", aks.ToStealthAddress(), EncodeDestination(PKHash(kTestId)));
                }
            }

            // Don't need to extract key now, wallet may be locked
            CKeyID idStealthKey = aks.GetID();
            CEKASCKey kNew(idStealthKey, sShared);
            if (0 != ExtKeySaveKey(ea, ckidMatch, kNew)) {
                WalletLogPrintf("%s: Error: ExtKeySaveKey failed!\n", __func__);
                continue;
            }

            CStealthAddressIndexed sxi;
            aks.ToRaw(sxi.addrRaw);
            uint32_t sxId;
            if (!UpdateStealthAddressIndex(ckidMatch, sxi, sxId)) {
                return werror("%s: UpdateStealthAddressIndex failed.\n", __func__);
            }

            ProcessStealthLookahead(ea, aks, false);
            ProcessStealthLookahead(ea, aks, true);
            return true;
        }
    }

    return false;
};

int CHDWallet::CheckForStealthAndNarration(const CTxOutBase *pb, const CTxOutData *pdata, std::string &sNarr)
{
    // Returns: -1 error, 0 nothing found, 1 narration, 2 stealth

    CKey sShared;
    std::vector<uint8_t> vchEphemPK;
    const std::vector<uint8_t> &vData = pdata->vData;

    if (vData.size() < 1) {
        return -1;
    }

    if (vData[0] == DO_NARR_PLAIN) {
        if (vData.size() < 2) {
            return -1; // error
        }
        sNarr = std::string(vData.begin() + 1, vData.end());
        return 1;
    }

    if (vData[0] == DO_STEALTH) {
        if (vData.size() < 34 ||
            !pb->IsStandardOutput()) {
            return -1; // error
        }

        vchEphemPK.resize(33);
        memcpy(&vchEphemPK[0], &vData[1], 33);

        uint32_t prefix = 0;
        bool fHavePrefix = ExtractStealthPrefix(vData, prefix, 34);

        const CTxOutStandard *so = (CTxOutStandard*)pb;
        CTxDestination address;
        if (!ExtractDestination(so->scriptPubKey, address) ||
            address.index() != DI::_PKHash) {
            //WalletLogPrintf("%s: ExtractDestination failed.\n",  __func__);
            return -1;
        }

        if (!ProcessStealthOutput(address, vchEphemPK, prefix, fHavePrefix, sShared, true)) {
            // TODO: check all other outputs?
            return 0;
        }

        int nNarrOffset = -1;
        if (vData.size() > 40 && vData[39] == DO_NARR_CRYPT) {
            nNarrOffset = 40;
        } else
        if (vData.size() > 35 && vData[34] == DO_NARR_CRYPT) {
            nNarrOffset = 35;
        }

        if (nNarrOffset > -1) {
            size_t lenNarr = vData.size() - nNarrOffset;
            if (lenNarr < 1 || lenNarr > 32) { // min block size 8?
                WalletLogPrintf("%s: Invalid narration data length: %d\n", __func__, lenNarr);
                return 2; // still found
            }

            SecMsgCrypter crypter;
            crypter.SetKey(sShared.begin(), &vchEphemPK[0]);

            std::vector<uint8_t> vchNarr;
            if (!crypter.Decrypt(&vData[nNarrOffset], lenNarr, vchNarr)) {
                WalletLogPrintf("%s: Decrypt narration failed.\n", __func__);
                return 2; // still found
            }
            sNarr = std::string(vchNarr.begin(), vchNarr.end());
        }

        return 2;
    }

    if (vData[0] == DO_FUND_MSG) {
        return 0;
    }

    WalletLogPrintf("%s: Unknown data output type %d.\n",  __func__, vData[0]);
    return -1;
};

void CHDWallet::FindStealthTransactions(const CTransaction &tx, mapValue_t &mapNarr)
{
    if (LogAcceptCategory(BCLog::HDWALLET)) {
        WalletLogPrintf("%s: tx: %s.\n", __func__, tx.GetHash().GetHex());
    }

    mapNarr.clear();

    LOCK(cs_wallet);

    // A data output always applies to the preceding output
    int32_t nOutputId = -1;
    for (const auto &txout : tx.vpout) {
        nOutputId++;
        if (txout->nVersion != OUTPUT_DATA) {
            continue;
        }

        CTxOutData *txd = (CTxOutData*) txout.get();

        if (nOutputId < 1) {
            if (LogAcceptCategory(BCLog::HDWALLET)) { // this is normal for CT / RCT txns
                WalletLogPrintf("%s: Ignoring data output in pos 0, tx: %s.\n", __func__, tx.GetHash().GetHex());
            }
            continue;
        }

        std::string sNarr;
        if (CheckForStealthAndNarration(tx.vpout[nOutputId-1].get(), txd, sNarr) < 0) {
            WalletLogPrintf("%s: txn %s, malformed data output %d.\n",  __func__, tx.GetHash().ToString(), nOutputId);
        }

        if (sNarr.length() > 0) {
            std::string sKey = strprintf("n%d", nOutputId-1);
            mapNarr[sKey] = sNarr;
        }
    }

    return;
};

bool CHDWallet::ScanForOwnedOutputs(const CTransaction &tx, size_t &nCT, size_t &nRingCT, mapValue_t &mapNarr)
{
    AssertLockHeld(cs_wallet);

    bool fIsMine = false;
    mapNarr.clear();

    int32_t nOutputId = -1;
    for (const auto &txout : tx.vpout) {
        nOutputId++;
        if (txout->IsType(OUTPUT_CT)) {
            nCT++;
            const CTxOutCT *ctout = (CTxOutCT*) txout.get();

            CTxDestination address;
            if (!ExtractDestination(ctout->scriptPubKey, address)) {
                //WalletLogPrintf("%s: ExtractDestination failed.\n", __func__);
                continue;
            }
            if (IsMine(address)) {
                fIsMine = true;
            }

            if (address.index() != DI::_PKHash) {
                continue;
            }


            // Uncover stealth
            uint32_t prefix = 0;
            bool fHavePrefix = ExtractStealthPrefix(ctout->vData, prefix);

            CKey sShared;
            std::vector<uint8_t> vchEphemPK;
            vchEphemPK.resize(33);
            memcpy(&vchEphemPK[0], &ctout->vData[0], 33);

            if (ProcessStealthOutput(address, vchEphemPK, prefix, fHavePrefix, sShared)) {
                fIsMine = true;
            }
        } else
        if (txout->IsType(OUTPUT_RINGCT)) {
            nRingCT++;
            const CTxOutRingCT *rctout = (CTxOutRingCT*) txout.get();

            CKeyID idk = rctout->pk.GetID();

            // Uncover stealth
            uint32_t prefix = 0;
            bool fHavePrefix = ExtractStealthPrefix(rctout->vData, prefix);

            CKey sShared;
            std::vector<uint8_t> vchEphemPK;
            vchEphemPK.resize(33);
            memcpy(&vchEphemPK[0], &rctout->vData[0], 33);

            if (ProcessStealthOutput(PKHash(idk), vchEphemPK, prefix, fHavePrefix, sShared)) {
                fIsMine = true;
            }
        } else
        if (txout->IsType(OUTPUT_STANDARD)) {
            if (nOutputId < (int)tx.vpout.size()-1
                && tx.vpout[nOutputId+1]->IsType(OUTPUT_DATA)) {
                CTxOutData *txd = (CTxOutData*) tx.vpout[nOutputId+1].get();

                std::string sNarr;
                if (CheckForStealthAndNarration(txout.get(), txd, sNarr) < 0) {
                    WalletLogPrintf("%s: txn %s, malformed data output %d.\n",  __func__, tx.GetHash().ToString(), nOutputId);
                }

                if (sNarr.length() > 0) {
                    std::string sKey = strprintf("n%d", nOutputId);
                    mapNarr[sKey] = sNarr;
                }
            }
            if (txout->GetValue() < m_min_owned_value) {
                continue;
            }

            if (IsMine(txout.get())) {
                fIsMine = true;
            }
        }
    }

    return fIsMine;
};

int CHDWallet::UnloadSpent(const uint256 &wtxid, int depth, const uint256 &wtxid_from)
{
    if (!m_chain) return 0;
    LOCK(cs_wallet);

    // Txns may be loaded out of order.
    auto it = mapWallet.find(wtxid);
    if (it == mapWallet.end()) {
        return 0;
    }
    CWalletTx &thisTx = it->second;

    for (const CTxIn& txin : thisTx.tx->vin) {
        UnloadSpent(txin.prevout.hash, depth+1, wtxid);
    }

    auto mcsi = mapTxCollapsedSpends.find(wtxid);
    std::set<uint256> try_unload;
    if (mcsi != mapTxCollapsedSpends.end()) {
        for (auto it = mcsi->second.begin(); it != mcsi->second.end(); ) {
            if (m_collapsed_txns.find(*it) != m_collapsed_txns.end()) {
                mcsi->second.erase(it++);
                continue;
            }
            ++it;
        }
        try_unload = mcsi->second;
    }
    for (const auto &hash : try_unload) {
        UnloadSpent(hash, m_min_collapse_depth+1, wtxid); // a txn in mapTxCollapsedSpends will always be > m_min_collapse_depth
    }

    if (depth < m_min_collapse_depth) {
        return 0;
    }

    if (m_collapse_spent_mode < 2 && !thisTx.IsCoinStake()) {
        return 0;
    }

    if (thisTx.GetDepthInMainChain() < 6) {
        return 0;
    }

    for (unsigned int i = 0; i < thisTx.tx->GetNumVOuts(); i++) {
        const auto &txout = thisTx.tx->vpout[i];
        if (IsMine(txout.get())
            && !IsSpent(wtxid, i)) {
            return 0;
        }
    }

    // Move collapsed spent connections from tx being destroyed to wtxid_from
    auto mcsi_r = mapTxCollapsedSpends.find(wtxid);
    if (mcsi_r != mapTxCollapsedSpends.end()) {
        if (mcsi_r->second.size() > 0) {
            mapTxCollapsedSpends[wtxid_from] = mcsi_r->second;
        }
        mapTxCollapsedSpends.erase(mcsi_r);
    }

    for (const CTxIn &txin : thisTx.tx->vin) {
        if (m_collapsed_txns.find(txin.prevout.hash) == m_collapsed_txns.end()) {
            m_collapsed_txn_inputs.insert(txin.prevout);
            mapTxCollapsedSpends[wtxid_from].insert(txin.prevout.hash);
        }
    }

    m_collapsed_txns.insert(wtxid);
    UnloadTransaction(wtxid);

    auto itl = m_collapsed_txn_inputs.lower_bound(COutPoint(wtxid, 0));
    while (itl != m_collapsed_txn_inputs.end() && itl->hash == wtxid) {
        m_collapsed_txn_inputs.erase(itl++);
    }

    return 1;
};

void CHDWallet::PostProcessUnloadSpent()
{
    LogPrint(BCLog::HDWALLET, "%s %s\n", GetDisplayName(), __func__);

    if (m_collapse_spent_mode < 1) {
        return;
    }

    // Some txns are missed when loading the wallet as txns are loaded out of order.

    std::set<std::pair<uint256, uint256>> try_unload;
    std::vector<COutput> availableCoins;

    {
        LOCK(cs_wallet);

        for (auto it = m_collapsed_txn_inputs.begin(); it != m_collapsed_txn_inputs.end(); ) {
            if (m_collapsed_txns.find(it->hash) != m_collapsed_txns.end()) {
                m_collapsed_txn_inputs.erase(it++);
                continue;
            }
            ++it;
        }

        AvailableCoins(availableCoins);
    }

    for (const COutput& coin : availableCoins) {
        if (coin.tx->IsCoinBase()) {
            return;
        }

        for (const CTxIn& txin : coin.tx->tx->vin) {
            try_unload.insert(std::make_pair(txin.prevout.hash, coin.tx->GetHash()));
        }
    }

    for (const auto &hash : try_unload) {
        UnloadSpent(hash.first, 1, hash.second);
    }
};

bool CHDWallet::HaveSpend(const COutPoint &outpoint, const uint256 &txid)
{
    std::pair<TxSpends::const_iterator, TxSpends::const_iterator> range = mapTxSpends.equal_range(outpoint);
    for (TxSpends::const_iterator it = range.first; it != range.second; ++it) {
        if (it->second == txid) {
            return true;
        }
    }
    return false;
};

void CHDWallet::AddToSpends(const uint256& wtxid)
{
    auto it = mapWallet.find(wtxid);
    assert(it != mapWallet.end());
    CWalletTx& thisTx = it->second;
    if (thisTx.IsCoinBase()) // Coinbases don't spend anything!
        return;

    for (const CTxIn& txin : thisTx.tx->vin) {
        AddToSpends(txin.prevout, wtxid);
        if (m_collapse_spent_mode > 0) {
            UnloadSpent(txin.prevout.hash, 1, wtxid);
        }
    }
}

bool CHDWallet::AddToWalletIfInvolvingMe(const CTransactionRef& ptx, CWalletTx::Confirmation confirm, bool fUpdate)
{
    const CTransaction& tx = *ptx;
    {
        AssertLockHeld(cs_wallet);
        if (!confirm.hashBlock.IsNull()) {
            for (const auto &txin : tx.vin) {
                if (txin.IsAnonInput()) {
                    continue;
                }
                std::pair<TxSpends::const_iterator, TxSpends::const_iterator> range = mapTxSpends.equal_range(txin.prevout);
                while (range.first != range.second) {
                    if (range.first->second != tx.GetHash()) {
                        const CWalletTx *wtxConflicted = GetWalletTx(range.first->second); // coinstakes will only be in mapwallet
                        if (wtxConflicted && wtxConflicted->isAbandoned() && wtxConflicted->IsCoinStake()) {
                            // Respending input from orphaned coinstake, leave abandoned
                            WalletLogPrintf("Reusing kernel from orphaned stake %s, new tx %s, \n    (kernel %s:%i).\n",
                                range.first->second.ToString(), tx.GetHash().ToString(), range.first->first.hash.ToString(), range.first->first.n);
                        } else {
                            WalletLogPrintf("Transaction %s (in block %s) conflicts with wallet transaction %s (both spend %s:%i)\n", tx.GetHash().ToString(), confirm.hashBlock.ToString(), range.first->second.ToString(), range.first->first.hash.ToString(), range.first->first.n);
                            MarkConflicted(confirm.hashBlock, confirm.block_height, range.first->second);
                        }
                    }
                    range.first++;
                }
            }
        }

        mapValue_t mapNarr;
        size_t nCT = 0, nRingCT = 0;
        bool fIsMine = ScanForOwnedOutputs(tx, nCT, nRingCT, mapNarr);

        bool fIsFromMe = false;
        MapWallet_t::const_iterator miw;
        MapRecords_t::const_iterator mir;
        for (const auto &txin : tx.vin) {
            if (txin.IsAnonInput()) {
                nRingCT++;
                uint32_t nInputs, nRingSize;
                txin.GetAnonInfo(nInputs, nRingSize);

                const std::vector<uint8_t> &vKeyImages = txin.scriptData.stack[0];
                if (vKeyImages.size() != nInputs * 33) {
                    WalletLogPrintf("Error: %s - Malformed anon txin, %s.\n", __func__, tx.GetHash().ToString());
                    continue;
                }

                CHDWalletDB wdb(*m_database);
                for (size_t k = 0; k < nInputs; ++k) {
                    const CCmpPubKey &ki = *((CCmpPubKey*)&vKeyImages[k*33]);
                    COutPoint prevout;

                    // TODO: Keep keyimages in memory
                    if (!wdb.ReadAnonKeyImage(ki, prevout)) {
                        continue;
                    }
                    fIsFromMe = true;
                    break;
                }
                if (fIsFromMe) {
                    break; // only need one match)
                }
            }

            miw = mapWallet.find(txin.prevout.hash);
            if (miw != mapWallet.end()) {
                const CWalletTx &prev = miw->second;
                if (txin.prevout.n < prev.tx->vpout.size() &&
                    IsMine(prev.tx->vpout[txin.prevout.n].get()) & ISMINE_ALL) {
                    fIsFromMe = true;
                    break; // only need one match
                }
                continue; // a txn in mapWallet shouldn't be in mapRecords too
            }

            mir = mapRecords.find(txin.prevout.hash);
            if (mir != mapRecords.end()) {
                const COutputRecord *r = mir->second.GetOutput(txin.prevout.n);
                if (r && r->nFlags & ORF_OWN_ANY) {
                    fIsFromMe = true;
                    break; // only need one match
                }
            }
        }

        // Tx spending frozen blinded won't have a change output, check for ct fee
        CAmount nFee;
        if (nCT > 0 || nRingCT > 0 || (!tx.IsCoinStake() && tx.GetCTFee(nFee))) {
            bool fExisted = mapRecords.count(tx.GetHash()) != 0;
            if (fExisted && !fUpdate) return false;

            if (fExisted || fIsMine || fIsFromMe) {
                CTransactionRecord rtx;
                m_found_tx_in_block = true;
                if (fIsFromMe) {
                    rtx.nFlags |= ORF_FROM;
                }
                return AddToRecord(rtx, tx, confirm, false);
            }
            return false;
        }

        bool fExisted = mapWallet.count(tx.GetHash()) != 0;
        if (fExisted && !fUpdate) return false;
        if (fExisted || fIsMine || fIsFromMe) {
            // A coinstake txn not linked to a block is being orphaned
            if (fExisted && tx.IsCoinStake() && confirm.hashBlock.IsNull()) {
                uint256 hashTx = tx.GetHash();
                WalletLogPrintf("Orphaning stake txn: %s\n", hashTx.ToString());

                // If block is later reconnected tx will be unabandoned by AddToWallet
                if (!AbandonTransaction(hashTx)) {
                    WalletLogPrintf("ERROR: %s - Orphaning stake, AbandonTransaction failed for %s\n", __func__, hashTx.ToString());
                }
                confirm.status = CWalletTx::ABANDONED;
            }

            // Block disconnection override an abandoned tx as unconfirmed
            // which means user may have to call abandontransaction again
            if (!AddToWallet(MakeTransactionRef(tx), confirm, /* update_wtx= */ nullptr, /* fFlushOnClose= */ false)) {
                return false;
            }

            CWalletTx& wtx = mapWallet.at(tx.GetHash());
            if (!mapNarr.empty()) {
                wtx.mapValue.insert(mapNarr.begin(), mapNarr.end());
            }

            m_found_tx_in_block = true;
            return true;
        }
    }

    return false;
};

CWalletTx *CHDWallet::GetTempWalletTx(const uint256& hash)
{
    LOCK(cs_wallet);
    MapWallet_t::iterator itr = mapTempWallet.find(hash);
    if (itr != mapTempWallet.end()) {
        return &(itr->second);
    }

    return nullptr;
};

const CWalletTx *CHDWallet::GetWalletTx(const uint256 &hash) const
{
    LOCK(cs_wallet);
    MapWallet_t::const_iterator it = mapTempWallet.find(hash);
    if (it != mapTempWallet.end()) {
        return &(it->second);
    }

    return CWallet::GetWalletTx(hash);
}

CWalletTx *CHDWallet::GetWalletTx(const uint256& hash)
{
    LOCK(cs_wallet);
    MapWallet_t::iterator itr = mapTempWallet.find(hash);
    if (itr != mapTempWallet.end()) {
        return &(itr->second);
    }

    MapWallet_t::iterator it = mapWallet.find(hash);
    if (it == mapWallet.end()) {
        return nullptr;
    }

    return &(it->second);
};

void CHDWallet::SetTempTxnStatus(CWalletTx &wtx, const CTransactionRecord *rtx) const
{
    wtx.m_confirm.hashBlock = rtx->blockHash;
    wtx.m_confirm.block_height = rtx->block_height;
    wtx.m_confirm.nIndex = rtx->nIndex;
    if (rtx->nIndex == -1 && rtx->blockHash == ABANDON_HASH) {
        wtx.setAbandoned();
    } else if (rtx->nIndex == -1) {
        wtx.setConflicted();
    } else if (!rtx->blockHash.IsNull()) {
        wtx.setConfirmed();
    }
    wtx.nTimeSmart = rtx->GetTxTime();
    wtx.nTimeReceived = rtx->nTimeReceived;
};

int CHDWallet::InsertTempTxn(const uint256 &txid, const CTransactionRecord *rtx) const
{
    LOCK(cs_wallet);

    CStoredTransaction stx;
    if (!CHDWalletDB(*m_database).ReadStoredTx(txid, stx)) {
        return werrorN(1, "%s: ReadStoredTx failed for %s.\n", __func__, txid.ToString().c_str());
    }

    auto ret = mapTempWallet.emplace(std::piecewise_construct, std::forward_as_tuple(txid), std::forward_as_tuple(this, stx.tx));

    // Get the inserted-CWalletTx from mapTempWallet so that the
    // fInMempool flag is cached properly
    CWalletTx& wtx = mapTempWallet.at(txid);
    if (rtx) {
        SetTempTxnStatus(wtx, rtx);
    }

    // Use ret to silence warning
    bool fInsertedNew = ret.second;
    if (fInsertedNew) {
        wtx.nTimeReceived = chain().getAdjustedTime();
        wtx.nTimeSmart = ComputeTimeSmart(wtx);
    }

    return 0;
};

const CWalletTx *CHDWallet::GetWalletOrTempTx(const uint256& hash, const CTransactionRecord *rtx) const
{
    const CWalletTx *pcoin = GetWalletTx(hash);
    if (pcoin) {
        return pcoin;
    }
    if (0 != InsertTempTxn(hash, rtx)) {
        return nullptr;
    }
    return GetWalletTx(hash);
};

int CHDWallet::OwnStandardOut(const CTxOutStandard *pout, const CTxOutData *pdata,
    COutputRecord &rout, bool &fUpdated, bool is_from_me)
{
    if (pout->nValue < m_min_owned_value) {
        return 0;
    }
    if (pdata) {
        std::string sNarr;
        if (CheckForStealthAndNarration((CTxOutBase*)pout, pdata, sNarr) < 0) {
            WalletLogPrintf("%s: malformed data output %d.\n",  __func__, rout.n);
        }

        if (sNarr.length() > 0) {
            rout.sNarration = sNarr;
        }
    }

    CKeyID idk;
    const CEKAKey *pak = nullptr;
    const CEKASCKey *pasc = nullptr;
    CExtKeyAccount *pa = nullptr;
    bool isInvalid = false;
    isminetype mine = IsMine(pout->scriptPubKey, idk, pak, pasc, pa, isInvalid);
    if (!(mine & ISMINE_ALL)) {
        return 0;
    }

    if (is_from_me && pa && pak && pa->nActiveInternal == pak->nParent) { // TODO: could check EKVT_KEY_TYPE
        fUpdated = fUpdated || (!rout.FlagSet(ORF_CHANGE) || !rout.FlagSet(ORF_FROM));
        rout.nFlags |= ORF_CHANGE | ORF_FROM;
    }

    rout.nType = OUTPUT_STANDARD;
    if (mine & ISMINE_SPENDABLE) {
        rout.nFlags |= ORF_OWNED;
        rout.nFlags &= ~(ORF_OWN_WATCH);
    } else
    if (mine & ISMINE_WATCH_COLDSTAKE) {
        rout.nFlags |= ORF_STAKEONLY;
    } else {
        rout.nFlags |= ORF_WATCHONLY;
    }

    if (mine & ISMINE_HARDWARE_DEVICE) {
        rout.nFlags |= ORF_HARDWARE_DEVICE;
    }

    rout.nValue = pout->nValue;
    rout.scriptPubKey = pout->scriptPubKey;
    rout.nFlags &= ~ORF_LOCKED;

    return 1;
};

int CHDWallet::OwnBlindOut(CHDWalletDB *pwdb, const uint256 &txhash, const CTxOutCT *pout, const CStoredExtKey *pc, uint32_t &nLastChild,
    COutputRecord &rout, CStoredTransaction &stx, bool &fUpdated, bool tx_is_from_me)
{
    /*
    bool fDecoded = false;
    if (pc && !IsLocked()) // check if output is from this wallet
    {
        CKey keyEphem;
        uint32_t nChildOut;
        if (0 == pc->DeriveKey(keyEphem, nLastChild, nChildOut, true))
        {
            // regenerate nonce
            //uint256 nonce = keyEphem.ECDH(pkto_outs[k]);
            //CSHA256().Write(nonce.begin(), 32).Finalize(nonce.begin());
        };
    };
    */
    rout.nType = OUTPUT_CT;
    CKeyID idk;
    const CEKAKey *pak = nullptr;
    const CEKASCKey *pasc = nullptr;
    CExtKeyAccount *pa = nullptr;
    bool isInvalid = false;
    isminetype mine = IsMine(pout->scriptPubKey, idk, pak, pasc, pa, isInvalid);
    if (!(mine & ISMINE_ALL)) {
        return 0;
    }
    if (tx_is_from_me && pa && pak && pa->nActiveInternal == pak->nParent) {
        fUpdated = fUpdated || (!rout.FlagSet(ORF_CHANGE) || !rout.FlagSet(ORF_FROM));
        rout.nFlags |= ORF_CHANGE | ORF_FROM;
    }
    if (mine & ISMINE_SPENDABLE) {
        rout.nFlags |= ORF_OWNED;
        rout.nFlags &= ~(ORF_OWN_WATCH);
    } else {
        rout.nFlags |= ORF_WATCHONLY;
    }
    if (mine & ISMINE_HARDWARE_DEVICE) {
        rout.nFlags |= ORF_HARDWARE_DEVICE;
    }

    if (IsLocked()) {
        COutPoint op(txhash, rout.n);
        if ((rout.nFlags & ORF_LOCKED) &&
            !pwdb->HaveLockedAnonOut(op)) {
            rout.nValue = 0;
            fUpdated = true;
            if (LogAcceptCategory(BCLog::HDWALLET)) WalletLogPrintf("%s: Adding locked blind output %s, %d.\n", __func__, txhash.ToString(), rout.n);
            if (!pwdb->WriteLockedAnonOut(op)) {
                WalletLogPrintf("Error: %s - WriteLockedAnonOut failed.\n", __func__);
            }
        }
        return 1;
    }

    if (pout->vData.size() < 33) {
        return werrorN(0, "%s: vData.size() < 33.", __func__);
    }

    CPubKey pkEphem;
    pkEphem.Set(pout->vData.begin(), pout->vData.begin() + 33);

    CKey key;
    // Regenerate nonce
    uint256 nonce;
    if (GetKey(idk, key)) {
        nonce = key.ECDH(pkEphem);
        CSHA256().Write(nonce.begin(), 32).Finalize(nonce.begin());
    }

    uint64_t min_value, max_value;
    uint8_t blindOut[32];
    unsigned char msg[256]; // Narration is capped at 32 bytes
    size_t mlen = sizeof(msg);
    memset(msg, 0, mlen);
    uint64_t amountOut = 0;

    if (pout->vRangeproof.size() < 1000) {
        int rewind_rv = 0;
        if (!nonce.IsNull()) {
            rewind_rv = secp256k1_bulletproof_rangeproof_rewind(secp256k1_ctx_blind, blind_gens,
                &amountOut, blindOut, pout->vRangeproof.data(), pout->vRangeproof.size(),
                0, &pout->commitment, &secp256k1_generator_const_h, nonce.begin(), nullptr, 0);
        }

        // Try again with the watch_only_nonce
        if (rewind_rv < 1) {
            CStealthAddress sx;
            CKey scan_secret;

            if (GetStealthLinked(pwdb, idk, sx) &&
                GetStealthSecret(sx, scan_secret)) {

                // pk_tweaked = pkEphem + G * tweak
                uint256 watch_only_nonce, tweak(uint256S("0x444"));
                secp256k1_pubkey R;
                if (!secp256k1_ec_pubkey_parse(secp256k1_ctx_blind, &R, pkEphem.data(), EC_COMPRESSED_SIZE)) {
                    return werrorN(0, "%s: secp256k1_ec_pubkey_parse R failed.", __func__);
                }
                if (!secp256k1_ec_pubkey_tweak_add(secp256k1_ctx_blind, &R, tweak.begin())) {
                    return werrorN(0, "%s: secp256k1_ec_pubkey_tweak_add failed.", __func__);
                }

                CPubKey pk_tweaked;
                unsigned char pub[33];
                size_t publen = 33;
                secp256k1_ec_pubkey_serialize(secp256k1_ctx_blind, pub, &publen, &R, SECP256K1_EC_COMPRESSED);
                pk_tweaked.Set(pub, pub + publen);

                watch_only_nonce = scan_secret.ECDH(pk_tweaked);
                CSHA256().Write(watch_only_nonce.begin(), 32).Finalize(watch_only_nonce.begin());

                rewind_rv = secp256k1_bulletproof_rangeproof_rewind(secp256k1_ctx_blind, blind_gens,
                    &amountOut, blindOut, pout->vRangeproof.data(), pout->vRangeproof.size(),
                    0, &pout->commitment, &secp256k1_generator_const_h, watch_only_nonce.begin(), nullptr, 0);
            }
        }
        if (rewind_rv != 1) {
            return werrorN(0, "%s: secp256k1_bulletproof_rangeproof_rewind failed.", __func__);
        }

        ExtractNarration(nonce, pout->vData, rout.sNarration);
    } else
    if (nonce.IsNull() ||
        1 != secp256k1_rangeproof_rewind(secp256k1_ctx_blind,
                blindOut, &amountOut, msg, &mlen, nonce.begin(),
                &min_value, &max_value,
                &pout->commitment, pout->vRangeproof.data(), pout->vRangeproof.size(),
                nullptr, 0,
                secp256k1_generator_h)) {
        return werrorN(0, "%s: secp256k1_rangeproof_rewind failed.", __func__);
    }
    if ((CAmount)amountOut < m_min_owned_value) {
        return 0;
    }

    msg[mlen-1] = '\0';
    size_t nNarr = strlen((const char*)msg);
    if (nNarr > 0) {
        rout.sNarration.assign((const char*)msg, nNarr);
    }

    rout.nValue = amountOut;
    rout.scriptPubKey = pout->scriptPubKey;
    rout.nFlags &= ~ORF_LOCKED;

    stx.InsertBlind(rout.n, blindOut);
    fUpdated = true;

    return 1;
};

int CHDWallet::OwnAnonOut(CHDWalletDB *pwdb, const uint256 &txhash, const CTxOutRingCT *pout, const CStoredExtKey *pc, uint32_t &nLastChild,
    COutputRecord &rout, CStoredTransaction &stx, bool &fUpdated, bool tx_is_from_me)
{
    CKeyID idk = pout->pk.GetID();
    CKey key;
    const CEKAKey *pak = nullptr;
    const CEKASCKey *pasc = nullptr;
    CExtKeyAccount *pa = nullptr;

    rout.nType = OUTPUT_RINGCT;
    isminetype mine = HaveKey(idk, pak, pasc, pa);
    if (!(mine & ISMINE_ALL)) {
        return 0;
    }
    if (tx_is_from_me && pa && pak && pa->nActiveInternal == pak->nParent) {
        fUpdated = fUpdated || (!rout.FlagSet(ORF_CHANGE) || !rout.FlagSet(ORF_FROM));
        rout.nFlags |= ORF_CHANGE | ORF_FROM;
    }
    if (mine & ISMINE_SPENDABLE) {
        rout.nFlags |= ORF_OWNED;
        rout.nFlags &= ~(ORF_OWN_WATCH);
    } else {
        rout.nFlags |= ORF_WATCHONLY;
    }
    if (mine & ISMINE_HARDWARE_DEVICE) {
        rout.nFlags |= ORF_HARDWARE_DEVICE;
    }

    if (IsLocked()) {
        COutPoint op(txhash, rout.n);
        if ((rout.nFlags & ORF_LOCKED) &&
            !pwdb->HaveLockedAnonOut(op)) {
            rout.nValue = 0;
            fUpdated = true;
            if (LogAcceptCategory(BCLog::HDWALLET)) WalletLogPrintf("%s: Adding locked anon output %s, %d.\n", __func__, txhash.ToString(), rout.n);
            if (!pwdb->WriteLockedAnonOut(op)) {
                WalletLogPrintf("Error: %s - WriteLockedAnonOut failed.\n", __func__);
            }
        }
        return 1;
    }

    if (pout->vData.size() < 33) {
        return werrorN(0, "%s: vData.size() < 33.", __func__);
    }

    CPubKey pkEphem;
    pkEphem.Set(pout->vData.begin(), pout->vData.begin() + 33);

    // Regenerate nonce
    uint256 nonce;
    if (GetKey(idk, key)) {
        nonce = key.ECDH(pkEphem);
        CSHA256().Write(nonce.begin(), 32).Finalize(nonce.begin());
    }

    uint64_t min_value, max_value;
    uint8_t blindOut[32];
    unsigned char msg[256]; // Currently narration is capped at 32 bytes
    size_t mlen = sizeof(msg);
    memset(msg, 0, mlen);
    uint64_t amountOut = 0;

    if (pout->vRangeproof.size() < 1000) {
        int rewind_rv = 0;
        if (!nonce.IsNull()) {
            rewind_rv = secp256k1_bulletproof_rangeproof_rewind(secp256k1_ctx_blind, blind_gens,
                &amountOut, blindOut, pout->vRangeproof.data(), pout->vRangeproof.size(),
                0, &pout->commitment, &secp256k1_generator_const_h, nonce.begin(), nullptr, 0);
        }

        // Try again with the watch_only_nonce
        if (rewind_rv < 1) {
            CStealthAddress sx;
            CKey scan_secret;
            if (GetStealthLinked(pwdb, idk, sx) &&
                GetStealthSecret(sx, scan_secret)) {

                // pk_tweaked = pkEphem + G * tweak
                uint256 watch_only_nonce, tweak(uint256S("0x444"));
                secp256k1_pubkey R;
                if (!secp256k1_ec_pubkey_parse(secp256k1_ctx_blind, &R, pkEphem.data(), EC_COMPRESSED_SIZE)) {
                    return werrorN(0, "%s: secp256k1_ec_pubkey_parse R failed.", __func__);
                }
                if (!secp256k1_ec_pubkey_tweak_add(secp256k1_ctx_blind, &R, tweak.begin())) {
                    return werrorN(0, "%s: secp256k1_ec_pubkey_tweak_add failed.", __func__);
                }

                CPubKey pk_tweaked;
                unsigned char pub[33];
                size_t publen = 33;
                secp256k1_ec_pubkey_serialize(secp256k1_ctx_blind, pub, &publen, &R, SECP256K1_EC_COMPRESSED);
                pk_tweaked.Set(pub, pub + publen);

                watch_only_nonce = scan_secret.ECDH(pk_tweaked);
                CSHA256().Write(watch_only_nonce.begin(), 32).Finalize(watch_only_nonce.begin());

                rewind_rv = secp256k1_bulletproof_rangeproof_rewind(secp256k1_ctx_blind, blind_gens,
                    &amountOut, blindOut, pout->vRangeproof.data(), pout->vRangeproof.size(),
                    0, &pout->commitment, &secp256k1_generator_const_h, watch_only_nonce.begin(), nullptr, 0);
            }
        }
        if (rewind_rv != 1) {
            return werrorN(0, "%s: secp256k1_bulletproof_rangeproof_rewind failed.", __func__);
        }

        ExtractNarration(nonce, pout->vData, rout.sNarration);
    } else
    if (1 != secp256k1_rangeproof_rewind(secp256k1_ctx_blind,
                blindOut, &amountOut, msg, &mlen, nonce.begin(),
                &min_value, &max_value,
                &pout->commitment, pout->vRangeproof.data(), pout->vRangeproof.size(),
                nullptr, 0,
                secp256k1_generator_h)) {
        return werrorN(0, "%s: secp256k1_rangeproof_rewind failed.", __func__);
    }
    if ((CAmount)amountOut < m_min_owned_value) {
        return 0;
    }

    msg[mlen-1] = '\0';
    size_t nNarr = strlen((const char*)msg);
    if (nNarr > 0) {
        rout.sNarration.assign((const char*)msg, nNarr);
    }

    if (rout.vPath.size() == 0) {
        CStealthAddress sx;
        if (GetStealthLinked(pwdb, idk, sx)) {
            CStealthAddressIndexed sxi;
            sx.ToRaw(sxi.addrRaw);
            uint32_t sxId;
            if (GetStealthKeyIndex(pwdb, sxi, sxId)) {
                rout.vPath.resize(5);
                rout.vPath[0] = ORA_STEALTH;
                memcpy(&rout.vPath[1], &sxId, 4);
            }
        }
    }

    COutPoint op(txhash, rout.n);
    CCmpPubKey ki;

    if (0 != secp256k1_get_keyimage(secp256k1_ctx_blind, ki.ncbegin(), pout->pk.begin(), key.begin())) {
        WalletLogPrintf("Error: %s - secp256k1_get_keyimage failed.\n", __func__);
    } else
    if (!pwdb->WriteAnonKeyImage(ki, op)) {
        WalletLogPrintf("Error: %s - WriteAnonKeyImage failed.\n", __func__);
    }

    rout.nValue = amountOut;
    rout.nFlags &= ~ORF_LOCKED;

    stx.InsertBlind(rout.n, blindOut);
    fUpdated = true;

    return 1;
};

bool CHDWallet::ProcessPlaceholder(const CTransaction &tx, CTransactionRecord &rtx)
{
    rtx.EraseOutput(OR_PLACEHOLDER_N);

    CAmount nDebit = GetDebit(rtx, ISMINE_ALL);
    CAmount nCredit = rtx.TotalOutput() + rtx.nFee;
    if (nDebit > 0 &&
        nDebit != nCredit) {
        LogPrint(BCLog::HDWALLET, "%s %s: Inserting placeholder output: %s, %d\n", GetDisplayName(), __func__, tx.GetHash().ToString(), nDebit - nCredit);

        const COutputRecord *pROutChange = rtx.GetChangeOutput();

        int nType = OUTPUT_STANDARD;
        for (size_t i = 0; i < tx.vpout.size(); ++i) {
            const auto &txout = tx.vpout[i];
            if (!(txout->IsType(OUTPUT_CT) || txout->IsType(OUTPUT_RINGCT))) {
                continue;
            }
            if (pROutChange && pROutChange->n == i) {
                continue;
            }
            nType = txout->GetType();
            break;
        }

        COutputRecord rout;
        rout.n = OR_PLACEHOLDER_N;
        rout.nType = nType;
        rout.nFlags |= ORF_FROM;
        rout.nValue = nDebit - nCredit;

        rtx.InsertOutput(rout);
    }
    return true;
};

bool CHDWallet::AddToRecord(CTransactionRecord &rtxIn, const CTransaction &tx, CWalletTx::Confirmation confirm, bool fFlushOnClose)
{
    if (LogAcceptCategory(BCLog::HDWALLET)) WalletLogPrintf("%s: %s, %s, %d\n", __func__, tx.GetHash().ToString(), confirm.hashBlock.ToString(), confirm.nIndex);

    AssertLockHeld(cs_wallet);
    CHDWalletDB wdb(*m_database, fFlushOnClose);

    const uint256 &txhash = tx.GetHash();

    // Inserts only if not exists, returns tx inserted or tx found
    std::pair<MapRecords_t::iterator, bool> ret = mapRecords.insert(std::make_pair(txhash, rtxIn));
    CTransactionRecord &rtx = ret.first->second;

    bool fUpdated = false;
    bool is_from_me = rtxIn.nFlags & ORF_FROM;
    if (is_from_me && !rtx.FlagSet(ORF_FROM)) {
        rtx.nFlags |= ORF_FROM;
        fUpdated = true;
    }
    if (rtx.blockHash != confirm.hashBlock ||
        rtx.block_height != confirm.block_height ||
        rtx.nIndex != confirm.nIndex) {
        fUpdated = true;

        // Don't set a null hashblock if it would unset an abandoned state
        if (!rtx.IsAbandoned() || !confirm.hashBlock.IsNull()) {
            rtx.blockHash = confirm.hashBlock;
            rtx.nIndex = confirm.nIndex;
        }
        rtx.block_height = confirm.block_height;

        int64_t block_time;
        if (chain().findBlock(rtx.blockHash, FoundBlock().time(block_time))) {
            rtx.nBlockTime = block_time;
        }

        // Update any temporary entries
        MapWallet_t::iterator it = mapTempWallet.find(txhash);
        if (it != mapTempWallet.end()) {
            SetTempTxnStatus(it->second, &rtx);
        }
    }

    // Anon input spend info depends on keys in wallet
    if (tx.vin.size() > 0 && tx.vin[0].IsAnonInput()) {  // Only check the first input, input types can't be mixed.
        rtx.nFlags |= (int16_t)ORF_ANON_IN;
    }
    if (rtx.nFlags & ORF_ANON_IN) {
        COutPoint op;
        std::vector<COutPoint> new_vin;
        for (const auto &txin : tx.vin) {
            if (!txin.IsAnonInput()) {
                // Should be impossible
                WalletLogPrintf("Error: Mixed input types %s.\n", txhash.ToString());
                continue;
            }
            uint32_t nInputs, nRingSize;
            txin.GetAnonInfo(nInputs, nRingSize);
            const std::vector<uint8_t> &vKeyImages = txin.scriptData.stack[0];
            assert(vKeyImages.size() == nInputs * 33);

            for (size_t k = 0; k < nInputs; ++k) {
                const CCmpPubKey &ki = *((CCmpPubKey*)&vKeyImages[k * 33]);
                if (!wdb.ReadAnonKeyImage(ki, op)) {
                    //WalletLogPrintf("Warning: Unknown keyimage %s.\n", ki.ToString());
                    continue;
                }
                new_vin.push_back(op);
                if (!HaveSpend(op, txhash)) {
                    AddToSpends(op, txhash);
                }
            }
        }
        if (rtx.vin != new_vin) {
            rtx.vin = new_vin;
            fUpdated = true;
        }
    }

    bool fInsertedNew = ret.second;
    if (fInsertedNew) {
        rtx.nTimeReceived = GetAdjustedTime();

        MapRecords_t::iterator mri = ret.first;
        rtxOrdered.insert(std::make_pair(rtx.nTimeReceived, mri));

        if (rtx.nFlags & ORF_ANON_IN) {
            // Processed above
        } else {
            rtx.vin.resize(tx.vin.size());
            for (size_t k = 0; k < tx.vin.size(); ++k) {
                rtx.vin[k] = tx.vin[k].prevout;
                AddToSpends(tx.vin[k].prevout, txhash);
            }

            // Lookup 1st input to set type
            ChainstateManager *pchainman{nullptr};
            if (HaveChain()) {
                pchainman = chain().getChainman();
            }
            if (GetOutputType(pchainman, tx.vin[0].prevout) == OUTPUT_CT) {
                rtx.nFlags |= ORF_BLIND_IN;
            }
        }
    }

    CExtKeyAccount *seaC = nullptr;
    CStoredExtKey *pcC = nullptr;
    std::vector<uint8_t> vEphemPath;
    uint32_t nCTStart = 0;
    mapRTxValue_t::iterator mvi = rtx.mapValue.find(RTXVT_EPHEM_PATH);
    if (mvi != rtx.mapValue.end()) {
        vEphemPath = mvi->second;

        if (vEphemPath.size() != 12) { // accid / chainchild / start
            WalletLogPrintf("Error: Bad vEphemPath.size() %s.\n", txhash.ToString());
            return false;
        }

        uint32_t accIndex, nChainChild;
        memcpy(&accIndex, &vEphemPath[0], 4);
        memcpy(&nChainChild, &vEphemPath[4], 4);
        memcpy(&nCTStart, &vEphemPath[8], 4);

        CKeyID idAccount;
        if (wdb.ReadExtKeyIndex(accIndex, idAccount)) {
            // TODO: load from db if not found
            ExtKeyAccountMap::iterator mi = mapExtAccounts.find(idAccount);
            if (mi != mapExtAccounts.end()) {
                seaC = mi->second;
                for (auto pchain : seaC->vExtKeys) {
                    if (pchain->kp.nChild == nChainChild) {
                        pcC = pchain;
                    }
                }
            }
        }
    }

    CStoredTransaction stx;
    if (!wdb.ReadStoredTx(txhash, stx)) {
        stx.vBlinds.clear();
    }

    CAmount smsg_fees = 0;
    int smsgs_funded = 0;
    for (size_t i = 0; i < tx.vpout.size(); ++i) {
        const auto &txout = tx.vpout[i];

        COutputRecord rout, *pout = rtx.GetOutput(i);

        bool fHave = false;
        if (pout) { // Have output recorded already, still need to check if owned
            fHave = true;
        } else {
            pout = &rout;
            pout->nFlags |= ORF_LOCKED; // mark new output as locked
        }

        pout->n = i;
        switch (txout->nVersion) {
            case OUTPUT_STANDARD:
                {
                CTxOutData *pdata = nullptr;
                if (i < tx.vpout.size()-1) {
                    if (tx.vpout[i+1]->nVersion == OUTPUT_DATA) {
                        pdata = (CTxOutData*)tx.vpout[i+1].get();
                    }
                }

                if (OwnStandardOut((CTxOutStandard*)txout.get(), pdata, *pout, fUpdated, is_from_me) &&
                    !fHave) {
                    fUpdated = true;
                    rtx.InsertOutput(*pout);
                }
                }
                break;
            case OUTPUT_CT:
                if (OwnBlindOut(&wdb, txhash, (CTxOutCT*)txout.get(), pcC, nCTStart, *pout, stx, fUpdated, is_from_me) &&
                    !fHave) {
                    fUpdated = true;
                    rtx.InsertOutput(*pout);
                }
                break;
            case OUTPUT_RINGCT:
                if (OwnAnonOut(&wdb, txhash, (CTxOutRingCT*)txout.get(), pcC, nCTStart, *pout, stx, fUpdated, is_from_me) &&
                    !fHave) {
                    fUpdated = true;
                    rtx.InsertOutput(*pout);
                }
                break;
            case OUTPUT_DATA:
                CTxOutData *txd = (CTxOutData*)txout.get();
                if (txd->vData.size() < 25 || txd->vData[0] != DO_FUND_MSG) {
                    continue;
                }
                size_t n = (txd->vData.size() - 1) / 24;
                for (size_t k = 0; k < n; ++k) {
                    uint32_t nAmount;
                    memcpy(&nAmount, &txd->vData[1 + k * 24 + 20], 4);
                    nAmount = le32toh(nAmount);
                    smsg_fees += nAmount;
                    smsgs_funded += 1;
                }
                break;
        }

        if (IsWalletFlagSet(WALLET_FLAG_AVOID_REUSE)) {
            const CScript *pscript = txout->GetPScriptPubKey();
            if (pscript) {
                SetSpentKeyState(pscript, true);
            }
        }
    }

    if (smsgs_funded > 0) {
        std::vector<uint8_t> v;
        v.resize(12);
        memcpy(v.data(), &smsgs_funded, 4);
        memcpy(v.data() + 4, &smsg_fees, 8);
        rtx.mapValue[RTXVT_SMSG_FEES] = v;
    }

    if (fInsertedNew || fUpdated) {
        // Plain to plain will always be a wtx, revisit if adding p2p to rtx
        if (!tx.GetCTFee(rtx.nFee)) {
            WalletLogPrintf("%s: ERROR - GetCTFee failed %s.\n", __func__, txhash.ToString());
        }

        // If txn has change, it must have been sent by this wallet
        if (rtx.HaveChange()) {
            for (auto &r : rtx.vout) {
                if (!(r.nFlags & ORF_CHANGE)) {
                    r.nFlags |= ORF_FROM;
                }
            }

            ProcessPlaceholder(tx, rtx);
        }

        stx.tx = MakeTransactionRef(tx);
        if (!wdb.WriteTxRecord(txhash, rtx) ||
            !wdb.WriteStoredTx(txhash, stx)) {
            return false;
        }
    }

    // Notify UI of new or updated transaction
    NotifyTransactionChanged(txhash, fInsertedNew ? CT_NEW : CT_UPDATED);

#if HAVE_SYSTEM
    // notify an external script when a wallet transaction comes in or is updated
    std::string strCmd = gArgs.GetArg("-walletnotify", "");

    if (!strCmd.empty()) {
        boost::replace_all(strCmd, "%s", txhash.GetHex());
        std::thread t(runCommand, strCmd);
        t.detach(); // thread runs free
    }
#endif

    std::string sName = GetName();
    GetMainSignals().TransactionAddedToWallet(sName, MakeTransactionRef(tx));
    ClearCachedBalances();

    return true;
};

CWallet::ScanResult CHDWallet::ScanForWalletTransactions(const uint256& start_block, int start_height, std::optional<int> max_height, const WalletRescanReserver& reserver, bool fUpdate)
{
    CExtKeyAccount *sea = nullptr;

    if (!IsLocked()) {
        ExtKeyAccountMap::iterator mi = mapExtAccounts.find(idDefaultAccount);
        if (mi != mapExtAccounts.end()) {
            sea = mi->second;
        }
    }

    if (sea && sea->nFlags & EAF_HAVE_SECRET) {
        LOCK(cs_wallet);
        CEKAStealthKey akStealth;

        uint32_t nChain = sea->nActiveStealth;
        CStoredExtKey *sek = sea->GetChain(nChain);
        if (sek) {
            uint32_t nKey = sek->nHGenerated;
            for (size_t k = 0; k < m_rescan_stealth_v1_lookahead; ++k) {
                NewStealthKeyFromAccount(nullptr, idDefaultAccount, "", akStealth, 0, nullptr, false, &nKey);
                nKey += 1;
                if (LogAcceptCategory(BCLog::HDWALLET)) {
                    CStealthAddress sxAddr;
                    if (0 == akStealth.SetSxAddr(sxAddr)) {
                        WalletLogPrintf("Adding stealth address %s to lookahead.\n", sxAddr.ToString());
                    }
                }
            }
        } else {
            WalletLogPrintf("%s: No active stealth chain found, not adding V1 stealth lookahead keys.\n", __func__);
        }

        uint32_t nScanKey = 0, nSpendKey = 0;
        mapEKValue_t::iterator mvi = sea->mapValue.find(EKVT_STEALTH_SCAN_CHAIN);
        if (mvi != sea->mapValue.end()) {
            uint64_t nScanChain;
            GetCompressedInt64(mvi->second, nScanChain);
            CStoredExtKey *sekScan = sea->GetChain(nScanChain);
            nScanKey = sekScan->nHGenerated;
        }
        mvi = sea->mapValue.find(EKVT_STEALTH_SPEND_CHAIN);
        if (mvi != sea->mapValue.end()) {
            uint64_t nSpendChain;
            GetCompressedInt64(mvi->second, nSpendChain);
            CStoredExtKey *sekSpend = sea->GetChain(nSpendChain);
            nSpendKey = sekSpend->nHGenerated;
        }

        // May need to initialise the stealth v2 chains
        CHDWalletDB wdb(*m_database);
        if (!wdb.TxnBegin()) {
            WalletLogPrintf("%s TxnBegin failed.\n", __func__);
        } else
        for (size_t k = 0; k < m_rescan_stealth_v2_lookahead; ++k) {
            NewStealthKeyV2FromAccount(&wdb, idDefaultAccount, "", akStealth, 0, nullptr, true, &nScanKey, &nSpendKey);
            nScanKey += 1;
            nSpendKey += 1;
        }

        if (!wdb.TxnCommit()) {
            WalletLogPrintf("%s TxnCommit failed.\n", __func__);
        }
    } else {
        WalletLogPrintf("%s: %s, not adding stealth lookahead keys.\n", __func__,
                        IsLocked() ? "Wallet is locked" : sea ? "Default account has no private key" : "Default account not found");
    }

    ScanResult rv = CWallet::ScanForWalletTransactions(start_block, start_height, max_height, reserver, fUpdate);

    // Remove lookahead keys
    if (sea) {
        for (const auto &lookahead : sea->setLookAheadStealth) {
            sea->mapStealthKeys.erase(lookahead->GetID());
        }
        for (const auto &lookahead : sea->setLookAheadStealthV2) {
            sea->mapStealthKeys.erase(lookahead->GetID());
        }
        sea->setLookAheadStealth.clear();
        sea->setLookAheadStealthV2.clear();
    }

    return rv;
};

std::vector<uint256> CHDWallet::ResendRecordTransactionsBefore(int64_t nTime)
{
    std::vector<uint256> result;

    LOCK(cs_wallet);

    for (RtxOrdered_t::iterator it = rtxOrdered.begin(); it != rtxOrdered.end(); ++it) {
        if (it->first > nTime) {
            continue;
        }

        const uint256 &txhash = it->second->first;
        CTransactionRecord &rtx = it->second->second;

        if (rtx.IsAbandoned()) {
            continue;
        }
        if (GetDepthInMainChain(rtx) != 0) {
            continue;
        }

        MapWallet_t::iterator twi = mapTempWallet.find(txhash);
        if (twi == mapTempWallet.end()) {
            if (0 != InsertTempTxn(txhash, &rtx)
                || (twi = mapTempWallet.find(txhash)) == mapTempWallet.end()) {
                WalletLogPrintf("ERROR: %s - InsertTempTxn failed %s.\n", __func__, txhash.ToString());
            }
        }

        if (twi != mapTempWallet.end()) {
            std::string unused_err_string;
            if (twi->second.SubmitMemoryPoolAndRelay(unused_err_string, true)) {
                result.push_back(txhash);
            }
        }
    }

    return result;
}

void CHDWallet::ResendWalletTransactions()
{
    // During reindex, importing and IBD, old wallet transactions become
    // unconfirmed. Don't resend them as that would spam other nodes.
    if (!chain().isReadyToBroadcast()) return;

    // Do this infrequently and randomly to avoid giving away
    // that these are our transactions.
    if (GetTime() < nNextResend || !fBroadcastTransactions) return;
    bool fFirst = (nNextResend == 0);
    // resend 12-36 hours from now, ~1 day on average.
    nNextResend = GetTime() + (12 * 60 * 60) + GetRand(24 * 60 * 60);
    if (fFirst) return;

    int relayed_tx_count = 0;

    {
        LOCK(cs_wallet);

        // Relay transactions
        for (std::pair<const uint256, CWalletTx>& item : mapWallet) {
            CWalletTx& wtx = item.second;
            // only rebroadcast unconfirmed txes older than 5 minutes before the
            // last block was found
            if (wtx.nTimeReceived > m_best_block_time - 5 * 60) continue;
            std::string unused_err_string;
            if (wtx.SubmitMemoryPoolAndRelay(unused_err_string, true)) ++relayed_tx_count;
        }

        std::vector<uint256> relayed_records = ResendRecordTransactionsBefore(m_best_block_time - 5 * 60);
        relayed_tx_count += relayed_records.size();
    } // cs_wallet

    if (relayed_tx_count > 0) {
        WalletLogPrintf("%s: rebroadcast %u unconfirmed transactions\n", __func__, relayed_tx_count);
    }
};

void CHDWallet::AvailableCoins(std::vector<COutput> &vCoins, const CCoinControl *coinControl, const CAmount &nMinimumAmount, const CAmount &nMaximumAmount, const CAmount &nMinimumSumAmount, const uint64_t nMaximumCount) const
{
    AssertLockHeld(cs_wallet);

    vCoins.clear();
    CAmount nTotal = 0;
    // Either the WALLET_FLAG_AVOID_REUSE flag is not set (in which case we always allow), or we default to avoiding, and only in the case where
    // a coin control object is provided, and has the avoid address reuse flag set to false, do we allow already used addresses
    bool allow_used_addresses = !IsWalletFlagSet(WALLET_FLAG_AVOID_REUSE) || (coinControl && !coinControl->m_avoid_address_reuse);
    const int min_depth = {coinControl ? coinControl->m_min_depth : DEFAULT_MIN_DEPTH};
    const int max_depth = {coinControl ? coinControl->m_max_depth : DEFAULT_MAX_DEPTH};
    const bool fIncludeImmature = {coinControl ? coinControl->m_include_immature : false};
    const bool allow_locked = {coinControl ? coinControl->fAllowLocked : false};
    const bool only_safe = {coinControl ? !coinControl->m_include_unsafe_inputs : true};

    for (const auto& item : mapWallet) {
        const uint256& wtxid = item.first;
        const CWalletTx& wtx = item.second;

        if (!chain().checkFinalTx(*wtx.tx)) {
            continue;
        }

        int nDepth = wtx.GetDepthInMainChain();
        if (nDepth < 0) {
            continue;
        }

        bool fMature = !(wtx.GetBlocksToMaturity() > 0);
        if (!fIncludeImmature
            && !fMature) {
            continue;
        }

        if (nDepth < min_depth || nDepth > max_depth) {
            continue;
        }

        // We should not consider coins which aren't at least in our mempool
        // It's possible for these to be conflicted via ancestors which we may never be able to detect
        if (nDepth == 0 && !wtx.InMempool()) {
            continue;
        }

        bool safeTx = wtx.IsTrusted();
        // We should not consider coins from transactions that are replacing
        // other transactions.
        //
        // Example: There is a transaction A which is replaced by bumpfee
        // transaction B. In this case, we want to prevent creation of
        // a transaction B' which spends an output of B.
        //
        // Reason: If transaction A were initially confirmed, transactions B
        // and B' would no longer be valid, so the user would have to create
        // a new transaction C to replace B'. However, in the case of a
        // one-block reorg, transactions B' and C might BOTH be accepted,
        // when the user only wanted one of them. Specifically, there could
        // be a 1-block reorg away from the chain where transactions A and C
        // were accepted to another chain where B, B', and C were all
        // accepted.
        if (nDepth == 0 && wtx.mapValue.count("replaces_txid")) {
            safeTx = false;
        }

        // Similarly, we should not consider coins from transactions that
        // have been replaced. In the example above, we would want to prevent
        // creation of a transaction A' spending an output of A, because if
        // transaction B were initially confirmed, conflicting with A and
        // A', we wouldn't want to the user to create a transaction D
        // intending to replace A', but potentially resulting in a scenario
        // where A, A', and D could all be accepted (instead of just B and
        // D, or just A and A' like the user would want).
        if (nDepth == 0 && wtx.mapValue.count("replaced_by_txid")) {
            safeTx = false;
        }

        if (only_safe && !safeTx) {
            continue;
        }

        for (unsigned int i = 0; i < wtx.tx->vpout.size(); i++) {
            if (!wtx.tx->vpout[i]->IsStandardOutput()) {
                continue;
            }

            const CTxOutStandard *txout = wtx.tx->vpout[i]->GetStandardOutput();

            if (txout->nValue < nMinimumAmount || txout->nValue > nMaximumAmount) {
                continue;
            }

            if (coinControl && coinControl->HasSelected() && !coinControl->fAllowOtherInputs && !coinControl->IsSelected(COutPoint(wtxid, i))) {
                continue;
            }

            if (!allow_locked && IsLockedCoin(wtxid, i)) {
                continue;
            }

            if (IsSpent(wtxid, i)) {
                continue;
            }

            isminetype mine = IsMine(txout);
            if (mine == ISMINE_NO) {
                continue;
            }

            if (!allow_used_addresses && IsSpentKey(wtxid, i)) {
                continue;
            }

            auto provider = GetLegacyScriptPubKeyMan();
            bool fSpendableIn = ((mine & ISMINE_SPENDABLE) != ISMINE_NO) || (coinControl && coinControl->fAllowWatchOnly && (mine & ISMINE_WATCH_ONLY_) != ISMINE_NO);
            //bool fSolvableIn = (mine & (ISMINE_SPENDABLE | ISMINE_WATCH_SOLVABLE)) != ISMINE_NO;
            bool fSolvableIn = provider ? IsSolvable(*provider, txout->scriptPubKey) : false;
            bool fNeedHardwareKey = (mine & ISMINE_HARDWARE_DEVICE);

            vCoins.emplace_back(&wtx, i, nDepth, fSpendableIn, fSolvableIn, safeTx, (coinControl && coinControl->fAllowWatchOnly), fMature, fNeedHardwareKey);

            // Checks the sum amount of all UTXO's.
            if (nMinimumSumAmount != MAX_MONEY) {
                nTotal += txout->nValue;

                if (nTotal >= nMinimumSumAmount) {
                    return;
                }
            }

            // Checks the maximum number of UTXO's.
            if (nMaximumCount > 0 && vCoins.size() >= nMaximumCount) {
                return;
            }
        }
    }

    for (MapRecords_t::const_iterator it = mapRecords.begin(); it != mapRecords.end(); ++it) {
        const uint256 &txid = it->first;
        const CTransactionRecord &rtx = it->second;

        // TODO: implement when moving coinbase and coinstake txns to mapRecords
        //if (pcoin->GetBlocksToMaturity() > 0)
        //    continue;

        int nDepth = GetDepthInMainChain(rtx);
        if (nDepth < 0) {
            continue;
        }

        if (nDepth < min_depth || nDepth > max_depth) {
            continue;
        }

        // We should not consider coins which aren't at least in our mempool
        // It's possible for these to be conflicted via ancestors which we may never be able to detect
        if (nDepth == 0 && !InMempool(txid)) {
            continue;
        }

        bool safeTx = IsTrusted(txid, rtx);
        if (nDepth == 0 && rtx.mapValue.count(RTXVT_REPLACES_TXID)) {
            safeTx = false;
        }

        if (nDepth == 0 && rtx.mapValue.count(RTXVT_REPLACED_BY_TXID)) {
            safeTx = false;
        }

        if (only_safe && !safeTx) {
            continue;
        }

        MapWallet_t::const_iterator twi = mapTempWallet.find(txid);
        for (const auto &r : rtx.vout) {
            if (r.nType != OUTPUT_STANDARD) {
                continue;
            }

            if (!(r.nFlags & ORF_OWN_ANY)) {
                continue;
            }

            if (IsSpent(txid, r.n)) {
                continue;
            }

            if (r.nValue < nMinimumAmount || r.nValue > nMaximumAmount) {
                continue;
            }

            if (coinControl && coinControl->HasSelected() && !coinControl->fAllowOtherInputs && !coinControl->IsSelected(COutPoint(txid, r.n))) {
                continue;
            }

            if (!allow_locked && IsLockedCoin(txid, r.n)) {
                continue;
            }

            if (!allow_used_addresses && IsSpentKey(&r.scriptPubKey)) {
                continue;
            }

            if (twi == mapTempWallet.end()
                && (twi = mapTempWallet.find(txid)) == mapTempWallet.end()) {
                if (0 != InsertTempTxn(txid, &rtx)
                    || (twi = mapTempWallet.find(txid)) == mapTempWallet.end()) {
                    WalletLogPrintf("ERROR: %s - InsertTempTxn failed %s.\n", __func__, txid.ToString());
                    return;
                }
            }

            bool fSpendableIn = (r.nFlags & ORF_OWNED) || (coinControl && coinControl->fAllowWatchOnly);
            bool fNeedHardwareKey = (r.nFlags & ORF_HARDWARE_DEVICE);

            vCoins.emplace_back(&twi->second, r.n, nDepth, fSpendableIn, true, safeTx, (coinControl && coinControl->fAllowWatchOnly), true, fNeedHardwareKey);

            if (nMinimumSumAmount != MAX_MONEY) {
                nTotal += r.nValue;

                if (nTotal >= nMinimumSumAmount) {
                    return;
                }
            }

            // Checks the maximum number of UTXO's.
            if (nMaximumCount > 0 && vCoins.size() >= nMaximumCount) {
                return;
            }
        }
    }
    return;
};

bool CHDWallet::SelectCoins(const std::vector<COutput>& vAvailableCoins, const CAmount& nTargetValue,
    std::set<CInputCoin>& setCoinsRet, CAmount& nValueRet, const CCoinControl& coin_control, CoinSelectionParams& coin_selection_params) const
{
    std::vector<COutput> vCoins(vAvailableCoins);

    // coin control -> return all selected outputs (we want all selected to go into the transaction for sure)
    if (coin_control.HasSelected() && !coin_control.fAllowOtherInputs) {
        for (const auto &out : vCoins) {
            COutPoint op(out.tx->GetHash(), out.i);
            if (!coin_control.IsSelected(op)) {
                continue;
            }
            if (!out.fSpendable) {
                continue;
            }
            CInputCoin ic(out.tx->tx, out.i);
            nValueRet += ic.GetValue();
            setCoinsRet.insert(ic);
        }
        return (nValueRet >= nTargetValue);
    }

    // calculate value from preset inputs and store them
    std::set<CInputCoin> setPresetCoins;
    CAmount nValueFromPresetInputs = 0;

    std::vector<COutPoint> vPresetInputs;
    coin_control.ListSelected(vPresetInputs);

    for (const auto &outpoint : vPresetInputs) {
        MapWallet_t::const_iterator it = mapTempWallet.find(outpoint.hash);
        if (it != mapTempWallet.end()) {
            const CWalletTx *pcoin = &it->second;
            // Clearly invalid input, fail
            if (pcoin->tx->vpout.size() <= outpoint.n) {
                return false;
            }
            CInputCoin ic(pcoin->tx, outpoint.n);
            nValueFromPresetInputs += ic.GetValue();
            setPresetCoins.insert(ic);
        } else {
            it = mapWallet.find(outpoint.hash);
            if (it != mapWallet.end()) {
                const CWalletTx *pcoin = &it->second;
                // Clearly invalid input, fail
                if (pcoin->tx->vpout.size() <= outpoint.n) {
                    return false;
                }
                CInputCoin ic(pcoin->tx, outpoint.n);
                nValueFromPresetInputs += ic.GetValue();
                setPresetCoins.insert(ic);
            } else {
                return false; // TODO: Allow non-wallet inputs
            }
        }
    }

    // remove preset inputs from vCoins
    for (std::vector<COutput>::iterator it = vCoins.begin(); it != vCoins.end() && coin_control.HasSelected();) {
        if (setPresetCoins.count(CInputCoin(it->tx->tx, it->i))) {
            it = vCoins.erase(it);
        } else {
            ++it;
        }
    }

    unsigned int limit_ancestor_count = 0;
    unsigned int limit_descendant_count = 0;
    chain().getPackageLimits(limit_ancestor_count, limit_descendant_count);
    size_t max_ancestors = (size_t)std::max<int64_t>(1, limit_ancestor_count);
    size_t max_descendants = (size_t)std::max<int64_t>(1, limit_descendant_count);
    bool fRejectLongChains = gArgs.GetBoolArg("-walletrejectlongchains", DEFAULT_WALLET_REJECT_LONG_CHAINS);

    CAmount value_to_select = nTargetValue - nValueFromPresetInputs;

    // Coin Selection attempts to select inputs from a pool of eligible UTXOs to fund the
    // transaction at a target feerate. If an attempt fails, more attempts may be made using a more
    // permissive CoinEligibilityFilter.
    const bool res = [&] {
        // Pre-selected inputs already cover the target amount.
        if (value_to_select <= 0) return true;

        // If possible, fund the transaction with confirmed UTXOs only. Prefer at least six
        // confirmations on outputs received from other wallets and only spend confirmed change.
        if (CWallet::AttemptSelection(value_to_select, CoinEligibilityFilter(1, 6, 0), vCoins, setCoinsRet, nValueRet, coin_selection_params)) return true;
        if (CWallet::AttemptSelection(value_to_select, CoinEligibilityFilter(1, 1, 0), vCoins, setCoinsRet, nValueRet, coin_selection_params)) return true;

        // Fall back to using zero confirmation change (but with as few ancestors in the mempool as
        // possible) if we cannot fund the transaction otherwise.
        if (m_spend_zero_conf_change) {
            if (CWallet::AttemptSelection(value_to_select, CoinEligibilityFilter(0, 1, 2), vCoins, setCoinsRet, nValueRet, coin_selection_params)) return true;
            if (CWallet::AttemptSelection(value_to_select, CoinEligibilityFilter(0, 1, std::min((size_t)4, max_ancestors/3), std::min((size_t)4, max_descendants/3)),
                                   vCoins, setCoinsRet, nValueRet, coin_selection_params)) {
                return true;
            }
            if (CWallet::AttemptSelection(value_to_select, CoinEligibilityFilter(0, 1, max_ancestors/2, max_descendants/2),
                                   vCoins, setCoinsRet, nValueRet, coin_selection_params)) {
                return true;
            }
            // If partial groups are allowed, relax the requirement of spending OutputGroups (groups
            // of UTXOs sent to the same address, which are obviously controlled by a single wallet)
            // in their entirety.
            if (CWallet::AttemptSelection(value_to_select, CoinEligibilityFilter(0, 1, max_ancestors-1, max_descendants-1, true /* include_partial_groups */),
                                   vCoins, setCoinsRet, nValueRet, coin_selection_params)) {
                return true;
            }
            // Try with unsafe inputs if they are allowed. This may spend unconfirmed outputs
            // received from other wallets.
            if (coin_control.m_include_unsafe_inputs
                && CWallet::AttemptSelection(value_to_select,
                    CoinEligibilityFilter(0 /* conf_mine */, 0 /* conf_theirs */, max_ancestors-1, max_descendants-1, true /* include_partial_groups */),
                    vCoins, setCoinsRet, nValueRet, coin_selection_params)) {
                return true;
            }
            // Try with unlimited ancestors/descendants. The transaction will still need to meet
            // mempool ancestor/descendant policy to be accepted to mempool and broadcasted, but
            // OutputGroups use heuristics that may overestimate ancestor/descendant counts.
            if (!fRejectLongChains && CWallet::AttemptSelection(value_to_select,
                                      CoinEligibilityFilter(0, 1, std::numeric_limits<uint64_t>::max(), std::numeric_limits<uint64_t>::max(), true /* include_partial_groups */),
                                      vCoins, setCoinsRet, nValueRet, coin_selection_params)) {
                return true;
            }
        }
        // Coin Selection failed.
        return false;
    }();

    // AttemptSelection clears setCoinsRet, so add the preset inputs from coin_control to the coinset
    setCoinsRet.insert(setPresetCoins.begin(), setPresetCoins.end());

    // add preset inputs to the total value selected
    nValueRet += nValueFromPresetInputs;

    return res;
};

void CHDWallet::AvailableBlindedCoins(std::vector<COutputR>& vCoins, const CCoinControl *coinControl, const CAmount& nMinimumAmount, const CAmount& nMaximumAmount, const CAmount& nMinimumSumAmount, const uint64_t& nMaximumCount) const
{
    AssertLockHeld(cs_wallet);

    vCoins.clear();

    const int min_depth = {coinControl ? coinControl->m_min_depth : DEFAULT_MIN_DEPTH};
    const int max_depth = {coinControl ? coinControl->m_max_depth : DEFAULT_MAX_DEPTH};
    //const bool fIncludeImmature = {coinControl ? coinControl->m_include_immature : false};  // Blinded coins can't stake
    const bool allow_locked = {coinControl ? coinControl->fAllowLocked : false};
    const bool spend_frozen = {coinControl ? coinControl->m_spend_frozen_blinded : false};
    const bool include_tainted_frozen = {coinControl ? coinControl->m_include_tainted_frozen : false};
    const bool only_safe = {coinControl ? !coinControl->m_include_unsafe_inputs : true};

    if (coinControl && coinControl->HasSelected()) {
        // Add specified coins which may not be in the chain
        for (MapRecords_t::const_iterator it = mapTempRecords.begin(); it !=  mapTempRecords.end(); ++it) {
            const uint256 &txid = it->first;
            const CTransactionRecord &rtx = it->second;
            for (const auto &r : rtx.vout) {
                if (!allow_locked && IsLockedCoin(txid, r.n)) {
                    continue;
                }
                if (coinControl->IsSelected(COutPoint(txid, r.n))) {
                    int nDepth = 0;
                    bool fSpendable = true;
                    bool fSolvable = true;
                    bool safeTx = true;
                    bool fMature = false;
                    bool fNeedHardwareKey = false;
                    vCoins.emplace_back(txid, it, r.n, nDepth, fSpendable, fSolvable, safeTx, fMature, fNeedHardwareKey);
                }
            }
        }
    }

    CAmount nTotal = 0;
    // Either the WALLET_FLAG_AVOID_REUSE flag is not set (in which case we always allow), or we default to avoiding, and only in the case where
    // a coin control object is provided, and has the avoid address reuse flag set to false, do we allow already used addresses
    bool allow_used_addresses = !IsWalletFlagSet(WALLET_FLAG_AVOID_REUSE) || (coinControl && !coinControl->m_avoid_address_reuse);

    const Consensus::Params &consensusParams = Params().GetConsensus();
    bool exploit_fix_2_active = GetTime() >= consensusParams.exploit_fix_2_time;
    for (MapRecords_t::const_iterator it = mapRecords.begin(); it != mapRecords.end(); ++it) {
        const uint256 &txid = it->first;
        const CTransactionRecord &rtx = it->second;

        if (exploit_fix_2_active && rtx.block_height > 0) { // height 0 is mempool
            if (!spend_frozen && rtx.block_height <= consensusParams.m_frozen_blinded_height) {
                continue;
            } else
            if (spend_frozen && rtx.block_height > consensusParams.m_frozen_blinded_height) {
                continue;
            }
        }

        // TODO: implement when moving coinbase and coinstake txns to mapRecords
        //if (pcoin->GetBlocksToMaturity() > 0)
        //    continue;

        int nDepth = GetDepthInMainChain(rtx);
        if (nDepth < 0)
            continue;

        if (nDepth < min_depth || nDepth > max_depth)
            continue;

        // We should not consider coins which aren't at least in our mempool
        // It's possible for these to be conflicted via ancestors which we may never be able to detect
        if (nDepth == 0 && !InMempool(txid))
            continue;

        bool safeTx = IsTrusted(txid, rtx);
        if (nDepth == 0 && rtx.mapValue.count(RTXVT_REPLACES_TXID)) {
            safeTx = false;
        }

        if (nDepth == 0 && rtx.mapValue.count(RTXVT_REPLACED_BY_TXID)) {
            safeTx = false;
        }

        if (only_safe && !safeTx) {
            continue;
        }

        for (const auto &r : rtx.vout) {
            if (r.nType != OUTPUT_CT) {
                continue;
            }

            if (!(r.nFlags & ORF_OWN_ANY)) {
                continue;
            }

            if (IsSpent(txid, r.n)) {
                continue;
            }

            if (r.nValue < nMinimumAmount || r.nValue > nMaximumAmount) {
                continue;
            }

            if (spend_frozen && !include_tainted_frozen) {
                if (r.nValue > consensusParams.m_max_tainted_value_out) {
                    if (IsFrozenBlindOutput(txid)) {
                        continue;
                    }
                }
            }

            if (coinControl && coinControl->HasSelected() && !coinControl->fAllowOtherInputs && !coinControl->IsSelected(COutPoint(txid, r.n))) {
                continue;
            }

            if (!allow_locked && IsLockedCoin(txid, r.n)) {
                continue;
            }

            if (!allow_used_addresses && IsSpentKey(&r.scriptPubKey)) {
                continue;
            }

            bool fMature = true;
            bool fSpendable = (coinControl && !coinControl->fAllowWatchOnly && !(r.nFlags & ORF_OWNED)) ? false : true;
            bool fSolvable = true;
            bool fNeedHardwareKey = (r.nFlags & ORF_HARDWARE_DEVICE);

            vCoins.emplace_back(txid, it, r.n, nDepth, fSpendable, fSolvable, safeTx, fMature, fNeedHardwareKey);

            if (nMinimumSumAmount != MAX_MONEY) {
                nTotal += r.nValue;

                if (nTotal >= nMinimumSumAmount) {
                    return;
                }
            }

            // Checks the maximum number of UTXO's.
            if (nMaximumCount > 0 && vCoins.size() >= nMaximumCount) {
                return;
            }
        }
    }

    return;
};

bool CHDWallet::SelectBlindedCoins(const std::vector<COutputR> &vAvailableCoins, const CAmount &nTargetValue, std::vector<std::pair<MapRecords_t::const_iterator,unsigned int> > &setCoinsRet, CAmount &nValueRet, const CCoinControl *coinControl, bool random_selection) const
{
    std::vector<COutputR> vCoins(vAvailableCoins);

    // calculate value from preset inputs and store them
    std::vector<std::pair<MapRecords_t::const_iterator,unsigned int> > vPresetCoins;
    CAmount nValueFromPresetInputs = 0;

    std::vector<COutPoint> vPresetInputs;
    if (coinControl) {
        coinControl->ListSelected(vPresetInputs);
    }

    for (const auto &outpoint : vPresetInputs) {
        MapRecords_t::const_iterator it;
        if ((it = mapTempRecords.find(outpoint.hash)) != mapTempRecords.end() // Must check mapTempRecords first, mapRecords may contain the same tx without the relevant output.
            || (it = mapRecords.find(outpoint.hash)) != mapRecords.end()) { // Allows non-wallet inputs
            const CTransactionRecord &rtx = it->second;
            const COutputRecord *oR = rtx.GetOutput(outpoint.n);
            if (!oR) {
                return werror("%s: Can't find output %s\n", __func__, outpoint.ToString());
            }

            nValueFromPresetInputs += oR->nValue;
            vPresetCoins.push_back(std::make_pair(it, outpoint.n));
        } else {
            return werror("%s: Can't find output %s\n", __func__, outpoint.ToString());
        }
    }

    // coin control -> return all selected outputs (we want all selected to go into the transaction for sure)
    if (coinControl && coinControl->HasSelected() && !coinControl->fAllowOtherInputs) {
        nValueRet = nValueFromPresetInputs;
        setCoinsRet.insert(setCoinsRet.end(), vPresetCoins.begin(), vPresetCoins.end());
        return (nValueRet >= nTargetValue);
    }

    // Remove preset inputs from vCoins
    if (vPresetCoins.size() > 0) {
        for (auto it = vCoins.begin(); it != vCoins.end();) {
            std::vector<std::pair<MapRecords_t::const_iterator,unsigned int> >::const_iterator it2;
            bool fFound = false;
            for (it2 = vPresetCoins.begin(); it2 != vPresetCoins.end(); it2++) {
                if (it2->first->first == it->txhash && it2->second == (uint32_t) it->i) {
                    fFound = true;
                    break;
                }
            }
            //if (std::find(vPresetCoins.begin(), vPresetCoins.end(), std::make_pair(it->rtx, it->i)) != vPresetCoins.end())
            if (fFound) {
                it = vCoins.erase(it);
            } else {
                ++it;
            }
        }
    }

    size_t max_ancestors = (size_t)std::max<int64_t>(1, gArgs.GetArg("-limitancestorcount", DEFAULT_ANCESTOR_LIMIT));
    size_t max_descendants = (size_t)std::max<int64_t>(1, gArgs.GetArg("-limitdescendantcount", DEFAULT_DESCENDANT_LIMIT));
    bool fRejectLongChains = gArgs.GetBoolArg("-walletrejectlongchains", DEFAULT_WALLET_REJECT_LONG_CHAINS);
    bool res = nTargetValue <= nValueFromPresetInputs;
    if (!res) {
        if (random_selection) {
            Shuffle(vCoins.begin(), vCoins.end(), FastRandomContext());

            CAmount target_val = nTargetValue - nValueFromPresetInputs;
            std::vector<CAmount> coin_values;
            for (auto it = vCoins.begin(); it != vCoins.end();) {
                MapRecords_t::const_iterator rtxi = it->rtx;
                const CTransactionRecord *rtx = &rtxi->second;
                const CWalletTx *pcoin = GetWalletOrTempTx(it->txhash, rtx);
                if (!pcoin) {
                    return werror("%s: GetWalletOrTempTx failed.\n", __func__);
                }
                const COutputRecord *oR = rtx->GetOutput(it->i);
                if (!oR) {
                    return werror("%s: GetOutput failed, %s, %d.\n", it->txhash.ToString(), it->i);
                }

                bool add_input = false;
                if (nValueRet < target_val) {
                    add_input = true;
                } else {
                    for (int k = 0; k < (int)setCoinsRet.size(); ++k) {
                        if (setCoinsRet.size() + (add_input ? 1 : 0) <= prefer_max_num_anon_inputs) {
                            break;
                        }
                        // Replace output if possible
                        if ((nValueRet + oR->nValue) - coin_values[k] >= target_val) {
                            add_input = true;
                            nValueRet -= coin_values[k];
                            setCoinsRet.erase(setCoinsRet.begin() + k);
                            coin_values.erase(coin_values.begin() + k);
                            k--;
                            continue;
                        }
                    }
                }
                if (add_input) {
                    nValueRet += oR->nValue;
                    setCoinsRet.push_back(std::make_pair(rtxi, it->i));
                    coin_values.push_back(oR->nValue);
                    it = vCoins.erase(it);
                    continue;
                }
                ++it;
            }
            res = nValueRet >= nTargetValue - nValueFromPresetInputs;
        } else {
             res = AttemptSelection(nTargetValue - nValueFromPresetInputs, CoinEligibilityFilter(1, 6, 0), vCoins, setCoinsRet, nValueRet) ||
                AttemptSelection(nTargetValue - nValueFromPresetInputs, CoinEligibilityFilter(1, 1, 0), vCoins, setCoinsRet, nValueRet) ||
                (m_spend_zero_conf_change && AttemptSelection(nTargetValue - nValueFromPresetInputs, CoinEligibilityFilter(0, 1, 2), vCoins, setCoinsRet, nValueRet)) ||
                (m_spend_zero_conf_change && AttemptSelection(nTargetValue - nValueFromPresetInputs, CoinEligibilityFilter(0, 1, std::min((size_t)4, max_ancestors/3), std::min((size_t)4, max_descendants/3)), vCoins, setCoinsRet, nValueRet)) ||
                (m_spend_zero_conf_change && AttemptSelection(nTargetValue - nValueFromPresetInputs, CoinEligibilityFilter(0, 1, max_ancestors/2, max_descendants/2), vCoins, setCoinsRet, nValueRet)) ||
                (m_spend_zero_conf_change && AttemptSelection(nTargetValue - nValueFromPresetInputs, CoinEligibilityFilter(0, 1, max_ancestors-1, max_descendants-1), vCoins, setCoinsRet, nValueRet)) ||
                (m_spend_zero_conf_change && !fRejectLongChains && AttemptSelection(nTargetValue - nValueFromPresetInputs, CoinEligibilityFilter(0, 1, std::numeric_limits<uint64_t>::max()), vCoins, setCoinsRet, nValueRet));
        }
    }

    // AttemptSelection clears setCoinsRet, so add the preset inputs from coin_control to the coinset
    setCoinsRet.insert(setCoinsRet.end(), vPresetCoins.begin(), vPresetCoins.end());

    // add preset inputs to the total value selected
    nValueRet += nValueFromPresetInputs;

    Shuffle(setCoinsRet.begin(), setCoinsRet.end(), FastRandomContext());

    return res;
};

void CHDWallet::AvailableAnonCoins(std::vector<COutputR> &vCoins, const CCoinControl *coinControl, const CAmount& nMinimumAmount, const CAmount& nMaximumAmount, const CAmount& nMinimumSumAmount, const uint64_t& nMaximumCount) const
{
    AssertLockHeld(cs_wallet);

    vCoins.clear();
    CAmount nTotal = 0;

    const int min_depth = {coinControl ? coinControl->m_min_depth : DEFAULT_MIN_DEPTH};
    const int max_depth = {coinControl ? coinControl->m_max_depth : DEFAULT_MAX_DEPTH};
    const bool fIncludeImmature = {coinControl ? coinControl->m_include_immature : false};
    const bool allow_locked = {coinControl ? coinControl->fAllowLocked : false};
    const bool spend_frozen = {coinControl ? coinControl->m_spend_frozen_blinded : false};
    const bool include_tainted_frozen = {coinControl ? coinControl->m_include_tainted_frozen : false};
    const bool only_safe = {coinControl ? !coinControl->m_include_unsafe_inputs : true};

    int64_t time_now = GetAdjustedTime();

    CHDWalletDB wdb(*m_database);

    const Consensus::Params &consensusParams = Params().GetConsensus();
    bool exploit_fix_2_active = GetTime() >= consensusParams.exploit_fix_2_time;
    for (MapRecords_t::const_iterator it = mapRecords.begin(); it != mapRecords.end(); ++it) {
        const uint256 &txid = it->first;
        const CTransactionRecord &rtx = it->second;

        if (exploit_fix_2_active && rtx.block_height > 0) { // height 0 is mempool
            if (!spend_frozen && rtx.block_height <= consensusParams.m_frozen_blinded_height) {
                continue;
            } else
            if (spend_frozen && rtx.block_height > consensusParams.m_frozen_blinded_height) {
                continue;
            }
        }

        // TODO: implement when moving coinbase and coinstake txns to mapRecords
        //if (pcoin->GetBlocksToMaturity() > 0)
        //    continue;

        int nDepth = GetDepthInMainChain(rtx);
        bool fMature = nDepth >= consensusParams.nMinRCTOutputDepth;
        if (!fIncludeImmature &&
            !fMature) {
            continue;
        }

        // Coins at depth 0 will never be available, no need to check depth0 cases

        if (nDepth < min_depth || nDepth > max_depth) {
            continue;
        }

        bool safeTx = IsTrusted(txid, rtx);

        if (only_safe && !safeTx) {
            continue;
        }

        for (const auto &r : rtx.vout) {
            if (r.nType != OUTPUT_RINGCT) {
                continue;
            }

            if (!(r.nFlags & ORF_OWNED)) {
                continue;
            }

            if (IsSpent(txid, r.n)) {
                continue;
            }

            if (r.nValue < nMinimumAmount || r.nValue > nMaximumAmount) {
                continue;
            }

            if (spend_frozen && !include_tainted_frozen) {
                // TODO: Store pubkey on COutputRecord - in scriptPubKey
                CStoredTransaction stx;
                int64_t index;
                if (!wdb.ReadStoredTx(txid, stx) ||
                    !stx.tx->vpout[r.n]->IsType(OUTPUT_RINGCT) ||
                    !pblocktree->ReadRCTOutputLink(((CTxOutRingCT*)stx.tx->vpout[r.n].get())->pk, index) ||
                    IsBlacklistedAnonOutput(index) ||
                    (!IsWhitelistedAnonOutput(index, time_now, consensusParams) && r.nValue > consensusParams.m_max_tainted_value_out)) {
                    continue;
                }
            }

            if (coinControl && coinControl->HasSelected() && !coinControl->fAllowOtherInputs && !coinControl->IsSelected(COutPoint(txid, r.n))) {
                continue;
            }

            if (!allow_locked && IsLockedCoin(txid, r.n)) {
                continue;
            }

            bool fSpendable = (coinControl && !coinControl->fAllowWatchOnly && !(r.nFlags & ORF_OWNED)) ? false : true;
            bool fSolvable = true;
            bool fNeedHardwareKey = (r.nFlags & ORF_HARDWARE_DEVICE);

            vCoins.emplace_back(txid, it, r.n, nDepth, fSpendable, fSolvable, safeTx, fMature, fNeedHardwareKey);

            if (nMinimumSumAmount != MAX_MONEY) {
                nTotal += r.nValue;

                if (nTotal >= nMinimumSumAmount) {
                    return;
                }
            }

            // Checks the maximum number of UTXO's.
            if (nMaximumCount > 0 && vCoins.size() >= nMaximumCount) {
                return;
            }
        }
    }

    Shuffle(vCoins.begin(), vCoins.end(), FastRandomContext());
    return;
};

const CTxOutBase* CHDWallet::FindNonChangeParentOutput(const CTransaction& tx, int output) const
{
    const CTransaction* ptx = &tx;
    int n = output;
    while (IsChange(ptx->vpout[n].get()) && ptx->vin.size() > 0) {
        const COutPoint& prevout = ptx->vin[0].prevout;

        auto it = mapWallet.find(prevout.hash);
        if (it == mapWallet.end())
            it = mapTempWallet.find(prevout.hash);

        if (it == mapTempWallet.end() || it->second.tx->vpout.size() <= prevout.n ||
            !IsMine(it->second.tx->vpout[prevout.n].get())) {
            break;
        }
        ptx = it->second.tx.get();
        n = prevout.n;
    }
    return ptx->vpout[n].get();
}

std::map<CTxDestination, std::vector<COutput>> CHDWallet::ListCoins() const
{
    AssertLockHeld(cs_wallet);

    std::map<CTxDestination, std::vector<COutput>> result;
    std::vector<COutput> availableCoins;

    CCoinControl coinControl;
    coinControl.fAllowLocked = true;
    AvailableCoins(availableCoins, &coinControl);

    for (const auto& coin : availableCoins) {
        CTxDestination address;
        if (coin.fSpendable &&
            ExtractDestination(*(FindNonChangeParentOutput(*coin.tx->tx, coin.i)->GetPScriptPubKey()), address)) {
            result[address].emplace_back(std::move(coin));
        }
    }

    return result;
};

bool CHDWallet::GetAddressFromOutputRecord(const uint256 &txhash, const COutputRecord *pout, CTxDestination &address) const
{
    if (ExtractDestination(pout->scriptPubKey, address)) {
        return true;
    }
    if (pout->vPath.size() > 0 && pout->vPath[0] == ORA_STEALTH) {
        if (pout->vPath.size() < 5) {
            WalletLogPrintf("%s: Warning, malformed vPath.\n", __func__);
        } else {
            uint32_t sidx;
            memcpy(&sidx, &pout->vPath[1], 4);
            CStealthAddress sx;
            if (GetStealthByIndex(sidx, sx)) {
                address = sx;
            }
        }
        return true;
    }

    // If an address can't be found for an RCT output, use the address of the output pubkey.
    if (pout->nType == OUTPUT_RINGCT) {
        CTransactionRef tx;
        if (GetTransaction(txhash, tx)) {
            if (tx->GetNumVOuts() > pout->n) {
                CCmpPubKey pk;
                if (tx->vpout[pout->n]->GetPubKey(pk)) {
                    CKeyID idk = pk.GetID();
                    address = PKHash(idk);
                    return true;
                }
            }
        }
    }

    return false;
}

bool CHDWallet::GetFirstNonChangeAddress(const uint256 &hash, const CTransactionRecord &txr, const COutputRecord *pout, CTxDestination &address) const
{
    AssertLockHeld(cs_wallet);

    const COutputRecord *por = pout;
    const uint256 *txhash = &hash;
    const CTransactionRecord *txn_r = &txr;
    int txo_n = -1;
    const CWalletTx *prevwtx{nullptr};
    bool is_record = true;

    auto set_next = [&] (const COutPoint &prevout) EXCLUSIVE_LOCKS_REQUIRED(cs_wallet) {
        MapWallet_t::const_iterator mwi;
        MapRecords_t::const_iterator mri;
        if ((mri = mapRecords.find(prevout.hash)) != mapRecords.end()) {
            const CTransactionRecord &prevtx = mri->second;
            const COutputRecord *txo = prevtx.GetOutput(prevout.n);
            if (txo) {
                is_record = true;
                txhash = &prevout.hash;
                txn_r = &prevtx;
                por = txo;
                return true;
            }
        } else
        if ((mwi = mapWallet.find(prevout.hash)) != mapWallet.end()) {
            prevwtx = &mwi->second;
            if (prevwtx->tx->vpout.size() > prevout.n &&
                IsMine(prevwtx->tx->vpout[prevout.n].get())) {
                is_record = false;
                txhash = &prevout.hash;
                txo_n = prevout.n;
                return true;
            }
        }
        return false;
    };

    while (true) {
        if (!is_record) {
            const CTxOutBase *txo = prevwtx->tx->vpout[txo_n].get();
            if (IsChange(txo)) {
                const COutPoint &prevout = prevwtx->tx->vin[0].prevout;
                if (set_next(prevout)) {
                    continue;
                }
            }
            return ExtractDestination(*(txo->GetPScriptPubKey()), address);
        }

        if (por->nType == OUTPUT_RINGCT) {
            // No point grouping RCT outputs
            return GetAddressFromOutputRecord(*txhash, por, address);
        }
        if (por->nFlags & ORF_CHANGE) {
            const COutPoint &prevout = txn_r->vin[0];
            if (set_next(prevout)) {
                continue;
            }
        }
        return GetAddressFromOutputRecord(*txhash, por, address);
    }

    return false;
}

std::map<CTxDestination, std::vector<COutputR>> CHDWallet::ListCoins(OutputTypes nType) const
{
    AssertLockHeld(cs_wallet);

    std::map<CTxDestination, std::vector<COutputR>> result;
    std::vector<COutputR> availableCoins;

    CCoinControl coinControl;
    coinControl.fAllowLocked = true;
    if (nType == OUTPUT_CT) {
        AvailableBlindedCoins(availableCoins, &coinControl);
    } else
    if (nType == OUTPUT_RINGCT) {
        AvailableAnonCoins(availableCoins, &coinControl);
    }

    for (const auto& coin : availableCoins) {
        CTxDestination address;
        if (!coin.fSpendable) {
            continue;
        }

        const COutputRecord *oR = coin.rtx->second.GetOutput(coin.i);
        if (GetFirstNonChangeAddress(coin.rtx->first, coin.rtx->second, oR, address)) {
            result[address].emplace_back(std::move(coin));
        } else {
            // Using CNoDestination as the key corrupts the result map, warn instead
            WalletLogPrintf("WARNING - Missing address for %s.%d\n", coin.rtx->first.ToString(), coin.i);
        }
    }

    return result;
};

struct CompareValueOnly
{
    bool operator()(const std::pair<CAmount, std::pair<MapRecords_t::const_iterator, unsigned int> >& t1,
                    const std::pair<CAmount, std::pair<MapRecords_t::const_iterator, unsigned int> >& t2) const
    {
        return t1.first < t2.first;
    }
};

static void ApproximateBestSubset(std::vector<std::pair<CAmount, std::pair<MapRecords_t::const_iterator,unsigned int> > >vValue, const CAmount& nTotalLower, const CAmount& nTargetValue,
                                  std::vector<char>& vfBest, CAmount& nBest, int iterations = 1000)
{
    std::vector<char> vfIncluded;

    vfBest.assign(vValue.size(), true);
    nBest = nTotalLower;

    FastRandomContext insecure_rand;

    for (int nRep = 0; nRep < iterations && nBest != nTargetValue; nRep++)
    {
        vfIncluded.assign(vValue.size(), false);
        CAmount nTotal = 0;
        bool fReachedTarget = false;
        for (int nPass = 0; nPass < 2 && !fReachedTarget; nPass++)
        {
            for (unsigned int i = 0; i < vValue.size(); i++)
            {
                //The solver here uses a randomized algorithm,
                //the randomness serves no real security purpose but is just
                //needed to prevent degenerate behavior and it is important
                //that the rng is fast. We do not use a constant random sequence,
                //because there may be some privacy improvement by making
                //the selection random.
                if (nPass == 0 ? insecure_rand.rand32()&1 : !vfIncluded[i])
                {
                    nTotal += vValue[i].first;
                    vfIncluded[i] = true;
                    if (nTotal >= nTargetValue)
                    {
                        fReachedTarget = true;
                        if (nTotal < nBest)
                        {
                            nBest = nTotal;
                            vfBest = vfIncluded;
                        }
                        nTotal -= vValue[i].first;
                        vfIncluded[i] = false;
                    }
                }
            }
        }
    }
    return;
}

bool CHDWallet::AttemptSelection(const CAmount& nTargetValue, const CoinEligibilityFilter& eligibility_filter,
    std::vector<COutputR> vCoins, std::vector<std::pair<MapRecords_t::const_iterator,unsigned int> >& setCoinsRet, CAmount& nValueRet) const
{
    setCoinsRet.clear();
    nValueRet = 0;

    // List of values less than target
    std::pair<CAmount, std::pair<MapRecords_t::const_iterator,unsigned int> > coinLowestLarger;
    coinLowestLarger.first = std::numeric_limits<CAmount>::max();
    coinLowestLarger.second.first = mapRecords.end();
    std::vector<std::pair<CAmount, std::pair<MapRecords_t::const_iterator,unsigned int> > > vValue;
    CAmount nTotalLower = 0;

    Shuffle(vCoins.begin(), vCoins.end(), FastRandomContext());

    for (const auto &r : vCoins) {
        //if (!r.fSpendable)
        //    continue;
        MapRecords_t::const_iterator rtxi = r.rtx;
        const CTransactionRecord *rtx = &rtxi->second;

        const CWalletTx *pcoin = GetWalletOrTempTx(r.txhash, rtx);
        if (!pcoin) {
            return werror("%s: GetWalletOrTempTx failed.\n", __func__);
        }

        if (r.nDepth < (pcoin->IsFromMe(ISMINE_ALL) ? eligibility_filter.conf_mine : eligibility_filter.conf_theirs)) {
            continue;
        }

        size_t ancestors, descendants;
        chain().getTransactionAncestry(r.txhash, ancestors, descendants);
        if (ancestors > eligibility_filter.max_ancestors || descendants > eligibility_filter.max_descendants) {
             continue;
        }

        const COutputRecord *oR = rtx->GetOutput(r.i);
        if (!oR) {
            return werror("%s: GetOutput failed, %s, %d.\n", r.txhash.ToString(), r.i);
        }

        CAmount nV = oR->nValue;
        std::pair<CAmount,std::pair<MapRecords_t::const_iterator,unsigned int> > coin = std::make_pair(nV, std::make_pair(rtxi, r.i));

        if (nV == nTargetValue) {
            setCoinsRet.push_back(coin.second);
            nValueRet += coin.first;
            return true;
        } else
        if (nV < nTargetValue + MIN_CHANGE) {
            vValue.push_back(coin);
            nTotalLower += nV;
        } else
        if (nV < coinLowestLarger.first) {
            coinLowestLarger = coin;
        }
    }

    if (nTotalLower == nTargetValue) {
        for (unsigned int i = 0; i < vValue.size(); ++i) {
            setCoinsRet.push_back(vValue[i].second);
            nValueRet += vValue[i].first;
        }
        return true;
    }

    if (nTotalLower < nTargetValue) {
        if (coinLowestLarger.second.first == mapRecords.end()) {
            return false;
        }
        setCoinsRet.push_back(coinLowestLarger.second);
        nValueRet += coinLowestLarger.first;
        return true;
    }

    // Solve subset sum by stochastic approximation
    std::sort(vValue.begin(), vValue.end(), CompareValueOnly());
    std::reverse(vValue.begin(), vValue.end());
    std::vector<char> vfBest;
    CAmount nBest;

    ApproximateBestSubset(vValue, nTotalLower, nTargetValue, vfBest, nBest);
    if (nBest != nTargetValue && nTotalLower >= nTargetValue + MIN_CHANGE) {
        ApproximateBestSubset(vValue, nTotalLower, nTargetValue + MIN_CHANGE, vfBest, nBest);
    }

    // If we have a bigger coin and (either the stochastic approximation didn't find a good solution,
    //                                   or the next bigger coin is closer), return the bigger coin
    if (coinLowestLarger.second.first != mapRecords.end() &&
        ((nBest != nTargetValue && nBest < nTargetValue + MIN_CHANGE) || coinLowestLarger.first <= nBest)) {
        setCoinsRet.push_back(coinLowestLarger.second);
        nValueRet += coinLowestLarger.first;
    } else {
        for (unsigned int i = 0; i < vValue.size(); i++) {
            if (vfBest[i]) {
                setCoinsRet.push_back(vValue[i].second);
                nValueRet += vValue[i].first;
            }
        }

        if (LogAcceptCategory(BCLog::SELECTCOINS)) {
            WalletLogPrintf("SelectCoins() best subset: "); /* Continued */
            for (unsigned int i = 0; i < vValue.size(); i++)
                if (vfBest[i])
                    LogPrintf("%s ", FormatMoney(vValue[i].first)); /* Continued */
            LogPrintf("total %s\n", FormatMoney(nBest));
        }
    }

    return true;
}

/**
 * Outpoint is spent if any non-conflicted transaction
 * spends it:
 */
bool CHDWallet::IsSpent(const uint256& hash, unsigned int n) const
{
    const COutPoint outpoint(hash, n);
    if (m_collapsed_txn_inputs.find(outpoint) != m_collapsed_txn_inputs.end()) {
        return true;
    }
    std::pair<TxSpends::const_iterator, TxSpends::const_iterator> range;
    range = mapTxSpends.equal_range(outpoint);

    for (TxSpends::const_iterator it = range.first; it != range.second; ++it) {
        const uint256 &wtxid = it->second;
        MapWallet_t::const_iterator mit = mapWallet.find(wtxid);
        if (mit != mapWallet.end()) {
            if (mit->second.isAbandoned()) {
                continue;
            }

            int depth = mit->second.GetDepthInMainChain();
            if (depth > 0 || (depth == 0 && !mit->second.isAbandoned())) {
                return true; // Spent
            }
        }

        MapRecords_t::const_iterator rit = mapRecords.find(wtxid);
        if (rit != mapRecords.end()) {
            if (rit->second.IsAbandoned()) {
                continue;
            }

            int depth = GetDepthInMainChain(rit->second);
            if (depth >= 0) {
                return true; // Spent
            }
        }
    }

    return false;
};

bool CHDWallet::GetSpendingTxid(const uint256& hash, unsigned int n, uint256 &spent_by_txid) const
{
    const COutPoint outpoint(hash, n);
    if (m_collapsed_txn_inputs.find(outpoint) != m_collapsed_txn_inputs.end()) {
        return true;
    }
    std::pair<TxSpends::const_iterator, TxSpends::const_iterator> range;
    range = mapTxSpends.equal_range(outpoint);

    for (TxSpends::const_iterator it = range.first; it != range.second; ++it) {
        const uint256 &wtxid = it->second;
        MapWallet_t::const_iterator mit = mapWallet.find(wtxid);
        if (mit != mapWallet.end()) {
            if (mit->second.isAbandoned()) {
                continue;
            }

            int depth = mit->second.GetDepthInMainChain();
            if (depth > 0 || (depth == 0 && !mit->second.isAbandoned())) {
                spent_by_txid = wtxid;
                return true; // Spent
            }
        }

        MapRecords_t::const_iterator rit = mapRecords.find(wtxid);
        if (rit != mapRecords.end()) {
            if (rit->second.IsAbandoned()) {
                continue;
            }

            int depth = GetDepthInMainChain(rit->second);
            if (depth >= 0) {
                spent_by_txid = wtxid;
                return true; // Spent
            }
        }
    }
    return false;
};

bool CHDWallet::IsSpentKey(const CScript *pscript) const
{
    CTxDestination dst;
    return pscript && ExtractDestination(*pscript, dst) && IsMine(dst) && IsAddressUsed(dst);
}

bool CHDWallet::IsSpentKey(const uint256& hash, unsigned int n) const
{
    const CWalletTx* srctx = GetWalletTx(hash);
    if (srctx) {
        const auto &txout = srctx->tx->vpout[n];
        const CScript *pscript = txout->GetPScriptPubKey();
        return IsSpentKey(pscript);
    }
    return false;
}

void CHDWallet::SetSpentKeyState(const CScript *pscript, bool used)
{
    WalletBatch batch(*m_database);
    CTxDestination dst;
    if (pscript && ExtractDestination(*pscript, dst)) {
        if (IsMine(dst)) {
            if (used != IsAddressUsed(dst)) {
                SetAddressUsed(batch, dst, used);
            }
        }
    }
}

void CHDWallet::SetSpentKeyState(WalletBatch& batch, const uint256& hash, unsigned int n, bool used, std::set<CTxDestination>& tx_destinations)
{
    const CWalletTx* srctx = GetWalletTx(hash);
    if (srctx) {
        const auto &txout = srctx->tx->vpout[n];
        const CScript *pscript = txout->GetPScriptPubKey();
        CTxDestination dst;
        if (pscript && ExtractDestination(*pscript, dst)) {
            if (IsMine(dst)) {
                if (used != IsAddressUsed(dst)) {
                    if (used) {
                        tx_destinations.insert(dst);
                    }
                    SetAddressUsed(batch, dst, used);
                }
            }
        }
    }
}

void CHDWallet::SetSpentKeyState(const uint256& hash, unsigned int n, bool used)
{
    const CWalletTx* srctx = GetWalletTx(hash);
    if (srctx) {
        const auto &txout = srctx->tx->vpout[n];
        const CScript *pscript = txout->GetPScriptPubKey();
        return SetSpentKeyState(pscript, used);
    }
}

std::set<uint256> CHDWallet::GetConflicts(const uint256 &txid) const
{
    std::set<uint256> result;
    AssertLockHeld(cs_wallet);

    MapRecords_t::const_iterator mri = mapRecords.find(txid);

    if (mri != mapRecords.end()) {
        const CTransactionRecord &rtx = mri->second;
        std::pair<TxSpends::const_iterator, TxSpends::const_iterator> range;

        for (const auto &prevout : rtx.vin) {
            if (mapTxSpends.count(prevout) <= 1)
                continue;  // No conflict if zero or one spends
            range = mapTxSpends.equal_range(prevout);
            for (TxSpends::const_iterator _it = range.first; _it != range.second; ++_it)
                result.insert(_it->second);
        }

        return result;
    }

    return CWallet::GetConflicts(txid);
}

bool CHDWallet::TransactionCanBeAbandoned(const uint256& hashTx) const
{
    LOCK(cs_wallet);

    MapRecords_t::const_iterator mri;
    if ((mri = mapRecords.find(hashTx)) != mapRecords.end()) {
        const CTransactionRecord &rtx = mri->second;
        return !rtx.IsAbandoned() && GetDepthInMainChain(rtx) == 0 && !InMempool(hashTx);
    }

    const CWalletTx* wtx = GetWalletTx(hashTx);
    return wtx && !wtx->isAbandoned() && wtx->GetDepthInMainChain() == 0 && !wtx->InMempool();
}

bool CHDWallet::AbandonTransaction(const uint256 &hashTx)
{
    LOCK(cs_wallet);

    CHDWalletDB walletdb(*m_database);

    std::set<uint256> todo, done;

    MapRecords_t::iterator mri;
    MapWallet_t::iterator mwi;

    // Can't mark abandoned if confirmed or in mempool

    if ((mri = mapRecords.find(hashTx)) != mapRecords.end()) {
        CTransactionRecord &rtx = mri->second;
        if (GetDepthInMainChain(rtx) > 0 || InMempool(hashTx)) {
            return false;
        }
    } else
    if ((mwi = mapWallet.find(hashTx)) != mapWallet.end()) {
        CWalletTx &wtx = mwi->second;
        if (wtx.GetDepthInMainChain() > 0 || InMempool(hashTx)) {
            return false;
        }
    } else {
        // hashTx not in wallet
        return false;
    }

    todo.insert(hashTx);

    while (!todo.empty()) {
        uint256 now = *todo.begin();
        todo.erase(now);
        done.insert(now);

        if ((mri = mapRecords.find(now)) != mapRecords.end()) {
            CTransactionRecord &rtx = mri->second;
            int currentconfirm = GetDepthInMainChain(rtx);
            if (currentconfirm > 0) {
                WalletLogPrintf("ERROR: %s - Txn %s is %d blocks deep.\n", __func__, now.ToString(), currentconfirm);
                continue;
            }

            if (!rtx.IsAbandoned() &&
                currentconfirm == 0) {
                // If the orig tx was not in block/mempool, none of its spends can be in mempool
                assert(!InMempool(now));
                rtx.nIndex = -1;
                rtx.SetAbandoned();
                walletdb.WriteTxRecord(now, rtx);
                NotifyTransactionChanged(now, CT_UPDATED);
            }

        } else
        if ((mwi = mapWallet.find(now)) != mapWallet.end()) {
            CWalletTx &wtx = mwi->second;
            int currentconfirm = wtx.GetDepthInMainChain();
            if (currentconfirm > 0) {
                WalletLogPrintf("ERROR: %s - Txn %s is %d blocks deep.\n", __func__, now.ToString(), currentconfirm);
                continue;
            }

            if (!wtx.isAbandoned() &&
                currentconfirm == 0) {
                // AbandonTransaction can happen before CWallet::transactionRemovedFromMempool is called
                wtx.fInMempool = chain().isInMempool(wtx.GetHash());

                // If the orig tx was not in block/mempool, none of its spends can be in mempool
                assert(!wtx.InMempool());
                wtx.setAbandoned();
                wtx.MarkDirty();
                walletdb.WriteTx(wtx);
                NotifyTransactionChanged(now, CT_UPDATED);

                // If a transaction changes 'conflicted' state, that changes the balance
                // available of the outputs it spends. So force those to be recomputed
                for (const auto &txin : wtx.tx->vin)
                {
                    auto it = mapWallet.find(txin.prevout.hash);
                    if (it != mapWallet.end()) {
                        it->second.MarkDirty();
                    }
                }
            }
        } else {
            // Not in wallet
            continue;
        }

        TxSpends::const_iterator iter = mapTxSpends.lower_bound(COutPoint(hashTx, 0));
        while (iter != mapTxSpends.end() && iter->first.hash == now) {
            if (!done.count(iter->second)) {
                todo.insert(iter->second);
            }
            iter++;
        }
    }

    return true;
};

void CHDWallet::MarkConflicted(const uint256 &hashBlock, int conflicting_height, const uint256 &hashTx)
{
    if (!m_chain) return;
    LOCK(cs_wallet);

    int conflictconfirms = (m_last_block_processed_height - conflicting_height + 1) * -1;
    // If number of conflict confirms cannot be determined, this means
    // that the block is still unknown or not yet part of the main chain,
    // for example when loading the wallet during a reindex. Do nothing in that
    // case.
    if (conflictconfirms >= 0)
        return;

    // Do not flush the wallet here for performance reasons
    CHDWalletDB walletdb(*m_database, false);

    MapRecords_t::iterator mri;
    MapWallet_t::iterator mwi;
    std::set<uint256> todo, done;
    todo.insert(hashTx);

    size_t nChangedRecords = 0;
    while (!todo.empty()) {
        uint256 now = *todo.begin();
        todo.erase(now);
        done.insert(now);

        if ((mri = mapRecords.find(now)) != mapRecords.end()) {
            CTransactionRecord &rtx = mri->second;

            int currentconfirm = GetDepthInMainChain(rtx);

            if (conflictconfirms < currentconfirm) {
                // Block is 'more conflicted' than current confirm; update.
                // Mark transaction as conflicted with this block.
                rtx.nIndex = -1;
                rtx.blockHash = hashBlock;
                rtx.block_height = conflicting_height;
                walletdb.WriteTxRecord(now, rtx);

                // Iterate over all its outputs, and mark transactions in the wallet that spend them conflicted too
                TxSpends::const_iterator iter = mapTxSpends.lower_bound(COutPoint(now, 0));
                while (iter != mapTxSpends.end() && iter->first.hash == now) {
                    if (!done.count(iter->second)) {
                         todo.insert(iter->second);
                    }
                    iter++;
                }
            }

            nChangedRecords++;
            continue;
        }

        if ((mwi = mapWallet.find(now)) != mapWallet.end()) {
            CWalletTx &wtx = mwi->second;
            int currentconfirm = wtx.GetDepthInMainChain();

            if (conflictconfirms < currentconfirm) {
                // Block is 'more conflicted' than current confirm; update.
                // Mark transaction as conflicted with this block.
                wtx.m_confirm.nIndex = 0;
                wtx.m_confirm.hashBlock = hashBlock;
                wtx.m_confirm.block_height = conflicting_height;
                wtx.setConflicted();
                wtx.MarkDirty();
                walletdb.WriteTx(wtx);
                // Iterate over all its outputs, and mark transactions in the wallet that spend them conflicted too
                TxSpends::const_iterator iter = mapTxSpends.lower_bound(COutPoint(now, 0));
                while (iter != mapTxSpends.end() && iter->first.hash == now) {
                    if (!done.count(iter->second)) {
                         todo.insert(iter->second);
                    }
                    iter++;
                }

                // If a transaction changes 'conflicted' state, that changes the balance
                // available of the outputs it spends. So force those to be recomputed
                for(const auto &txin : wtx.tx->vin) {
                    auto it = mapWallet.find(txin.prevout.hash);
                    if (it != mapWallet.end()) {
                        it->second.MarkDirty();
                    }
                }
            }

            continue;
        }

        WalletLogPrintf("%s: Warning txn %s not recorded in wallet.\n", __func__, now.ToString());
    }

    if (nChangedRecords > 0) { // HACK, alternative is to load CStoredTransaction to get vin
        MarkDirty();
    }

    if (LogAcceptCategory(BCLog::HDWALLET)) {
        WalletLogPrintf("%s: %s, %s processed %d txns.\n", __func__, hashBlock.ToString(), hashTx.ToString(), done.size());
    }

    return;
};

void CHDWallet::SyncMetaData(std::pair<TxSpends::iterator, TxSpends::iterator> range)
{
    // We want all the wallet transactions in range to have the same metadata as
    // the oldest (smallest nOrderPos).
    // So: find smallest nOrderPos:

    int nMinOrderPos = std::numeric_limits<int>::max();
    const CWalletTx* copyFrom = nullptr;
    for (TxSpends::iterator it = range.first; it != range.second; ++it) {
        const uint256& hash = it->second;
        CWalletTx *wtx = GetWalletTx(hash);
        if (!wtx)
            continue;

        int n = wtx->nOrderPos;
        if (n < nMinOrderPos) {
            nMinOrderPos = n;
            copyFrom = wtx;
        }
    }
    // Now copy data from copyFrom to rest:
    for (TxSpends::iterator it = range.first; it != range.second; ++it) {
        const uint256& hash = it->second;

        CWalletTx* copyTo = GetWalletTx(hash);
        if (!copyTo)
            continue;

        if (copyFrom == copyTo) continue;
        if (!copyFrom->IsEquivalentTo(*copyTo)) continue;
        copyTo->mapValue = copyFrom->mapValue;
        copyTo->vOrderForm = copyFrom->vOrderForm;
        // fTimeReceivedIsTxTime not copied on purpose
        // nTimeReceived not copied on purpose
        copyTo->nTimeSmart = copyFrom->nTimeSmart;
        copyTo->fFromMe = copyFrom->fFromMe;
        // nOrderPos not copied on purpose
        // cached members not copied on purpose
    }
    return;
}

bool CHDWallet::GetSetting(const std::string &setting, UniValue &json)
{
    LOCK(cs_wallet);

    CHDWalletDB wdb(*m_database);

    std::string sJson;

    if (!wdb.ReadWalletSetting(setting, sJson)) {
        return false;
    }

    if (!json.read(sJson)) {
        return false;
    }
    return true;
};

bool CHDWallet::SetSetting(const std::string &setting, const UniValue &json)
{
    LOCK(cs_wallet);

    CHDWalletDB wdb(*m_database);

    std::string sJson = json.write();

    if (!wdb.WriteWalletSetting(setting, sJson)) {
        return false;
    }
    return true;
};

bool CHDWallet::EraseSetting(const std::string &setting)
{
    LOCK(cs_wallet);

    CHDWalletDB wdb(*m_database);

    if (!wdb.EraseWalletSetting(setting)) {
        return false;
    }
    return true;
};

int64_t CHDWallet::GetTimeFirstKey()
{
    int64_t time_first_key = 0;
    for (const auto& spk_man_pair : m_spk_managers) {
        int64_t time = spk_man_pair.second->GetTimeFirstKey();
        if (!time_first_key || time < time_first_key) time_first_key = time;
    }
    return time_first_key;
};

bool CHDWallet::GetPrevout(const COutPoint &prevout, CTxOutBaseRef &txout)
{
    MapWallet_t::const_iterator mi = mapWallet.find(prevout.hash);
    if (mi != mapWallet.end()) {
        if (prevout.n >= mi->second.tx->vpout.size()) {
            return false;
        }

        txout = mi->second.tx->vpout[prevout.n];
        return true;
    }

    MapRecords_t::const_iterator mir = mapRecords.find(prevout.hash);
    if (mir != mapRecords.end()) {
        const COutputRecord *oR = mir->second.GetOutput(prevout.n);

        if (oR && oR->nType == OUTPUT_STANDARD) { // get outputs other than standard from the utxodb or chain instead
            txout = MAKE_OUTPUT<CTxOutStandard>(oR->nValue, oR->scriptPubKey);
            return true;
        }
    }

    return false;
};

size_t CHDWallet::CountColdstakeOutputs()
{
    LOCK(cs_wallet);

    size_t nColdstakeOutputs = 0;
    std::vector<COutput> vAvailableCoins;
    CAmount nMinimumAmount = 0, nMaximumAmount = MAX_MONEY, nMinimumSumAmount = 0;
    uint64_t nMaximumCount = 0;

    CCoinControl coinControl;
    coinControl.m_include_immature = true;
    coinControl.m_include_unsafe_inputs = true;
    AvailableCoins(vAvailableCoins, &coinControl, nMinimumAmount, nMaximumAmount, nMinimumSumAmount, nMaximumCount);
    for (const auto &coin : vAvailableCoins) {
        assert(coin.i < (int)coin.tx->tx->GetNumVOuts());
        auto txoutBase = coin.tx->tx->vpout[coin.i];
        if (!txoutBase->IsStandardOutput()) {
            continue;
        }
        if (HasIsCoinstakeOp(*txoutBase->GetPScriptPubKey())) {
            nColdstakeOutputs++;
        }
    }

    return nColdstakeOutputs;
};

void CHDWallet::ClearMapTempRecords()
{
    mapTempRecords.clear();
};

bool CHDWallet::GetScriptForDest(CScript &script, const CTxDestination &dest, bool fUpdate, std::vector<uint8_t> *vData, uint32_t *last_key)
{
    LOCK(cs_wallet);

    if (dest.index() == DI::_CStealthAddress) {
        if (!vData) {
            return werror("%s: StealthAddress, vData is null .", __func__);
        }

        CStealthAddress sx = std::get<CStealthAddress>(dest);
        std::vector<CTempRecipient> vecSend;
        std::string strError;
        CTempRecipient r;
        r.nType = OUTPUT_STANDARD;
        r.address = sx;
        vecSend.push_back(r);

        if (0 != ExpandTempRecipients(vecSend, NULL, strError) || vecSend.size() != 2) {
            return werror("%s: ExpandTempRecipients failed, %s.", __func__, strError);
        }

        script = vecSend[0].scriptPubKey;
        *vData = vecSend[1].vData;
    } else
    if (dest.index() == DI::_CExtPubKey) {
        CTxDestination dest_nc = dest;
        CExtKeyPair ek = CExtKeyPair(std::get<CExtPubKey>(dest_nc));
        uint32_t nChildKey = 0;

        CPubKey pkTemp;
        if (0 != ExtKeyGetDestination(ek, pkTemp, nChildKey)) {
            return werror("%s: ExtKeyGetDestination failed.", __func__);
        }
        if (last_key) {
            *last_key = nChildKey;
        }

        nChildKey++;
        if (fUpdate) {
            ExtKeyUpdateLooseKey(ek, nChildKey, false);
        }

        script = GetScriptForDestination(PKHash(pkTemp));
    } else {
        script = GetScriptForDestination(dest);
        if (script.size() < 1) {
            return werror("%s: Unknown destination type.", __func__);
        }
    }

    return true;
};

bool CHDWallet::SetReserveBalance(CAmount nNewReserveBalance)
{
    WalletLogPrintf("SetReserveBalance %d\n", nReserveBalance);
    LOCK(cs_wallet);

    nReserveBalance = nNewReserveBalance;
    NotifyReservedBalanceChanged(nReserveBalance);
    return true;
};

void CHDWallet::SetStakeLimitHeight(int stake_limit)
{
    LOCK(cs_wallet);
    nStakeLimitHeight = stake_limit;
};

uint64_t CHDWallet::GetStakeWeight() const
{
    // Choose coins to use
    int64_t nBalance = GetSpendableBalance();
    if (nBalance <= nReserveBalance)
        return 0;

    int nHeight;
    {
        LOCK(cs_main);
        nHeight = chain().getHeightInt() + 1;
    }

    // Choose coins to use
    std::vector<const CWalletTx*> vwtxPrev;
    std::set<std::pair<const CWalletTx*,unsigned int> > setCoins;
    CAmount nValueIn = 0;

    // Select coins with suitable depth
    if (!SelectCoinsForStaking(nBalance - nReserveBalance, GetTime(), nHeight, setCoins, nValueIn))
        return 0;

    if (setCoins.empty())
        return 0;

    uint64_t nWeight = 0;

    for (const auto &pcoin : setCoins) {
        nWeight += pcoin.first->tx->vpout[pcoin.second]->GetValue();
    }

    return nWeight;
};

void CHDWallet::AvailableCoinsForStaking(std::vector<COutput> &vCoins, int64_t nTime, int nHeight) const
{
    ChainstateManager *pchainman{nullptr};
    if (HaveChain()) {
        pchainman = chain().getChainman();
    }
    if (!pchainman) {
        WalletLogPrintf("Error: Chainstate manager not found.\n");
        return;
    }

    vCoins.clear();
    m_greatest_txn_depth = 0;

    {
        LOCK(cs_wallet);

        int nHeight = pchainman->ActiveChain().Tip()->nHeight;
        int min_stake_confirmations = Params().GetStakeMinConfirmations();
        int nRequiredDepth = std::min(min_stake_confirmations-1, (int)(nHeight / 2));

        for (const auto &walletEntry : mapWallet) {
            const CWalletTx *pcoin = &walletEntry.second;
            CTransactionRef tx = pcoin->tx;

            int nDepth = pcoin->GetDepthInMainChain();
            if (nDepth > m_greatest_txn_depth) {
                m_greatest_txn_depth = nDepth;
            }
            if (nDepth < nRequiredDepth) {
                continue;
            }
            if (pcoin->IsCoinStake() && min_stake_confirmations < COINBASE_MATURITY) {
                // min_stake_confirmations is only less than COINBASE_MATURITY in regtest mode
                if (nDepth < std::min(COINBASE_MATURITY, (int)(nHeight / 2))) {
                    continue;
                }
            }

            const uint256 &wtxid = walletEntry.first;
            for (size_t i = 0; i < tx->vpout.size(); ++i) {
                const auto &txout = tx->vpout[i];
                if (!txout->IsType(OUTPUT_STANDARD)) {
                    continue;
                }
                if (txout->GetValue() < m_min_stakeable_value) {
                    continue;
                }
                COutPoint kernel(wtxid, i);
                if (!particl::CheckStakeUnused(kernel)
                     || IsSpent(wtxid, i)
                     || IsLockedCoin(wtxid, i)) {
                    continue;
                }

                const CScript *pscriptPubKey = txout->GetPScriptPubKey();
                CKeyID keyID;
                if (!particl::ExtractStakingKeyID(*pscriptPubKey, keyID)) {
                    continue;
                }

                isminetype mine = IsMine(keyID);
                if (!(mine & ISMINE_SPENDABLE)) {
                    continue;
                }

                bool fSpendableIn = true;
                bool fSolvableIn = true;
                bool fNeedHardwareKey = (mine & ISMINE_HARDWARE_DEVICE);
                if (fNeedHardwareKey) {
                    continue;
                }

                vCoins.emplace_back(pcoin, i, nDepth, fSpendableIn, fSolvableIn, true, true, fNeedHardwareKey, false);
            }
        }

        for (const auto &ri : mapRecords) {
            const uint256 &txid = ri.first;
            const CTransactionRecord &rtx = ri.second;

            int nDepth = GetDepthInMainChain(rtx);
            if (nDepth > m_greatest_txn_depth) {
                m_greatest_txn_depth = nDepth;
            }

            if (nDepth < nRequiredDepth) {
                continue;
            }

            MapWallet_t::const_iterator twi = mapTempWallet.end();
            for (const auto &r : rtx.vout) {
                if (r.nType != OUTPUT_STANDARD) {
                    continue;
                }
                if (r.nValue < m_min_stakeable_value) {
                    continue;
                }
                if (!(r.nFlags & ORF_OWNED || r.nFlags & ORF_STAKEONLY)) {
                    continue;
                }
                COutPoint kernel(txid, r.n);
                if (!particl::CheckStakeUnused(kernel)
                    || IsSpent(txid, r.n)
                    || IsLockedCoin(txid, r.n)) {
                    continue;
                }

                CKeyID keyID;
                if (!particl::ExtractStakingKeyID(r.scriptPubKey, keyID)) {
                    continue;
                }

                isminetype mine = IsMine(keyID);
                if (!(mine & ISMINE_SPENDABLE)) {
                    continue;
                }
                if ((mine & ISMINE_HARDWARE_DEVICE)) {
                    continue;
                }

                if (twi == mapTempWallet.end()
                    && (twi = mapTempWallet.find(txid)) == mapTempWallet.end()) {
                    if (0 != InsertTempTxn(txid, &rtx)
                        || (twi = mapTempWallet.find(txid)) == mapTempWallet.end()) {
                        WalletLogPrintf("ERROR: %s - InsertTempTxn failed %s.\n", __func__, txid.ToString());
                        return;
                    }
                }

                bool fSpendableIn = true;
                bool fNeedHardwareKey = false;
                vCoins.emplace_back(&twi->second, r.n, nDepth, fSpendableIn, true, true, true, fNeedHardwareKey, false);
            }
        }
    }

    Shuffle(vCoins.begin(), vCoins.end(), FastRandomContext());
    return;
};

bool CHDWallet::SelectCoinsForStaking(int64_t nTargetValue, int64_t nTime, int nHeight, std::set<std::pair<const CWalletTx*,unsigned int> >& setCoinsRet, int64_t& nValueRet) const
{
    if (m_have_cached_stakeable_coins) {
        Shuffle(m_cached_stakeable_coins.begin(), m_cached_stakeable_coins.end(), FastRandomContext());
    } else {
        m_cached_stakeable_coins.clear();
        AvailableCoinsForStaking(m_cached_stakeable_coins, nTime, nHeight);
        m_have_cached_stakeable_coins = true;
    }

    std::vector<COutput> &vCoins = m_cached_stakeable_coins;

    setCoinsRet.clear();
    nValueRet = 0;

    for (const auto &output : vCoins) {
        const CWalletTx *pcoin = output.tx;
        int i = output.i;

        // Stop if we've chosen enough inputs
        if (nValueRet >= nTargetValue) {
            break;
        }

        int64_t n = pcoin->tx->vpout[i]->GetValue();

        std::pair<int64_t, std::pair<const CWalletTx*, unsigned int> > coin = std::make_pair(n, std::make_pair(pcoin, i));

        if (n >= nTargetValue) {
            // If input value is greater or equal to target then simply insert
            //    it into the current subset and exit
            setCoinsRet.insert(coin.second);
            nValueRet += coin.first;
            break;
        } else
        if (n < nTargetValue + CENT) {
            setCoinsRet.insert(coin.second);
            nValueRet += coin.first;
        }
    }

    return true;
};

bool CHDWallet::CreateCoinStake(unsigned int nBits, int64_t nTime, int nBlockHeight, int64_t nFees, CMutableTransaction &txNew, CKey &key)
{
    ClearTxCreationState();

    ChainstateManager *pchainman{nullptr};
    if (HaveChain()) {
        pchainman = chain().getChainman();
    }
    if (!pchainman) {
        LogPrintf("Error: Chainstate manager not found.\n");
        return false;
    }

    CBlockIndex *pindexPrev = pchainman->ActiveChain().Tip();
    arith_uint256 bnTargetPerCoinDay;
    bnTargetPerCoinDay.SetCompact(nBits);

    CAmount nBalance = GetSpendableBalance();
    if (nBalance <= nReserveBalance) {
        return false;
    }

    // Choose coins to use
    std::vector<const CWalletTx*> vwtxPrev;
    std::set<std::pair<const CWalletTx*,unsigned int> > setCoins;
    CAmount nValueIn = 0;

    // Select coins with suitable depth
    if (!SelectCoinsForStaking(nBalance - nReserveBalance, nTime, nBlockHeight, setCoins, nValueIn)) {
        return false;
    }

    if (setCoins.empty()) {
        return false;
    }

    CAmount nCredit = 0;
    CScript scriptPubKeyKernel;

    std::set<std::pair<const CWalletTx*,unsigned int> >::iterator it = setCoins.begin();

    for (; it != setCoins.end(); ++it) {
        auto pcoin = *it;
        if (ThreadStakeMinerStopped()) {
            return false;
        }

        COutPoint prevoutStake = COutPoint(pcoin.first->GetHash(), pcoin.second);

        int64_t nBlockTime;
        if (CheckKernel(pchainman->ActiveChainstate(), pindexPrev, nBits, nTime, prevoutStake, &nBlockTime)) {
            LOCK(cs_wallet);
            // Found a kernel
            if (LogAcceptCategory(BCLog::POS)) {
                WalletLogPrintf("%s: Kernel found.\n", __func__);
            }

            if (!pcoin.first->tx->vpout[pcoin.second]->IsStandardOutput()) {
                continue;
            }
            CTxOutStandard *kernelOut = (CTxOutStandard*)pcoin.first->tx->vpout[pcoin.second].get();

            std::vector<valtype> vSolutions;
            TxoutType whichType;

            const CScript *pscriptPubKey = &kernelOut->scriptPubKey;
            CScript coinstakePath;
            bool fConditionalStake = false;
            if ((HasIsCoinstakeOp(*pscriptPubKey))) {
                fConditionalStake = true;
                if (!GetCoinstakeScriptPath(*pscriptPubKey, coinstakePath)) {
                    continue;
                }
                pscriptPubKey = &coinstakePath;
            }

            whichType = Solver(*pscriptPubKey, vSolutions);

            if (LogAcceptCategory(BCLog::POS)) {
                WalletLogPrintf("%s: Parsed kernel type=%d.\n", __func__, particl::FromTxoutType(whichType));
            }
            CKeyID spendId;
            if (whichType == TxoutType::PUBKEYHASH) {
                spendId = CKeyID(uint160(vSolutions[0]));
            } else
            if (whichType == TxoutType::PUBKEYHASH256) {
                spendId = CKeyID(uint256(vSolutions[0]));
            } else {
                if (LogAcceptCategory(BCLog::POS)) {
                    WalletLogPrintf("%s: No support for kernel type=%d.\n", __func__, particl::FromTxoutType(whichType));
                }
                break;  // only support pay to address (pay to pubkey hash)
            }

            if (!GetKey(spendId, key)) {
                if (LogAcceptCategory(BCLog::POS)) {
                    WalletLogPrintf("%s: Failed to get key for kernel type=%d.\n", __func__, particl::FromTxoutType(whichType));
                }
                break;  // unable to find corresponding key
            }

            if (fConditionalStake) {
                scriptPubKeyKernel = kernelOut->scriptPubKey;
            } else {
                scriptPubKeyKernel << OP_DUP << OP_HASH160 << ToByteVector(spendId) << OP_EQUALVERIFY << OP_CHECKSIG;

                // If the wallet has a coldstaking-change-address loaded, send the output to a coldstaking-script.
                UniValue jsonSettings;
                if (GetSetting("changeaddress", jsonSettings)
                    && jsonSettings["coldstakingaddress"].isStr()) {
                    std::string sAddress;
                    try { sAddress = jsonSettings["coldstakingaddress"].get_str();
                    } catch (std::exception &e) {
                        return werror("%s: Get coldstakingaddress failed %s.", __func__, e.what());
                    }

                    if (LogAcceptCategory(BCLog::POS)) {
                        WalletLogPrintf("%s: Sending output to coldstakingscript %s.\n", __func__, sAddress);
                    }

                    CTxDestination destColdStake = DecodeDestination(sAddress, true);
                    CScript scriptStaking;
                    if (!GetScriptForDest(scriptStaking, destColdStake, true, nullptr)) {
                        return werror("%s: GetScriptForDest failed.", __func__);
                    }

                    // Get new key from the active internal chain
                    CPubKey pkSpend;
                    if (0 != GetChangeAddress(pkSpend)) {
                        return werror("%s: GetChangeAddress failed.", __func__);
                    }

                    CKeyID256 id256 = pkSpend.GetID256();
                    scriptPubKeyKernel = GetScriptForDestination(id256);

                    if (scriptStaking.IsPayToPublicKeyHash()) {
                        CScript script = CScript() << OP_ISCOINSTAKE << OP_IF;
                        script.append(scriptStaking);
                        script << OP_ELSE;
                        script.append(scriptPubKeyKernel);
                        script << OP_ENDIF;

                        scriptPubKeyKernel = script;
                    } else {
                        return werror("%s: Unknown scriptStaking type, must be pay-to-public-key-hash.", __func__);
                    }
                }
            }

            // Ensure txn is empty
            txNew.vin.clear();
            txNew.vout.clear();
            txNew.vpout.clear();

            // Mark as coin stake transaction
            txNew.nVersion = PARTICL_TXN_VERSION;
            txNew.SetType(TXN_COINSTAKE);

            txNew.vin.push_back(CTxIn(pcoin.first->GetHash(), pcoin.second));

            nCredit += kernelOut->nValue;
            vwtxPrev.push_back(pcoin.first);

            OUTPUT_PTR<CTxOutData> out0 = MAKE_OUTPUT<CTxOutData>();
            out0->vData.resize(4);
            uint32_t tmp = htole32(nBlockHeight);
            memcpy(&out0->vData[0], &tmp, 4);

            uint32_t voteToken = 0;
            if (GetVote(nBlockHeight, voteToken)) {
                size_t origSize = out0->vData.size();
                out0->vData.resize(origSize + 5);
                out0->vData[origSize] = DO_VOTE;
                uint32_t tmp = htole32(voteToken);
                memcpy(&out0->vData[origSize+1], &tmp, 4);
            }

            txNew.vpout.push_back(out0);

            OUTPUT_PTR<CTxOutStandard> out1 = MAKE_OUTPUT<CTxOutStandard>();
            out1->nValue = 0;
            out1->scriptPubKey = scriptPubKeyKernel;
            txNew.vpout.push_back(out1);

            if (LogAcceptCategory(BCLog::POS)) {
                WalletLogPrintf("%s: Added kernel.\n", __func__);
            }

            setCoins.erase(it);
            break;
        }
    }

    if (nCredit == 0 || nCredit > nBalance - WITH_LOCK(cs_wallet, return nReserveBalance)) {
        return false;
    }

    // Attempt to add more inputs
    // Only advantage here is to setup the next stake using this output as a kernel to have a higher chance of staking
    size_t nStakesCombined = 0;
    it = setCoins.begin();
    while (it != setCoins.end()) {
        if (nStakesCombined >= nMaxStakeCombine) {
            break;
        }

        // Stop adding more inputs if already too many inputs
        if (txNew.vin.size() >= 100) {
            break;
        }

        // Stop adding more inputs if value is already pretty significant
        if (nCredit >= nStakeCombineThreshold) {
            break;
        }

        std::set<std::pair<const CWalletTx*, unsigned int> >::iterator itc = it++; // copy the current iterator then increment it
        auto pcoin = *itc;

        if (!pcoin.first->tx->vpout[pcoin.second]->IsStandardOutput()) {
            continue;
        }
        CTxOutStandard *prevOut = (CTxOutStandard*)pcoin.first->tx->vpout[pcoin.second].get();

        // Only add coins of the same key/address as kernel
        if (prevOut->scriptPubKey != scriptPubKeyKernel) {
            continue;
        }

        // Stop adding inputs if reached reserve limit
        if (nCredit + prevOut->nValue > nBalance - nReserveBalance) {
            break;
        }

        // Do not add additional significant input
        if (prevOut->nValue >= nStakeCombineThreshold) {
            continue;
        }

        txNew.vin.push_back(CTxIn(pcoin.first->GetHash(), pcoin.second));
        nCredit += prevOut->nValue;
        vwtxPrev.push_back(pcoin.first);

        if (LogAcceptCategory(BCLog::POS)) {
            WalletLogPrintf("%s: Combining kernel %s, %d.\n", __func__, pcoin.first->GetHash().ToString(), pcoin.second);
        }
        nStakesCombined++;
        setCoins.erase(itc);
    }

    const Consensus::Params &consensusParams = Params().GetConsensus();
    // Get block reward
    CAmount nReward = Params().GetProofOfStakeReward(pindexPrev, nFees);
    if (nReward < 0) {
        return false;
    }

    // Process development fund
    CTransactionRef txPrevCoinstake = nullptr;
    CAmount nRewardOut;
    const TreasuryFundSettings *pTreasuryFundSettings = Params().GetTreasuryFundSettings(nTime);
    if (!pTreasuryFundSettings || pTreasuryFundSettings->nMinTreasuryStakePercent <= 0) {
        nRewardOut = nReward;
    } else {
        int64_t nStakeSplit = std::max(pTreasuryFundSettings->nMinTreasuryStakePercent, nWalletTreasuryFundCedePercent);

        CAmount nTreasuryPart = (nReward * nStakeSplit) / 100;
        nRewardOut = nReward - nTreasuryPart;

        CAmount nTreasuryBfwd = 0;
        if (nBlockHeight > 1) { // genesis block is pow
            LOCK(cs_main);
            if (!particl::coinStakeCache.GetCoinStake(chain().getChainman()->ActiveChainstate(), pindexPrev->GetBlockHash(), txPrevCoinstake)) {
                return werror("%s: Failed to get previous coinstake: %s.", __func__, pindexPrev->GetBlockHash().ToString());
            }

            if (!txPrevCoinstake->GetTreasuryFundCfwd(nTreasuryBfwd)) {
                nTreasuryBfwd = 0;
            }
        }

        CAmount nTreasuryCfwd = nTreasuryBfwd + nTreasuryPart;
        if (nBlockHeight % pTreasuryFundSettings->nTreasuryOutputPeriod == 0) {
            // Place treasury fund output
            OUTPUT_PTR<CTxOutStandard> outTreasurySplit = MAKE_OUTPUT<CTxOutStandard>();
            outTreasurySplit->nValue = nTreasuryCfwd;

            CTxDestination dfDest = CBitcoinAddress(pTreasuryFundSettings->sTreasuryFundAddresses).Get();
            if (dfDest.index() == DI::_CNoDestination) {
                return werror("%s: Failed to get treasury fund destination: %s.", __func__, pTreasuryFundSettings->sTreasuryFundAddresses);
            }
            outTreasurySplit->scriptPubKey = GetScriptForDestination(dfDest);

            txNew.vpout.insert(txNew.vpout.begin() + 1, outTreasurySplit);
        } else {
            // Add to carried forward
            std::vector<uint8_t> vCfwd(1), &vData = *txNew.vpout[0]->GetPData();
            vCfwd[0] = DO_TREASURY_FUND_CFWD;
            if (0 != part::PutVarInt(vCfwd, nTreasuryCfwd)) {
                return werror("%s: PutVarInt failed: %d.", __func__, nTreasuryCfwd);
            }
            vData.insert(vData.end(), vCfwd.begin(), vCfwd.end());
            CAmount test_cfwd = 0;
            assert(ExtractCoinStakeInt64(vData, DO_TREASURY_FUND_CFWD, test_cfwd));
            assert(test_cfwd == nTreasuryCfwd);
        }
        if (LogAcceptCategory(BCLog::POS)) {
            WalletLogPrintf("%s: Coinstake reward split %d%%, treasury %s, reward %s.\n",
                __func__, nStakeSplit, FormatMoney(nTreasuryPart), FormatMoney(nRewardOut));
        }
    }

    // Place SMSG fee rate
    if (nTime >= consensusParams.smsg_fee_time) {
        CAmount smsg_fee_rate = consensusParams.smsg_fee_msg_per_day_per_k;
        if (nBlockHeight > 1) { // genesis block is pow
            LOCK(cs_main);
            if (!txPrevCoinstake && !particl::coinStakeCache.GetCoinStake(chain().getChainman()->ActiveChainstate(), pindexPrev->GetBlockHash(), txPrevCoinstake)) {
                return werror("%s: Failed to get previous coinstake: %s.", __func__, pindexPrev->GetBlockHash().ToString());
            }
            txPrevCoinstake->GetSmsgFeeRate(smsg_fee_rate);
        }

        if (m_smsg_fee_rate_target > 0) {
            int64_t diff = m_smsg_fee_rate_target - smsg_fee_rate;
            int64_t max_delta = Params().GetMaxSmsgFeeRateDelta(smsg_fee_rate, nTime);
            if (diff > max_delta) {
                diff = max_delta;
            } else
            if (diff < -max_delta) {
                diff = -max_delta;
            }
            smsg_fee_rate += diff;
            if (smsg_fee_rate < 1) {
                smsg_fee_rate = 1;
            }
        }
        std::vector<uint8_t> vSmsgFeeRate(1), &vData = *txNew.vpout[0]->GetPData();
        vSmsgFeeRate[0] = DO_SMSG_FEE;
        if (0 != part::PutVarInt(vSmsgFeeRate, smsg_fee_rate)) {
            return werror("%s: PutVarInt failed: %d.", __func__, smsg_fee_rate);
        }
        vData.insert(vData.end(), vSmsgFeeRate.begin(), vSmsgFeeRate.end());
        CAmount test_fee = 0;
        assert(ExtractCoinStakeInt64(vData, DO_SMSG_FEE, test_fee));
        assert(test_fee == smsg_fee_rate);
    }

    // Place SMSG difficulty
    {
        uint32_t last_compact = consensusParams.smsg_min_difficulty, next_compact = m_smsg_difficulty_target;
        if (nBlockHeight > 1) { // genesis block is pow
            LOCK(cs_main);
            if (!txPrevCoinstake && !particl::coinStakeCache.GetCoinStake(chain().getChainman()->ActiveChainstate(), pindexPrev->GetBlockHash(), txPrevCoinstake)) {
                return werror("%s: Failed to get previous coinstake: %s.", __func__, pindexPrev->GetBlockHash().ToString());
            }
            txPrevCoinstake->GetSmsgDifficulty(last_compact);
        }

        if (m_smsg_difficulty_target == 0) {
            next_compact = last_compact;
            int auto_adjust = smsgModule.AdjustDifficulty(nTime);
            if (auto_adjust > 0 && last_compact != consensusParams.smsg_min_difficulty) {
                next_compact += auto_adjust;
            } else
            if (auto_adjust < 0) {
                next_compact += auto_adjust;
            }
        }

        uint32_t test_compact;
        if (last_compact != next_compact) {

            uint32_t delta;
            if (last_compact > next_compact) {
                delta = last_compact - next_compact;
                if (delta > consensusParams.smsg_difficulty_max_delta) {
                    next_compact = last_compact - consensusParams.smsg_difficulty_max_delta;
                }
            } else {
                delta = next_compact - last_compact;
                if (delta > consensusParams.smsg_difficulty_max_delta) {
                    next_compact = last_compact + consensusParams.smsg_difficulty_max_delta;
                }
            }

            if (next_compact > consensusParams.smsg_min_difficulty) {
                next_compact = consensusParams.smsg_min_difficulty;
            }
        }

        std::vector<uint8_t> vSmsgDifficulty(5), &vData = *txNew.vpout[0]->GetPData();
        vSmsgDifficulty[0] = DO_SMSG_DIFFICULTY;
        uint32_t tmp = htole32(next_compact);
        memcpy(&vSmsgDifficulty[1], &tmp, 4);
        vData.insert(vData.end(), vSmsgDifficulty.begin(), vSmsgDifficulty.end());
        assert(ExtractCoinStakeUint32(vData, DO_SMSG_DIFFICULTY, test_compact));
        assert(test_compact == next_compact);
    }


    if (!IsValidDestination(m_reward_address)) {
        nCredit += nRewardOut;
    }

    // Set output amount, split outputs if > nStakeSplitThreshold
    if (nCredit >= nStakeSplitThreshold) {
        OUTPUT_PTR<CTxOutStandard> outSplit = MAKE_OUTPUT<CTxOutStandard>();
        outSplit->nValue = 0;
        outSplit->scriptPubKey = scriptPubKeyKernel;

        txNew.vpout.back()->SetValue(nCredit / 2);
        outSplit->SetValue(nCredit - txNew.vpout.back()->GetValue());
        txNew.vpout.push_back(outSplit);
    } else {
        txNew.vpout.back()->SetValue(nCredit);
    }

    // Create output for reward
    if (IsValidDestination(m_reward_address)) {
        CScript scriptReward;
        std::vector<uint8_t> vData;
        if (!GetScriptForDest(scriptReward, m_reward_address, true, &vData)) {
            return werror("%s: Could not get script for reward address.", __func__);
        }
        OUTPUT_PTR<CTxOutStandard> outReward = MAKE_OUTPUT<CTxOutStandard>();
        outReward->nValue = nRewardOut;
        outReward->scriptPubKey = scriptReward;
        txNew.vpout.push_back(outReward);
        if (vData.size() > 0) {
            OUTPUT_PTR<CTxOutData> outData = MAKE_OUTPUT<CTxOutData>();
            outData->vData = vData;
            txNew.vpout.push_back(outData);
        }
    }


    // Sign
    int nIn = 0;
    for (const auto &pcoin : vwtxPrev) {
        uint32_t nPrev = txNew.vin[nIn].prevout.n;

        CTxOutStandard *prevOut = (CTxOutStandard*)pcoin->tx->vpout[nPrev].get();
        CScript &scriptPubKeyOut = prevOut->scriptPubKey;
        auto provider = GetLegacyScriptPubKeyMan();
        std::vector<uint8_t> vchAmount;
        prevOut->PutValue(vchAmount);

        SignatureData sigdata;
        if (!ProduceSignature(*provider, MutableTransactionSignatureCreator(&txNew, nIn, vchAmount, SIGHASH_ALL), scriptPubKeyOut, sigdata)) {
            return werror("%s: ProduceSignature failed.", __func__);
        }

        UpdateInput(txNew.vin[nIn], sigdata);
        nIn++;
    }

    // Limit size
    unsigned int nBytes = ::GetSerializeSize(txNew);
    if (nBytes >= DEFAULT_BLOCK_MAX_SIZE / 5) {
        return werror("%s: Exceeded coinstake size limit.", __func__);
    }

    // Successfully generated coinstake
    return true;
};

bool CHDWallet::SignBlock(CBlockTemplate *pblocktemplate, int nHeight, int64_t nSearchTime)
{
    if (LogAcceptCategory(BCLog::POS)) {
        WalletLogPrintf("%s, Height %d\n", __func__, nHeight);
    }
    if (!HaveChain()) {
        WalletLogPrintf("%s, Don't have chain.\n", __func__);
    }

    assert(pblocktemplate);
    CBlock *pblock = &pblocktemplate->block;
    assert(pblock);
    if (pblock->vtx.size() < 1) {
        return werror("%s: Malformed block.", __func__);
    }

    int64_t nFees = -pblocktemplate->vTxFees[0];
    CBlockIndex *pindexPrev = chain().getTip();

    CKey key;
    pblock->nVersion = PARTICL_BLOCK_VERSION;
    pblock->nBits = GetNextTargetRequired(pindexPrev);
    if (LogAcceptCategory(BCLog::POS)) {
        WalletLogPrintf("%s, nBits %d\n", __func__, pblock->nBits);
    }

    CMutableTransaction txCoinStake;
    if (CreateCoinStake(pblock->nBits, nSearchTime, nHeight, nFees, txCoinStake, key)) {
        if (LogAcceptCategory(BCLog::POS)) {
            WalletLogPrintf("%s: Kernel found.\n", __func__);
        }

        if (nSearchTime >= pindexPrev->GetPastTimeLimit() + 1) {
            // make sure coinstake would meet timestamp protocol
            //    as it would be the same as the block timestamp
            pblock->nTime = nSearchTime;

            // Remove coinbasetxn
            pblock->vtx[0].reset();
            pblock->vtx.erase(pblock->vtx.begin());

            // Insert coinstake as txn0
            pblock->vtx.insert(pblock->vtx.begin(), MakeTransactionRef(txCoinStake));

            bool mutated;
            pblock->hashMerkleRoot = BlockMerkleRoot(*pblock, &mutated);
            pblock->hashWitnessMerkleRoot = BlockWitnessMerkleRoot(*pblock, &mutated);

            // Append a signature to the block
            return key.Sign(pblock->GetHash(), pblock->vchBlockSig);
        }
    }
    {
        LOCK(cs_wallet);
        nLastCoinStakeSearchTime = nSearchTime;
    }
    return false;
};

std::unique_ptr<CBlockTemplate> CHDWallet::CreateNewBlock()
{
    if (!HaveChain()) {
        return nullptr;
    }
    return chain().createNewBlock();
};

int LoopExtKeysInDB(CHDWallet *pwallet, bool fInactive, bool fInAccount, LoopExtKeyCallback &callback)
{
    AssertLockHeld(pwallet->cs_wallet);

    CHDWalletDB wdb(pwallet->GetDatabase());

    Dbc *pcursor;
    if (!(pcursor = wdb.GetCursor())) {
        throw std::runtime_error(strprintf("%s : cannot create DB cursor", __func__).c_str());
    }

    CDataStream ssKey(SER_DISK, CLIENT_VERSION);
    CDataStream ssValue(SER_DISK, CLIENT_VERSION);

    CKeyID ckeyId;
    CStoredExtKey sek;
    std::string strType;

    uint32_t fFlags = DB_SET_RANGE;
    ssKey << std::string(DBKeys::PART_EXTKEY);

    while (wdb.ReadAtCursor(pcursor, ssKey, ssValue, fFlags) == 0) {
        fFlags = DB_NEXT;

        ssKey >> strType;
        if (strType != DBKeys::PART_EXTKEY) {
            break;
        }

        ssKey >> ckeyId;
        ssValue >> sek;
        if (!fInAccount
            && sek.nFlags & EAF_IN_ACCOUNT) {
            continue;
        }
        callback.ProcessKey(ckeyId, sek);
    }
    pcursor->close();

    return 0;
};


int LoopExtAccountsInDB(CHDWallet *pwallet, bool fInactive, LoopExtKeyCallback &callback)
{
    AssertLockHeld(pwallet->cs_wallet);
    CHDWalletDB wdb(pwallet->GetDatabase());
    // List accounts

    Dbc *pcursor;
    if (!(pcursor = wdb.GetCursor())) {
        throw std::runtime_error(strprintf("%s : cannot create DB cursor", __func__).c_str());
    }

    CDataStream ssKey(SER_DISK, CLIENT_VERSION);
    CDataStream ssValue(SER_DISK, CLIENT_VERSION);
    CKeyID idAccount;
    CExtKeyAccount sea;
    std::string strType, sError;

    uint32_t fFlags = DB_SET_RANGE;
    ssKey << std::string(DBKeys::PART_EXTACC);

    while (wdb.ReadAtCursor(pcursor, ssKey, ssValue, fFlags) == 0) {
        fFlags = DB_NEXT;

        ssKey >> strType;
        if (strType != DBKeys::PART_EXTACC) {
            break;
        }

        ssKey >> idAccount;
        ssValue >> sea;

        sea.vExtKeys.resize(sea.vExtKeyIDs.size());
        for (size_t i = 0; i < sea.vExtKeyIDs.size(); ++i) {
            CKeyID &id = sea.vExtKeyIDs[i];
            CStoredExtKey *sek = new CStoredExtKey();

            if (wdb.ReadExtKey(id, *sek)) {
                sea.vExtKeys[i] = sek;
            } else {
                pwallet->WalletLogPrintf("WARNING: Could not read key %d of account %s\n", i, HDAccIDToString(idAccount));
                sea.vExtKeys[i] = nullptr;
                delete sek;
            }
        }
        callback.ProcessAccount(idAccount, sea);

        sea.FreeChains();
    }

    pcursor->close();

    return 0;
};

void SetCTOutVData(std::vector<uint8_t> &vData, CPubKey &pkEphem, const CTempRecipient &r)
{
    vData.resize((r.nStealthPrefix > 0 ? 38 : 33));

    memcpy(&vData[0], pkEphem.begin(), 33);
    if (r.nStealthPrefix > 0) {
        vData[33] = DO_STEALTH_PREFIX;
        uint32_t tmp = htole32(r.nStealthPrefix);
        memcpy(&vData[34], &tmp, 4);
    }
};

int CreateOutput(OUTPUT_PTR<CTxOutBase> &txbout, CTempRecipient &r, std::string &sError)
{
    switch (r.nType) {
        case OUTPUT_DATA:
            txbout = MAKE_OUTPUT<CTxOutData>(r.vData);
            break;
        case OUTPUT_STANDARD:
            txbout = MAKE_OUTPUT<CTxOutStandard>(r.nAmount, r.scriptPubKey);
            break;
        case OUTPUT_CT:
            {
            txbout = MAKE_OUTPUT<CTxOutCT>();
            CTxOutCT *txout = (CTxOutCT*)txbout.get();

            if (r.fNonceSet) {
                if (r.vData.size() < 33) {
                    return errorN(1, sError, __func__, "Missing ephemeral value, vData size %d", r.vData.size());
                }
                txout->vData = r.vData;
            } else {
                CPubKey pkEphem = r.sEphem.GetPubKey();
                SetCTOutVData(txout->vData, pkEphem, r);
            }

            txout->scriptPubKey = r.scriptPubKey;
            }
            break;
        case OUTPUT_RINGCT:
            {
            txbout = MAKE_OUTPUT<CTxOutRingCT>();
            CTxOutRingCT *txout = (CTxOutRingCT*)txbout.get();

            txout->pk = CCmpPubKey(r.pkTo);

            if (r.fNonceSet) {
                if (r.vData.size() < 33) {
                    return errorN(1, sError, __func__, "Missing ephemeral value, vData size %d", r.vData.size());
                }
                txout->vData = r.vData;
            } else {
                CPubKey pkEphem = r.sEphem.GetPubKey();
                SetCTOutVData(txout->vData, pkEphem, r);
            }

            }
            break;
        default:
            return errorN(1, sError, __func__, "Unknown output type %d", r.nType);
    }

    return 0;
};

void ExtractNarration(const uint256 &nonce, const std::vector<uint8_t> &vData, std::string &sNarr)
{
    if (vData.size() < 33) {
        return;
    }

    CPubKey pkEphem;
    pkEphem.Set(vData.begin(), vData.begin() + 33);

    int nNarrOffset = -1;
    if (vData.size() > 38 && vData[38] == DO_NARR_CRYPT) {
        nNarrOffset = 39;
    } else
    if (vData.size() > 33 && vData[33] == DO_NARR_CRYPT) {
        nNarrOffset = 34;
    }

    if (nNarrOffset == -1) {
        return;
    }

    size_t lenNarr = vData.size() - nNarrOffset;
    if (lenNarr < 1 || lenNarr > 32) { // min block size 8?
        LogPrintf("%s: Invalid narration data length: %d\n", __func__, lenNarr);
        return;
    }

    SecMsgCrypter crypter;
    crypter.SetKey(nonce.begin(), pkEphem.begin());

    std::vector<uint8_t> vchNarr;
    if (!crypter.Decrypt(&vData[nNarrOffset], lenNarr, vchNarr)) {
        LogPrintf("%s: Decrypt narration failed.\n", __func__);
        return;
    }
    sNarr = std::string(vchNarr.begin(), vchNarr.end());
};

int64_t CalculateMaximumSignedTxSize(const CTransaction &tx, const CHDWallet *wallet)
{
    std::vector<CTxOutBaseRef> txouts;

    // Look up the inputs.  We should have already checked that this transaction
    // IsAllFromMe(ISMINE_SPENDABLE), so every input should already be in our
    // wallet, with a valid index into the vout array, and the ability to sign.
    for (const auto& input : tx.vin) {
        const auto mi = wallet->mapWallet.find(input.prevout.hash);
        if (mi != wallet->mapWallet.end()) {
            assert(input.prevout.n < mi->second.tx->GetNumVOuts());
            txouts.emplace_back(mi->second.tx->vpout[input.prevout.n]);
            continue;
        }
        const auto mri = wallet->mapRecords.find(input.prevout.hash);
        if (mri != wallet->mapRecords.end()) {
            const COutputRecord *oR = mri->second.GetOutput(input.prevout.n);
            if (oR && (oR->nFlags & ORF_OWNED)) {
                if (oR->nType != OUTPUT_STANDARD) {
                    wallet->WalletLogPrintf("ERROR: %s non standard output - TODO.\n", __func__);
                    return -1;
                }
                txouts.emplace_back(MAKE_OUTPUT<CTxOutStandard>(oR->nValue, oR->scriptPubKey));
                continue;
            }
        }

        return -1;
    }

    return CalculateMaximumSignedTxSize(tx, wallet, txouts);
}

// txouts needs to be in the order of tx.vin
int64_t CalculateMaximumSignedTxSize(const CTransaction &tx, const CHDWallet *wallet, const std::vector<CTxOutBaseRef>& txouts)
{
    CMutableTransaction txNew(tx);

    if (!wallet->DummySignTx(txNew, txouts)) {
        // This should never happen, because IsAllFromMe(ISMINE_SPENDABLE)
        // implies that we can sign for every input.
        return -1;
    }

    return GetVirtualTransactionSize(CTransaction(txNew));
}

void RestartStakingThreads(ChainstateManager &chainman)
{
    StopThreadStakeMiner();
    StartThreadStakeMiner(chainman);
};

bool IsParticlWallet(const WalletStorage *win)
{
    return win && dynamic_cast<const CHDWallet*>(win);
};

CHDWallet *GetParticlWallet(WalletStorage *win)
{
    CHDWallet *rv;
    if (!win) {
        return nullptr;
    }
    if (!(rv = dynamic_cast<CHDWallet*>(win))) {
        throw std::runtime_error("Wallet pointer is not an instance of class CHDWallet.");
    }
    return rv;
};

const CHDWallet *GetParticlWallet(const WalletStorage *win)
{
    const CHDWallet *rv;
    if (!win) {
        return nullptr;
    }
    if (!(rv = dynamic_cast<const CHDWallet*>(win))) {
        throw std::runtime_error("Wallet pointer is not an instance of class CHDWallet.");
    }
    return rv;
};
