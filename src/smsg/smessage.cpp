// Copyright (c) 2014-2016 The ShadowCoin developers
// Copyright (c) 2017-2019 The Particl Core developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

/*
Notes:
    Running with -debug could leave to and from address hashes and public keys in the log.

    Wallet Locked
        A copy of each incoming message is stored in bucket files ending in _wl.dat
        wl (wallet locked) bucket files are deleted if they expire, like normal buckets
        When the wallet is unlocked all the messages in wl files are scanned.

    Address Whitelist
        Owned Addresses are stored in addresses vector
        Saved to smsg.ini
        Modify options using the smsglocalkeys rpc command or edit the smsg.ini file (with client closed)

    TODO:
        For buckets older than current, only need to store no. messages and hash in memory

*/

#include <smsg/smessage.h>

#include <secp256k1.h>
#include <secp256k1_ecdh.h>
#include <crypto/hmac_sha256.h>
#include <crypto/sha512.h>
#include <wallet/ismine.h>
#include <support/allocators/secure.h>
#include <util/strencodings.h>
#include <consensus/validation.h>
#include <validation.h>
#include <validationinterface.h>
#include <smsg/crypter.h>
#include <smsg/db.h>
#include <sync.h>
#include <random.h>
#include <chain.h>
#include <netmessagemaker.h>
#include <net.h>
#include <streams.h>
#include <univalue.h>
#include <node/context.h>
#include <util/string.h>

#ifdef ENABLE_WALLET
#include <wallet/coincontrol.h>
#include <wallet/hdwallet.h>
#include <interfaces/chain.h>
#include <policy/policy.h>
#endif


#include <stdint.h>
#include <time.h>
#include <map>
#include <stdexcept>
#include <errno.h>
#include <limits>

#include <xxhash/xxhash.h>
#include <boost/algorithm/string/replace.hpp>
#include <boost/thread/thread.hpp>


extern NodeContext* g_rpc_node;

extern void Misbehaving(NodeId nodeid, int howmuch, const std::string& message="");
extern CCriticalSection cs_main;

smsg::CSMSG smsgModule;

namespace SMSGMsgType {
const char *PING="smsgPing";
const char *PONG="smsgPong";
const char *DISABLED="smsgDisabled";
const char *INV="smsgInv";
const char *SHOW="smsgShow";
const char *HAVE="smsgHave";
const char *WANT="smsgWant";
const char *MSG="smsgMsg";
const char *IGNORING="smsgIgnore";

const static std::string allTypes[] = {
    PING, PONG, DISABLED, INV, SHOW, HAVE, WANT, MSG, IGNORING
};
} // namespace SMSGMsgType

namespace smsg {
bool fSecMsgEnabled = false;

uint32_t SMSG_SECONDS_IN_HOUR   = 60 * 60;
uint32_t SMSG_BUCKET_LEN        = SMSG_SECONDS_IN_HOUR * 1;
uint32_t SMSG_SECONDS_IN_DAY    = SMSG_SECONDS_IN_HOUR * 24;
uint32_t SMSG_MIN_TTL           = SMSG_SECONDS_IN_HOUR;
uint32_t SMSG_MAX_FREE_TTL      = SMSG_SECONDS_IN_DAY * 14;
uint32_t SMSG_MAX_PAID_TTL      = SMSG_SECONDS_IN_DAY * 31;
uint32_t SMSG_RETENTION         = SMSG_MAX_PAID_TTL;

const size_t MAX_BUNCH_MESSAGES = 500;
const size_t MAX_BUNCH_BYTES = SMSG_MAX_MSG_BYTES_PAID * 4;
const uint16_t MAX_WANT_SENT = 16000;
const size_t SMSG_MAX_SHOW = 64;

boost::thread_group threadGroupSmsg;

boost::signals2::signal<void (SecMsgStored &inboxHdr)> NotifySecMsgInboxChanged;
boost::signals2::signal<void (SecMsgStored &outboxHdr)> NotifySecMsgOutboxChanged;
boost::signals2::signal<void ()> NotifySecMsgWalletUnlocked;

const std::string STORE_DIR = "smsgstore2";


secp256k1_context *secp256k1_context_smsg = nullptr;

std::string SecMsgToken::ToString() const
{
    return strprintf("%d-%08x", timestamp, *((uint64_t*)sample));
}

void SecMsgBucket::hashBucket(int64_t bucket_time)
{
    XXH32_state_t *state = XXH32_createState();
    XXH32_reset(state, 1);

    int64_t now = GetAdjustedTime();

    nActive = 0;
    nLeastTTL = 0;
    for (auto it = setTokens.begin(); it != setTokens.end(); ++it) {
        if (it->timestamp + it->ttl < now) {
            continue;
        }

        XXH32_update(state, it->sample, 8);
        if (it->ttl > 0 && (nLeastTTL == 0 || it->ttl < nLeastTTL)) {
            nLeastTTL = it->ttl;
        }
        nActive++;
    }

    uint32_t hash_new = XXH32_digest(state);
    XXH32_freeState(state);

    if (hash != hash_new) {
        LogPrint(BCLog::SMSG, "Bucket %d hashed %u messages updated from %u to %u.\n", bucket_time, nActive, hash, hash_new);

        hash = hash_new;
        timeChanged = GetTime();
    }
    return;
};

size_t SecMsgBucket::CountActive() const
{
    size_t nMessages = 0;

    int64_t now = GetAdjustedTime();
    for (auto it = setTokens.begin(); it != setTokens.end(); ++it) {
        if (it->timestamp + it->ttl < now) {
            continue;
        }
        nMessages++;
    }

    return nMessages;
};

void ThreadSecureMsg()
{
    // Bucket management thread

    static uint32_t nLoop = 0;
    std::vector<std::pair<int64_t, NodeId> > vTimedOutLocks;
    while (fSecMsgEnabled) {
        nLoop++;
        int64_t now = GetAdjustedTime();

        vTimedOutLocks.resize(0);
        int64_t cutoffTime = now - SMSG_RETENTION;
        {
            LOCK(smsgModule.cs_smsg);
            for (std::map<int64_t, SecMsgBucket>::iterator it(smsgModule.buckets.begin()); it != smsgModule.buckets.end(); ) {
                bool fErase = it->first < cutoffTime;

                if (!fErase
                    && it->first + it->second.nLeastTTL < now) {
                    it->second.hashBucket(it->first);

                    // TODO: periodically prune files
                    if (it->second.nActive < 1) {
                        fErase = true;
                    }
                }

                if (fErase) {
                    LogPrint(BCLog::SMSG, "Removing bucket %d.\n", it->first);

                    std::string fileName = std::to_string(it->first);

                    fs::path fullPath = GetDataDir() / STORE_DIR / (fileName + "_01.dat");
                    if (fs::exists(fullPath)) {
                        try { fs::remove(fullPath);
                        } catch (const fs::filesystem_error &ex) {
                            LogPrintf("Error removing bucket file %s.\n", ex.what());
                        }
                    } else {
                        LogPrintf("Path %s does not exist.\n", fullPath.string());
                    }

                    // Look for a wl file, it stores incoming messages when wallet is locked
                    fullPath = GetDataDir() / STORE_DIR / (fileName + "_01_wl.dat");
                    if (fs::exists(fullPath)) {
                        try { fs::remove(fullPath);
                        } catch (const fs::filesystem_error &ex) {
                            LogPrintf("Error removing wallet locked file %s.\n", ex.what());
                        }
                    }

                    smsgModule.buckets.erase(it++);
                } else {
                    if (it->second.nLockCount > 0) { // Tick down nLockCount, to eventually expire if peer never sends data
                        it->second.nLockCount--;

                        if (it->second.nLockCount == 0) { // lock timed out
                            vTimedOutLocks.push_back(std::make_pair(it->first, it->second.nLockPeerId)); // g_connman->cs_vNodes
                            it->second.nLockPeerId = -1;
                        }
                    }
                    ++it;
                }
            }

            if (smsgModule.nLastProcessedPurged + SMSG_SECONDS_IN_DAY < now) {
                smsgModule.BuildPurgedSets();
            }

            if (nLoop % 20 == 0) {
                // Erase any unreceived show_requests
                int64_t local_time = GetTime();
                for (auto it = smsgModule.m_show_requests.begin(); it != smsgModule.m_show_requests.end(); ) {
                    if (it->second < local_time) {
                        it = smsgModule.m_show_requests.erase(it);
                    } else {
                        ++it;
                    }
                }
            }
        } // cs_smsg

        if (nLoop % 20 == 0) {
            LOCK(g_rpc_node->connman->cs_vNodes);
            for (auto *pnode : g_rpc_node->connman->vNodes) {
                LOCK(pnode->smsgData.cs_smsg_net);
                int64_t cutoffTime = now - SMSG_SECONDS_IN_DAY;
                for (auto it = pnode->smsgData.m_buckets_last_shown.begin(); it != pnode->smsgData.m_buckets_last_shown.end(); ) {
                    if (it->first < cutoffTime) {
                        it = pnode->smsgData.m_buckets_last_shown.erase(it);
                    } else {
                        ++it;
                    }
                }
            }
        }

        for (std::vector<std::pair<int64_t, NodeId> >::iterator it(vTimedOutLocks.begin()); it != vTimedOutLocks.end(); it++) {
            NodeId nPeerId = it->second;
            uint32_t fExists = 0;

            LogPrint(BCLog::SMSG, "Lock on bucket %d for peer %d timed out.\n", it->first, nPeerId);

            // Look through the nodes for the peer that locked this bucket

            {
                LOCK(g_rpc_node->connman->cs_vNodes);
                for (auto *pnode : g_rpc_node->connman->vNodes) {
                    if (pnode->GetId() != nPeerId) {
                        continue;
                    }

                    fExists = 1; //found in g_connman->vNodes

                    LOCK(pnode->smsgData.cs_smsg_net);
                    int64_t ignoreUntil = GetTime() + SMSG_TIME_IGNORE;
                    pnode->smsgData.ignoreUntil = ignoreUntil;

                    // Alert peer that they are being ignored
                    std::vector<uint8_t> vchData;
                    vchData.resize(8);
                    memcpy(&vchData[0], &ignoreUntil, 8);
                    g_rpc_node->connman->PushMessage(pnode,
                        CNetMsgMaker(INIT_PROTO_VERSION).Make(SMSGMsgType::IGNORING, vchData));

                    LogPrint(BCLog::SMSG, "This node will ignore peer %d until %d.\n", nPeerId, ignoreUntil);
                    break;
                }
            } // g_connman->cs_vNodes
        }

        MilliSleep(SMSG_THREAD_DELAY * 1000); //  // check every SMSG_THREAD_DELAY seconds
    }
    return;
};

void ThreadSecureMsgPow()
{
    // Proof of work thread

    int rv;
    std::vector<uint8_t> vchKey;
    SecMsgStored smsgStored;

    uint8_t chKey[30];

    while (fSecMsgEnabled) {
        // Sleep at end, then fSecMsgEnabled is tested on wake

        SecMsgDB dbOutbox;
        leveldb::Iterator *it;
        {
            LOCK(cs_smsgDB);
            if (!dbOutbox.Open("cr+")) {
                continue;
            }

            // fifo (smallest key first)
            it = dbOutbox.pdb->NewIterator(leveldb::ReadOptions());
        }
        // Break up lock, SecureMsgSetHash will take long

        for (;;) {
            if (!fSecMsgEnabled) {
                break;
            }
            {
                LOCK(cs_smsgDB);
                if (!dbOutbox.NextSmesg(it, DBK_QUEUED, chKey, smsgStored)) {
                    break;
                }
            }

            uint8_t *pHeader = &smsgStored.vchMessage[0];
            uint8_t *pPayload = &smsgStored.vchMessage[SMSG_HDR_LEN];
            SecureMessage *psmsg = (SecureMessage*) pHeader;

            const int64_t FUND_TXN_TIMEOUT = 3600 * 48;
            int64_t now = GetTime();

            if (psmsg->version[0] == 3) {
                uint256 txid;
                uint160 msgId;
                if (0 != smsgModule.HashMsg(*psmsg, pPayload, psmsg->nPayload-32, msgId)
                    || !GetFundingTxid(pPayload, psmsg->nPayload, txid)) {
                    LogPrintf("%s: Get msgID or Txn Hash failed.\n", __func__);
                    LOCK(cs_smsgDB);
                    dbOutbox.EraseSmesg(chKey);
                    continue;
                }

                CTransactionRef txOut;
                uint256 hashBlock;
                int blockDepth = -1;
                {
                    LOCK(cs_main);
                    if (!GetTransaction(txid, txOut, Params().GetConsensus(), hashBlock)) {
                        // drop through
                    }

                    if (!hashBlock.IsNull()) {
                        BlockMap::iterator mi = ::BlockIndex().find(hashBlock);
                        if (mi != ::BlockIndex().end()) {
                            CBlockIndex *pindex = mi->second;
                            if (pindex && ::ChainActive().Contains(pindex)) {
                                blockDepth = ::ChainActive().Height() - pindex->nHeight + 1;
                            }
                        }
                    }
                }
                if (blockDepth > 0) {
                    LogPrintf("Found txn %s at depth %d\n", txid.ToString(), blockDepth);
                } else {
                    // Failure
                    if (psmsg->timestamp > now + FUND_TXN_TIMEOUT) {
                        LogPrintf("%s: Funding txn timeout, dropping message %s\n", __func__, msgId.ToString());
                        LOCK(cs_smsgDB);
                        dbOutbox.EraseSmesg(chKey);
                    }
                    continue;
                }
            } else {
                // Do proof of work
                rv = smsgModule.SetHash(pHeader, pPayload, psmsg->nPayload);
                if (rv == SMSG_SHUTDOWN_DETECTED) {
                    break; // leave message in db, if terminated due to shutdown
                }
                if (rv != 0) {
                    LogPrintf("SecMsgPow: Could not get proof of work hash, message removed.\n");
                    LOCK(cs_smsgDB);
                    dbOutbox.EraseSmesg(chKey);
                    continue;
                }
            }


            // Remove message from queue
            {
                LOCK(cs_smsgDB);
                dbOutbox.EraseSmesg(chKey);
            }

            // Add to message store
            {
                LOCK(smsgModule.cs_smsg);
                if (smsgModule.Store(pHeader, pPayload, psmsg->nPayload, true) != 0) {
                    LogPrintf("SecMsgPow: Could not place message in buckets, message removed.\n");
                    continue;
                }
            }

            // Test if message was sent to self
            bool fOwnMessage;
            if (smsgModule.ScanMessage(pHeader, pPayload, psmsg->nPayload, true, fOwnMessage) != 0) {
                // Message recipient is not this node (or failed)
            }
        }

        delete it;

        // Shutdown thread waits 5 seconds, this should be less
        MilliSleep(2000);
    }
    return;
};

void AddOptions()
{
    gArgs.AddArg("-smsg", "Enable secure messaging. (default: true)", ArgsManager::ALLOW_ANY, OptionsCategory::SMSG);
    gArgs.AddArg("-smsgscanchain", "Scan the block chain for public key addresses on startup. (default: false)", ArgsManager::ALLOW_ANY, OptionsCategory::SMSG);
    gArgs.AddArg("-smsgscanincoming", "Scan incoming blocks for public key addresses. (default: false)", ArgsManager::ALLOW_ANY, OptionsCategory::SMSG);
    gArgs.AddArg("-smsgnotify=<cmd>", "Execute command when a message is received. (%s in cmd is replaced by receiving address)", ArgsManager::ALLOW_ANY, OptionsCategory::SMSG);
    gArgs.AddArg("-smsgsaddnewkeys", "Scan for incoming messages on new wallet keys. (default: false)", ArgsManager::ALLOW_ANY, OptionsCategory::SMSG);
    gArgs.AddArg("-smsgbantime=<n>", strprintf("Number of seconds to ignore misbehaving peers for (default: %u)", SMSG_DEFAULT_BANTIME), ArgsManager::ALLOW_ANY, OptionsCategory::SMSG);
    gArgs.AddArg("-smsgmaxreceive=<n>", strprintf("Max number of data messages to tolerate from peers, counter decreases over time (default: %u)", SMSG_DEFAULT_MAXRCV), ArgsManager::ALLOW_ANY, OptionsCategory::SMSG);
    gArgs.AddArg("-smsgsregtestadjust", "Adjust durations in regtest (default: true)", ArgsManager::ALLOW_ANY, OptionsCategory::HIDDEN);
    return;
};

const char *GetString(size_t errorCode)
{
    switch(errorCode) {
        case SMSG_UNKNOWN_VERSION:                      return "Unknown version";
        case SMSG_INVALID_ADDRESS:                      return "Invalid address";
        case SMSG_INVALID_ADDRESS_FROM:                 return "Invalid address from";
        case SMSG_INVALID_ADDRESS_TO:                   return "Invalid address to";
        case SMSG_INVALID_PUBKEY:                       return "Invalid public key";
        case SMSG_PUBKEY_MISMATCH:                      return "Public key does not match address";
        case SMSG_PUBKEY_EXISTS:                        return "Public key exists in database";
        case SMSG_PUBKEY_NOT_EXISTS:                    return "Public key not in database";
        case SMSG_KEY_EXISTS:                           return "Key exists in database";
        case SMSG_KEY_NOT_EXISTS:                       return "Key not in database";
        case SMSG_UNKNOWN_KEY:                          return "Unknown key";
        case SMSG_UNKNOWN_KEY_FROM:                     return "Unknown private key for from address";
        case SMSG_ALLOCATE_FAILED:                      return "Allocate failed";
        case SMSG_MAC_MISMATCH:                         return "MAC mismatch";
        case SMSG_WALLET_UNSET:                         return "Wallet unset";
        case SMSG_WALLET_NO_PUBKEY:                     return "Pubkey not found in wallet";
        case SMSG_WALLET_NO_KEY:                        return "Key not found in wallet";
        case SMSG_WALLET_LOCKED:                        return "Wallet is locked";
        case SMSG_DISABLED:                             return "SMSG is disabled";
        case SMSG_UNKNOWN_MESSAGE:                      return "Unknown Message";
        case SMSG_PAYLOAD_OVER_SIZE:                    return "Payload too large";
        case SMSG_TIME_IN_FUTURE:                       return "Timestamp is in the future";
        case SMSG_TIME_EXPIRED:                         return "Time to live expired";
        case SMSG_INVALID_HASH:                         return "Invalid hash";
        case SMSG_CHECKSUM_MISMATCH:                    return "Checksum mismatch";
        case SMSG_SHUTDOWN_DETECTED:                    return "Shutdown detected";
        case SMSG_MESSAGE_TOO_LONG:                     return "Message is too long";
        case SMSG_COMPRESS_FAILED:                      return "Compression failed";
        case SMSG_ENCRYPT_FAILED:                       return "Encryption failed";
        case SMSG_FUND_FAILED:                          return "Fund message failed";
        default:
            return "Unknown error";
    }
    return "No Error";
};

static void NotifyUnload(CSMSG *ps, CWallet *pw)
{
    LogPrintf("SMSG NotifyUnload\n");
    ps->WalletUnloaded(pw);
};

static void ListenWalletAdded(CSMSG *ps, const std::shared_ptr<CWallet>& wallet)
{
#ifdef ENABLE_WALLET
    LogPrintf("SMSG NotifyWalletAdded: %s\n", wallet->GetName());
    ps->LoadWallet(wallet);
#endif
};

int CSMSG::BuildBucketSet()
{
    /*
        Build the bucket set by scanning the files in the smsgstore dir.
        buckets should be empty
    */

    LogPrint(BCLog::SMSG, "%s\n", __func__);

    int64_t  now            = GetAdjustedTime();
    uint32_t nFiles         = 0;
    uint32_t nMessages      = 0;

    fs::path pathSmsgDir = GetDataDir() / STORE_DIR;
    fs::directory_iterator itend;

    if (!fs::exists(pathSmsgDir)
        || !fs::is_directory(pathSmsgDir)) {
        LogPrintf("Message store directory does not exist.\n");
        return SMSG_NO_ERROR; // not an error
    }

    for (fs::directory_iterator itd(pathSmsgDir); itd != itend; ++itd) {
        if (!fs::is_regular_file(itd->status())) {
            continue;
        }

        std::string fileType = itd->path().extension().string();

        if (fileType.compare(".dat") != 0) {
            continue;
        }

        nFiles++;
        std::string fileName = itd->path().filename().string();

        LogPrint(BCLog::SMSG, "Processing file: %s.\n", fileName);

        // TODO files must be split if > 2GB
        // time_noFile.dat
        size_t sep = fileName.find_first_of("_");
        if (sep == std::string::npos) {
            continue;
        }

        std::string stime = fileName.substr(0, sep);
        int64_t fileTime;
        if (!ParseInt64(stime, &fileTime)) {
            LogPrintf("%s: ParseInt64 failed %s.\n", __func__, stime);
            continue;
        }

        if (fileTime < now - SMSG_RETENTION) {
            LogPrintf("Dropping file %s, expired.\n", fileName);
            try {
                fs::remove(itd->path());
            } catch (const fs::filesystem_error &ex) {
                LogPrintf("Error removing bucket file %s, %s.\n", fileName, ex.what());
            }
            continue;
        }

        if (part::endsWith(fileName, "_wl.dat")) {
            LogPrint(BCLog::SMSG, "Skipping wallet locked file: %s.\n", fileName);
            continue;
        }

        size_t nTokenSetSize = 0;
        SecureMessage smsg;
        {
            LOCK(cs_smsg);

            SecMsgBucket &bucket = buckets[fileTime];
            std::set<SecMsgToken> &tokenSet = bucket.setTokens;

            FILE *fp;
            if (!(fp = fopen(itd->path().string().c_str(), "rb"))) {
                LogPrintf("Error opening file: %s\n", strerror(errno));
                continue;
            }

            for (;;) {
                long int ofs = ftell(fp);
                SecMsgToken token;
                token.offset = ofs;
                errno = 0;
                if (fread(smsg.data(), sizeof(uint8_t), SMSG_HDR_LEN, fp) != (size_t)SMSG_HDR_LEN) {
                    if (errno != 0) {
                        LogPrintf("fread header failed: %s\n", strerror(errno));
                    } else {
                        //LogPrintf("End of file.\n");
                    }
                    break;
                }
                token.timestamp = smsg.timestamp;
                token.ttl = smsg.version[0] == 0 && smsg.version[1] == 0 ? 0  // Purged message header
                    : smsg.m_ttl;
                token.m_changed = now - fileTime;
                if (smsg.m_ttl > 0 && (bucket.nLeastTTL == 0 || smsg.m_ttl < bucket.nLeastTTL)) {
                    bucket.nLeastTTL = smsg.m_ttl;
                }
                if (smsg.nPayload < 8) {
                    continue;
                }
                if (fread(token.sample, sizeof(uint8_t), 8, fp) != 8) {
                    LogPrintf("fread failed: %s\n", strerror(errno));
                    break;
                }
                if (fseek(fp, smsg.nPayload-8, SEEK_CUR) != 0) {
                    LogPrintf("fseek failed: %s.\n", strerror(errno));
                    break;
                }
                tokenSet.insert(token);
            }

            fclose(fp);
            bucket.hashBucket(fileTime);
            nTokenSetSize = tokenSet.size();
        } // cs_smsg

        nMessages += nTokenSetSize;
        LogPrint(BCLog::SMSG, "Bucket %d contains %u messages.\n", fileTime, nTokenSetSize);
    }

    LogPrintf("Processed %u files, loaded %u buckets containing %u messages.\n", nFiles, buckets.size(), nMessages);
    return SMSG_NO_ERROR;
};

int CSMSG::BuildPurgedSets()
{
    LogPrint(BCLog::SMSG, "%s\n", __func__);
    LOCK2(cs_smsg, cs_smsgDB);

    setPurged.clear();
    setPurgedTimestamps.clear();

    SecMsgDB db;
    if (!db.Open("cr+")) {
        return SMSG_GENERAL_ERROR;
    }

    int64_t now = GetTime();
    size_t nPurged = 0;
    uint8_t chKey[30];
    SecMsgPurged purged;
    leveldb::Iterator *it = db.pdb->NewIterator(leveldb::ReadOptions());
    while (db.NextPurged(it, DBK_PURGED_TOKEN, chKey, purged)) {
        if (purged.timepurged + 31 * SMSG_SECONDS_IN_DAY < now) {
            db.ErasePurged(chKey);
            continue;
        }
        setPurged.insert(purged);
        setPurgedTimestamps.insert(purged.timestamp);
        nPurged++;
    }
    delete it;

    LogPrint(BCLog::SMSG, "Loaded %u purged tokens from database.\n", nPurged);

    nLastProcessedPurged = now;

    return SMSG_NO_ERROR;
};

int CSMSG::AddWalletAddresses()
{
    LogPrint(BCLog::SMSG, "%s\n", __func__);

#ifdef ENABLE_WALLET
    if (!gArgs.GetBoolArg("-smsgsaddnewkeys", false)) {
        LogPrint(BCLog::SMSG, "%s smsgsaddnewkeys option is disabled.\n", __func__);
        return SMSG_NO_ERROR;
    }

    uint32_t nAdded = 0;
    for (const auto &pw : m_vpwallets) {
        LOCK(pw->cs_wallet);
        for (const auto &entry : pw->mapAddressBook) { // PAIRTYPE(CTxDestination, CAddressBookData)
            if (!pw->IsMine(entry.first)) {
                continue;
            }

            // TODO: skip addresses for stealth transactions
            CKeyID keyID;
            CBitcoinAddress coinAddress(entry.first);
            if (!coinAddress.IsValid()
                || !coinAddress.GetKeyID(keyID)) {
                continue;
            }

            bool fExists = false;
            for (std::vector<SecMsgAddress>::iterator it = addresses.begin(); it != addresses.end(); ++it) {
                if (keyID != it->address) {
                    continue;
                }
                fExists = true;
                break;
            }

            if (fExists) {
                continue;
            }

            bool recvEnabled    = true;
            bool recvAnon       = false;

            addresses.push_back(SecMsgAddress(keyID, recvEnabled, recvAnon));
            nAdded++;
        }
    }

    LogPrint(BCLog::SMSG, "Added %u addresses to whitelist.\n", nAdded);
#endif
    return SMSG_NO_ERROR;
};

int CSMSG::LoadKeyStore()
{
    LOCK(cs_smsgDB);

    SecMsgDB db;
    if (!db.Open("cr+")) {
        return SMSG_GENERAL_ERROR;
    }

    size_t nKeys = 0;
    CKeyID idk;
    SecMsgKey key;
    leveldb::Iterator *it = db.pdb->NewIterator(leveldb::ReadOptions());
    while (db.NextPrivKey(it, DBK_SECRETKEY, idk, key)) {
        if (!(key.nFlags & SMK_RECEIVE_ON)) {
            continue;
        }
        keyStore.AddKey(idk, key);
        nKeys++;
    }
    delete it;

    LogPrint(BCLog::SMSG, "Loaded %u keys from database.\n", nKeys);
    return SMSG_NO_ERROR;
};

int CSMSG::ReadIni()
{
    if (!fSecMsgEnabled) {
        return SMSG_DISABLED;
    }

    LogPrint(BCLog::SMSG, "%s\n", __func__);

    fs::path fullpath = GetDataDir() / "smsg.ini";

    FILE *fp;
    errno = 0;
    if (!(fp = fopen(fullpath.string().c_str(), "r"))) {
        return errorN(SMSG_GENERAL_ERROR, "%s: Error opening file: %s", __func__, strerror(errno));
    }

    char cLine[512];
    char *pName, *pValue, *token;

    char cAddress[64];
    int addrRecv, addrRecvAnon;

    while (fgets(cLine, 512, fp))  {
        cLine[strcspn(cLine, "\n")] = '\0';
        cLine[strcspn(cLine, "\r")] = '\0';
        cLine[511] = '\0'; // for safety

        // Check that line contains a name value pair and is not a comment, or section header
        if (cLine[0] == '#' || cLine[0] == '[' || strcspn(cLine, "=") < 1) {
            continue;
        }

        if (!(pName = strtok_r(cLine, "=", &token))
            || !(pValue = strtok_r(nullptr, "=", &token))) {
            continue;
        }

        if (strcmp(pName, "newAddressRecv") == 0) {
            options.fNewAddressRecv = (strcmp(pValue, "true") == 0) ? true : false;
        } else
        if (strcmp(pName, "newAddressAnon") == 0) {
            options.fNewAddressAnon = (strcmp(pValue, "true") == 0) ? true : false;
        } else
        if (strcmp(pName, "scanIncoming") == 0) {
            options.fScanIncoming = (strcmp(pValue, "true") == 0) ? true : false;
        } else
        if (strcmp(pName, "key") == 0) {
            int rv = sscanf(pValue, "%63[^|]|%d|%d", cAddress, &addrRecv, &addrRecvAnon);
            if (rv == 3) {
                CKeyID k;
                CBitcoinAddress(cAddress).GetKeyID(k);

                if (k.IsNull()) {
                    LogPrintf("Could not parse key line %s, rv %d.\n", pValue, rv);
                } else {
                    addresses.push_back(SecMsgAddress(k, addrRecv, addrRecvAnon));
                }
            } else {
                LogPrintf("Could not parse key line %s, rv %d.\n", pValue, rv);
            }
        } else {
            LogPrintf("Unknown setting name: '%s'.\n", pName);
        }
    }

    fclose(fp);
    LogPrintf("Loaded %u addresses.\n", addresses.size());
    return SMSG_NO_ERROR;
};

int CSMSG::WriteIni()
{
    if (!fSecMsgEnabled) {
        return SMSG_DISABLED;
    }

    LogPrint(BCLog::SMSG, "%s\n", __func__);

    fs::path fullpath = GetDataDir() / "smsg.ini~";

    FILE *fp;
    errno = 0;
    if (!(fp = fopen(fullpath.string().c_str(), "w"))) {
        return errorN(SMSG_GENERAL_ERROR, "%s: Error opening file: %s", __func__, strerror(errno));
    }

    if (fwrite("[Options]\n", sizeof(char), 10, fp) != 10) {
        LogPrintf("fwrite error: %s\n", strerror(errno));
        fclose(fp);
        return SMSG_GENERAL_ERROR;
    }

    if (fprintf(fp, "newAddressRecv=%s\n", options.fNewAddressRecv ? "true" : "false") < 0
        || fprintf(fp, "newAddressAnon=%s\n", options.fNewAddressAnon ? "true" : "false") < 0
        || fprintf(fp, "scanIncoming=%s\n", options.fScanIncoming ? "true" : "false") < 0) {
        LogPrintf("fprintf error: %s\n", strerror(errno));
        fclose(fp);
        return SMSG_GENERAL_ERROR;
    }

    if (fwrite("\n[Keys]\n", sizeof(char), 8, fp) != 8) {
        LogPrintf("fwrite error: %s\n", strerror(errno));
        fclose(fp);
        return SMSG_GENERAL_ERROR;
    }

    for (std::vector<SecMsgAddress>::iterator it = addresses.begin(); it != addresses.end(); ++it) {
        errno = 0;

        CBitcoinAddress cAddress(PKHash(it->address));

        if (!cAddress.IsValid()) {
            LogPrintf("%s: Error saving address - invalid.\n", __func__);
            continue;
        }

        if (fprintf(fp, "key=%s|%d|%d\n", cAddress.ToString().c_str(), it->fReceiveEnabled, it->fReceiveAnon) < 0) {
            LogPrintf("fprintf error: %s\n", strerror(errno));
            continue;
        }
    }

    fclose(fp);

    try {
        fs::path finalpath = GetDataDir() / "smsg.ini";
        fs::rename(fullpath, finalpath);
    } catch (const fs::filesystem_error &ex) {
        LogPrintf("Error renaming file %s, %s.\n", fullpath.string(), ex.what());
    }
    return SMSG_NO_ERROR;
};

bool CSMSG::Start(std::shared_ptr<CWallet> pwalletIn, std::vector<std::shared_ptr<CWallet>> &vpwallets, bool fScanChain)
{
    LogPrintf("Secure messaging starting.\n");

    if (fSecMsgEnabled) {
        return error("%s: Secure messaging is already started.", __func__);
    }
    if (Params().NetworkIDString() == "regtest" &&
        gArgs.GetArg("-smsgsregtestadjust", true)) {
        SMSG_SECONDS_IN_HOUR    = 60 * 2; // seconds
        SMSG_BUCKET_LEN         = 60 * 2; // seconds
        SMSG_SECONDS_IN_DAY     = 600;
        SMSG_MIN_TTL            = SMSG_SECONDS_IN_HOUR;
        SMSG_MAX_PAID_TTL       = SMSG_SECONDS_IN_DAY * 31;
        SMSG_MAX_FREE_TTL       = SMSG_MAX_PAID_TTL;
        SMSG_RETENTION          = SMSG_MAX_PAID_TTL;
        LogPrintf("Adjusted SMSG_SECONDS_IN_DAY to %d for regtest.\n", SMSG_SECONDS_IN_DAY);
    }

    m_smsg_max_receive_count = gArgs.GetArg("-smsgmaxreceive", SMSG_DEFAULT_MAXRCV);

#ifdef ENABLE_WALLET
    UnloadAllWallets();

    for (const auto &pw : vpwallets) {
        CHDWallet *const ppartw = GetParticlWallet(pw.get());
        if (!ppartw || !ppartw->m_smsg_enabled) {
            continue;
        }
        LoadWallet(pw);
    }
    SetActiveWallet(pwalletIn);
#endif

    fSecMsgEnabled = true;
    g_rpc_node->connman->SetLocalServices(ServiceFlags(g_rpc_node->connman->GetLocalServices() | NODE_SMSG));

    if (ReadIni() != 0) {
        LogPrintf("Failed to read smsg.ini\n");
    }

    if (addresses.size() < 1) {
        LogPrintf("No address keys loaded.\n");
        if (AddWalletAddresses() != 0) {
            LogPrintf("Failed to load addresses from wallet.\n");
        } else {
            LogPrintf("Loaded addresses from wallet.\n");
        }
    } else {
        LogPrintf("Loaded addresses from smsg.ini\n");
    }

    if (LoadKeyStore() != 0) {
        return error("%s: LoadKeyStore failed.", __func__);
    }

    if (secp256k1_context_smsg) {
        return error("%s: secp256k1_context_smsg already exists.", __func__);
    }

    if (!(secp256k1_context_smsg = secp256k1_context_create(SECP256K1_CONTEXT_SIGN))) {
        return error("%s: secp256k1_context_create failed.", __func__);
    }

    {
        // Pass in a random blinding seed to the secp256k1 context.
        std::vector<uint8_t, secure_allocator<uint8_t>> vseed(32);
        GetRandBytes(vseed.data(), 32);
        bool ret = secp256k1_context_randomize(secp256k1_context_smsg, vseed.data());
        assert(ret);
    }

    if (fScanChain) {
        ScanBlockChain();
    }

    if (BuildBucketSet() != 0) {
        Disable();
        return error("%s: Could not load bucket sets, secure messaging disabled.", __func__);
    }

    if (BuildPurgedSets() != 0) {
        Disable();
        return error("%s: Could not load purged sets, secure messaging disabled.", __func__);
    }

    start_time = GetAdjustedTime();

    threadGroupSmsg.create_thread(boost::bind(&TraceThread<void (*)()>, "smsg", &ThreadSecureMsg));
    threadGroupSmsg.create_thread(boost::bind(&TraceThread<void (*)()>, "smsg-pow", &ThreadSecureMsgPow));

#ifdef ENABLE_WALLET
    m_wallet_load_handler = interfaces::MakeHandler(NotifyWalletAdded.connect(boost::bind(&ListenWalletAdded, this, _1)));
#endif

    return true;
};

bool CSMSG::Shutdown()
{
    if (!fSecMsgEnabled) {
        return false;
    }

    LogPrintf("Stopping secure messaging.\n");

    if (WriteIni() != 0) {
        LogPrintf("Failed to save smsg.ini\n");
    }

    fSecMsgEnabled = false;
    g_rpc_node->connman->SetLocalServices(ServiceFlags(g_rpc_node->connman->GetLocalServices() & ~NODE_SMSG));

    threadGroupSmsg.interrupt_all();
    threadGroupSmsg.join_all();

    if (smsgDB) {
        LOCK(cs_smsgDB);
        delete smsgDB;
        smsgDB = nullptr;
    }

    keyStore.Clear();

    if (secp256k1_context_smsg) {
        secp256k1_context_destroy(secp256k1_context_smsg);
    }
    secp256k1_context_smsg = nullptr;

    UnloadAllWallets();
#ifdef ENABLE_WALLET
    if (m_wallet_load_handler) {
        m_wallet_load_handler->disconnect();
    }
#endif
    return true;
};

bool CSMSG::Enable(std::shared_ptr<CWallet> pactive_wallet, std::vector<std::shared_ptr<CWallet>> &vpwallets)
{
    // Start secure messaging at runtime
    if (fSecMsgEnabled) {
        LogPrintf("SecureMsgEnable: secure messaging is already enabled.\n");
        return false;
    }

    {
        LOCK(cs_smsg);

        addresses.clear(); // should be empty already
        buckets.clear(); // should be empty already

        if (!Start(pactive_wallet, vpwallets, false)) {
            return error("%s: SecureMsgStart failed.\n", __func__);
        }
    }

    // Ping each peer advertising smsg
    {
        LOCK(g_rpc_node->connman->cs_vNodes);
        for (auto *pnode : g_rpc_node->connman->vNodes) {
            if (!(pnode->GetLocalServices() & NODE_SMSG)) {
                continue;
            }
            g_rpc_node->connman->PushMessage(pnode,
                CNetMsgMaker(INIT_PROTO_VERSION).Make(SMSGMsgType::PING)); // smsgData.fEnabled will be set on receiving smsgPong response from peer
            g_rpc_node->connman->PushMessage(pnode,
                CNetMsgMaker(INIT_PROTO_VERSION).Make(SMSGMsgType::PONG)); // Send pong as have missed initial ping sent by peer when it connected
        }
    }

    LogPrintf("Secure messaging enabled.\n");
    return true;
};

bool CSMSG::Disable()
{
    // Stop secure messaging at runtime
    if (!fSecMsgEnabled) {
        return error("%s: Secure messaging is already disabled.", __func__);
    }

    {
        LOCK(cs_smsg);

        if (!Shutdown()) {
            return error("%s: SecureMsgShutdown failed.\n", __func__);
        }

        // Clear buckets
        std::map<int64_t, SecMsgBucket>::iterator it;
        for (it = buckets.begin(); it != buckets.end(); ++it) {
            it->second.setTokens.clear();
        }
        buckets.clear();
        addresses.clear();
    }

    // Tell each smsg enabled peer that this node is disabling
    {
        LOCK(g_rpc_node->connman->cs_vNodes);
        for (auto *pnode : g_rpc_node->connman->vNodes) {
            if (!pnode->smsgData.fEnabled) {
                continue;
            }
            LOCK(pnode->smsgData.cs_smsg_net);
            g_rpc_node->connman->PushMessage(pnode,
                CNetMsgMaker(INIT_PROTO_VERSION).Make(SMSGMsgType::DISABLED));
            pnode->smsgData.fEnabled = false;
        }
    }

    LogPrintf("Secure messaging disabled.\n");
    return true;
};

bool CSMSG::UnloadAllWallets()
{
#ifdef ENABLE_WALLET
    for (auto it = m_wallet_unload_handlers.begin(); it != m_wallet_unload_handlers.end(); ++it) {
        it->second->disconnect();
    }
    m_wallet_unload_handlers.clear();
    pactive_wallet.reset();
    m_vpwallets.clear();
#endif
    return true;
};

bool CSMSG::LoadWallet(std::shared_ptr<CWallet> pwallet_in)
{
#ifdef ENABLE_WALLET
    std::vector<std::shared_ptr<CWallet>>::iterator i = std::find(m_vpwallets.begin(), m_vpwallets.end(), pwallet_in);
    if (i != m_vpwallets.end()) return true;
    m_wallet_unload_handlers[pwallet_in.get()] = interfaces::MakeHandler(pwallet_in->NotifyUnload.connect(boost::bind(&NotifyUnload, this, pwallet_in.get())));
    m_vpwallets.push_back(pwallet_in);
#endif
    return true;
};

bool CSMSG::WalletUnloaded(CWallet *pwallet_removed)
{
    LOCK(cs_smsg);
    bool removed = false;
#ifdef ENABLE_WALLET
    if (pwallet_removed && pactive_wallet.get() == pwallet_removed) {
        SetActiveWallet(nullptr);
    }
    for (size_t i = 0; i < m_vpwallets.size(); ++i) {
        if (m_vpwallets[i].get() != pwallet_removed) {
            continue;
        }
        m_vpwallets.erase(m_vpwallets.begin() + i);
        removed = true;
        break;
    }
    auto it = m_wallet_unload_handlers.find(pwallet_removed);
    if (it != m_wallet_unload_handlers.end()) {
        it->second->disconnect();
        m_wallet_unload_handlers.erase(it);
    }
#endif
    return removed;
};

bool CSMSG::SetActiveWallet(std::shared_ptr<CWallet> pwallet_in)
{
#ifdef ENABLE_WALLET
    LOCK(cs_smsg);
    pactive_wallet.reset();

    if (pwallet_in) {
        pactive_wallet = pwallet_in;
        LoadWallet(pwallet_in);
        LogPrintf("Secure messaging using active wallet %s.\n", pactive_wallet->GetName());
    } else {
        LogPrintf("Secure messaging unset active wallet.\n");
    }
    return true;
#endif
    return false;
};

std::string CSMSG::GetWalletName()
{
#ifdef ENABLE_WALLET
    return pactive_wallet ? pactive_wallet->GetName() : "Not set.";
#endif
    return "Wallet Disabled.";
};

std::string CSMSG::LookupLabel(PKHash &hash)
{
#ifdef ENABLE_WALLET
    for (const auto &pw : m_vpwallets) {
        LOCK(pw->cs_wallet);
        auto mi(pw->mapAddressBook.find(hash));
        if (mi != pw->mapAddressBook.end()) {
            return mi->second.name;
        }
    }
#endif
    return "";
};

void CSMSG::GetNodesStats(int node_id, UniValue &result)
{
    LOCK(g_rpc_node->connman->cs_vNodes);
    for (auto *pnode : g_rpc_node->connman->vNodes) {
        if (node_id > -1 && node_id != pnode->GetId()) {
            continue;
        }
        LOCK(pnode->smsgData.cs_smsg_net);
        if (!pnode->smsgData.fEnabled) {
            continue;
        }
        UniValue obj(UniValue::VOBJ);
        obj.pushKV("id", pnode->GetId());
        obj.pushKV("address", pnode->GetAddrName());
        obj.pushKV("version", pnode->smsgData.m_version);
        obj.pushKV("ignoreuntil", pnode->smsgData.ignoreUntil);
        obj.pushKV("misbehaving", (int) pnode->smsgData.misbehaving);
        obj.pushKV("numwantsent", (int) pnode->smsgData.m_num_want_sent);
        obj.pushKV("receivecounter", (int) pnode->smsgData.m_receive_counter);
        obj.pushKV("ignoredcounter", (int) pnode->smsgData.m_ignored_counter);
        obj.pushKV("num_pending_inv", (int) pnode->smsgData.m_buckets.size());
        obj.pushKV("num_shown_buckets", (int) pnode->smsgData.m_buckets_last_shown.size());
        if (node_id > -1) {
            UniValue pending_inv_buckets(UniValue::VARR);
            for (auto it = pnode->smsgData.m_buckets.begin(); it != pnode->smsgData.m_buckets.end(); ++it) {
                UniValue bucket(UniValue::VOBJ);
                obj.pushKV("active", (int) it->second.m_active);
                obj.pushKV("hash", std::to_string(it->second.m_hash));
                pending_inv_buckets.push_back(bucket);
            }
            obj.pushKV("pending_inv_buckets", pending_inv_buckets);
            UniValue shown_buckets(UniValue::VARR);
            for (auto it = pnode->smsgData.m_buckets_last_shown.begin(); it != pnode->smsgData.m_buckets_last_shown.end(); ++it) {
                UniValue bucket(UniValue::VOBJ);
                obj.pushKV("time", it->first);
                obj.pushKV("last_shown", it->second);
                shown_buckets.push_back(bucket);
            }
            obj.pushKV("shown_buckets", shown_buckets);
        }

        result.push_back(obj);
    }
};

void CSMSG::ClearBanned()
{
    LOCK(g_rpc_node->connman->cs_vNodes);
    for (auto *pnode : g_rpc_node->connman->vNodes) {
        LOCK(pnode->smsgData.cs_smsg_net);
        if (!pnode->smsgData.fEnabled) {
            continue;
        }
        pnode->smsgData.ignoreUntil = 0;
        pnode->smsgData.misbehaving = 0;
    }
};

int CSMSG::ReceiveData(CNode *pfrom, const std::string &strCommand, CDataStream &vRecv)
{
    /*
        Called from ProcessMessage
        Runs in ThreadMessageHandler2
    */

    /*
        returns SecureMessageCodes

        TODO:
        Explain better and make use of better terminology such as
        Node A <-> Node B <-> Node C

        Commands
        + smsgInv =
            (1) received inventory of other node.
                (1.1) sanity checks
            (2) loop through buckets
                (2.1) sanity checks
                (2.2) check if bucket is locked to node C, if so continue but don't match. TODO: handle this properly, add critical section, lock on write. On read: nothing changes = no lock
                    (2.2.3) If our bucket is not locked to another node then add hash to buffer to be requested..
            (3) send smsgShow with list of hashes to request.

        + smsgShow =
            (1) received a list of requested bucket hashes which the other party does not have.
            (2) respond with smsgHave - contains all the message hashes within the requested buckets.
        + smsgHave =
            (1) A list of all the message hashes which a node has in response to smsgShow.
        + smsgWant =
            (1) A list of the message hashes that a node does not have and wants to retrieve from the node which sent smsgHave
        + smsgMsg =
            (1) In response to
        + smsgPing = ping request
        + smsgPong = pong response
    */

    if (LogAcceptCategory(BCLog::SMSG)) {
        LogPrintf("%s: %s %s.\n", __func__, pfrom->GetAddrName(), strCommand);
    }

    if (::ChainstateActive().IsInitialBlockDownload()) { // Wait until chain synced
        if (strCommand == SMSGMsgType::PING) {
            pfrom->smsgData.lastSeen = -1; // Mark node as requiring a response once chain is synced
        }
        return SMSG_NO_ERROR;
    }

    if (!fSecMsgEnabled) {
        if (strCommand == SMSGMsgType::PING) { // Ignore smsgPing
            return SMSG_NO_ERROR;
        }
        return SMSG_UNKNOWN_MESSAGE;
    }

    if (pfrom->nVersion < MIN_SMSG_PROTO_VERSION) {
        LogPrint(BCLog::SMSG, "Peer %d version %d too low.\n", pfrom->GetId(), pfrom->nVersion);
        return SMSG_NO_ERROR;
    }

    int64_t now = GetAdjustedTime();
    {
        LOCK(pfrom->smsgData.cs_smsg_net);

        if (pfrom->smsgData.m_receive_counter < m_smsg_max_receive_count) {
            pfrom->smsgData.m_receive_counter++;
        }

        if (now < pfrom->smsgData.ignoreUntil) {
            LogPrint(BCLog::SMSG, "Node is ignoring peer %d until %d.\n", pfrom->GetId(), pfrom->smsgData.ignoreUntil);
            return SMSG_GENERAL_ERROR;
        }

        if (pfrom->smsgData.m_receive_counter >= m_smsg_max_receive_count) {
            LogPrintf("Peer %d exceeded rate limit.\n", pfrom->GetId());
            pfrom->smsgData.m_ignored_counter += 1;
            // Try ignore peer for short periods before banning from smsg
            if (pfrom->smsgData.m_ignored_counter < 5) {
                pfrom->smsgData.ignoreUntil = GetTime() + SMSG_TIME_IGNORE;
            } else {
                SmsgMisbehaving(pfrom, 100);
            }
            return SMSG_GENERAL_ERROR;
        }
    }

    if (strCommand == SMSGMsgType::INV) {
        std::vector<uint8_t> vchData;
        vRecv >> vchData;

        if (vchData.size() < 4) {
            Misbehaving(pfrom->GetId(), 1);
            return SMSG_GENERAL_ERROR; // Not enough data received to be a valid smsgInv
        }

        uint32_t nLocked = 0;           // no. of locked buckets on this node
        uint32_t nInvBuckets;           // no. of bucket headers sent by peer in smsgInv
        memcpy(&nInvBuckets, &vchData[0], 4);
        if (LogAcceptCategory(BCLog::SMSG)) {
            LOCK(cs_smsg);
            LogPrintf("Peer %d sent %d bucket headers, this has %d.\n", pfrom->GetId(), nInvBuckets, buckets.size());
        }

        // Check no of buckets:
        if (nInvBuckets > (SMSG_RETENTION / SMSG_BUCKET_LEN) + 1) { // +1 for some leeway
            LogPrintf("Peer sent more bucket headers than possible %u, %u.\n", nInvBuckets, (SMSG_RETENTION / SMSG_BUCKET_LEN));
            SmsgMisbehaving(pfrom, 10);
            return SMSG_GENERAL_ERROR;
        }

        if (vchData.size() < 4 + nInvBuckets * 16) {
            LogPrintf("Peer did not send enough data.\n");
            SmsgMisbehaving(pfrom, 10);
            return SMSG_GENERAL_ERROR;
        }

        uint8_t *p = &vchData[4];
        for (uint32_t i = 0; i < nInvBuckets; ++i) {
            int64_t time;
            uint32_t ncontent, hash;
            memcpy(&time, p, 8);
            memcpy(&ncontent, p+8, 4);
            memcpy(&hash, p+12, 4);

            p += 16;

            // Check time valid:

            if (time % SMSG_BUCKET_LEN) {
                LogPrint(BCLog::SMSG, "Not a valid bucket time %d.\n", time);
                SmsgMisbehaving(pfrom, 10);
            }
            if (time < now - SMSG_RETENTION) {
                LogPrint(BCLog::SMSG, "Not interested in peer bucket %d, has expired.\n", time);

                if (time < now - SMSG_RETENTION - SMSG_TIME_LEEWAY) {
                    SmsgMisbehaving(pfrom, 1);
                }
                continue;
            }
            if (time > now + SMSG_TIME_LEEWAY) {
                LogPrint(BCLog::SMSG, "Not interested in peer bucket %d, in the future.\n", time);
                SmsgMisbehaving(pfrom, 1);
                continue;
            }

            if (ncontent < 1) {
                LogPrint(BCLog::SMSG, "Peer sent empty bucket, ignore %d %u %u.\n", time, ncontent, hash);
                continue;
            }

            {
                LOCK(cs_smsg);
                const auto it_lb = buckets.find(time);
                if (LogAcceptCategory(BCLog::SMSG)) {
                    LogPrintf("Peer bucket %d %u %u.\n", time, ncontent, hash);
                    if (it_lb != buckets.end()) {
                        LogPrintf("This bucket %d %u %u.\n", time, it_lb->second.setTokens.size(), it_lb->second.hash);
                    }
                }

                if (it_lb != buckets.end() && it_lb->second.nLockCount > 0) {
                    LogPrint(BCLog::SMSG, "Bucket is locked %u, waiting for peer %u to send data.\n", it_lb->second.nLockCount, it_lb->second.nLockPeerId);
                    nLocked++;
                    continue;
                }

                // If this node has more than the peer node, peer node will pull from this
                //  if then peer node has more this node will pull fom peer

                if (it_lb == buckets.end()
                    || it_lb->second.nActive < ncontent
                    || (it_lb->second.nActive == ncontent
                        && it_lb->second.hash != hash)) { // if same amount in buckets check hash
                        auto nv = PeerBucket(ncontent, hash);
                        auto ret = pfrom->smsgData.m_buckets.insert(std::pair<int64_t, PeerBucket>(time, nv));
                        if (!ret.second) {
                            ret.first->second = nv;
                        }
                }
            } // cs_smsg
        }
    } else
    if (strCommand == SMSGMsgType::SHOW) {
        std::vector<uint8_t> vchData;
        vRecv >> vchData;

        if (vchData.size() < 4) {
            return SMSG_GENERAL_ERROR;
        }

        uint32_t nBuckets;
        memcpy(&nBuckets, &vchData[0], 4);

        if (vchData.size() < 4 + nBuckets * 8) {
            return SMSG_GENERAL_ERROR;
        }

        LogPrint(BCLog::SMSG, "Peer %d requests contents of %u buckets.\n", pfrom->GetId(), nBuckets);

        std::map<int64_t, SecMsgBucket>::iterator itb;
        std::set<SecMsgToken>::iterator it;

        std::vector<uint8_t> vchDataOut;
        int64_t time;
        uint8_t *pIn = &vchData[4];
        for (uint32_t i = 0; i < nBuckets; ++i, pIn += 8) {
            memcpy(&time, pIn, 8);

            int64_t last_shown = 0;
            {
                LOCK(pfrom->smsgData.cs_smsg_net);
                auto it = pfrom->smsgData.m_buckets_last_shown.find(time);
                if (it != pfrom->smsgData.m_buckets_last_shown.end()) {
                    last_shown = it->second;
                }
            }

            {
                LOCK(cs_smsg);
                itb = buckets.find(time);
                if (itb == buckets.end()) {
                    LogPrint(BCLog::SMSG, "Don't have bucket %d.\n", time);
                    continue;
                }

                std::set<SecMsgToken> &tokenSet = itb->second.setTokens;

                try { vchDataOut.resize(8 + 16 * tokenSet.size());
                } catch (std::exception &e) {
                    LogPrintf("vchDataOut.resize %u threw: %s.\n", 8 + 16 * tokenSet.size(), e.what());
                    continue;
                }
                memcpy(&vchDataOut[0], &time, 8);

                int64_t now = GetAdjustedTime();
                size_t nMessages = 0;
                uint8_t *p = &vchDataOut[8];
                for (it = tokenSet.begin(); it != tokenSet.end(); ++it) {
                    if (it->timestamp + it->ttl < now) {
                        continue;
                    }
                    if (time + it->m_changed < last_shown) {
                        continue;
                    }
                    memcpy(p, &it->timestamp, 8);
                    memcpy(p+8, &it->sample, 8);

                    p += 16;
                    nMessages++;
                }
                if (nMessages != tokenSet.size()) {
                    try { vchDataOut.resize(8 + 16 * nMessages);
                    } catch (std::exception &e) {
                        LogPrintf("vchDataOut.resize %u threw: %s.\n", 8 + 16 * nMessages, e.what());
                        continue;
                    }
                }
            }
            {
                LOCK(pfrom->smsgData.cs_smsg_net);
                pfrom->smsgData.m_buckets_last_shown[time] = now;
            }

            g_rpc_node->connman->PushMessage(pfrom,
                CNetMsgMaker(INIT_PROTO_VERSION).Make(SMSGMsgType::HAVE, vchDataOut));
        }
    } else
    if (strCommand == SMSGMsgType::HAVE) {
        // Peer has these messages in bucket
        std::vector<uint8_t> vchData;
        vRecv >> vchData;

        if (vchData.size() < 8) {
            return SMSG_GENERAL_ERROR;
        }

        int n = (vchData.size() - 8) / 16;

        int64_t time;
        memcpy(&time, &vchData[0], 8);

        // Check time valid:
        int64_t now = GetAdjustedTime();
        if (time < now - SMSG_RETENTION) {
            LogPrint(BCLog::SMSG, "Not interested in peer %d bucket %d, has expired.\n", pfrom->GetId(), time);
            return SMSG_GENERAL_ERROR;
        }
        if (time > now + SMSG_TIME_LEEWAY) {
            LogPrint(BCLog::SMSG, "Not interested in peer %d bucket %d, in the future.\n", pfrom->GetId(), time);
            Misbehaving(pfrom->GetId(), 1);
            return SMSG_GENERAL_ERROR;
        }

        std::vector<uint8_t> vchDataOut;

        {
            LOCK(cs_smsg);
            m_show_requests.erase(time);

            if (pfrom->smsgData.m_num_want_sent >= MAX_WANT_SENT) {
                LogPrint(BCLog::SMSG, "Too many messages already requested from peer: %d, %d.\n", pfrom->GetId(), pfrom->smsgData.m_num_want_sent);
                return SMSG_NO_ERROR;
            }

            SecMsgBucket &bucket = buckets[time];
            if (bucket.nLockCount > 0) {
                LogPrint(BCLog::SMSG, "Bucket %d lock count %u, waiting for message data from peer %u.\n", time, bucket.nLockCount, bucket.nLockPeerId);
                return SMSG_GENERAL_ERROR;
            }

            LogPrint(BCLog::SMSG, "Sifting through bucket %d.\n", time);

            vchDataOut.resize(8);
            memcpy(&vchDataOut[0], &vchData[0], 8);

            std::set<SecMsgToken> &tokenSet = bucket.setTokens;
            SecMsgToken token;
            SecMsgPurged purgedToken;
            uint8_t *p = &vchData[8];

            for (int i = 0; i < n; ++i, p += 16) {
                memcpy(&token.timestamp, p, 8);
                memcpy(&token.sample, p+8, 8);

                if (setPurgedTimestamps.find(token.timestamp) != setPurgedTimestamps.end()) {
                    memcpy(&purgedToken.timestamp, p, 8);
                    memcpy(&purgedToken.sample, p+8, 8);
                    if (setPurged.find(purgedToken) != setPurged.end()) {
                        continue;
                    }
                }

                std::set<SecMsgToken>::const_iterator it = tokenSet.find(token);
                if (it == tokenSet.end()) {
                    int nd = vchDataOut.size();
                    try {
                        vchDataOut.resize(nd + 16);
                    } catch (std::exception &e) {
                        LogPrintf("vchDataOut.resize %d threw: %s.\n", nd + 16, e.what());
                        continue;
                    }

                    memcpy(&vchDataOut[nd], p, 16);
                }
            }

            if (vchDataOut.size() > 8) {
                size_t n_messages = (vchDataOut.size() - 8) / 16;
                pfrom->smsgData.m_num_want_sent += n_messages;
                if (LogAcceptCategory(BCLog::SMSG)) {
                    LogPrintf("Asking peer for %u messages.\n", n_messages);
                    LogPrintf("Locking bucket %u for peer %d.\n", time, pfrom->GetId());
                }
                bucket.nLockCount   = 3; // lock this bucket for at most 3 * SMSG_THREAD_DELAY seconds, unset when peer sends smsgMsg
                bucket.nLockPeerId  = pfrom->GetId();
                g_rpc_node->connman->PushMessage(pfrom,
                    CNetMsgMaker(INIT_PROTO_VERSION).Make(SMSGMsgType::WANT, vchDataOut));
            }
        } // cs_smsg
    } else
    if (strCommand == SMSGMsgType::WANT) {
        std::vector<uint8_t> vchData;
        vRecv >> vchData;

        if (vchData.size() < 8) {
            return SMSG_GENERAL_ERROR;
        }

        std::vector<uint8_t> vchOne, vchBunch;

        vchBunch.resize(4 + 8); // nMessages + bucketTime

        int n = (vchData.size() - 8) / 16;

        int64_t time;
        uint32_t nBunch = 0;
        memcpy(&time, &vchData[0], 8);

        {
            LOCK(cs_smsg);
            auto itb = buckets.find(time);
            if (itb == buckets.end()) {
                LogPrint(BCLog::SMSG, "Don't have bucket %d.\n", time);
                return SMSG_GENERAL_ERROR;
            }

            std::set<SecMsgToken> &tokenSet = itb->second.setTokens;
            std::set<SecMsgToken>::iterator it;
            SecMsgToken token;
            uint8_t *p = &vchData[8];
            for (int i = 0; i < n; ++i) {
                memcpy(&token.timestamp, p, 8);
                memcpy(&token.sample, p+8, 8);

                it = tokenSet.find(token);
                if (it == tokenSet.end()) {
                    LogPrint(BCLog::SMSG, "Don't have wanted message %d.\n", token.timestamp);
                } else {
                    token.offset = it->offset;

                    // Place in vchOne so if SecureMsgRetrieve fails it won't corrupt vchBunch
                    if (Retrieve(token, vchOne) != SMSG_NO_ERROR) {
                        LogPrintf("SecureMsgRetrieve failed %d.\n", token.timestamp);
                        continue;
                    }

                    if (nBunch >= MAX_BUNCH_MESSAGES
                        || vchBunch.size() + vchOne.size() >= MAX_BUNCH_BYTES) {
                        LogPrint(BCLog::SMSG, "Break bunch %u, %u.\n", nBunch, vchBunch.size());
                        break; // end here, peer will send more want messages if needed.
                    }
                    nBunch++;
                    vchBunch.insert(vchBunch.end(), vchOne.begin(), vchOne.end()); // append
                }
                p += 16;
            }
        } // cs_smsg

        if (nBunch > 0) {
            LogPrint(BCLog::SMSG, "Sending block of %u messages for bucket %d.\n", nBunch, time);

            memcpy(&vchBunch[0], &nBunch, 4);
            memcpy(&vchBunch[4], &time, 8);
            g_rpc_node->connman->PushMessage(pfrom,
                CNetMsgMaker(INIT_PROTO_VERSION).Make(SMSGMsgType::MSG, vchBunch));
        }
    } else
    if (strCommand == SMSGMsgType::MSG) {
        std::vector<uint8_t> vchData;
        vRecv >> vchData;

        LogPrint(BCLog::SMSG, "smsgMsg vchData.size() %u.\n", vchData.size());

        Receive(pfrom, vchData);
    } else
    if (strCommand == SMSGMsgType::PING) {
        // smsgPing is the initial message, send reply
        g_rpc_node->connman->PushMessage(pfrom,
            CNetMsgMaker(INIT_PROTO_VERSION).Make(SMSGMsgType::PONG, SMSG_VERSION));
    } else
    if (strCommand == SMSGMsgType::PONG) {
        LogPrint(BCLog::SMSG, "Peer replied, secure messaging enabled.\n");

        bool was_enabled = false;
        {
            LOCK(pfrom->smsgData.cs_smsg_net);
            was_enabled = pfrom->smsgData.fEnabled;
            pfrom->smsgData.fEnabled = true;

            if (vRecv.size() >= 4) {
                vRecv >> pfrom->smsgData.m_version;
            }
        }
        if (!was_enabled) {
            LOCK(pfrom->cs_vRecv);
            // Init counters
            size_t num_types = ARRAYLEN(SMSGMsgType::allTypes);
            for (size_t t = 0; t < num_types; ++t) {
                mapMsgCmdSize::iterator i = pfrom->mapRecvBytesPerMsgCmd.find(SMSGMsgType::allTypes[t]);
                if (i == pfrom->mapRecvBytesPerMsgCmd.end()) {
                    pfrom->mapRecvBytesPerMsgCmd[SMSGMsgType::allTypes[t]] = 0;
                }
            }
        }
    } else
    if (strCommand == SMSGMsgType::DISABLED) {
        LogPrint(BCLog::SMSG, "Peer %d has disabled secure messaging.\n", pfrom->GetId());

        {
            LOCK(pfrom->smsgData.cs_smsg_net);
            pfrom->smsgData.fEnabled = false;
        }
    } else
    if (strCommand == SMSGMsgType::IGNORING) {
        // Peer is reporting that it will ignore this node until time.
        //  Ignore peer too
        std::vector<uint8_t> vchData;
        vRecv >> vchData;

        if (vchData.size() < 8) {
            LogPrintf("smsgIgnore, not enough data %u.\n", vchData.size());
            Misbehaving(pfrom->GetId(), 1);
            return SMSG_GENERAL_ERROR;
        }

        int64_t time;
        memcpy(&time, &vchData[0], 8);

        {
            LOCK(pfrom->smsgData.cs_smsg_net);
            pfrom->smsgData.ignoreUntil = time;
        }

        LogPrint(BCLog::SMSG, "Peer %d is ignoring this node until %d, ignore peer too.\n", pfrom->GetId(), time);
    } else {
        return SMSG_UNKNOWN_MESSAGE;
    }

    return SMSG_NO_ERROR;
};

bool CSMSG::SendData(CNode *pto, bool fSendTrickle)
{
    /*
        Called from ProcessMessage
        Runs in ThreadMessageHandler2
    */

    if (::ChainstateActive().IsInitialBlockDownload()) { // Wait until chain synced
        return true;
    }

    LOCK(pto->smsgData.cs_smsg_net);

    int64_t now = GetTime();

    if (pto->smsgData.lastSeen <= 0) {
        // First contact
        LogPrint(BCLog::SMSG, "%s: New node %s, peer id %u.\n", __func__, pto->GetAddrName(), pto->GetId());
        // Send smsgPing once, do nothing until receive 1st smsgPong (then set fEnabled)
        g_rpc_node->connman->PushMessage(pto,
            CNetMsgMaker(INIT_PROTO_VERSION).Make(SMSGMsgType::PING));

        // Send smsgPong message if received smsgPing from peer while syncing chain
        if (pto->smsgData.lastSeen < 0) {
            g_rpc_node->connman->PushMessage(pto,
                CNetMsgMaker(INIT_PROTO_VERSION).Make(SMSGMsgType::PONG));
        }

        pto->smsgData.lastSeen = GetTime();
        return true;
    } else
    if (!pto->smsgData.fEnabled
        || now - pto->smsgData.lastSeen < SMSG_SEND_DELAY
        || now < pto->smsgData.ignoreUntil) {
        return true;
    }

    uint32_t nBucketsShown = 0;
    std::vector<uint8_t> vchData;
    {
        LOCK(cs_smsg);
        if (pto->smsgData.lastMatched <= m_last_changed) {

            std::map<int64_t, SecMsgBucket>::iterator it;

            /*
            Get time before loop and after looping through messages set nLastMatched to time before loop.
            This prevents scenario where:
                Loop()
                    message = locked and  thus skipped
                   message become free and nTimeChanged is updated
                End loop

                nLastMatched = GetTime()
                => bucket that became free in loop is now skipped :/

            Scenario 2:
                Same as one but time is updated before

                    bucket nTimeChanged is updated but not unlocked yet
                    now = GetTime()
                    Loop of buckets skips message
             */

            for (it = buckets.begin(); it != buckets.end(); ++it) {
                SecMsgBucket &bkt = it->second;

                uint32_t nMessages = bkt.nActive;

                if (bkt.timeChanged < pto->smsgData.lastMatched     // peer was last sent all buckets at time of lastMatched. It should have this bucket
                    || nMessages < 1) {                             // this bucket is empty
                    continue;
                }

                uint32_t hash = bkt.hash;

                if (LogAcceptCategory(BCLog::SMSG)) {
                    LogPrintf("Preparing bucket with hash %d for transfer to node %d. timeChanged=%d > lastMatched=%d\n", hash, pto->GetId(), bkt.timeChanged, pto->smsgData.lastMatched);
                }

                size_t sz = vchData.size();
                try { vchData.resize(sz + 16 + (sz == 0 ? 4 : 0)); } catch (std::exception& e) {
                    LogPrintf("vchData.resize %u threw: %s.\n", vchData.size() + 16 + (sz == 0 ? 4 : 0), e.what());
                    continue;
                }
                if (sz == 0) {
                    sz = 4;
                }

                uint8_t *p = &vchData[sz];
                memcpy(p, &it->first, 8);
                memcpy(p+8, &nMessages, 4);
                memcpy(p+12, &hash, 4);

                nBucketsShown++;
            }
        }
    }
    if (nBucketsShown > 0) {
        memcpy(&vchData[0], &nBucketsShown, 4);
        LogPrint(BCLog::SMSG, "Sending %d bucket headers.\n", nBucketsShown);

        g_rpc_node->connman->PushMessage(pto,
            CNetMsgMaker(INIT_PROTO_VERSION).Make(SMSGMsgType::INV, vchData));
        pto->smsgData.lastMatched = now;
    }
    if (vchData.size() > 0) {
        vchData.clear();
    }

    size_t nBucketsContestReq = 0;
    if (pto->smsgData.m_buckets.size() > 0) {
        LOCK(cs_smsg);
        for (auto it = pto->smsgData.m_buckets.begin(); it != pto->smsgData.m_buckets.end();) {
            if (nBucketsContestReq >= SMSG_MAX_SHOW) {
                 break;
            }

            const auto it_sr = m_show_requests.find(it->first);
            if (it_sr != m_show_requests.end() && it_sr->second > now) {
                ++it;
                continue; // Waiting for peer response
            }

            PeerBucket &bkt = it->second;
            const auto it_lb = buckets.find(it->first);

            if (it_lb == buckets.end()
                || (it_lb->second.nLockPeerId < 0 || it_lb->second.nLockPeerId == pto->GetId())) {
                if (it_lb != buckets.end() &&
                    (it_lb->second.nActive > bkt.m_active || (it_lb->second.nActive == bkt.m_active && it_lb->second.hash == bkt.m_hash))) {
                    LogPrint(BCLog::SMSG, "Not requesting list of bucket %d.\n", it->first);
                } else {
                    LogPrint(BCLog::SMSG, "Requesting list of bucket %d from peer %d.\n", it->first, pto->GetId());
                    size_t sz = vchData.size();
                    try { vchData.resize(sz + 8 + (sz == 0 ? 4 : 0)); } catch (std::exception& e) {
                        LogPrintf("vchData.resize %u threw: %s.\n", vchData.size() + 8 + (sz == 0 ? 4 : 0), e.what());
                        continue;
                    }
                    if (sz == 0) {
                        sz = 4;
                    }
                    memcpy(&vchData[sz], &it->first, 8);
                    nBucketsContestReq++;
                    m_show_requests[it->first] = now + 10;
                }
                pto->smsgData.m_buckets.erase(it++);
                continue;
            }
            ++it;
        }
    }
    if (nBucketsContestReq > 0) {
        memcpy(&vchData[0], &nBucketsContestReq, 4);
        g_rpc_node->connman->PushMessage(pto,
            CNetMsgMaker(INIT_PROTO_VERSION).Make(SMSGMsgType::SHOW, vchData));
    }

    pto->smsgData.lastSeen = now + GetRandInt(1);

    return true;
};

static int InsertAddress(CKeyID &hashKey, CPubKey &pubKey, SecMsgDB &addrpkdb)
{
    /*
    Insert key hash and public key to addressdb.

    (+) Called when receiving a message, it will automatically add the public key of the sender to our database so we can reply.

    Should have LOCK(cs_smsg) where db is opened

    returns SecureMessageCodes
    */

    if (addrpkdb.ExistsPK(hashKey)) {
        //LogPrintf("DB already contains public key for address.\n");
        CPubKey cpkCheck;
        if (!addrpkdb.ReadPK(hashKey, cpkCheck)) {
            LogPrintf("addrpkdb.Read failed.\n");
        } else {
            if (cpkCheck != pubKey) {
                LogPrintf("DB already contains existing public key that does not match .\n");
            }
        }
        return SMSG_PUBKEY_EXISTS;
    }

    if (!addrpkdb.WritePK(hashKey, pubKey)) {
        return errorN(SMSG_GENERAL_ERROR, "%s: Write pair failed.", __func__);
    }

    return SMSG_NO_ERROR;
};

static int InsertAddress(CKeyID &hashKey, CPubKey &pubKey)
{
    LOCK(cs_smsgDB);
    SecMsgDB addrpkdb;

    if (!addrpkdb.Open("cr+")) {
        return SMSG_GENERAL_ERROR;
    }

    return InsertAddress(hashKey, pubKey, addrpkdb);
};

static bool ScanBlock(CSMSG &smsg, const CBlock &block, SecMsgDB &addrpkdb,
    uint32_t &nTransactions, uint32_t &nElements, uint32_t &nPubkeys, uint32_t &nDuplicates)
{
    AssertLockHeld(cs_smsgDB);

    std::string reason;

    // Only scan inputs of standard txns and coinstakes
    for (const auto &tx : block.vtx) {
        // Harvest public keys from coinstake txns

        if (!tx->IsParticlVersion()) {
            continue;
        }

        for (const auto &txin : tx->vin) {
            if (txin.IsAnonInput()) {
                continue;
            }
            if (txin.scriptWitness.stack.size() != 2) {
                continue;
            }
            if (txin.scriptWitness.stack[1].size() != 33) {
                continue;
            }

            CPubKey pubKey(txin.scriptWitness.stack[1]);

            if (!pubKey.IsValid()
                || !pubKey.IsCompressed()) {
                LogPrintf("Public key is invalid %s.\n", HexStr(pubKey));
                continue;
            }

            CKeyID addrKey = pubKey.GetID();
            switch (InsertAddress(addrKey, pubKey, addrpkdb)) {
                case SMSG_NO_ERROR: nPubkeys++; break;          // added key
                case SMSG_PUBKEY_EXISTS: nDuplicates++; break;  // duplicate key
            }

            if (tx->IsCoinStake()) { // coinstake inputs are always from the same address/pubkey
                break;
            }
        }

        nTransactions++;

        if (nTransactions % 10000 == 0) { // for ScanChainForPublicKeys
            LogPrintf("Scanning transaction no. %u.\n", nTransactions);
        }
    }
    return true;
};


bool CSMSG::ScanBlock(const CBlock &block)
{
    // - scan block for public key addresses

    if (!options.fScanIncoming) {
        return true;
    }

    LogPrint(BCLog::SMSG, "%s.\n", __func__);

    uint32_t nTransactions  = 0;
    uint32_t nElements      = 0;
    uint32_t nPubkeys       = 0;
    uint32_t nDuplicates    = 0;

    {
        LOCK(cs_smsgDB);

        SecMsgDB addrpkdb;
        if (!addrpkdb.Open("cw")
            || !addrpkdb.TxnBegin()) {
            return false;
        }

        smsg::ScanBlock(*this, block, addrpkdb,
            nTransactions, nElements, nPubkeys, nDuplicates);

        addrpkdb.TxnCommit();
    } // cs_smsgDB

    LogPrint(BCLog::SMSG, "Found %u transactions, %u elements, %u new public keys, %u duplicates.\n", nTransactions, nElements, nPubkeys, nDuplicates);

    return true;
};

bool CSMSG::ScanChainForPublicKeys(CBlockIndex *pindexStart)
{
    LogPrintf("Scanning block chain for public keys.\n");
    int64_t nStart = GetTimeMillis();

    LogPrint(BCLog::SMSG, "From height %u.\n", pindexStart->nHeight);

    // Public keys are in txin.scriptSig
    //  matching addresses are in scriptPubKey of txin's referenced output

    uint32_t nBlocks        = 0;
    uint32_t nTransactions  = 0;
    uint32_t nInputs        = 0;
    uint32_t nPubkeys       = 0;
    uint32_t nDuplicates    = 0;

    {
        LOCK(cs_smsgDB);

        SecMsgDB addrpkdb;
        if (!addrpkdb.Open("cw")
            || !addrpkdb.TxnBegin()) {
            return false;
        }

        CBlockIndex *pindex = pindexStart;
        while (pindex) {
            nBlocks++;
            CBlock block;
            if (!ReadBlockFromDisk(block, pindex, Params().GetConsensus())) {
                LogPrintf("%s: ReadBlockFromDisk failed.\n", __func__);
            } else {
                smsg::ScanBlock(*this, block, addrpkdb,
                    nTransactions, nInputs, nPubkeys, nDuplicates);
            }

            pindex = ::ChainActive().Next(pindex);
        }

        addrpkdb.TxnCommit();
    } // cs_smsgDB

    LogPrintf("Scanned %u blocks, %u transactions, %u inputs\n", nBlocks, nTransactions, nInputs);
    LogPrintf("Found %u public keys, %u duplicates.\n", nPubkeys, nDuplicates);
    LogPrintf("Took %d ms\n", GetTimeMillis() - nStart);

    return true;
};

bool CSMSG::ScanBlockChain()
{
    TRY_LOCK(cs_main, lockMain);
    if (lockMain) {
        CBlockIndex *pindexScan = ::ChainActive().Genesis();
        if (pindexScan == nullptr) {
            return error("%s: pindexGenesisBlock not set.", __func__);
        }

        try { // In try to catch errors opening db,
            if (!ScanChainForPublicKeys(pindexScan)) {
                return false;
            }
        } catch (std::exception &e) {
            return error("%s: threw: %s.", __func__, e.what());
        }
    } else {
        return error("%s: Could not lock main.", __func__);
    }

    return true;
};

bool CSMSG::ScanBuckets(bool scan_all)
{
    LogPrint(BCLog::SMSG, "%s\n", __func__);

    if (!fSecMsgEnabled) {
        return error("%s: SMSG is disabled.\n", __func__);
    }

    int64_t  mStart         = GetTimeMillis();
    int64_t  now            = GetTime();
    uint32_t nFiles         = 0;
    uint32_t nMessages      = 0;
    uint32_t nFoundMessages = 0;

    fs::path pathSmsgDir = GetDataDir() / STORE_DIR;
    fs::directory_iterator itend;

    if (!fs::exists(pathSmsgDir)
        || !fs::is_directory(pathSmsgDir)) {
        LogPrintf("Message store directory does not exist.\n");
        return true; // not an error
    }

    SecureMessage smsg;
    std::vector<uint8_t> vchData;

    for (fs::directory_iterator itd(pathSmsgDir); itd != itend; ++itd) {
        if (!fs::is_regular_file(itd->status())) {
            continue;
        }

        std::string fileType = itd->path().extension().string();

        if (fileType.compare(".dat") != 0) {
            continue;
        }

        std::string fileName = itd->path().filename().string();

        LogPrint(BCLog::SMSG, "Processing file: %s.\n", fileName);
        nFiles++;

        // TODO files must be split if > 2GB
        // time_noFile.dat
        size_t sep = fileName.find_first_of("_");
        if (sep == std::string::npos) {
            continue;
        }

        std::string stime = fileName.substr(0, sep);
        int64_t fileTime;
        if (!ParseInt64(stime, &fileTime)) {
            LogPrintf("%s: ParseInt64 failed %s.\n", __func__, stime);
            continue;
        }

        if (fileTime < now - SMSG_RETENTION) {
            LogPrintf("Dropping file %s, expired.\n", fileName);
            try {
                fs::remove(itd->path());
            } catch (const fs::filesystem_error &ex) {
                LogPrintf("Error removing bucket file %s, %s.\n", fileName, ex.what());
            }
            continue;
        }

        if (part::endsWith(fileName, "_wl.dat")) {
            // ScanBuckets must be run with unlocked wallet (if any receiving keys are wallet keys), remove any redundant _wl files
            LogPrint(BCLog::SMSG, "Removing wallet locked file: %s.\n", fileName);
            try { fs::remove(itd->path());
            } catch (const fs::filesystem_error &ex) {
                LogPrintf("Error removing wallet locked file %s.\n", ex.what());
            }
            continue;
        }

        {
            LOCK(cs_smsg);
            FILE *fp;
            errno = 0;
            if (!(fp = fopen(itd->path().string().c_str(), "rb"))) {
                LogPrintf("Error opening file: %s\n", strerror(errno));
                continue;
            }

            for (;;) {
                errno = 0;
                if (fread(smsg.data(), sizeof(uint8_t), SMSG_HDR_LEN, fp) != (size_t)SMSG_HDR_LEN) {
                    if (errno != 0) {
                        LogPrintf("fread header failed: %s\n", strerror(errno));
                    } else {
                        //LogPrintf("End of file.\n");
                    }
                    break;
                }

                try { vchData.resize(smsg.nPayload); } catch (std::exception &e) {
                    LogPrintf("SecureMsgWalletUnlocked(): Could not resize vchData, %u, %s\n", smsg.nPayload, e.what());
                    fclose(fp);
                    return false;
                }

                if (fread(&vchData[0], sizeof(uint8_t), smsg.nPayload, fp) != smsg.nPayload) {
                    LogPrintf("fread data failed: %s\n", strerror(errno));
                    break;
                }

                if (smsg.version[0] == 0 && smsg.version[1] == 0) {
                    // Purged message header
                } else
                if (!scan_all && smsg.timestamp + smsg.m_ttl < now) {
                    // Expired message
                } else {
                    bool fOwnMessage;
                    int rv = ScanMessage(smsg.data(), &vchData[0], smsg.nPayload, false, fOwnMessage);
                    if (rv == SMSG_NO_ERROR) {
                        nFoundMessages++;
                    } else {
                        // SecureMsgScanMessage failed
                    }
                }
                nMessages++;
            }

            fclose(fp);
        } // cs_smsg
    }

    LogPrintf("Processed %u files, scanned %u messages, received %u messages.\n", nFiles, nMessages, nFoundMessages);
    LogPrintf("Took %d ms\n", GetTimeMillis() - mStart);

    return true;
}

int CSMSG::ManageLocalKey(CKeyID &keyId, ChangeType mode)
{
    // TODO: default recv and recvAnon
    {
        LOCK(cs_smsg);

        std::vector<SecMsgAddress>::iterator itFound = addresses.end();
        for (std::vector<SecMsgAddress>::iterator it = addresses.begin(); it != addresses.end(); ++it) {
            if (keyId != it->address) {
                continue;
            }
            itFound = it;
            break;
        }

        switch(mode) {
            case CT_REPLACE:
            case CT_NEW:
                if (itFound == addresses.end()) {
                    addresses.push_back(SecMsgAddress(keyId, options.fNewAddressRecv, options.fNewAddressAnon));
                } else {
                    LogPrint(BCLog::SMSG, "%s: Already have address: %s.\n", __func__, EncodeDestination(PKHash(keyId)));
                    return SMSG_KEY_EXISTS;
                }
                break;
            case CT_DELETED:
                if (itFound != addresses.end()) {
                    addresses.erase(itFound);
                } else {
                    return SMSG_KEY_NOT_EXISTS;
                }
                break;
            default:
                break;
        }
    } // cs_smsg

    return SMSG_NO_ERROR;
};

int CSMSG::WalletUnlocked(CWallet *pwallet)
{
#ifdef ENABLE_WALLET
    /*
    When the wallet is unlocked, scan messages received while wallet was locked.
    */
    if (!fSecMsgEnabled || m_vpwallets.size() < 1) {
        return SMSG_WALLET_UNSET;
    }

    LogPrintf("SecureMsgWalletUnlocked()\n");

    int64_t  now            = GetTime();
    uint32_t nFiles         = 0;
    uint32_t nMessages      = 0;
    uint32_t nFoundMessages = 0;

    fs::path pathSmsgDir = GetDataDir() / STORE_DIR;
    fs::directory_iterator itend;

    if (!fs::exists(pathSmsgDir)
        || !fs::is_directory(pathSmsgDir)) {
        LogPrintf("Message store directory does not exist.\n");
        return SMSG_NO_ERROR; // not an error
    }

    SecureMessage smsg;
    std::vector<uint8_t> vchData;

    for (fs::directory_iterator itd(pathSmsgDir); itd != itend; ++itd) {
        if (!fs::is_regular_file(itd->status())) {
            continue;
        }

        std::string fileName = itd->path().filename().string();

        if (!part::endsWith(fileName, "_wl.dat")) {
            continue;
        }

        LogPrint(BCLog::SMSG, "Processing file: %s.\n", fileName);

        nFiles++;

        // TODO files must be split if > 2GB
        // time_noFile_wl.dat
        size_t sep = fileName.find_first_of("_");
        if (sep == std::string::npos) {
            continue;
        }

        std::string stime = fileName.substr(0, sep);
        int64_t fileTime;
        if (!ParseInt64(stime, &fileTime)) {
            LogPrintf("%s: ParseInt64 failed %s.\n", __func__, stime);
            continue;
        }

        if (fileTime < now - SMSG_RETENTION) {
            LogPrintf("Dropping wallet locked file %s, expired.\n", fileName);
            try {
                fs::remove(itd->path());
            } catch (const fs::filesystem_error &ex) {
                return errorN(SMSG_GENERAL_ERROR, "%s: Could not remove file %s - %s.", __func__, fileName, ex.what());
            }
            continue;
        }

        bool remove_file = true;
        {
            LOCK(cs_smsg);
            FILE *fp;
            errno = 0;
            if (!(fp = fopen(itd->path().string().c_str(), "rb"))) {
                LogPrintf("Error opening file: %s\n", strerror(errno));
                continue;
            }

            for (;;) {
                errno = 0;
                if (fread(smsg.data(), sizeof(uint8_t), SMSG_HDR_LEN, fp) != (size_t)SMSG_HDR_LEN) {
                    if (errno != 0) {
                        LogPrintf("fread header failed: %s\n", strerror(errno));
                    } else {
                        //LogPrintf("End of file.\n");
                    }
                    break;
                }

                try { vchData.resize(smsg.nPayload); } catch (std::exception &e) {
                    LogPrintf("%s: Could not resize vchData, %u, %s\n", __func__, smsg.nPayload, e.what());
                    fclose(fp);
                    return SMSG_GENERAL_ERROR;
                }

                if (fread(&vchData[0], sizeof(uint8_t), smsg.nPayload, fp) != smsg.nPayload) {
                    LogPrintf("fread data failed: %s\n", strerror(errno));
                    break;
                }

                if (now > smsg.timestamp + smsg.m_ttl) {
                    LogPrint(BCLog::SMSG, "Time expired %d, ttl %d.\n", smsg.timestamp, smsg.m_ttl);
                    continue;
                }

                // Don't report to gui,
                bool fOwnMessage;
                int rv = ScanMessage(smsg.data(), &vchData[0], smsg.nPayload, false, fOwnMessage, true);
                if (rv == 0) {
                    nFoundMessages++;
                } else
                if (rv == SMSG_WALLET_LOCKED) {
                    remove_file = false;
                } else {
                    // SecureMsgScanMessage failed
                }

                nMessages++;
            }

            fclose(fp);

            // Remove wl file when scanned
            if (remove_file) {
                try {
                    fs::remove(itd->path());
                } catch (const fs::filesystem_error &ex) {
                    return errorN(SMSG_GENERAL_ERROR, "%s: Could not remove file %s - %s.", __func__, fileName, ex.what());
                }
            }
        } // cs_smsg
    }

    LogPrintf("Processed %u files, scanned %u messages, received %u messages.\n", nFiles, nMessages, nFoundMessages);

    // Notify gui
    NotifySecMsgWalletUnlocked();
#endif
    return SMSG_NO_ERROR;
};

int CSMSG::WalletKeyChanged(CKeyID &keyId, const std::string &sLabel, ChangeType mode)
{
    /*
    SecureMsgWalletKeyChanged():
    When a key changes in the wallet, this function should be called to update the addresses vector.

    mode:
        CT_NEW : a new key was added
        CT_DELETED : delete an existing key from vector.
    */

    if (!fSecMsgEnabled) {
        return SMSG_DISABLED;
    }

    LogPrintf("%s\n", __func__);

    if (!gArgs.GetBoolArg("-smsgsaddnewkeys", false)) {
        LogPrint(BCLog::SMSG, "%s smsgsaddnewkeys option is disabled.\n", __func__);
        return SMSG_GENERAL_ERROR;
    }

    return ManageLocalKey(keyId, mode);
};

int CSMSG::ScanMessage(const uint8_t *pHeader, const uint8_t *pPayload, uint32_t nPayload, bool reportToGui, bool &fOwnMessage, bool unlocking)
{
    LogPrint(BCLog::SMSG, "%s\n", __func__);
    /*
    Check if message belongs to this node.
    If so add to inbox db.

    if !reportToGui don't fire NotifySecMsgInboxChanged
     - loads messages received when wallet locked in bulk.

    returns SecureMessageCodes
    */

    fOwnMessage = false;
    MessageData msg; // placeholder
    CKeyID addressTo;
    for (auto &p : smsgModule.keyStore.mapKeys) {
        auto &address = p.first;
        auto &key = p.second;

        if (!(key.nFlags & SMK_RECEIVE_ON)) {
            continue;
        }

        if (!(key.nFlags & SMK_RECEIVE_ANON)) {
            // Have to do full decrypt to see address from
            if (Decrypt(false, key.key, address, pHeader, pPayload, nPayload, msg) == 0) {
                if (LogAcceptCategory(BCLog::SMSG)) {
                    LogPrintf("Decrypted message with %s.\n", EncodeDestination(PKHash(addressTo)));
                }
                if (msg.sFromAddress.compare("anon") != 0) {
                    fOwnMessage = true;
                }
                addressTo = address;
                break;
            }
        } else {
            if (Decrypt(true, key.key, address, pHeader, pPayload, nPayload, msg) == 0) {
                if (LogAcceptCategory(BCLog::SMSG)) {
                    LogPrintf("Decrypted message with %s.\n", EncodeDestination(PKHash(addressTo)));
                }
                fOwnMessage = true;
                addressTo = address;
                break;
            }
        }
    }

    bool was_locked = false;
    if (!fOwnMessage) {
#ifdef ENABLE_WALLET

        for (std::vector<SecMsgAddress>::iterator it = addresses.begin(); it != addresses.end(); ++it) {
            if (!it->fReceiveEnabled) {
                continue;
            }

            addressTo = it->address;

            CKey keyDest;
            for (const auto &pw : m_vpwallets) {
                if (pw->IsLocked()) {
                    if (pw->HaveKey(addressTo)) {
                        was_locked = true;
                    }
                    continue;
                }
                if (pw->GetKey(addressTo, keyDest)) {
                    break;
                }
            }
            if (!keyDest.IsValid()) {
                continue;
            }

            if (!it->fReceiveAnon) {
                // Have to do full decrypt to see address from
                if (Decrypt(false, keyDest, addressTo, pHeader, pPayload, nPayload, msg) == 0) {
                    if (LogAcceptCategory(BCLog::SMSG)) {
                        LogPrintf("Decrypted message with %s.\n", EncodeDestination(PKHash(addressTo)));
                    }
                    if (msg.sFromAddress.compare("anon") != 0) {
                        fOwnMessage = true;
                    }
                    break;
                }
            } else {
                if (Decrypt(true, keyDest, addressTo, pHeader, pPayload, nPayload, msg) == 0) {
                    if (LogAcceptCategory(BCLog::SMSG)) {
                        LogPrintf("Decrypted message with %s.\n", EncodeDestination(PKHash(addressTo)));
                    }
                    fOwnMessage = true;
                    break;
                }
            }
        }
#endif
    }

    if (!fOwnMessage && was_locked && !unlocking) {
        LogPrint(BCLog::SMSG, "%s: Wallet is locked, storing message to scan later.\n", __func__);
        // Only save unscanned if there are addresses
        // was_locked will onlye be set if addresses.size() > 0
        int rv;
        if ((rv = StoreUnscanned(pHeader, pPayload, nPayload)) != 0) {
            return SMSG_GENERAL_ERROR;
        }
        return SMSG_WALLET_LOCKED;
    }

    if (fOwnMessage) {
        // Save to inbox
        SecureMessage *psmsg = (SecureMessage*) pHeader;

        uint160 hash;
        HashMsg(*psmsg, pPayload, nPayload-(psmsg->IsPaidVersion() ? 32 : 0), hash);

        uint8_t chKey[30];
        int64_t timestamp_be = bswap_64(psmsg->timestamp);
        memcpy(&chKey[0], DBK_INBOX.data(), 2);
        memcpy(&chKey[2], &timestamp_be, 8);
        memcpy(&chKey[10], hash.begin(), 20);

        SecMsgStored smsgInbox;
        smsgInbox.timeReceived  = GetTime();
        smsgInbox.status        = (SMSG_MASK_UNREAD) & 0xFF;
        smsgInbox.addrTo        = addressTo;

        try { smsgInbox.vchMessage.resize(SMSG_HDR_LEN + nPayload); } catch (std::exception &e) {
            return errorN(SMSG_ALLOCATE_FAILED, "%s: Could not resize vchData, %u, %s.", __func__, SMSG_HDR_LEN + nPayload, e.what());
        }
        memcpy(&smsgInbox.vchMessage[0], pHeader, SMSG_HDR_LEN);
        memcpy(&smsgInbox.vchMessage[SMSG_HDR_LEN], pPayload, nPayload);

        bool fExisted = false;
        {
            LOCK(cs_smsgDB);
            SecMsgDB dbInbox;

            if (dbInbox.Open("cw")) {
                if (dbInbox.ExistsSmesg(chKey)) {
                    fExisted = true;
                    LogPrint(BCLog::SMSG, "Message already exists in inbox db.\n");
                } else {
                    dbInbox.WriteSmesg(chKey, smsgInbox);
                    if (reportToGui) {
                        NotifySecMsgInboxChanged(smsgInbox);
                    }
                    LogPrintf("SecureMsg saved to inbox, received with %s.\n", EncodeDestination(PKHash(addressTo)));
                }
            }
        } // cs_smsgDB

        if (!fExisted) {
            // notify an external script when a message comes in
            std::string strCmd = gArgs.GetArg("-smsgnotify", "");

            //TODO: Format message
            if (!strCmd.empty()) {
                boost::replace_all(strCmd, "%s", EncodeDestination(PKHash(addressTo)));
                std::thread t(runCommand, strCmd);
                t.detach(); // thread runs free
            }

            GetMainSignals().NewSecureMessage(psmsg, hash);
        }
    }

    return SMSG_NO_ERROR;
};

int CSMSG::GetLocalKey(const CKeyID &ckid, CPubKey &cpkOut)
{
    if (keyStore.GetPubKey(ckid, cpkOut)) {
        return SMSG_NO_ERROR;
    }

#ifdef ENABLE_WALLET
    for (const auto &pw : m_vpwallets) {
        if (pw->GetPubKey(ckid, cpkOut) && cpkOut.IsValid()) {
            return SMSG_NO_ERROR;
        }
    }
#endif

    return SMSG_WALLET_NO_PUBKEY;
};

int CSMSG::GetLocalKey(const CKeyID &key_id, CKey &key_out)
{
    if (keyStore.GetKey(key_id, key_out)) {
        return SMSG_NO_ERROR;
    }

#ifdef ENABLE_WALLET
    for (const auto &pw : m_vpwallets) {
        if (pw->IsLocked()) {
            continue;
        }
        if (pw->GetKey(key_id, key_out)) {
            return SMSG_NO_ERROR;
        }
    }
#endif

    return SMSG_WALLET_NO_KEY;
};

int CSMSG::GetLocalPublicKey(const std::string &strAddress, std::string &strPublicKey)
{
    // returns SecureMessageCodes

    CBitcoinAddress address;
    CKeyID keyID;
    if (!address.SetString(strAddress) || !address.GetKeyID(keyID)) {
        return SMSG_INVALID_ADDRESS;
    }

    int rv;
    CPubKey pubKey;
    if ((rv = GetLocalKey(keyID, pubKey)) != 0) {
        return rv;
    }

    strPublicKey = EncodeBase58(pubKey.begin(), pubKey.end());
    return SMSG_NO_ERROR;
};

int CSMSG::GetStoredKey(const CKeyID &ckid, CPubKey &cpkOut)
{
    /* returns SecureMessageCodes
    */
    LogPrint(BCLog::SMSG, "%s\n", __func__);

    {
        LOCK(cs_smsgDB);
        SecMsgDB addrpkdb;

        if (!addrpkdb.Open("r")) {
            return SMSG_GENERAL_ERROR;
        }

        if (!addrpkdb.ReadPK(ckid, cpkOut)) {
            //LogPrintf("addrpkdb.Read failed: %s.\n", coinAddress.ToString());
            return SMSG_PUBKEY_NOT_EXISTS;
        }
    } // cs_smsgDB

    return SMSG_NO_ERROR;
};

int CSMSG::AddAddress(std::string &address, std::string &publicKey)
{
    /*
    Add address and matching public key to the database
    address and publicKey are in base58

    returns SecureMessageCodes
    */

    CBitcoinAddress coinAddress(address);
    if (!coinAddress.IsValid()) {
        return errorN(SMSG_INVALID_ADDRESS, "%s - Address is not valid: %s.", __func__, address);
    }

    CKeyID idk;
    if (!coinAddress.GetKeyID(idk)) {
        return errorN(SMSG_INVALID_ADDRESS, "%s - coinAddress.GetKeyID failed: %s.", __func__, address);
    }

    std::vector<uint8_t> vchTest;

    if (IsHex(publicKey)) {
       vchTest = ParseHex(publicKey);
    } else {
        if (!DecodeBase58(publicKey, vchTest)) {
            return errorN(SMSG_INVALID_PUBKEY, "%s - Invalid PubKey.", __func__);
        }
    }

    CPubKey pubKey(vchTest);
    if (!pubKey.IsValid()) {
        return errorN(SMSG_INVALID_PUBKEY, "%s - Invalid PubKey.", __func__);
    }

    // Check that public key matches address hash
    CKeyID keyIDT = pubKey.GetID();
    if (idk != keyIDT) {
        return errorN(SMSG_PUBKEY_MISMATCH, "%s - Public key does not hash to address %s.", __func__, address);
    }

    return InsertAddress(idk, pubKey);
};

int CSMSG::AddLocalAddress(const std::string &sAddress)
{
#ifdef ENABLE_WALLET
    LogPrintf("%s: %s\n", __func__, sAddress);

    CBitcoinAddress addr(sAddress);
    if (!addr.IsValid(CChainParams::PUBKEY_ADDRESS)) {
        return errorN(SMSG_INVALID_ADDRESS, "%s - Address is not valid: %s.", __func__, sAddress);
    }

    CKeyID idk;
    if (!addr.GetKeyID(idk)) {
        return errorN(SMSG_INVALID_ADDRESS, "%s - GetKeyID failed: %s.", __func__, sAddress);
    }

    bool have_key = false;
    for (const auto &pw : m_vpwallets) {
        if (pw->HaveKey(idk)) {
            have_key = true;
            break;
        }
    }

    if (!have_key) {
        return errorN(SMSG_WALLET_NO_KEY, "%s: Key to %s not found in wallets.", __func__, sAddress);
    }

    return ManageLocalKey(idk, CT_NEW);
#else
    return SMSG_WALLET_UNSET;
#endif
};

int CSMSG::ImportPrivkey(const CBitcoinSecret &vchSecret, const std::string &sLabel)
{
    SecMsgKey key;
    key.key = vchSecret.GetKey();
    key.sLabel = sLabel;
    CKeyID idk = key.key.GetPubKey().GetID();
    key.nFlags |= SMK_RECEIVE_ON;
    key.nFlags |= SMK_RECEIVE_ANON;

    LOCK(cs_smsgDB);

    SecMsgDB db;
    if (!db.Open("cr+")) {
        return SMSG_GENERAL_ERROR;
    }

    if (!db.WriteKey(idk, key)) {
        return errorN(SMSG_GENERAL_ERROR, "%s - WriteKey failed.", __func__);
    }

    keyStore.AddKey(idk, key);

    return SMSG_NO_ERROR;
};

int CSMSG::DumpPrivkey(const CKeyID &idk, CKey &key_out)
{
    LOCK(cs_smsgDB);

    SecMsgDB db;
    if (!db.Open("cr+")) {
        return SMSG_GENERAL_ERROR;
    }

    SecMsgKey key;
    if (!db.ReadKey(idk, key)) {
        return 1;
    }

    key_out = key.key;

    return SMSG_NO_ERROR;
};

bool CSMSG::SetWalletAddressOption(const CKeyID &idk, std::string sOption, bool fValue)
{
    std::vector<smsg::SecMsgAddress>::iterator it;
    for (it = addresses.begin(); it != addresses.end(); ++it) {
        if (idk != it->address) {
            continue;
        }
        break;
    }

    if (it == addresses.end()) {
        return false;
    }

    if (sOption == "anon") {
        it->fReceiveAnon = fValue;
    } else
    if (sOption == "receive") {
        it->fReceiveEnabled = fValue;
    } else {
        return error("%s: Unknown option %s.\n", __func__, sOption);
    }

    return true;
};

bool CSMSG::SetSmsgAddressOption(const CKeyID &idk, std::string sOption, bool fValue)
{
    LOCK(cs_smsgDB);

    SecMsgDB db;
    if (!db.Open("cr+")) {
        return error("%s: Failed to open db.\n", __func__);
    }

    SecMsgKey key;
    if (!db.ReadKey(idk, key)) {
        return false;
    }

    if (sOption == "anon") {
        if (fValue) {
            key.nFlags |= SMK_RECEIVE_ANON;
        } else {
            key.nFlags &= ~SMK_RECEIVE_ANON;
        }
    } else
    if (sOption == "receive") {
        if (fValue) {
            key.nFlags |= SMK_RECEIVE_ON;
        } else {
            key.nFlags &= ~SMK_RECEIVE_ON;
        }
    } else {
        return error("%s: Unknown option %s.\n", __func__, sOption);
    }

    if (!db.WriteKey(idk, key)) {
        return false;
    }

    if (key.nFlags & SMK_RECEIVE_ON) {
        keyStore.AddKey(idk, key);
    } else {
        keyStore.EraseKey(idk);
    }

    return true;
};

int CSMSG::ReadSmsgKey(const CKeyID &idk, CKey &key)
{
    LOCK(cs_smsgDB);

    SecMsgDB db;
    if (!db.Open("cr+")) {
        return SMSG_GENERAL_ERROR;
    }

    SecMsgKey smk;
    if (!db.ReadKey(idk, smk)) {
        return SMSG_KEY_NOT_EXISTS;
    }

    key = smk.key;

    return SMSG_NO_ERROR;
};

int CSMSG::Retrieve(const SecMsgToken &token, std::vector<uint8_t> &vchData)
{
    LogPrint(BCLog::SMSG, "%s: %d.\n", __func__, token.timestamp);
    AssertLockHeld(cs_smsg);

    fs::path pathSmsgDir = GetDataDir() / STORE_DIR;

    int64_t bucket = token.timestamp - (token.timestamp % SMSG_BUCKET_LEN);
    std::string fileName = std::to_string(bucket) + "_01.dat";
    fs::path fullpath = pathSmsgDir / fileName;

    FILE *fp;
    errno = 0;
    if (!(fp = fopen(fullpath.string().c_str(), "rb"))) {
        return errorN(SMSG_GENERAL_ERROR, "%s - Can't open file: %s\nPath %s.", __func__, strerror(errno), fullpath.string());
    }

    errno = 0;
    if (fseek(fp, token.offset, SEEK_SET) != 0) {
        fclose(fp);
        return errorN(SMSG_GENERAL_ERROR, "%s - fseek, strerror: %s.", __func__, strerror(errno));
    }

    SecureMessage smsg;
    errno = 0;
    if (fread(smsg.data(), sizeof(uint8_t), SMSG_HDR_LEN, fp) != (size_t)SMSG_HDR_LEN) {
        fclose(fp);
        return errorN(SMSG_GENERAL_ERROR, "%s - read header failed, strerror: %s.", __func__, strerror(errno));
    }

    try {vchData.resize(SMSG_HDR_LEN + smsg.nPayload);} catch (std::exception &e) {
        fclose(fp);
        return errorN(SMSG_ALLOCATE_FAILED, "%s - Could not resize vchData, %u, %s.", __func__, SMSG_HDR_LEN + smsg.nPayload, e.what());
    }

    memcpy(vchData.data(), smsg.data(), SMSG_HDR_LEN);
    errno = 0;
    if (fread(&vchData[SMSG_HDR_LEN], sizeof(uint8_t), smsg.nPayload, fp) != smsg.nPayload) {
        fclose(fp);
        return errorN(SMSG_GENERAL_ERROR, "%s - fread data failed: %s. Wanted %u bytes.", __func__, strerror(errno), smsg.nPayload);
    }

    fclose(fp);
    return SMSG_NO_ERROR;
};

int CSMSG::Remove(const SecMsgToken &token)
{
    LogPrint(BCLog::SMSG, "%s: %d.\n", __func__, token.timestamp);
    AssertLockHeld(cs_smsg);

    fs::path pathSmsgDir = GetDataDir() / STORE_DIR;

    int64_t bucket = token.timestamp - (token.timestamp % SMSG_BUCKET_LEN);
    std::string fileName = std::to_string(bucket) + "_01.dat";
    fs::path fullpath = pathSmsgDir / fileName;

    FILE *fp;
    errno = 0;
    if (!(fp = fopen(fullpath.string().c_str(), "rb+"))) {
        return errorN(SMSG_GENERAL_ERROR, "%s - Can't open file: %s\nPath %s.", __func__, strerror(errno), fullpath.string());
    }

    errno = 0;
    if (fseek(fp, token.offset, SEEK_SET) != 0) {
        fclose(fp);
        return errorN(SMSG_GENERAL_ERROR, "%s - fseek, strerror: %s.", __func__, strerror(errno));
    }

    SecureMessage smsg;
    errno = 0;
    if (fread(smsg.data(), sizeof(uint8_t), SMSG_HDR_LEN, fp) != (size_t)SMSG_HDR_LEN) {
        fclose(fp);
        return errorN(SMSG_GENERAL_ERROR, "%s - read header failed, strerror: %s.", __func__, strerror(errno));
    }

    uint16_t z = 0;
    if (0 != fseek(fp, token.offset + 4, SEEK_SET)
        || 2 != fwrite(&z, 1, 2, fp)) {
        fclose(fp);
        return errorN(SMSG_GENERAL_ERROR, "%s - zero version strerror: %s.", __func__, strerror(errno));
    }

    if (fseek(fp, token.offset + SMSG_HDR_LEN + 8, SEEK_SET) != 0) {
        fclose(fp);
        return errorN(SMSG_GENERAL_ERROR, "%s - fseek, strerror: %s.", __func__, strerror(errno));
    }

    size_t zlen = smsg.nPayload - 8;
    std::vector<uint8_t> zbuf;
    zbuf.resize(zlen);
    memset(zbuf.data(), 0, zlen);
    if (smsg.nPayload <= 8 ||  zlen != fwrite(zbuf.data(), 1, zlen, fp)) {
        fclose(fp);
        return errorN(SMSG_GENERAL_ERROR, "%s - fwrite, zlen %d, strerror: %s.", __func__, zlen, strerror(errno));
    }

    fclose(fp);
    return SMSG_NO_ERROR;
};

int CSMSG::SmsgMisbehaving(CNode *pfrom, uint8_t n)
{
    LOCK(pfrom->smsgData.cs_smsg_net);
    pfrom->smsgData.misbehaving += n;
    LogPrintf("SmsgMisbehaving peer %d, %d.\n", pfrom->GetId(), pfrom->smsgData.misbehaving);

    if (pfrom->smsgData.misbehaving > 100) {
        pfrom->smsgData.misbehaving = 0;
        pfrom->smsgData.ignoreUntil = GetTime() + gArgs.GetArg("-smsgbantime", SMSG_DEFAULT_BANTIME);
        LogPrintf("Node is ignoring peer %d until %d.\n", pfrom->GetId(), pfrom->smsgData.ignoreUntil);
    }

    return 0;
};

int CSMSG::Receive(CNode *pfrom, std::vector<uint8_t> &vchData)
{
    LogPrint(BCLog::SMSG, "%s\n", __func__);

    if (vchData.size() < 12) { // nBunch4 + timestamp8
        return errorN(SMSG_GENERAL_ERROR, "%s - Not enough data.", __func__);
    }

    uint32_t nBunch;
    int64_t bktTime;

    memcpy(&nBunch, &vchData[0], 4);
    memcpy(&bktTime, &vchData[4], 8);

    // Check bktTime ()
    //  Bucket may not exist yet - will be created when messages are added
    int64_t now = GetAdjustedTime();
    if (bktTime % SMSG_BUCKET_LEN) {
        LogPrint(BCLog::SMSG, "Not a valid bucket time %d.\n", bktTime);
        SmsgMisbehaving(pfrom, 10);
    }
    if (bktTime > now + SMSG_TIME_LEEWAY) {
        LogPrint(BCLog::SMSG, "bktTime > now.\n");
        // misbehave?
        return SMSG_GENERAL_ERROR;
    }
    if (bktTime < now - SMSG_RETENTION) {
        LogPrint(BCLog::SMSG, "bktTime < now - SMSG_RETENTION.\n");
        // misbehave?
        return SMSG_GENERAL_ERROR;
    }

    if (nBunch > pfrom->smsgData.m_num_want_sent) {
        LogPrintf("Error: Received unsolicited message bunch from peer %d: %d, %d.\n", pfrom->GetId(), nBunch, pfrom->smsgData.m_num_want_sent);
        SmsgMisbehaving(pfrom, 20);
    }
    pfrom->smsgData.m_num_want_sent -= nBunch;

    if (nBunch == 0 || nBunch > MAX_BUNCH_MESSAGES || vchData.size() > MAX_BUNCH_BYTES) {
        LogPrintf("Error: Invalid message bunch received for bucket %d: %d, %d.\n", bktTime, nBunch, vchData.size());
        SmsgMisbehaving(pfrom, 20);

        {
            LOCK(cs_smsg);
            // Release lock on bucket if it exists
            auto itb = buckets.find(bktTime);
            if (itb != buckets.end()) {
                itb->second.nLockCount = 0;
                itb->second.nLockPeerId = -1;
            }
        } // cs_smsg
        return SMSG_GENERAL_ERROR;
    }

    uint32_t n = 12;

    for (uint32_t i = 0; i < nBunch; ++i) {
        if (vchData.size() - n < SMSG_HDR_LEN) {
            LogPrintf("Error: not enough data sent, n = %u.\n", n);
            break;
        }

        const SecureMessage *psmsg = (SecureMessage*) &vchData[n];
        const uint8_t *pPayload = &vchData[n + SMSG_HDR_LEN];
        if (!psmsg->IsPaidVersion() &&
            now - start_time > SMSG_BUCKET_LEN * 2) { // buckets should be fully matched after time
            if (psmsg->timestamp < now - SMSG_BUCKET_LEN * 3) {
                // If a free message is backdated, compare the hash to the current difficulty

                uint256 msg_hash;
                arith_uint256 target;
                GetPowHash(psmsg, pPayload, psmsg->nPayload, msg_hash);
                {
                LOCK(cs_main);
                target.SetCompact(GetSmsgDifficulty(now, true));
                }

                if (UintToArith256(msg_hash) > target) {
                    LogPrint(BCLog::SMSG, "Refusing free message %d, in the past.\n", psmsg->timestamp);
                    continue;
                }
            }
        }

        int rv;
        if ((rv = Validate(psmsg->data(), pPayload, psmsg->nPayload)) != 0) {
            // Message dropped
            if (rv == SMSG_INVALID_HASH) { // Invalid proof of work
                SmsgMisbehaving(pfrom, 10);
            } else
            if (rv == SMSG_FUND_FAILED) { // Bad funding tx
                Misbehaving(pfrom->GetId(), 10);
            } else {
                Misbehaving(pfrom->GetId(), 1);
            }
            continue;
        }

        {
            LOCK(cs_smsg);
            // Store message, but don't hash bucket
            if (Store(&vchData[n], &vchData[n + SMSG_HDR_LEN], psmsg->nPayload, false) != 0) {
                // Message dropped
                break;
            }

            bool fOwnMessage;
            if (ScanMessage(&vchData[n], &vchData[n + SMSG_HDR_LEN], psmsg->nPayload, true, fOwnMessage) != 0) {
                // message recipient is not this node (or failed)
            }
        } // cs_smsg

        n += SMSG_HDR_LEN + psmsg->nPayload;
    }

    {
        LOCK(cs_smsg);
        // If messages have been added, bucket must exist now
        auto itb = buckets.find(bktTime);
        if (itb == buckets.end()) {
            LogPrint(BCLog::SMSG, "Don't have bucket %d.\n", bktTime);
            return SMSG_GENERAL_ERROR;
        }

        itb->second.nLockCount  = 0; // This node has received data from peer, release lock
        itb->second.nLockPeerId = -1;
        itb->second.hashBucket(itb->first);
    } // cs_smsg

    return SMSG_NO_ERROR;
};

int CSMSG::CheckPurged(const SecureMessage *psmsg, const uint8_t *pPayload)
{
    int64_t ts = psmsg->timestamp; // ubsan
    if (setPurgedTimestamps.find(ts) != setPurgedTimestamps.end()) {
        return SMSG_NO_ERROR;
    }

    std::vector<uint8_t> vMsgId = GetMsgID(psmsg, pPayload);

    uint8_t chKey[30];
    chKey[0] = DBK_PURGED_TOKEN[0];
    chKey[1] = DBK_PURGED_TOKEN[1];
    memcpy(chKey+2, vMsgId.data(), 28);

    LOCK2(cs_smsg, cs_smsgDB);

    SecMsgDB db;
    if (!db.Open("cr+")) {
        return SMSG_GENERAL_ERROR;
    }

    SecMsgPurged purged;
    if (db.ReadPurged(chKey, purged)) {
        LogPrint(BCLog::SMSG, "%s Found purged %s\n", __func__, HexStr(vMsgId));

        // Add sample to purged token
        memcpy(purged.sample, pPayload, 8);
        setPurged.insert(purged);

        return SMSG_PURGED_MSG;
    }

    return SMSG_NO_ERROR;
};

int CSMSG::StoreUnscanned(const uint8_t *pHeader, const uint8_t *pPayload, uint32_t nPayload)
{
    /*
    When the wallet is locked a copy of each received message is stored to be scanned later if wallet is unlocked
    */

    LogPrint(BCLog::SMSG, "%s\n", __func__);

    if (!pHeader
        || !pPayload) {
        return errorN(SMSG_GENERAL_ERROR, "%s - Null pointer to header or payload.", __func__);
    }

    SecureMessage *psmsg = (SecureMessage*) pHeader;

    if (SMSG_NO_ERROR != CheckPurged(psmsg, pPayload)) {
        return errorN(SMSG_PURGED_MSG, "%s: Purged message.", __func__);
    }

    fs::path pathSmsgDir;
    try {
        pathSmsgDir = GetDataDir() / STORE_DIR;
        fs::create_directory(pathSmsgDir);
    } catch (const fs::filesystem_error &ex) {
        return errorN(SMSG_GENERAL_ERROR, "%s - Failed to create directory %s - %s.", __func__, pathSmsgDir.string(), ex.what());
    }

    int64_t now = GetAdjustedTime();
    if (psmsg->timestamp > now + SMSG_TIME_LEEWAY) {
        return errorN(SMSG_GENERAL_ERROR, "%s: Message > now.", __func__);
    }
    if (psmsg->timestamp < now - SMSG_RETENTION) {
        return errorN(SMSG_GENERAL_ERROR, "%s: Message < SMSG_RETENTION.", __func__);
    }

    int64_t bucket = psmsg->timestamp - (psmsg->timestamp % SMSG_BUCKET_LEN);

    std::string fileName = std::to_string(bucket) + "_01_wl.dat";
    fs::path fullpath = pathSmsgDir / fileName;

    FILE *fp;
    errno = 0;
    if (!(fp = fopen(fullpath.string().c_str(), "ab"))) {
        return errorN(SMSG_GENERAL_ERROR, "%s - Can't open file, strerror: %s.", __func__, strerror(errno));
    }

    if (fwrite(pHeader, sizeof(uint8_t), SMSG_HDR_LEN, fp) != (size_t)SMSG_HDR_LEN
        || fwrite(pPayload, sizeof(uint8_t), nPayload, fp) != nPayload) {
        fclose(fp);
        return errorN(SMSG_GENERAL_ERROR, "%s - fwrite failed, strerror: %s.", __func__, strerror(errno));
    }

    fclose(fp);
    return SMSG_NO_ERROR;
};


int CSMSG::Store(const uint8_t *pHeader, const uint8_t *pPayload, uint32_t nPayload, bool fHashBucket)
{
    LogPrint(BCLog::SMSG, "%s\n", __func__);
    AssertLockHeld(cs_smsg);

    if (!pHeader || !pPayload) {
        return errorN(SMSG_GENERAL_ERROR, "Null pointer to header or payload.");
    }

    SecureMessage *psmsg = (SecureMessage*) pHeader;

    if (SMSG_NO_ERROR != CheckPurged(psmsg, pPayload)) {
        return errorN(SMSG_PURGED_MSG, "%s: Purged message.", __func__);
    }

    long int ofs;
    fs::path pathSmsgDir;
    try {
        pathSmsgDir = GetDataDir() / STORE_DIR;
        fs::create_directory(pathSmsgDir);
    } catch (const fs::filesystem_error &ex) {
        return errorN(SMSG_GENERAL_ERROR, "Failed to create directory %s - %s.", pathSmsgDir.string(), ex.what());
    }

    int64_t now = GetAdjustedTime();
    if (psmsg->timestamp > now + SMSG_TIME_LEEWAY) {
        return errorN(SMSG_GENERAL_ERROR, "%s: Message > now.", __func__);
    }
    if (psmsg->timestamp < now - SMSG_RETENTION) {
        return errorN(SMSG_GENERAL_ERROR, "%s: Message < SMSG_RETENTION.", __func__);
    }

    int64_t bucketTime = psmsg->timestamp - (psmsg->timestamp % SMSG_BUCKET_LEN);
    uint32_t nTTL = psmsg->m_ttl;
    SecMsgToken token(psmsg->timestamp, pPayload, nPayload, 0, nTTL);
    token.m_changed = now - bucketTime;

    SecMsgBucket &bucket = buckets[bucketTime];
    std::set<SecMsgToken> &tokenSet = bucket.setTokens;
    if (tokenSet.find(token) != tokenSet.end()) {
        LogPrint(BCLog::SMSG, "Already have message.\n");
        if (LogAcceptCategory(BCLog::SMSG)) {
            LogPrintf("bucketTime: %d\n", bucketTime);
            LogPrintf("Message token: %s, nPayload %u\n", token.ToString(), nPayload);
        }
        return SMSG_GENERAL_ERROR;
    }

    std::string fileName = std::to_string(bucketTime) + "_01.dat";
    fs::path fullpath = pathSmsgDir / fileName;

    FILE *fp;
    errno = 0;
    if (!(fp = fopen(fullpath.string().c_str(), "ab"))) {
        return errorN(SMSG_GENERAL_ERROR, "fopen failed: %s.", strerror(errno));
    }

    // On windows ftell will always return 0 after fopen(ab), call fseek to set.
    errno = 0;
    if (fseek(fp, 0, SEEK_END) != 0) {
        fclose(fp);
        return errorN(SMSG_GENERAL_ERROR, "fseek failed: %s.", strerror(errno));
    }

    ofs = ftell(fp);
    if (fwrite(pHeader,  sizeof(uint8_t), SMSG_HDR_LEN, fp) != (size_t)SMSG_HDR_LEN
        || fwrite(pPayload, sizeof(uint8_t), nPayload, fp) != nPayload) {
        fclose(fp);
        return errorN(SMSG_GENERAL_ERROR, "fwrite failed: %s.", strerror(errno));
    }

    fclose(fp);

    token.offset = ofs;
    tokenSet.insert(token);

    if (nTTL > 0 && (bucket.nLeastTTL == 0 || nTTL < bucket.nLeastTTL)) {
        bucket.nLeastTTL = nTTL;
    }

    if (fHashBucket) {
        bucket.hashBucket(bucketTime);
    }

    LogPrint(BCLog::SMSG, "SecureMsg added to bucket %d.\n", bucketTime);

    m_last_changed = GetTime();

    return SMSG_NO_ERROR;
};

int CSMSG::Store(const SecureMessage &smsg, bool fHashBucket)
{
    return Store(smsg.data(), smsg.pPayload, smsg.nPayload, fHashBucket);
};

int CSMSG::Purge(std::vector<uint8_t> &vMsgId, std::string &sError)
{
    LogPrint(BCLog::SMSG, "%s %s\n", __func__, HexStr(vMsgId));

    LOCK(cs_smsg);
    LOCK(cs_smsgDB);
    SecMsgDB db;
    if (!db.Open("cw")) {
        return SMSG_GENERAL_ERROR;
    }
    int64_t now = GetTime();
    int64_t msgtime;
    memcpy(&msgtime, vMsgId.data(), 8);
    msgtime = bswap_64(msgtime);
    SecMsgPurged purged(msgtime, now);

    uint8_t chKey[30];
    chKey[0] = DBK_INBOX[0];
    chKey[1] = DBK_INBOX[1];
    memcpy(chKey+2, vMsgId.data(), 28);
    db.EraseSmesg(chKey);

    // Find in buckets
    int64_t bucketTime = msgtime - (msgtime % SMSG_BUCKET_LEN);

    SecMsgBucket &bucket = buckets[bucketTime];
    std::set<SecMsgToken> &tokenSet = bucket.setTokens;

    std::vector<uint8_t> vchOne;
    for (auto it = tokenSet.begin(); it != tokenSet.end(); ++it) {
        if (it->timestamp != msgtime) {
            continue;
        }

        if (Retrieve(*it, vchOne) != SMSG_NO_ERROR) {
            LogPrintf("%s: Retrieve failed, msgid: %s\n", __func__, HexStr(vMsgId));
            continue;
        }

        const SecureMessage *psmsg = (SecureMessage*) vchOne.data();
        if (GetMsgID(psmsg, vchOne.data() + SMSG_HDR_LEN) != vMsgId) {
            continue;
        }

        if (Remove(*it) != SMSG_NO_ERROR) {
            LogPrintf("%s: Remove failed, msgid: %s\n", __func__, HexStr(vMsgId));
            break;
        }
        memcpy(purged.sample, vchOne.data() + SMSG_HDR_LEN, 8);
        it->ttl = 0;
        LogPrint(BCLog::SMSG, "Purged message %s in bucket %d\n", it->ToString(), bucketTime);
        memcpy(purged.sample, it->sample, 8);

        break;
    }

    chKey[0] = 'p';
    db.WritePurged(chKey, purged);

    setPurged.insert(purged);
    setPurgedTimestamps.insert(purged.timestamp); // So network sync can prefilter on timestamp before checking for purged msgid in db

    return SMSG_NO_ERROR;
};

int CSMSG::AdjustDifficulty(int64_t time)
{
    if (!fSecMsgEnabled) {
        return 0;
    }

    const int64_t few_messages = 250;
    const int64_t excessive_messages = 500;

    int64_t bucket_time = time - (time % SMSG_BUCKET_LEN);
    int64_t prev_bucket_time = (bucket_time-1) - ((bucket_time-1) % SMSG_BUCKET_LEN);
    int64_t bucket_times[2] = {bucket_time, prev_bucket_time};

    int rv = 0;
    for (auto bucket_time : bucket_times) {
        auto it = buckets.find(bucket_time);
        if (it != buckets.end()) {
            if (it->second.nActive > excessive_messages) {
                rv += -1 * 10000 * float(it->second.nActive / excessive_messages);
            } else
            if (it->second.nActive < few_messages) {
                rv += 1 * 10000;
            }
        }
    }

    return rv;
};

int CSMSG::Validate(const uint8_t *pHeader, const uint8_t *pPayload, uint32_t nPayload)
{
    // return SecureMessageCodes
    const SecureMessage *psmsg = (SecureMessage*) pHeader;

    if (psmsg->IsPaidVersion()) {
        if (nPayload > SMSG_MAX_MSG_BYTES_PAID) {
            return SMSG_PAYLOAD_OVER_SIZE;
        }
    } else
    if (nPayload > SMSG_MAX_MSG_WORST) {
        return SMSG_PAYLOAD_OVER_SIZE;
    }

    int64_t now = GetAdjustedTime();
    if (psmsg->timestamp > now + SMSG_TIME_LEEWAY) {
        LogPrint(BCLog::SMSG, "Time in future %d.\n", psmsg->timestamp);
        return SMSG_TIME_IN_FUTURE;
    }

    const uint32_t ttl = psmsg->m_ttl;
    size_t nDaysRetention = psmsg->m_ttl / SMSG_SECONDS_IN_DAY;
    if (nDaysRetention < 1) {
        nDaysRetention = 1;
    }
    if (now > psmsg->timestamp + ttl) {
        LogPrint(BCLog::SMSG, "Time expired %d, ttl %d.\n", psmsg->timestamp, ttl);
        return SMSG_TIME_EXPIRED;
    }

    if (psmsg->IsPaidVersion()) {
        const Consensus::Params &consensusParams = Params().GetConsensus();
        if (consensusParams.nPaidSmsgTime > now) {
            LogPrintf("%s: Paid SMSG not yet active on mainnet.\n", __func__);
            return SMSG_GENERAL_ERROR;
        }
        if (ttl < SMSG_MIN_TTL || ttl > SMSG_MAX_PAID_TTL) {
            LogPrint(BCLog::SMSG, "TTL out of range %d.\n", ttl);
            return SMSG_GENERAL_ERROR;
        }

        size_t nMsgBytes = SMSG_HDR_LEN + psmsg->nPayload;
        uint256 txid;
        uint160 msgId;
        if (0 != HashMsg(*psmsg, pPayload, psmsg->nPayload-32, msgId)
            || !GetFundingTxid(pPayload, psmsg->nPayload, txid)) {
            LogPrintf("%s: Get msgID or Txn Hash failed.\n", __func__);
            return SMSG_GENERAL_ERROR;
        }

        CTransactionRef txOut;
        uint256 hashBlock;
        {
            LOCK(cs_main);
            if (!GetTransaction(txid, txOut, consensusParams, hashBlock) || hashBlock.IsNull()) {
                return errorN(SMSG_GENERAL_ERROR, "%s: Transaction %s not found for message %s.\n", __func__, txid.ToString(), msgId.ToString());
            }
            if (txOut->IsCoinStake()) {
                return errorN(SMSG_GENERAL_ERROR, "%s: Transaction %s for message %s, is coinstake.\n", __func__, txid.ToString(), msgId.ToString());
            }

            int blockDepth = -1;
            const CBlockIndex *pindex = nullptr;
            BlockMap::iterator mi = ::BlockIndex().find(hashBlock);
            int64_t nMsgFeePerKPerDay = 0;
            if (mi != ::BlockIndex().end()) {
                pindex = mi->second;
                if (pindex && ::ChainActive().Contains(pindex)) {
                    blockDepth = ::ChainActive().Height() - pindex->nHeight + 1;
                    nMsgFeePerKPerDay = GetSmsgFeeRate(pindex);
                }
            }

            if (blockDepth < 1) {
                return errorN(SMSG_GENERAL_ERROR, "%s: Transaction %s for message %s, low depth %d.\n", __func__, txid.ToString(), msgId.ToString(), blockDepth);
            }

            // blockDepth >= 1 -> nMsgFeePerKPerDay must have been set
            int64_t nExpectFee = ((nMsgFeePerKPerDay * nMsgBytes) / 1000) * nDaysRetention;

            bool fFound = false;
            // Find all msg pairs
            // Message funding is enforced in tx_verify.cpp
            for (const auto &v : txOut->vpout) {
                if (!v->IsType(OUTPUT_DATA)) {
                    continue;
                }
                const std::vector<uint8_t> &vData = *v->GetPData();
                if (vData.size() < 25 || vData[0] != DO_FUND_MSG) {
                    continue;
                }

                size_t n = (vData.size()-1) / 24;
                for (size_t k = 0; k < n; ++k) {
                    const uint8_t *pMsgIdTxStart = &vData[1+k*24];
                    if (memcmp(pMsgIdTxStart, msgId.begin(), 20) == 0) {
                        uint32_t nAmount;
                        memcpy(&nAmount, &vData[1+k*24+20], 4);

                        if (nAmount < nExpectFee) {
                            // Grace period after fee period transition where prev fee is still allowed
                            bool matched_last_fee = false;
                            if (pindex->nHeight % consensusParams.smsg_fee_period < 10) {
                                int64_t nMsgFeePerKPerDayLast = GetSmsgFeeRate(pindex, true);
                                int64_t nExpectFeeLast = ((nMsgFeePerKPerDayLast * nMsgBytes) / 1000) * nDaysRetention;

                                if (nAmount >= nExpectFeeLast) {
                                    matched_last_fee = true;
                                }
                            }

                            if (!matched_last_fee) {
                                LogPrintf("%s: Transaction %s underfunded message %s, expected %d paid %d.\n", __func__, txid.ToString(), msgId.ToString(), nExpectFee, nAmount);
                                return SMSG_FUND_FAILED;
                            }
                        }
                        fFound = true;
                    }
                }
            }

            if (!fFound) {
                return errorN(SMSG_FUND_FAILED, "%s: Transaction %s does not fund message %s.\n", __func__, txid.ToString(), msgId.ToString());
            }
        }

        return SMSG_NO_ERROR; // smsg is valid and funded
    }

    if (ttl < SMSG_MIN_TTL || ttl > SMSG_MAX_FREE_TTL) {
        LogPrint(BCLog::SMSG, "TTL out of range %d.\n", ttl);
        return SMSG_GENERAL_ERROR;
    }

    if (psmsg->version[0] != 2) {
        return SMSG_UNKNOWN_VERSION;
    }

    int rv = SMSG_INVALID_HASH;

    uint256 msg_hash;
    if (!GetPowHash(psmsg, pPayload, nPayload, msg_hash)) {
        return SMSG_INVALID_HASH;
    }

    if (part::memcmp_nta(psmsg->hash, msg_hash.begin(), 4) != 0) {
        LogPrint(BCLog::SMSG, "Checksum mismatch.\n");
        return SMSG_CHECKSUM_MISMATCH;
    }

    arith_uint256 target;
    {
    LOCK(cs_main);
    target.SetCompact(GetSmsgDifficulty(psmsg->timestamp, true));
    }

    if (UintToArith256(msg_hash) <= target) {
        rv = SMSG_NO_ERROR; // smsg is valid
    }

    return rv;
};

int CSMSG::SetHash(uint8_t *pHeader, uint8_t *pPayload, uint32_t nPayload)
{
    /*  proof of work and checksum

        May run in a thread, if shutdown detected, return.

        returns SecureMessageCodes
    */

    SecureMessage *psmsg = (SecureMessage*) pHeader;

    int64_t nStart = GetTimeMillis();
    uint8_t civ[32];

    bool found = false;

    uint32_t nonce = 0;
    memcpy(&nonce, &psmsg->nonce[0], 4);

    uint256 msg_hash;
    arith_uint256 target_difficulty;
    {
    LOCK(cs_main);
    target_difficulty.SetCompact(GetSmsgDifficulty(psmsg->timestamp));
    }

    // Break for HMAC_CTX_cleanup
    for (;;) {
        if (!fSecMsgEnabled) {
           break;
        }

        memcpy(&psmsg->nonce[0], &nonce, 4);

        for (int i = 0; i < 32; i+=4) {
            memcpy(civ+i, &nonce, 4);
        }

        CHMAC_SHA256 ctx(&civ[0], 32);
        ctx.Write((uint8_t*) pHeader+4, SMSG_HDR_LEN-4);
        ctx.Write((uint8_t*) pPayload, nPayload);
        ctx.Finalize(msg_hash.begin());

        if (UintToArith256(msg_hash) <= target_difficulty) {
            found = true;
            break;
        }

        if (nonce >= 0xFFFFFFFFU) {
            LogPrint(BCLog::SMSG, "No match %u\n", nonce);
            break;
        }
        nonce++;
    }

    if (!fSecMsgEnabled) {
        LogPrint(BCLog::SMSG, "%s: Stopped, shutdown detected.\n", __func__);
        return SMSG_SHUTDOWN_DETECTED;
    }

    if (!found) {
        LogPrint(BCLog::SMSG, "%s: Failed, took %d ms, nonce %u\n", __func__, GetTimeMillis() - nStart, nonce);
        return SMSG_GENERAL_ERROR;
    }

    memcpy(psmsg->hash, msg_hash.begin(), 4);

    LogPrint(BCLog::SMSG, "%s: Took %d ms, nonce %u\n", __func__, GetTimeMillis() - nStart, nonce);

    return SMSG_NO_ERROR;
};

int CSMSG::Encrypt(SecureMessage &smsg, const CKeyID &addressFrom, const CKeyID &addressTo, const std::string &message)
{
    /* Create a secure message

    Using similar method to bitmessage.
    If bitmessage is secure this should be too.
    https://bitmessage.org/wiki/Encryption

    Some differences:
    bitmessage seems to use curve sect283r1
    *coin addresses use secp256k1

    returns SecureMessageCodes

    */

    bool fSendAnonymous = addressFrom.IsNull();

    if (LogAcceptCategory(BCLog::SMSG)) {
        LogPrint(BCLog::SMSG, "SecureMsgEncrypt(%s, %s, ...)\n",
            fSendAnonymous ? "anon" : EncodeDestination(PKHash(addressFrom)),
            EncodeDestination(PKHash(addressTo)));
    }

    if (smsg.timestamp == 0) {
        smsg.timestamp = GetTime();
    }

    CBitcoinAddress coinAddrFrom;
    CKeyID ckidFrom;
    CKey keyFrom;

    if (!fSendAnonymous) {
        if (!coinAddrFrom.Set(addressFrom)
            || !coinAddrFrom.GetKeyID(ckidFrom)) {
            return errorN(SMSG_INVALID_ADDRESS_FROM, "%s: addressFrom is not valid: %s.", __func__, coinAddrFrom.ToString());
        }
    }

    CBitcoinAddress coinAddrDest;
    CKeyID ckidDest = addressTo;

    // Public key K is the destination address
    CPubKey cpkDestK;
    if (GetStoredKey(ckidDest, cpkDestK) != 0
        && GetLocalKey(ckidDest, cpkDestK) != 0) { // maybe it's a local key (outbox?)
        return errorN(SMSG_PUBKEY_NOT_EXISTS, "%s: Could not get public key for destination address.", __func__);
    }

    // Generate 16 random bytes as IV.
    GetStrongRandBytes(&smsg.iv[0], 16);

    // Generate a new random EC key pair with private key called r and public key called R.
    CKey keyR;
    keyR.MakeNewKey(true); // make compressed key

    //uint256 P = keyR.ECDH(cpkDestK);
    secp256k1_pubkey pubkey;
    if (!secp256k1_ec_pubkey_parse(secp256k1_context_smsg, &pubkey, cpkDestK.begin(), cpkDestK.size())) {
        return errorN(SMSG_INVALID_ADDRESS_TO, "%s: secp256k1_ec_pubkey_parse failed: %s.", __func__, HexStr(cpkDestK));
    }

    uint256 P;
    if (!secp256k1_ecdh(secp256k1_context_smsg, P.begin(), &pubkey, keyR.begin(), nullptr, nullptr)) {
        return errorN(SMSG_GENERAL_ERROR, "%s: secp256k1_ecdh failed.", __func__);
    }

    CPubKey cpkR = keyR.GetPubKey();
    if (!cpkR.IsValid()) {
        return errorN(SMSG_GENERAL_ERROR, "%s: Could not get public key for key R.", __func__);
    }

    memcpy(smsg.cpkR, cpkR.begin(), 33);

    // Use public key P and calculate the SHA512 hash H.
    //   The first 32 bytes of H are called key_e and the last 32 bytes are called key_m.
    std::vector<uint8_t> vchHashed;
    vchHashed.resize(64); // 512
    memset(vchHashed.data(), 0, 64);
    CSHA512().Write(P.begin(), 32).Finalize(&vchHashed[0]);
    std::vector<uint8_t> key_e(&vchHashed[0], &vchHashed[0]+32);
    std::vector<uint8_t> key_m(&vchHashed[32], &vchHashed[32]+32);

    std::vector<uint8_t> vchPayload;
    std::vector<uint8_t> vchCompressed;
    uint8_t *pMsgData;
    uint32_t lenMsgData;

    uint32_t lenMsg = message.size();
    if (lenMsg > 128) {
        // Only compress if over 128 bytes
        int worstCase = LZ4_compressBound(message.size());
        try { vchCompressed.resize(worstCase); } catch (std::exception &e) {
            return errorN(SMSG_ALLOCATE_FAILED, "%s: vchCompressed.resize %u threw: %s.", __func__, worstCase, e.what());
        }

        int lenComp = LZ4_compress_default((char*)message.c_str(), (char*)vchCompressed.data(), lenMsg, worstCase);
        if (lenComp < 1) {
            return errorN(SMSG_COMPRESS_FAILED, "%s: Could not compress message data.", __func__);
        }

        pMsgData = vchCompressed.data();
        lenMsgData = lenComp;
    } else {
        // No compression
        pMsgData = (uint8_t*)message.c_str();
        lenMsgData = lenMsg;
    }

    if (fSendAnonymous) {
        try { vchPayload.resize(9 + lenMsgData); } catch (std::exception &e) {
            return errorN(SMSG_ALLOCATE_FAILED, "%s: vchPayload.resize %u threw: %s.", __func__, 9 + lenMsgData, e.what());
        }

        memcpy(&vchPayload[9], pMsgData, lenMsgData);

        vchPayload[0] = 250; // id as anonymous message
        // Next 4 bytes are unused - there to ensure encrypted payload always > 8 bytes
        memcpy(&vchPayload[5], &lenMsg, 4); // length of uncompressed plain text
    } else {
        try { vchPayload.resize(SMSG_PL_HDR_LEN + lenMsgData); } catch (std::exception &e) {
            return errorN(SMSG_ALLOCATE_FAILED, "%s: vchPayload.resize %u threw: %s.", __func__, SMSG_PL_HDR_LEN + lenMsgData, e.what());
        }

        memcpy(&vchPayload[SMSG_PL_HDR_LEN], pMsgData, lenMsgData);
        // Compact signature proves ownership of from address and allows the public key to be recovered, recipient can always reply.
        if (GetLocalKey(ckidFrom, keyFrom) != 0) {
            return errorN(SMSG_UNKNOWN_KEY_FROM, "%s: Could not get private key for addressFrom.", __func__);
        }

        // Sign the plaintext
        std::vector<uint8_t> vchSignature;
        vchSignature.resize(65);
        keyFrom.SignCompact(Hash(message.begin(), message.end()), vchSignature);

        // Save some bytes by sending address raw
        vchPayload[0] = (static_cast<CBitcoinAddress*>(&coinAddrFrom))->getVersion(); // vchPayload[0] = coinAddrDest.nVersion;
        memcpy(&vchPayload[1], ckidFrom.begin(), 20); // memcpy(&vchPayload[1], ckidDest.pn, 20);

        memcpy(&vchPayload[1+20], &vchSignature[0], vchSignature.size());
        memcpy(&vchPayload[1+20+65], &lenMsg, 4); // length of uncompressed plain text
    }

    SecMsgCrypter crypter;
    crypter.SetKey(key_e, smsg.iv);
    std::vector<uint8_t> vchCiphertext;

    if (!crypter.Encrypt(vchPayload.data(), vchPayload.size(), vchCiphertext)) {
        return errorN(SMSG_ENCRYPT_FAILED, "%s: Encrypt failed.", __func__);
    }

    bool fPaid = smsg.version[0] == 3;
    try { smsg.pPayload = new uint8_t[vchCiphertext.size() + (fPaid ? 32 : 0)]; } catch (std::exception &e) {
        return errorN(SMSG_ALLOCATE_FAILED, "%s: Could not allocate pPayload, exception: %s.", __func__, e.what());
    }

    memcpy(smsg.pPayload, vchCiphertext.data(), vchCiphertext.size());
    smsg.nPayload = vchCiphertext.size() + (fPaid ? 32 : 0);

    // Calculate a 32 byte MAC with HMACSHA256, using key_m as salt
    //  Message authentication code, (hash of timestamp + iv + destination + payload)
    CHMAC_SHA256 ctx(&key_m[0], 32);
    ctx.Write((uint8_t*) &smsg.timestamp, sizeof(smsg.timestamp));
    ctx.Write((uint8_t*) smsg.iv, sizeof(smsg.iv));
    ctx.Write((uint8_t*) vchCiphertext.data(), vchCiphertext.size());
    ctx.Finalize(smsg.mac);

    return SMSG_NO_ERROR;
};

int CSMSG::Import(SecureMessage *psmsg, std::string &sError, bool setread, bool submitmsg)
{
    if (psmsg->IsPaidVersion() && psmsg->nPayload < 33) {
        sError = "Payload too short.";
        return SMSG_GENERAL_ERROR;
    }

    uint256 msg_hash;
    size_t hash_bytes = psmsg->IsPaidVersion() ? psmsg->nPayload-32 : psmsg->nPayload;
    GetPowHash(psmsg, psmsg->pPayload, hash_bytes, msg_hash);
    if (part::memcmp_nta(psmsg->hash, msg_hash.begin(), 4) != 0) {
       sError = "Checksum mismatch.";
        return SMSG_CHECKSUM_MISMATCH;
    }

    bool fOwnMessage;
    if (ScanMessage(psmsg->data(), psmsg->pPayload, psmsg->nPayload, false, fOwnMessage) != 0) {
        // message recipient is not this node (or failed)
        return SMSG_GENERAL_ERROR;
    }

    if (!fOwnMessage && !submitmsg) {
        sError = "Message not received.";
        return SMSG_GENERAL_ERROR;
    }

    if (!submitmsg) {
        return SMSG_NO_ERROR;
    }
    LOCK(cs_smsg);

    int rv = SetHash(psmsg->data(), psmsg->pPayload, psmsg->nPayload);
    if (rv != SMSG_NO_ERROR) {
        sError = "SetHash failed " + std::string(GetString(rv));
        return rv;
    }

    rv = Validate(psmsg->data(), psmsg->pPayload, psmsg->nPayload);
    if (rv != SMSG_NO_ERROR) {
        sError = "Validation failed " + std::string(GetString(rv));
        return rv;
    }

    Store(*psmsg, true);

    return SMSG_NO_ERROR;
};

int CSMSG::Send(CKeyID &addressFrom, CKeyID &addressTo, std::string &message,
    SecureMessage &smsg, std::string &sError, bool fPaid,
    size_t nRetention, bool fTestFee, CAmount *nFee, size_t *nTxBytes, bool fFromFile, bool submit_msg, bool add_to_outbox, bool fund_from_rct, size_t nRingSize, CCoinControl *coin_control)
{
    /* Encrypt secure message, and place it on the network
        Make a copy of the message to sender's first address and place in send queue db
        proof of work thread will pick up messages from  send queue db
    */

    bool fSendAnonymous = (addressFrom.IsNull());

    if (LogAcceptCategory(BCLog::SMSG)) {
        LogPrintf("SecureMsgSend(%s, %s, ...)\n",
            fSendAnonymous ? "anon" : EncodeDestination(PKHash(addressFrom)), EncodeDestination(PKHash(addressTo)));
    }

    if (nRetention < SMSG_MIN_TTL || nRetention > SMSG_MAX_PAID_TTL) {
        LogPrint(BCLog::SMSG, "TTL out of range %d.\n", nRetention);
        return SMSG_GENERAL_ERROR;
    }

    std::string sFromFile;
    if (fFromFile) {
        FILE *fp;
        errno = 0;
        if (!(fp = fopen(message.c_str(), "rb"))) {
            return errorN(SMSG_GENERAL_ERROR, sError, __func__, "fopen failed: %s", strerror(errno));
        }

        if (fseek(fp, 0, SEEK_END) != 0) {
            fclose(fp);
            return errorN(SMSG_GENERAL_ERROR, sError, __func__, "fseek failed: %s", strerror(errno));
        }

        int64_t ofs = ftell(fp);
        if (ofs > SMSG_MAX_MSG_BYTES_PAID) {
            fclose(fp);
            return errorN(SMSG_MESSAGE_TOO_LONG, sError, __func__, "Message is too long, %d > %d", ofs, SMSG_MAX_MSG_BYTES_PAID);
        }
        rewind(fp);

        sFromFile.resize(ofs);

        int64_t nRead = fread(&sFromFile[0], 1, ofs, fp);
        fclose(fp);
        if (ofs != nRead) {
            return errorN(SMSG_GENERAL_ERROR, sError, __func__, "fread failed: %s", strerror(errno));
        }
    }

    std::string &sData = fFromFile ? sFromFile : message;

    if (fPaid) {
        if (sData.size() > SMSG_MAX_MSG_BYTES_PAID) {
            sError = strprintf("Message is too long, %d > %d", sData.size(), SMSG_MAX_MSG_BYTES_PAID);
            return errorN(SMSG_MESSAGE_TOO_LONG, "%s: %s.", __func__, sError);
        }
    } else
    if (sData.size() > (fSendAnonymous ? SMSG_MAX_AMSG_BYTES : SMSG_MAX_MSG_BYTES)) {
        sError = strprintf("Message is too long, %d > %d", sData.size(), fSendAnonymous ? SMSG_MAX_AMSG_BYTES : SMSG_MAX_MSG_BYTES);
        return errorN(SMSG_MESSAGE_TOO_LONG, "%s: %s.", __func__, sError);
    }

    int rv;
    smsg = SecureMessage(fPaid, nRetention);
    if ((rv = Encrypt(smsg, addressFrom, addressTo, sData)) != 0) {
        sError = GetString(rv);
        return errorN(rv, "%s: %s.", __func__, sError);
    }

    if (fPaid || !submit_msg) {
        uint256 msg_hash;
        size_t hash_bytes = smsg.IsPaidVersion() ? smsg.nPayload-32 : smsg.nPayload;
        GetPowHash(&smsg, smsg.pPayload, hash_bytes, msg_hash);
        memcpy(smsg.hash, msg_hash.begin(), 4);
    }
    if (fPaid) {
        if (0 != FundMsg(smsg, sError, fTestFee, nFee, nTxBytes, fund_from_rct, nRingSize, coin_control)) {
            return errorN(SMSG_FUND_FAILED, "%s: SecureMsgFund failed %s.", __func__, sError);
        }

        if (fTestFee) {
            return SMSG_NO_ERROR;
        }
    }

    uint160 msgId;
    HashMsg(smsg, smsg.pPayload, smsg.nPayload-(fPaid ? 32 : 0), msgId);

    if (submit_msg) {
        // Place message in send queue, proof of work will happen in a thread.
        uint8_t chKey[30];
        int64_t timestamp_be = bswap_64(smsg.timestamp);
        memcpy(&chKey[0], DBK_QUEUED.data(), 2);
        memcpy(&chKey[2], &timestamp_be, 8);
        memcpy(&chKey[10], msgId.begin(), 20);

        SecMsgStored smsgSQ;
        smsgSQ.timeReceived  = GetTime();
        smsgSQ.addrTo        = addressTo;

        try { smsgSQ.vchMessage.resize(SMSG_HDR_LEN + smsg.nPayload); } catch (std::exception &e) {
            LogPrintf("smsgSQ.vchMessage.resize %u threw: %s.\n", SMSG_HDR_LEN + smsg.nPayload, e.what());
            sError = "Could not allocate memory.";
            return SMSG_ALLOCATE_FAILED;
        }

        memcpy(&smsgSQ.vchMessage[0], smsg.data(), SMSG_HDR_LEN);
        memcpy(&smsgSQ.vchMessage[SMSG_HDR_LEN], smsg.pPayload, smsg.nPayload);

        {
            LOCK(cs_smsgDB);
            SecMsgDB dbSendQueue;
            if (dbSendQueue.Open("cw")) {
                dbSendQueue.WriteSmesg(chKey, smsgSQ);
                //NotifySecMsgSendQueueChanged(smsgOutbox);
            }
        } // cs_smsgDB

        if (LogAcceptCategory(BCLog::SMSG)) {
            LogPrintf("Secure message queued for sending to %s.\n", EncodeDestination(PKHash(addressTo)));
        }
    }

    if (!add_to_outbox) {
        return SMSG_NO_ERROR;
    }

    //  For outbox create a copy encrypted for owned address
    //   if the wallet is encrypted private key needed to decrypt will be unavailable

    LogPrint(BCLog::SMSG, "Encrypting message for outbox.\n");
    CKeyID addressOutbox;
#ifdef ENABLE_WALLET
    if (!pactive_wallet) {
        addressOutbox = addressFrom;
    } else {
        LOCK(pactive_wallet->cs_wallet);
        for (const auto &entry : pactive_wallet->mapAddressBook) { // PAIRTYPE(CTxDestination, CAddressBookData)
            // Get first owned address
            if (!pactive_wallet->IsMine(entry.first)) {
                continue;
            }
            if (entry.first.type() == typeid(PKHash)) {
                addressOutbox = CKeyID(boost::get<PKHash>(entry.first));
                break;
            }
        }
    }
#else
    addressOutbox = addressFrom;
#endif

    if (addressOutbox.IsNull()) {
        LogPrintf("%s: Warning, could not find an address to encrypt outbox message with.\n", __func__);
    } else {
        if (LogAcceptCategory(BCLog::SMSG)) {
            LogPrintf("Encrypting a copy for outbox, using address %s\n", EncodeDestination(PKHash(addressOutbox)));
        }

        SecureMessage smsgForOutbox(fPaid, nRetention);
        smsgForOutbox.timestamp = smsg.timestamp;
        if ((rv = Encrypt(smsgForOutbox, addressFrom, addressOutbox, sData)) != 0) {
            LogPrintf("%s: Encrypt for outbox failed, %d.\n", __func__, rv);
        } else {
            if (fPaid) {
                uint256 txfundId;
                if (!smsg.GetFundingTxid(txfundId)) {
                    return errorN(SMSG_GENERAL_ERROR, "%s: GetFundingTxid failed.\n");
                }
                // SecureMsgEncrypt will alloc an extra 32 bytes when smsg version describes paid msg
                memcpy(smsgForOutbox.pPayload+smsgForOutbox.nPayload-32, txfundId.begin(), 32);
            }

            // Save sent message to db
            uint8_t chKey[30];
            int64_t timestamp_be = bswap_64(smsgForOutbox.timestamp);
            memcpy(&chKey[0], DBK_OUTBOX.data(), 2);
            memcpy(&chKey[2], &timestamp_be, 8);
            memcpy(&chKey[10], msgId.begin(), 20);

            SecMsgStored smsgOutbox;

            smsgOutbox.timeReceived  = GetTime();
            smsgOutbox.addrTo        = addressTo;
            smsgOutbox.addrOutbox    = addressOutbox;

            try {
                smsgOutbox.vchMessage.resize(SMSG_HDR_LEN + smsgForOutbox.nPayload);
            } catch (std::exception &e) {
                LogPrintf("smsgOutbox.vchMessage.resize %u threw: %s.\n", SMSG_HDR_LEN + smsgForOutbox.nPayload, e.what());
                sError = "Could not allocate memory.";
                return SMSG_ALLOCATE_FAILED;
            }
            memcpy(&smsgOutbox.vchMessage[0], &smsgForOutbox.hash[0], SMSG_HDR_LEN);
            memcpy(&smsgOutbox.vchMessage[SMSG_HDR_LEN], smsgForOutbox.pPayload, smsgForOutbox.nPayload);

            {
                LOCK(cs_smsgDB);
                SecMsgDB dbSent;

                if (dbSent.Open("cw")) {
                    dbSent.WriteSmesg(chKey, smsgOutbox);
                    NotifySecMsgOutboxChanged(smsgOutbox);
                }
            } // cs_smsgDB
        }
    }

    return SMSG_NO_ERROR;
};

bool CSMSG::GetPowHash(const SecureMessage *psmsg, const uint8_t *pPayload, uint32_t nPayload, uint256 &hash)
{
    uint8_t civ[32];
    uint32_t nonce;
    memcpy(&nonce, &psmsg->nonce[0], 4);

    for (int i = 0; i < 32; i+=4) {
        memcpy(civ+i, &nonce, 4);
    }

    CHMAC_SHA256 ctx(&civ[0], 32);
    ctx.Write(((uint8_t*) psmsg)+4, SMSG_HDR_LEN-4);
    ctx.Write((uint8_t*) pPayload, nPayload);
    ctx.Finalize(hash.begin());

    return true;
};

int CSMSG::HashMsg(const SecureMessage &smsg, const uint8_t *pPayload, uint32_t nPayload, uint160 &hash)
{
    if (smsg.nPayload < nPayload) {
        return errorN(SMSG_GENERAL_ERROR, "%s: Data length mismatch.\n", __func__);
    }

    CRIPEMD160()
        .Write(smsg.data() + 8, SMSG_HDR_LEN - 8) // MsgId excludes checksum and nonce
        .Write(pPayload, nPayload)
        .Finalize(hash.begin());

    return SMSG_NO_ERROR;
};

int CSMSG::FundMsg(SecureMessage &smsg, std::string &sError, bool fTestFee, CAmount *nFee, size_t *nTxBytes, bool fund_from_rct, size_t nRingSize, CCoinControl *coin_control)
{
    // smsg.pPayload must have smsg.nPayload + 32 bytes allocated
#ifdef ENABLE_WALLET
    assert(coin_control);

    if (!pactive_wallet) {
        return SMSG_WALLET_UNSET;
    }

    if (smsg.version[0] != 3) {
        return errorN(SMSG_UNKNOWN_VERSION, sError, __func__, "Bad message version.");
    }

    size_t nDaysRetention = smsg.m_ttl / SMSG_SECONDS_IN_DAY;
    if (nDaysRetention < 1 || nDaysRetention > 31) {
        return errorN(SMSG_GENERAL_ERROR, sError, __func__, "Bad message ttl.");
    }

    uint256 txfundId;
    uint160 msgId;
    CMutableTransaction txFund;

    if (0 != HashMsg(smsg, smsg.pPayload, smsg.nPayload-32, msgId)) {
        return errorN(SMSG_GENERAL_ERROR, sError, __func__, "Message hash failed.");
    }

    size_t nMsgBytes = SMSG_HDR_LEN + smsg.nPayload;
    CAmount nFeeRet;
    OutputTypes fund_from = fund_from_rct ? OUTPUT_RINGCT : OUTPUT_STANDARD;
    {
        auto locked_chain = pactive_wallet->chain().lock();
        LOCK(pactive_wallet->cs_wallet);

        const Consensus::Params &consensusParams = Params().GetConsensus();
        coin_control->m_feerate = CFeeRate(consensusParams.smsg_fee_funding_tx_per_k);
        coin_control->fOverrideFeeRate = true;
        coin_control->m_extrafee = ((locked_chain->getSmsgFeeRate(nullptr) * nMsgBytes) / 1000) * nDaysRetention;
        assert(coin_control->m_extrafee <= std::numeric_limits<uint32_t>::max());
        uint32_t msgFee = coin_control->m_extrafee;

        std::vector<CTempRecipient> vec_send;
        CTransactionRecord rtx;
        CTempRecipient tr;
        tr.nType = OUTPUT_DATA;
        tr.vData.resize(25); // 4 byte fee, max 42.94967295
        tr.vData[0] = DO_FUND_MSG;
        memcpy(&tr.vData[1], msgId.begin(), 20);
        memcpy(&tr.vData[21], &msgFee, 4);
        vec_send.push_back(tr);

        CHDWallet *const pw = GetParticlWallet(pactive_wallet.get());
        CTransactionRef tx_new;
        CWalletTx wtx(pactive_wallet.get(), tx_new);

        if (fund_from == OUTPUT_STANDARD) {
            if (0 != pw->AddStandardInputs(*locked_chain, wtx, rtx, vec_send, !fTestFee, nFeeRet, coin_control, sError)) {
                return SMSG_FUND_FAILED;
            }
        } else
        if (fund_from == OUTPUT_RINGCT) {
            const Consensus::Params &consensusParams = Params().GetConsensus();
            if (consensusParams.extra_dataoutput_time > GetAdjustedTime()) {
                tr.nType = OUTPUT_STANDARD;
                tr.fScriptSet = true;
                tr.scriptPubKey.resize(1);
                tr.scriptPubKey[0] = OP_RETURN;
                tr.vData.clear();
                vec_send.push_back(tr);
            }
            size_t nInputsPerSig = 1;
            if (0 != pw->AddAnonInputs(*locked_chain, wtx, rtx, vec_send, !fTestFee, nRingSize, nInputsPerSig, nFeeRet, coin_control, sError)) {
                return SMSG_FUND_FAILED;
            }
        } else {
            return errorN(SMSG_GENERAL_ERROR, sError, __func__, "Unknown fund from coin type.");
        }

        if (nFee) {
            *nFee = nFeeRet;
        }
        if (nTxBytes) {
            *nTxBytes = GetVirtualTransactionSize(*(wtx.tx));
        }

        if (fTestFee) {
            return SMSG_NO_ERROR;
        }

        txfundId = wtx.tx->GetHash();

        if (!pactive_wallet->GetBroadcastTransactions()) {
            return errorN(SMSG_GENERAL_ERROR, sError, __func__, "Broadcast transactions disabled.");
        }

        wtx.BindWallet(pactive_wallet.get());
        std::string err_string;
        if (!wtx.SubmitMemoryPoolAndRelay(err_string, true, m_absurd_smsg_fee)) {
            return errorN(SMSG_GENERAL_ERROR, sError, __func__, "Transaction cannot be broadcast immediately: %s.", err_string);
        }
        pactive_wallet->AddToWallet(wtx);
    }
    memcpy(smsg.pPayload+(smsg.nPayload-32), txfundId.begin(), 32);
#else
    return SMSG_WALLET_UNSET;
#endif
    return SMSG_NO_ERROR;
};

std::vector<uint8_t> CSMSG::GetMsgID(const SecureMessage *psmsg, const uint8_t *pPayload)
{
    std::vector<uint8_t> rv(28);
    int64_t timestamp_be = bswap_64(psmsg->timestamp);
    memcpy(rv.data(), &timestamp_be, 8);

    HashMsg(*psmsg, pPayload, psmsg->nPayload-(psmsg->IsPaidVersion() ? 32 : 0), *((uint160*)&rv[8]));

    return rv;
};

std::vector<uint8_t> CSMSG::GetMsgID(const SecureMessage &smsg)
{
    std::vector<uint8_t> rv(28);
    int64_t timestamp_be = bswap_64(smsg.timestamp);
    memcpy(rv.data(), &timestamp_be, 8);

    HashMsg(smsg, smsg.pPayload, smsg.nPayload-(smsg.IsPaidVersion() ? 32 : 0), *((uint160*)&rv[8]));

    return rv;
};

int CSMSG::Decrypt(bool fTestOnly, const CKey &keyDest, const CKeyID &address, const uint8_t *pHeader, const uint8_t *pPayload, uint32_t nPayload, MessageData &msg)
{
    /* Decrypt secure message

        address is the owned address to decrypt with.

        validate first in SecureMsgValidate

        returns SecureMessageErrors
    */

    if (LogAcceptCategory(BCLog::SMSG)) {
        LogPrintf("%s: using %s, testonly %d.\n", __func__, EncodeDestination(PKHash(address)), fTestOnly);
    }

    if (!pHeader
        || !pPayload) {
        return errorN(SMSG_GENERAL_ERROR, "%s: null pointer to header or payload.", __func__);
    }

    SecureMessage *psmsg = (SecureMessage*) pHeader;
    if (psmsg->version[0] == 3) {
        nPayload -= 32; // Exclude funding txid
    } else
    if (psmsg->version[0] != 2) {
        return errorN(SMSG_UNKNOWN_VERSION, "%s: Unknown version number.", __func__);
    }

    // Do an EC point multiply with private key k and public key R. This gives you public key P.
    //CPubKey R(psmsg->cpkR, psmsg->cpkR+33);
    //uint256 P = keyDest.ECDH(R);
    secp256k1_pubkey R;
    if (!secp256k1_ec_pubkey_parse(secp256k1_context_smsg, &R, psmsg->cpkR, 33)) {
        return errorN(SMSG_GENERAL_ERROR, "%s: secp256k1_ec_pubkey_parse failed: %s.", __func__, HexStr(psmsg->cpkR, psmsg->cpkR+33));
    }

    uint256 P;
    if (!secp256k1_ecdh(secp256k1_context_smsg, P.begin(), &R, keyDest.begin(), nullptr, nullptr)) {
        return errorN(SMSG_GENERAL_ERROR, "%s: secp256k1_ecdh failed.", __func__);
    }

    // Use public key P to calculate the SHA512 hash H.
    //  The first 32 bytes of H are called key_e and the last 32 bytes are called key_m.
    std::vector<uint8_t> vchHashedDec;
    vchHashedDec.resize(64);    // 512 bits
    memset(vchHashedDec.data(), 0, 64);
    CSHA512().Write(P.begin(), 32).Finalize(&vchHashedDec[0]);
    std::vector<uint8_t> key_e(&vchHashedDec[0], &vchHashedDec[0]+32);
    std::vector<uint8_t> key_m(&vchHashedDec[32], &vchHashedDec[32]+32);

    // Message authentication code, (hash of timestamp + iv + destination + payload)
    uint8_t MAC[32];

    CHMAC_SHA256 ctx(key_m.data(), 32);
    ctx.Write((uint8_t*) &psmsg->timestamp, sizeof(psmsg->timestamp));
    ctx.Write((uint8_t*) psmsg->iv, sizeof(psmsg->iv));
    ctx.Write((uint8_t*) pPayload, nPayload);
    ctx.Finalize(MAC);

    if (part::memcmp_nta(MAC, psmsg->mac, 32) != 0) {
        LogPrint(BCLog::SMSG, "MAC does not match.\n"); // expected if message is not to address on node
        return SMSG_MAC_MISMATCH;
    }

    if (fTestOnly) {
        return SMSG_NO_ERROR;
    }

    SecMsgCrypter crypter;
    crypter.SetKey(key_e, psmsg->iv);
    std::vector<uint8_t> vchPayload;
    if (!crypter.Decrypt(pPayload, nPayload, vchPayload)) {
        return errorN(SMSG_GENERAL_ERROR, "%s: Decrypt failed.", __func__);
    }

    msg.timestamp = psmsg->timestamp;
    uint32_t lenData, lenPlain;

    uint8_t *pMsgData;
    bool fFromAnonymous;
    if ((uint32_t)vchPayload[0] == 250) {
        fFromAnonymous = true;
        lenData = vchPayload.size() - (9);
        memcpy(&lenPlain, &vchPayload[5], 4);
        pMsgData = &vchPayload[9];
    } else {
        fFromAnonymous = false;
        lenData = vchPayload.size() - (SMSG_PL_HDR_LEN);
        memcpy(&lenPlain, &vchPayload[1+20+65], 4);
        pMsgData = &vchPayload[SMSG_PL_HDR_LEN];
    }

    try {
        msg.vchMessage.resize(lenPlain + 1);
    } catch (std::exception &e) {
        return errorN(SMSG_ALLOCATE_FAILED, "%s: msg.vchMessage.resize %u threw: %s.", __func__, lenPlain + 1, e.what());
    }

    if (lenPlain > 128) {
        // Decompress
        if (LZ4_decompress_safe((char*) pMsgData, (char*) &msg.vchMessage[0], lenData, lenPlain) != (int) lenPlain) {
            return errorN(SMSG_GENERAL_ERROR, "%s: Could not decompress message data.", __func__);
        }
    } else {
        // Plaintext
        memcpy(&msg.vchMessage[0], pMsgData, lenPlain);
    }

    msg.vchMessage[lenPlain] = '\0';

    if (fFromAnonymous) {
        // Anonymous sender
        msg.sFromAddress = "anon";
    } else {
        std::vector<uint8_t> vchUint160;
        vchUint160.resize(20);

        memcpy(&vchUint160[0], &vchPayload[1], 20);

        uint160 ui160(vchUint160);
        CKeyID ckidFrom(ui160);

        CBitcoinAddress coinAddrFrom;
        coinAddrFrom.Set(ckidFrom);
        if (!coinAddrFrom.IsValid()) {
            return errorN(SMSG_INVALID_ADDRESS, "%s: From Address is invalid.", __func__);
        }

        std::vector<uint8_t> vchSig;
        vchSig.resize(65);

        memcpy(&vchSig[0], &vchPayload[1+20], 65);

        CPubKey cpkFromSig;
        cpkFromSig.RecoverCompact(Hash(msg.vchMessage.begin(), msg.vchMessage.end()-1), vchSig);
        if (!cpkFromSig.IsValid()) {
            return errorN(SMSG_GENERAL_ERROR, "%s: Signature validation failed.", __func__);
        }

        // Get address for the compressed public key
        CBitcoinAddress coinAddrFromSig;
        coinAddrFromSig.Set(cpkFromSig.GetID());

        if (!(coinAddrFrom == coinAddrFromSig)) {
            return errorN(SMSG_GENERAL_ERROR, "%s: Signature validation failed.", __func__);
        }

        int rv = SMSG_GENERAL_ERROR;
        try {
            rv = InsertAddress(ckidFrom, cpkFromSig);
        } catch (std::exception &e) {
            LogPrintf("%s, exception: %s.\n", __func__, e.what());
            //return 1;
        }

        if (rv != SMSG_NO_ERROR) {
            if (rv == SMSG_PUBKEY_EXISTS) {
                LogPrint(BCLog::SMSG, "%s: Sender public key not added to db, %s.\n", __func__, GetString(rv));
            } else {
                LogPrintf("%s: Sender public key not added to db, %s.\n", __func__, GetString(rv));
            }
        }

        msg.sFromAddress = coinAddrFrom.ToString();
    }

    if (LogAcceptCategory(BCLog::SMSG)) {
        LogPrintf("Decrypted message for %s.\n", EncodeDestination(PKHash(address)));
    }

    return SMSG_NO_ERROR;
};

int CSMSG::Decrypt(bool fTestOnly, const CKey &keyDest, const CKeyID &address, const SecureMessage &smsg, MessageData &msg)
{
    return CSMSG::Decrypt(fTestOnly, keyDest, address, smsg.data(), smsg.pPayload, smsg.nPayload, msg);
};

int CSMSG::Decrypt(bool fTestOnly, const CKeyID &address, const uint8_t *pHeader, const uint8_t *pPayload, uint32_t nPayload, MessageData &msg)
{
    // Fetch private key k, used to decrypt
    CKey keyDest;
    ReadSmsgKey(address, keyDest);

#ifdef ENABLE_WALLET
    if (!keyDest.IsValid()) {
        for (const auto &pw : smsgModule.m_vpwallets) {
            if (pw->IsLocked()) {
                if (pw->HaveKey(address)) {
                    return SMSG_WALLET_LOCKED;
                }
                continue;
            }
            pw->GetKey(address, keyDest);
            if (keyDest.IsValid()) {
                break;
            }
        }
    }
#endif
    if (!keyDest.IsValid()) {
        return errorN(SMSG_UNKNOWN_KEY, "%s: Could not get private key for addressDest.", __func__);
    }

    return CSMSG::Decrypt(fTestOnly, keyDest, address, pHeader, pPayload, nPayload, msg);
};

int CSMSG::Decrypt(bool fTestOnly, const CKeyID &address, const SecureMessage &smsg, MessageData &msg)
{
    return CSMSG::Decrypt(fTestOnly, address, smsg.data(), smsg.pPayload, smsg.nPayload, msg);
};

double GetDifficulty(uint32_t compact)
{
    int nShift = (compact >> 24) & 0xff;
    double dDiff =
        (double)0x00ffffff / (double)(compact & 0x00ffffff);

    while (nShift < 30)
    {
        dDiff *= 256.0;
        nShift++;
    }
    while (nShift > 30)
    {
        dDiff /= 256.0;
        nShift--;
    }

    return dDiff;
}

} // namespace smsg
