// Copyright (c) 2017-2019 The Particl Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef PARTICL_WALLET_HDWALLETTYPES_H
#define PARTICL_WALLET_HDWALLETTYPES_H

#include <key_io.h>
#include <key/extkey.h>
#include <key/stealth.h>
#include <amount.h>
#include <serialize.h>

#include <stdint.h>
#include <map>
#include <vector>
#include <string>

class CTransactionRecord;

typedef std::map<uint256, CTransactionRecord> MapRecords_t;
typedef std::map<uint8_t, std::vector<uint8_t> > mapRTxValue_t;
typedef std::multimap<int64_t, std::map<uint256, CTransactionRecord>::iterator> RtxOrdered_t;

const uint16_t OR_PLACEHOLDER_N = 0xFFFF; // index of a fake output to contain reconstructed amounts for txns with undecodeable outputs

extern const uint256 ABANDON_HASH;

enum OutputRecordFlags
{
    ORF_OWNED               = (1 << 0),
    ORF_FROM                = (1 << 1),
    ORF_CHANGE              = (1 << 2),
    ORF_SPENT               = (1 << 3),
    ORF_LOCKED              = (1 << 4), // Needs wallet to be unlocked for further processing
    ORF_STAKEONLY           = (1 << 5),
    ORF_WATCHONLY           = (1 << 6),
    ORF_HARDWARE_DEVICE     = (1 << 7),

    ORF_OWN_WATCH           = ORF_STAKEONLY | ORF_WATCHONLY,
    ORF_OWN_ANY             = ORF_OWNED | ORF_OWN_WATCH,

    ORF_BLIND_IN            = (1 << 14),
    ORF_ANON_IN             = (1 << 15),
};

enum OutputRecordAddressTypes
{
    ORA_EXTKEY       = 1,
    ORA_STEALTH      = 2,
    ORA_STANDARD     = 3,
};

enum RTxAddonValueTypes
{
    RTXVT_EPHEM_PATH            = 1, // path ephemeral keys are derived from packed 4bytes no separators

    RTXVT_REPLACES_TXID         = 2,
    RTXVT_REPLACED_BY_TXID      = 3,

    RTXVT_COMMENT               = 4,
    RTXVT_TO                    = 5,

    /*
    RTXVT_STEALTH_KEYID     = 2,
    RTXVT_STEALTH_KEYID_N   = 3, // n0:pk0:n1:pk1:...
    */
};

class COutputRecord
{
public:
    COutputRecord() : nType(0), nFlags(0), n(0), nValue(-1) {};
    uint8_t nType;
    uint8_t nFlags;
    uint16_t n;
    CAmount nValue;
    CScript scriptPubKey;
    std::string sNarration;

    /*
    vPath 0 - ORA_EXTKEY
        1 - index to m
        2... path

    vPath 0 - ORA_STEALTH
        [1, 21] stealthkeyid
        [22, 55] pubkey (if not using ephemkey)

    vPath 0 - ORA_STANDARD
        [1, 34] pubkey
    */
    std::vector<uint8_t> vPath; // index to m is stored in first entry

    ADD_SERIALIZE_METHODS;
    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream &s, Operation ser_action)
    {
        READWRITE(nType);
        READWRITE(nFlags);
        READWRITE(n);
        READWRITE(nValue);
        READWRITE(*(CScriptBase*)(&scriptPubKey));
        READWRITE(sNarration);
        READWRITE(vPath);
    }
};

class CTransactionRecord
{
// Stored by uint256 txnHash;
public:
    // Conflicted state is marked by set blockHash and nIndex -1
    uint256 blockHash;
    int block_height = 0;
    int16_t nFlags = 0;
    int16_t nIndex = 0;

    int64_t nBlockTime = 0;
    int64_t nTimeReceived = 0;
    CAmount nFee = 0;
    mapRTxValue_t mapValue;

    std::vector<COutPoint> vin;
    std::vector<COutputRecord> vout;

    int InsertOutput(COutputRecord &r);
    bool EraseOutput(uint16_t n);

    COutputRecord *GetOutput(int n);
    const COutputRecord *GetOutput(int n) const;
    const COutputRecord *GetChangeOutput() const;

    void SetMerkleBranch(const uint256 &blockHash_, int posInBlock)
    {
        blockHash = blockHash_;
        nIndex = posInBlock;
    }

    bool IsAbandoned() const { return (blockHash == ABANDON_HASH); }
    bool isConflicted() const { return (nIndex == -1); }
    bool HashUnset() const { return (blockHash.IsNull() || blockHash == ABANDON_HASH); }

    void SetAbandoned()
    {
        blockHash = ABANDON_HASH;
    }

    int64_t GetTxTime() const
    {
        if (HashUnset() || nIndex < 0) {
            return nTimeReceived;
        }
        return std::min(nTimeReceived, nBlockTime);
    }

    bool HaveChange() const
    {
        for (const auto &r : vout) {
            if (r.nFlags & ORF_CHANGE) {
                return true;
            }
        }
        return false;
    }

    CAmount TotalOutput()
    {
        CAmount nTotal = 0;
        for (const auto &r : vout) {
            nTotal += r.nValue;
        }
        return nTotal;
    }

    bool InMempool() const;
    bool IsCoinBase() const {return false;};
    bool IsCoinStake() const {return false;};

    ADD_SERIALIZE_METHODS;
    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream &s, Operation ser_action)
    {
        READWRITE(blockHash);
        READWRITE(nFlags);
        READWRITE(nIndex);
        READWRITE(nBlockTime);
        READWRITE(nTimeReceived);
        READWRITE(mapValue);
        READWRITE(nFee);
        READWRITE(vin);
        READWRITE(vout);
    }
};

class CTempRecipient
{
public:
    CTempRecipient() : nType(0), nAmount(0), nAmountSelected(0), fSubtractFeeFromAmount(false) {SetNull();};
    CTempRecipient(CAmount nAmount_, bool fSubtractFeeFromAmount_, CScript scriptPubKey_)
        : nAmount(nAmount_), nAmountSelected(nAmount_), fSubtractFeeFromAmount(fSubtractFeeFromAmount_), scriptPubKey(scriptPubKey_) {SetNull();};

    void SetNull()
    {
        fScriptSet = false;
        fChange = false;
        fNonceSet = false; // if true use nonce and vData from CTempRecipient
        nChildKey = 0;
        nChildKeyColdStaking = 0;
        nStealthPrefix = 0;
        fSplitBlindOutput = false;
        fExemptFeeSub = false;
    }

    void SetAmount(CAmount nValue)
    {
        nAmount = nValue;
        nAmountSelected = nValue;
    }

    bool ApplySubFee(CAmount nFee, size_t nSubtractFeeFromAmount, bool &fFirst);

    uint8_t nType;
    CAmount nAmount;            // If fSubtractFeeFromAmount, nAmount = nAmountSelected - feeForOutput
    CAmount nAmountSelected;
    bool fSubtractFeeFromAmount;
    bool fSplitBlindOutput;
    bool fExemptFeeSub;         // Value too low to sub fee when blinded value split into two outputs
    CTxDestination address;
    CTxDestination addressColdStaking;
    CScript scriptPubKey;
    std::vector<uint8_t> vData;
    std::vector<uint8_t> vBlind;
    std::vector<uint8_t> vRangeproof;
    secp256k1_pedersen_commitment commitment;
    uint256 nonce;

    // TODO: range proof parameters, try to keep similar for fee
    // Allow an overwrite of the parameters.
    bool fOverwriteRangeProofParams = false;
    uint64_t min_value;
    int ct_exponent;
    int ct_bits;        // set to 0 to mark bulletproof

    CKey sEphem;
    CPubKey pkTo;
    int n;
    std::string sNarration;
    bool fScriptSet;
    bool fChange;
    bool fNonceSet;
    uint32_t nChildKey; // update later
    uint32_t nChildKeyColdStaking; // update later
    uint32_t nStealthPrefix;
};

class COutputR
{
public:
    COutputR() {};

    COutputR(const uint256 &txhash_, MapRecords_t::const_iterator rtx_, int i_, int nDepth_,
        bool fSpendable_, bool fSolvable_, bool fSafe_, bool fMature_, bool fNeedHardwareKey_)
        : txhash(txhash_), rtx(rtx_), i(i_), nDepth(nDepth_),
        fSpendable(fSpendable_), fSolvable(fSolvable_), fSafe(fSafe_), fMature(fMature_), fNeedHardwareKey(fNeedHardwareKey_) {};

    uint256 txhash;
    MapRecords_t::const_iterator rtx;
    int i;
    int nDepth;
    bool fSpendable;
    bool fSolvable;
    bool fSafe;
    bool fMature;
    bool fNeedHardwareKey;
};

class CHDWalletBalances
{
public:
    CAmount nPart = 0;
    CAmount nPartUnconf = 0;
    CAmount nPartStaked = 0;
    CAmount nPartImmature = 0;
    CAmount nPartWatchOnly = 0;
    CAmount nPartWatchOnlyUnconf = 0;
    CAmount nPartWatchOnlyStaked = 0;
    CAmount nPartWatchOnlyImmature = 0;

    CAmount nBlind = 0;
    CAmount nBlindUnconf = 0;

    CAmount nAnon = 0;
    CAmount nAnonUnconf = 0;
    CAmount nAnonImmature = 0;

    //CAmount nPartUsed = 0;
    //CAmount nBlindUsed = 0;
};

#endif // PARTICL_WALLET_HDWALLETTYPES_H

