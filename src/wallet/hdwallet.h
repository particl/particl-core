// Copyright (c) 2017-2019 The Particl Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef PARTICL_WALLET_HDWALLET_H
#define PARTICL_WALLET_HDWALLET_H

#include <wallet/wallet.h>
#include <wallet/hdwalletdb.h>
#include <wallet/hdwallettypes.h>

#include <key_io.h>
#include <key/extkey.h>
#include <key/stealth.h>

static const size_t DEFAULT_STEALTH_LOOKAHEAD_SIZE = 5;

//! -fallbackfee default
static const CAmount DEFAULT_FALLBACK_FEE_PART = 20000;

typedef std::map<CKeyID, CStealthKeyMetadata> StealthKeyMetaMap;
typedef std::map<CKeyID, CExtKeyAccount*> ExtKeyAccountMap;
typedef std::map<CKeyID, CStoredExtKey*> ExtKeyMap;

typedef std::map<uint256, CWalletTx> MapWallet_t;

class UniValue;
typedef struct secp256k1_scratch_space_struct secp256k1_scratch_space;

struct CBlockTemplate;
class TxValidationState;

class CStoredTransaction
{
public:
    CTransactionRef tx;
    std::vector<std::pair<int, uint256> > vBlinds;

    bool InsertBlind(int n, const uint8_t *p)
    {
        for (auto &bp : vBlinds) {
            if (bp.first == n) {
                memcpy(bp.second.begin(), p, 32);
                return true;
            }
        }
        uint256 insert;
        memcpy(insert.begin(), p, 32);
        vBlinds.push_back(std::make_pair(n, insert));
        return true;
    }

    bool GetBlind(int n, uint8_t *p) const
    {
        for (auto &bp : vBlinds) {
            if (bp.first == n) {
                memcpy(p, bp.second.begin(), 32);
                return true;
            }
        }
        return false;
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action)
    {
        READWRITE(tx);
        READWRITE(vBlinds);
    }
};

class CHDWallet : public CWallet
{
public:
    CHDWallet(interfaces::Chain* chain, const WalletLocation& location, std::unique_ptr<WalletDatabase> dbw_in) : CWallet(chain, location, std::move(dbw_in))
    {
        m_default_address_type = OutputType::LEGACY; // In Particl segwit is enabled for all types
        m_fallback_fee = CFeeRate(DEFAULT_FALLBACK_FEE_PART);
        m_spk_man->m_particl = this;
    }

    ~CHDWallet()
    {
        Finalise();
    }

    bool IsParticlWallet() const override { return true; };

    int Finalise();
    int FreeExtKeyMaps();

    static void AddOptions();

    bool Initialise();

    bool ProcessStakingSettings(std::string &sError);
    bool ProcessWalletSettings(std::string &sError);

    /* Returns true if HD is enabled, and default account set */
    bool IsHDEnabled() const override;

    /* Returns true if the wallet's default account requires a hardware device to sign */
    bool IsHardwareLinkedWallet() const;

    /** Unsets a single wallet flag, returns false on fail */
    bool UnsetWalletFlagRV(CHDWalletDB *pwdb, uint64_t flag);

    bool DumpJson(UniValue &rv, std::string &sError);
    bool LoadJson(const UniValue &inj, std::string &sError);

    bool LoadAddressBook(CHDWalletDB *pwdb);

    bool LoadVoteTokens(CHDWalletDB *pwdb);
    bool GetVote(int nHeight, uint32_t &token);

    bool LoadTxRecords(CHDWalletDB *pwdb);

    bool IsLocked() const override;
    bool EncryptWallet(const SecureString &strWalletPassphrase) override;
    bool Lock() override;
    bool Unlock(const SecureString &strWalletPassphrase, bool accept_no_keys = false) override;
    size_t CountKeys() const;


    isminetype HaveAddress(const CTxDestination &dest);
    isminetype HaveKey(const CKeyID &address, const CEKAKey *&pak, const CEKASCKey *&pasc, CExtKeyAccount *&pa) const;
    isminetype IsMine(const CKeyID &address) const override;
    bool HaveKey(const CKeyID &address) const override;

    isminetype HaveExtKey(const CKeyID &keyID) const;
    bool GetExtKey(const CKeyID &keyID, CStoredExtKey &extKeyOut) const;

    bool HaveTransaction(const uint256 &txhash) const EXCLUSIVE_LOCKS_REQUIRED(cs_wallet);

    int GetKey(const CKeyID &address, CKey &keyOut, CExtKeyAccount *&pa, CEKAKey &ak, CKeyID &idStealth) const;
    bool GetKey(const CKeyID &address, CKey &keyOut) const override;
    bool GetPubKey(const CKeyID &address, CPubKey &pkOut) const override;
    bool GetKeyFromPool(CPubKey &key, bool internal = false) override;

    isminetype HaveStealthAddress(const CStealthAddress &sxAddr) const EXCLUSIVE_LOCKS_REQUIRED(cs_wallet);
    isminetype IsMine(const CStealthAddress &sxAddr, const CExtKeyAccount *&pa, const CEKAStealthKey *&pask) const EXCLUSIVE_LOCKS_REQUIRED(cs_wallet);
    bool GetStealthAddressScanKey(CStealthAddress &sxAddr) const;
    bool GetStealthAddressSpendKey(CStealthAddress &sxAddr, CKey &key) const;

    bool ImportStealthAddress(const CStealthAddress &sxAddr, const CKey &skSpend);

    DBErrors LoadWallet(bool& fFirstRunRet) override;

    bool AddressBookChangedNotify(const CTxDestination &address, ChangeType nMode);
    bool SetAddressBook(CHDWalletDB *pwdb, const CTxDestination &address, const std::string &strName,
        const std::string &purpose, const std::vector<uint32_t> &vPath, bool fNotifyChanged=true, bool fBech32=false);
    bool SetAddressBook(const CTxDestination &address, const std::string &strName, const std::string &strPurpose, bool fBech32=false) override;
    bool DelAddressBook(const CTxDestination &address) override;


    int64_t GetOldestActiveAccountTime();
    int64_t CountActiveAccountKeys();

    std::set< std::set<CTxDestination> > GetAddressGroupings() override EXCLUSIVE_LOCKS_REQUIRED(cs_wallet);
    std::map<CTxDestination, CAmount> GetAddressBalances(interfaces::Chain::Lock& locked_chain) override;

    using CWallet::IsMine;
    isminetype IsMine(const CTxIn& txin) const override;
    isminetype IsMine(const CScript &scriptPubKey, CKeyID &keyID,
        const CEKAKey *&pak, const CEKASCKey *&pasc, CExtKeyAccount *&pa, bool &isInvalid, SigVersion = SigVersion::BASE) const;

    isminetype IsMine(const CTxOutBase *txout) const override;
    bool IsMine(const CTransaction& tx) const override;
    bool IsFromMe(const CTransaction& tx) const override;


    /**
     * Returns amount of debit if the input matches the
     * filter, otherwise returns 0
     */
    CAmount GetDebit(const CTxIn& txin, const isminefilter& filter) const override;
    CAmount GetDebit(const CTransaction& tx, const isminefilter& filter) const override;
    CAmount GetDebit(CHDWalletDB *pwdb, const CTransactionRecord &rtx, const isminefilter& filter) const;

    /** Returns whether all of the inputs match the filter */
    bool IsAllFromMe(const CTransaction& tx, const isminefilter& filter) const override;

    CAmount GetCredit(const CTxOutBase *txout, const isminefilter &filter) const override;
    CAmount GetCredit(const CTransaction &tx, const isminefilter &filter) const override;

    void GetCredit(const CTransaction &tx, CAmount &nSpendable, CAmount &nWatchOnly) const;

    CAmount GetOutputValue(const COutPoint &op, bool fAllowTXIndex) const EXCLUSIVE_LOCKS_REQUIRED(cs_wallet);
    CAmount GetOwnedOutputValue(const COutPoint &op, isminefilter filter) const EXCLUSIVE_LOCKS_REQUIRED(cs_wallet);

    int GetDepthInMainChain(const CTransactionRecord &rtx) const EXCLUSIVE_LOCKS_REQUIRED(cs_wallet);
    bool InMempool(const uint256 &hash) const;
    bool IsTrusted(interfaces::Chain::Lock& locked_chain, const uint256 &txhash, const CTransactionRecord &rtx, int *depth_out = nullptr) const EXCLUSIVE_LOCKS_REQUIRED(cs_wallet);

    CAmount GetSpendableBalance() const; // Includes watch_only_cs balance
    CAmount GetBlindBalance();
    CAmount GetAnonBalance();
    CAmount GetStaked();

    Balance GetBalance(int min_depth = 0, bool avoid_reuse = true) const override;
    bool GetBalances(CHDWalletBalances &bal, bool avoid_reuse = true);
    CAmount GetAvailableBalance(const CCoinControl* coinControl = nullptr) const override;
    CAmount GetAvailableAnonBalance(const CCoinControl* coinControl = nullptr) const;
    CAmount GetAvailableBlindBalance(const CCoinControl* coinControl = nullptr) const;


    bool IsChange(const CTxOutBase *txout) const override;

    int GetChangeAddress(CPubKey &pk);

    void AddOutputRecordMetaData(CTransactionRecord &rtx, std::vector<CTempRecipient> &vecSend);
    int ExpandTempRecipients(std::vector<CTempRecipient> &vecSend, CStoredExtKey *pc, std::string &sError);

    int AddCTData(CTxOutBase *txout, CTempRecipient &r, std::string &sError) EXCLUSIVE_LOCKS_REQUIRED(cs_wallet);

    bool SetChangeDest(const CCoinControl *coinControl, CTempRecipient &r, std::string &sError);

    /** Update wallet after successful transaction */
    int PostProcessTempRecipients(std::vector<CTempRecipient> &vecSend);

    int AddStandardInputs(interfaces::Chain::Lock& locked_chain, CWalletTx &wtx, CTransactionRecord &rtx,
        std::vector<CTempRecipient> &vecSend,
        CExtKeyAccount *sea, CStoredExtKey *pc,
        bool sign, CAmount &nFeeRet, const CCoinControl *coinControl, std::string &sError);
    int AddStandardInputs(interfaces::Chain::Lock& locked_chain, CWalletTx &wtx, CTransactionRecord &rtx,
        std::vector<CTempRecipient> &vecSend, bool sign, CAmount &nFeeRet, const CCoinControl *coinControl, std::string &sError);

    int AddBlindedInputs(interfaces::Chain::Lock& locked_chain, CWalletTx &wtx, CTransactionRecord &rtx,
        std::vector<CTempRecipient> &vecSend,
        CExtKeyAccount *sea, CStoredExtKey *pc,
        bool sign, CAmount &nFeeRet, const CCoinControl *coinControl, std::string &sError);
    int AddBlindedInputs(interfaces::Chain::Lock& locked_chain, CWalletTx &wtx, CTransactionRecord &rtx,
        std::vector<CTempRecipient> &vecSend, bool sign, CAmount &nFeeRet, const CCoinControl *coinControl, std::string &sError);


    int PlaceRealOutputs(std::vector<std::vector<int64_t> > &vMI, size_t &nSecretColumn, size_t nRingSize, std::set<int64_t> &setHave,
        const std::vector<std::pair<MapRecords_t::const_iterator,unsigned int> > &vCoins, std::vector<uint8_t> &vInputBlinds, std::string &sError);
    int PickHidingOutputs(interfaces::Chain::Lock& locked_chain, std::vector<std::vector<int64_t> > &vMI, size_t nSecretColumn, size_t nRingSize, std::set<int64_t> &setHave,
        std::string &sError);

    int AddAnonInputs(interfaces::Chain::Lock& locked_chain, CWalletTx &wtx, CTransactionRecord &rtx,
        std::vector<CTempRecipient> &vecSend,
        CExtKeyAccount *sea, CStoredExtKey *pc,
        bool sign, size_t nRingSize, size_t nInputsPerSig, CAmount &nFeeRet, const CCoinControl *coinControl, std::string &sError);
    int AddAnonInputs(interfaces::Chain::Lock& locked_chain, CWalletTx &wtx, CTransactionRecord &rtx,
        std::vector<CTempRecipient> &vecSend, bool sign, size_t nRingSize, size_t nInputsPerSig, CAmount &nFeeRet, const CCoinControl *coinControl, std::string &sError);


    void ClearCachedBalances() override;
    void LoadToWallet(CWalletTx& wtxIn) override EXCLUSIVE_LOCKS_REQUIRED(cs_wallet);
    void LoadToWallet(const uint256 &hash, CTransactionRecord &rtx) EXCLUSIVE_LOCKS_REQUIRED(cs_wallet);

    /** Remove txn from mapwallet and TxSpends */
    void RemoveFromTxSpends(const uint256 &hash, const CTransactionRef pt) EXCLUSIVE_LOCKS_REQUIRED(cs_wallet);
    int UnloadTransaction(const uint256 &hash) EXCLUSIVE_LOCKS_REQUIRED(cs_wallet);

    int GetDefaultConfidentialChain(CHDWalletDB *pwdb, CExtKeyAccount *&sea, CStoredExtKey *&pc);

    int MakeDefaultAccount();

    int ExtKeyNew32(CExtKey &out);
    int ExtKeyNew32(CExtKey &out, const char *sPassPhrase, int32_t nHash, const char *sSeed);
    int ExtKeyNew32(CExtKey &out, uint8_t *data, uint32_t lenData);

    int ExtKeyImportLoose(CHDWalletDB *pwdb, CStoredExtKey &sekIn, CKeyID &idDerived, bool fBip44, bool fSaveBip44);
    int ExtKeyImportAccount(CHDWalletDB *pwdb, CStoredExtKey &sekIn, int64_t nCreatedAt, const std::string &sLabel);

    int ExtKeySetMaster(CHDWalletDB *pwdb, CKeyID &idMaster); // set master to existing key, remove master key tag from old key if exists
    int ExtKeyNewMaster(CHDWalletDB *pwdb, CKeyID &idMaster, bool fAutoGenerated = false); // make and save new root key to wallet

    int ExtKeyCreateAccount(CStoredExtKey *ekAccount, CKeyID &idMaster, CExtKeyAccount &ekaOut, const std::string &sLabel);
    int ExtKeyDeriveNewAccount(CHDWalletDB *pwdb, CExtKeyAccount *sea, const std::string &sLabel, const std::string &sPath=""); // derive a new account from the master key and save to wallet
    int ExtKeySetDefaultAccount(CHDWalletDB *pwdb, CKeyID &idNewDefault);

    int ExtKeyEncrypt(CStoredExtKey *sek, const CKeyingMaterial &vMKey, bool fLockKey);
    int ExtKeyEncrypt(CExtKeyAccount *sea, const CKeyingMaterial &vMKey, bool fLockKey);
    int ExtKeyEncryptAll(CHDWalletDB *pwdb, const CKeyingMaterial &vMKey);
    int ExtKeyLock();

    int ExtKeyUnlock(CExtKeyAccount *sea);
    int ExtKeyUnlock(CExtKeyAccount *sea, const CKeyingMaterial &vMKey);
    int ExtKeyUnlock(CStoredExtKey *sek);
    int ExtKeyUnlock(CStoredExtKey *sek, const CKeyingMaterial &vMKey);
    int ExtKeyUnlock(const CKeyingMaterial &vMKey) override;

    int ExtKeyLoadMaster();

    int ExtKeyLoadAccountKeys(CHDWalletDB *pwdb, CExtKeyAccount *sea);
    int ExtKeyLoadAccount(CHDWalletDB *pwdb, const CKeyID &idAccount);
    int ExtKeyLoadAccounts();

    int ExtKeySaveAccountToDB(CHDWalletDB *pwdb, const CKeyID &idAccount, CExtKeyAccount *sea);
    int ExtKeyAddAccountToMaps(const CKeyID &idAccount, CExtKeyAccount *sea, bool fAddToLookAhead = true);
    int ExtKeyRemoveAccountFromMapsAndFree(CExtKeyAccount *sea);
    int ExtKeyRemoveAccountFromMapsAndFree(const CKeyID &idAccount);
    int ExtKeyLoadAccountPacks();
    int PrepareLookahead();

    int ExtKeyAppendToPack(CHDWalletDB *pwdb, CExtKeyAccount *sea, const CKeyID &idKey, const CEKAKey &ak, bool &fUpdateAcc) const;
    int ExtKeyAppendToPack(CHDWalletDB *pwdb, CExtKeyAccount *sea, const CKeyID &idKey, const CEKASCKey &asck, bool &fUpdateAcc) const;

    int ExtKeySaveKey(CHDWalletDB *pwdb, CExtKeyAccount *sea, const CKeyID &keyId, const CEKAKey &ak) const;
    int ExtKeySaveKey(CExtKeyAccount *sea, const CKeyID &keyId, const CEKAKey &ak) const;

    int ExtKeySaveKey(CHDWalletDB *pwdb, CExtKeyAccount *sea, const CKeyID &keyId, const CEKASCKey &asck) const;
    int ExtKeySaveKey(CExtKeyAccount *sea, const CKeyID &keyId, const CEKASCKey &asck) const;

    int ExtKeyUpdateStealthAddress(CHDWalletDB *pwdb, CExtKeyAccount *sea, CKeyID &sxId, std::string &sLabel);

    /**
     * Create an index db record for idKey
     */
    int ExtKeyNewIndex(CHDWalletDB *pwdb, const CKeyID &idKey, uint32_t &index);
    int ExtKeyGetIndex(CHDWalletDB *pwdb, CExtKeyAccount *sea, uint32_t &index, bool &fUpdate);
    int ExtKeyGetIndex(CExtKeyAccount *sea, uint32_t &index);

    int NewKeyFromAccount(CHDWalletDB *pwdb, const CKeyID &idAccount, CPubKey &pkOut, bool fInternal, bool fHardened, bool f256bit=false, bool fBech32=false, const char *plabel=nullptr);
    int NewKeyFromAccount(CPubKey &pkOut, bool fInternal=false, bool fHardened=false, bool f256bit=false, bool fBech32=false, const char *plabel=nullptr); // wrapper - use default account

    int NewStealthKeyFromAccount(CHDWalletDB *pwdb, const CKeyID &idAccount, const std::string &sLabel, CEKAStealthKey &akStealthOut, uint32_t nPrefixBits, const char *pPrefix, bool fBech32=false, uint32_t *pscankey_num=nullptr) EXCLUSIVE_LOCKS_REQUIRED(cs_wallet);
    int NewStealthKeyFromAccount(const std::string &sLabel, CEKAStealthKey &akStealthOut, uint32_t nPrefixBits, const char *pPrefix, bool fBech32=false); // wrapper - use default account

    int InitAccountStealthV2Chains(CHDWalletDB *pwdb, CExtKeyAccount *sea);
    int SaveStealthAddress(CHDWalletDB *pwdb, CExtKeyAccount *sea, const CEKAStealthKey &akStealth, bool fBech32) EXCLUSIVE_LOCKS_REQUIRED(cs_wallet);
    int NewStealthKeyV2FromAccount(CHDWalletDB *pwdb, const CKeyID &idAccount, const std::string &sLabel, CEKAStealthKey &akStealthOut, uint32_t nPrefixBits, const char *pPrefix, bool fBech32=false, uint32_t *pscankey_num=nullptr, uint32_t *pspendkey_num=nullptr) EXCLUSIVE_LOCKS_REQUIRED(cs_wallet);
    int NewStealthKeyV2FromAccount(const std::string &sLabel, CEKAStealthKey &akStealthOut, uint32_t nPrefixBits, const char *pPrefix, bool fBech32=false); // wrapper - use default account

    int NewExtKeyFromAccount(CHDWalletDB *pwdb, const CKeyID &idAccount, std::string &sLabel, CStoredExtKey *sekOut, const char *plabel=nullptr, const uint32_t *childNo=nullptr, bool fHardened=false, bool fBech32=false) EXCLUSIVE_LOCKS_REQUIRED(cs_wallet);
    int NewExtKeyFromAccount(std::string &sLabel, CStoredExtKey *sekOut, const char *plabel=nullptr, const uint32_t *childNo=nullptr, bool fHardened=false, bool fBech32=false); // wrapper - use default account

    int ExtKeyGetDestination(const CExtKeyPair &ek, CPubKey &pkDest, uint32_t &nKey);
    int ExtKeyUpdateLooseKey(const CExtKeyPair &ek, uint32_t nKey, bool fAddToAddressBook) EXCLUSIVE_LOCKS_REQUIRED(cs_wallet);

    bool GetFullChainPath(const CExtKeyAccount *pa, size_t nChain, std::vector<uint32_t> &vPath) const;

    /**
     * Insert additional inputs into the transaction by
     * calling CreateTransaction();
     */
    bool FundTransaction(CMutableTransaction& tx, CAmount& nFeeRet, int& nChangePosInOut, std::string& strFailReason, bool lockUnspents, const std::set<int>& setSubtractFeeFromOutputs, CCoinControl) override;
    bool SignTransaction(CMutableTransaction& tx) override EXCLUSIVE_LOCKS_REQUIRED(cs_wallet);

    bool CreateTransaction(interfaces::Chain::Lock& locked_chain, const std::vector<CRecipient>& vecSend, CTransactionRef& tx, CAmount& nFeeRet, int& nChangePosInOut,
                           std::string& strFailReason, const CCoinControl& coin_control, bool sign = true) override;
    bool CreateTransaction(interfaces::Chain::Lock& locked_chain, std::vector<CTempRecipient>& vecSend, CTransactionRef& tx, CAmount& nFeeRet, int& nChangePosInOut,
                           std::string& strFailReason, const CCoinControl& coin_control, bool sign = true);
    void CommitTransaction(CTransactionRef tx, mapValue_t mapValue, std::vector<std::pair<std::string, std::string>> orderForm) override;
    bool CommitTransaction(CWalletTx &wtxNew, CTransactionRecord &rtx, TxValidationState &state);

    bool DummySignInput(CTxIn &tx_in, const CTxOut &txout, bool use_max_sig = false) const override;

    bool DummySignInput(CTxIn &tx_in, const CTxOutBaseRef &txout) const;
    bool DummySignTx(CMutableTransaction &txNew, const std::vector<CTxOutBaseRef> &txouts) const;

    int LoadStealthAddresses();
    int LoadMasterKeys();
    bool IndexStealthKey(CHDWalletDB *pwdb, uint160 &hash, const CStealthAddressIndexed &sxi, uint32_t &id);
    bool GetStealthKeyIndex(const CStealthAddressIndexed &sxi, uint32_t &id);
    bool UpdateStealthAddressIndex(const CKeyID &idK, const CStealthAddressIndexed &sxi, uint32_t &id); // Get stealth index or create new index if none found
    bool GetStealthByIndex(uint32_t sxId, CStealthAddress &sx) const;
    bool GetStealthLinked(const CKeyID &idK, CStealthAddress &sx) const;
    bool ProcessLockedStealthOutputs();
    bool ProcessLockedBlindedOutputs();
    bool CountRecords(std::string sPrefix, int64_t rv);

    void ProcessStealthLookahead(CExtKeyAccount *ea, const CEKAStealthKey &aks, bool v2) EXCLUSIVE_LOCKS_REQUIRED(cs_wallet);
    bool ProcessStealthOutput(const CTxDestination &address,
        std::vector<uint8_t> &vchEphemPK, uint32_t prefix, bool fHavePrefix, CKey &sShared, bool fNeedShared=false);

    int CheckForStealthAndNarration(const CTxOutBase *pb, const CTxOutData *pdata, std::string &sNarr);
    bool FindStealthTransactions(const CTransaction &tx, mapValue_t &mapNarr);

    bool ScanForOwnedOutputs(const CTransaction &tx, size_t &nCT, size_t &nRingCT, mapValue_t &mapNarr);

    int UnloadSpent(const uint256 &wtxid, int depth, const uint256 &wtxid_from);
    void PostProcessUnloadSpent();

    using CWallet::AddToSpends;
    void AddToSpends(const uint256& wtxid) override EXCLUSIVE_LOCKS_REQUIRED(cs_wallet);
    bool AddToWalletIfInvolvingMe(const CTransactionRef& ptx, CWalletTx::Confirmation confirm, bool fUpdate) override EXCLUSIVE_LOCKS_REQUIRED(cs_wallet);

    CWalletTx *GetTempWalletTx(const uint256& hash);

    const CWalletTx *GetWalletTx(const uint256& hash) const override;
    CWalletTx *GetWalletTx(const uint256& hash);

    void SetTempTxnStatus(CWalletTx &wtx, const CTransactionRecord *rtx) const;
    int InsertTempTxn(const uint256 &txid, const CTransactionRecord *rtx) const;
    const CWalletTx *GetWalletOrTempTx(const uint256& hash, const CTransactionRecord *rtx) const;

    int OwnStandardOut(const CTxOutStandard *pout, const CTxOutData *pdata, COutputRecord &rout, bool &fUpdated);
    int OwnBlindOut(CHDWalletDB *pwdb, const uint256 &txhash, const CTxOutCT *pout, const CStoredExtKey *pc, uint32_t &nLastChild,
        COutputRecord &rout, CStoredTransaction &stx, bool &fUpdated);
    int OwnAnonOut(CHDWalletDB *pwdb, const uint256 &txhash, const CTxOutRingCT *pout, const CStoredExtKey *pc, uint32_t &nLastChild,
        COutputRecord &rout, CStoredTransaction &stx, bool &fUpdated);

    bool AddTxinToSpends(const CTxIn &txin, const uint256 &txhash);

    bool ProcessPlaceholder(CHDWalletDB *pwdb, const CTransaction &tx, CTransactionRecord &rtx);
    bool AddToRecord(CTransactionRecord &rtxIn, const CTransaction &tx, CWalletTx::Confirmation confirm, bool fFlushOnClose=true);

    ScanResult ScanForWalletTransactions(const uint256& first_block, const uint256& last_block, const WalletRescanReserver& reserver, bool fUpdate) override;
    std::vector<uint256> ResendRecordTransactionsBefore(int64_t nTime);
    void ResendWalletTransactions() override;

    /**
     * populate vCoins with vector of available COutputs.
     */
    void AvailableCoins(interfaces::Chain::Lock& locked_chain, std::vector<COutput>& vCoins, bool fOnlySafe=true, const CCoinControl *coinControl = nullptr, const CAmount& nMinimumAmount = 1, const CAmount& nMaximumAmount = MAX_MONEY, const CAmount& nMinimumSumAmount = MAX_MONEY, const uint64_t nMaximumCount = 0) const override EXCLUSIVE_LOCKS_REQUIRED(cs_wallet);
    bool SelectCoins(const std::vector<COutput>& vAvailableCoins, const CAmount& nTargetValue, std::set<CInputCoin>& setCoinsRet, CAmount& nValueRet,
        const CCoinControl& coin_control, CoinSelectionParams& coin_selection_params, bool& bnb_used) const override EXCLUSIVE_LOCKS_REQUIRED(cs_wallet);

    void AvailableBlindedCoins(interfaces::Chain::Lock& locked_chain, std::vector<COutputR>& vCoins, bool fOnlySafe=true, const CCoinControl *coinControl = nullptr, const CAmount& nMinimumAmount = 1, const CAmount& nMaximumAmount = MAX_MONEY, const CAmount& nMinimumSumAmount = MAX_MONEY, const uint64_t& nMaximumCount = 0) const EXCLUSIVE_LOCKS_REQUIRED(cs_wallet);
    bool SelectBlindedCoins(const std::vector<COutputR>& vAvailableCoins, const CAmount& nTargetValue, std::vector<std::pair<MapRecords_t::const_iterator,unsigned int> > &setCoinsRet, CAmount &nValueRet, const CCoinControl *coinControl = nullptr, bool random_selection = false) const EXCLUSIVE_LOCKS_REQUIRED(cs_wallet);

    void AvailableAnonCoins(interfaces::Chain::Lock& locked_chain, std::vector<COutputR> &vCoins, bool fOnlySafe=true, const CCoinControl *coinControl = nullptr, const CAmount& nMinimumAmount = 1, const CAmount& nMaximumAmount = MAX_MONEY, const CAmount& nMinimumSumAmount = MAX_MONEY, const uint64_t& nMaximumCount = 0) const EXCLUSIVE_LOCKS_REQUIRED(cs_wallet);

    /**
     * Return list of available coins and locked coins grouped by non-change output address.
     */
    const CTxOutBase* FindNonChangeParentOutput(const CTransaction& tx, int output) const EXCLUSIVE_LOCKS_REQUIRED(cs_wallet);
    std::map<CTxDestination, std::vector<COutput>> ListCoins(interfaces::Chain::Lock& locked_chain) const override EXCLUSIVE_LOCKS_REQUIRED(cs_wallet);
    std::map<CTxDestination, std::vector<COutputR>> ListCoins(interfaces::Chain::Lock& locked_chain, OutputTypes nType) const EXCLUSIVE_LOCKS_REQUIRED(cs_wallet);

    bool SelectCoinsMinConf(const CAmount& nTargetValue, const CoinEligibilityFilter& eligibility_filter, std::vector<COutputR> vCoins, std::vector<std::pair<MapRecords_t::const_iterator,unsigned int> > &setCoinsRet, CAmount &nValueRet) const;

    bool IsSpent(const uint256& hash, unsigned int n) const override EXCLUSIVE_LOCKS_REQUIRED(cs_wallet);

    // Whether this or any UTXO with the same CTxDestination has been spent.
    using CWallet::IsUsedDestination;
    bool IsUsedDestination(const CScript *pscript) const;
    bool IsUsedDestination(const uint256& hash, unsigned int n) const override;
    void SetUsedDestinationState(const CScript *pscript, bool used);
    void SetUsedDestinationState(const uint256& hash, unsigned int n, bool used);
    void SetUsedDestinationState(WalletBatch& batch, const uint256& hash, unsigned int n, bool used) override;


    std::set<uint256> GetConflicts(const uint256 &txid) const;

    /* Mark a transaction (and it in-wallet descendants) as abandoned so its inputs may be respent. */
    bool AbandonTransaction(const uint256 &hashTx) override;

    void MarkConflicted(const uint256 &hashBlock, int conflicting_height, const uint256 &hashTx) override;
    void SyncMetaData(std::pair<TxSpends::iterator, TxSpends::iterator>) override EXCLUSIVE_LOCKS_REQUIRED(cs_wallet);

    bool GetSetting(const std::string &setting, UniValue &json);
    bool SetSetting(const std::string &setting, const UniValue &json);
    bool EraseSetting(const std::string &setting);

    int64_t GetTimeFirstKey();

    /* Return a prevout if it exists in the wallet. */
    bool GetPrevout(const COutPoint &prevout, CTxOutBaseRef &txout) EXCLUSIVE_LOCKS_REQUIRED(cs_wallet);

    size_t CountColdstakeOutputs();

    /* Return a script for a simple address type (normal/extended) */
    bool GetScriptForAddress(CScript &script, const CBitcoinAddress &addr, bool fUpdate = false, std::vector<uint8_t> *vData = NULL, bool allow_stakeonly = false);

    bool SetReserveBalance(CAmount nNewReserveBalance);
    uint64_t GetStakeWeight() const;
    void AvailableCoinsForStaking(std::vector<COutput> &vCoins, int64_t nTime, int nHeight) const;
    bool SelectCoinsForStaking(int64_t nTargetValue, int64_t nTime, int nHeight, std::set<std::pair<const CWalletTx*,unsigned int> >& setCoinsRet, int64_t& nValueRet) const;
    bool CreateCoinStake(unsigned int nBits, int64_t nTime, int nBlockHeight, int64_t nFees, CMutableTransaction &txNew, CKey &key);
    bool SignBlock(CBlockTemplate *pblocktemplate, int nHeight, int64_t nSearchTime);

    boost::signals2::signal<void (CAmount nReservedBalance)> NotifyReservedBalanceChanged;

    size_t CountTxSpends() EXCLUSIVE_LOCKS_REQUIRED(cs_wallet) { return mapTxSpends.size(); };

    int64_t nLastCoinStakeSearchTime = 0;
    uint32_t nStealth, nFoundStealth; // for reporting, zero before use
    int64_t nReserveBalance = 0;
    size_t nStakeThread = 9999999; // unset

    mutable int m_greatest_txn_depth = 0; // depth of most deep txn
    //mutable int m_least_txn_depth = 0; // depth of least deep txn
    mutable std::atomic_bool m_have_spendable_balance_cached {false};
    mutable CAmount m_spendable_balance_cached = 0;

    enum eStakingState {
        NOT_STAKING = 0,
        IS_STAKING = 1,
        NOT_STAKING_BALANCE = -1,
        NOT_STAKING_DEPTH = -2,
        NOT_STAKING_LOCKED = -3,
        NOT_STAKING_LIMITED = -4,
        NOT_STAKING_DISABLED = -5,
    };
    std::atomic<eStakingState> m_is_staking {NOT_STAKING};

    std::set<CStealthAddress> stealthAddresses;

    CStoredExtKey *pEKMaster = nullptr;
    CKeyID idDefaultAccount;
    ExtKeyAccountMap mapExtAccounts;
    ExtKeyMap mapExtKeys;

    mutable MapWallet_t mapTempWallet;

    MapRecords_t mapRecords;
    RtxOrdered_t rtxOrdered;
    mutable MapRecords_t mapTempRecords; // Hack for sending unmined inputs through fundrawtransactionfrom

    std::vector<CVoteToken> vVoteTokens;

    // Staking Settings
    std::atomic<bool> fStakingEnabled{false};
    CAmount nStakeCombineThreshold;
    CAmount nStakeSplitThreshold;
    size_t nMaxStakeCombine = 3;
    int nWalletDevFundCedePercent;
    CBitcoinAddress rewardAddress;
    int nStakeLimitHeight = 0; // for regtest, don't stake above nStakeLimitHeight

    mutable std::atomic_bool m_have_cached_stakeable_coins {false};
    mutable std::vector<COutput> m_cached_stakeable_coins;

    bool fUnlockForStakingOnly = false; // Use coldstaking instead

    int64_t nRCTOutSelectionGroup1 = 5000;
    int64_t nRCTOutSelectionGroup2 = 50000;
    size_t prefer_max_num_anon_inputs = 5; // if > x anon inputs are randomly selected attempt to reduce
    int m_mixin_selection_mode = 1;
    secp256k1_scratch_space *m_blind_scratch = nullptr;

    int m_collapse_spent_mode = 0;
    int m_min_collapse_depth = 3;
    std::map<uint256, std::set<uint256> > mapTxCollapsedSpends;
    std::set<uint256> m_collapsed_txns;
    std::set<COutPoint> m_collapsed_txn_inputs;

    int64_t m_smsg_fee_rate_target = 0;
    uint32_t m_smsg_difficulty_target = 0; // 0 = auto
    bool m_is_only_instance = true; // Set to false if spends can happen in a different wallet

    size_t m_rescan_stealth_v1_lookahead = DEFAULT_STEALTH_LOOKAHEAD_SIZE;
    size_t m_rescan_stealth_v2_lookahead = DEFAULT_STEALTH_LOOKAHEAD_SIZE;

    bool m_smsg_enabled = true;

private:
    void ParseAddressForMetaData(const CTxDestination &addr, COutputRecord &rec);

    template<typename... Params>
    bool werror(std::string fmt, Params... parameters) const {
        return error(("%s " + fmt).c_str(), GetDisplayName(), parameters...);
    }
    template<typename... Params>
    int werrorN(int rv, std::string fmt, Params... parameters) const {
        return errorN(rv, ("%s " + fmt).c_str(), GetDisplayName(), parameters...);
    }
    template<typename... Params>
    int wserrorN(int rv, std::string &s, const char *func, std::string fmt, Params... parameters) const {
        return errorN(rv, s, func, ("%s " + fmt).c_str(), GetDisplayName(), parameters...);
    }
};


class LoopExtKeyCallback
{
public:
    CHDWallet *pwallet = nullptr;

    // NOTE: the key and account instances passed to Process are temporary
    virtual int ProcessKey(CKeyID &id, CStoredExtKey &sek) {return 1;};
    virtual int ProcessAccount(CKeyID &id, CExtKeyAccount &sek) {return 1;};
};

int LoopExtKeysInDB(CHDWallet *pwallet, bool fInactive, bool fInAccount, LoopExtKeyCallback &callback);
int LoopExtAccountsInDB(CHDWallet *pwallet, bool fInactive, LoopExtKeyCallback &callback);

bool CheckOutputValue(interfaces::Chain& chain, const CTempRecipient &r, const CTxOutBase *txbout, CAmount nFeeRet, std::string &sError);
int CreateOutput(OUTPUT_PTR<CTxOutBase> &txbout, CTempRecipient &r, std::string &sError);
void ExtractNarration(const uint256 &nonce, const std::vector<uint8_t> &vData, std::string &sNarr);

// Calculate the size of the transaction assuming all signatures are max size
// Use DummySignatureCreator, which inserts 72 byte signatures everywhere.
// NOTE: this requires that all inputs must be in mapWallet (eg the tx should
// be IsAllFromMe).
int64_t CalculateMaximumSignedTxSize(const CTransaction &tx, const CHDWallet *wallet) EXCLUSIVE_LOCKS_REQUIRED(wallet->cs_wallet);
int64_t CalculateMaximumSignedTxSize(const CTransaction &tx, const CHDWallet *wallet, const std::vector<CTxOutBaseRef>& txouts);

void RestartStakingThreads();

bool IsParticlWallet(const WalletStorage *win);
CHDWallet *GetParticlWallet(WalletStorage *win);
const CHDWallet *GetParticlWallet(const WalletStorage *win);


#endif // PARTICL_WALLET_HDWALLET_H

