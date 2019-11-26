// Copyright (c) 2017-2019 The Particl Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <wallet/hdwallet.h>

#include <wallet/test/hdwallet_test_fixture.h>
#include <base58.h>
#include <chainparams.h>
#include <smsg/smessage.h>
#include <smsg/crypter.h>
#include <blind.h>
#include <primitives/transaction.h>
#include <consensus/tx_verify.h>
#include <consensus/validation.h>
#include <wallet/ismine.h>
#include <policy/policy.h>

#include <boost/test/unit_test.hpp>

extern bool CheckAnonOutput(TxValidationState &state, const CTxOutRingCT *p);
extern void SetCTOutVData(std::vector<uint8_t> &vData, CPubKey &pkEphem, const CTempRecipient &r);

BOOST_FIXTURE_TEST_SUITE(hdwallet_tests, HDWalletTestingSetup)

class Test1
{
public:
    Test1(std::string s1, std::string s2, int nH, std::string s3) : sPassphrase(s1), sSeed(s2), nHash(nH), sOutput(s3) {};
    std::string sPassphrase;
    std::string sSeed;
    int nHash;
    std::string sOutput;
};


std::vector<Test1> vTestVector1 = {
    Test1("crazy horse battery staple", "Bitcoin seed", 50000, "xprv9s21ZrQH143K2JF8RafpqtKiTbsbaxEeUaMnNHsm5o6wCW3z8ySyH4UxFVSfZ8n7ESu7fgir8imbZKLYVBxFPND1pniTZ81vKfd45EHKX73"),
    Test1("doesn'tneedtobewords",       "Bitcoin seed", 50000, "xprv9s21ZrQH143K24uheQvx9etuBgxXfGZrBuHdmmZXQ1Gv9n1sXE2BE85PHRmSFixb1i8ngZFV6n4mufebUEg55n1epDFsFXKhQ4abU7gvThb")
};

static void AddKey(CWallet& wallet, const CKey& key)
{
    LOCK(wallet.m_spk_man->cs_wallet);
    wallet.m_spk_man->AddKeyPubKey(key, key.GetPubKey());
}

BOOST_AUTO_TEST_CASE(new_ext_key)
{
    // Match keys from http://bip32.org/

    CHDWallet *pwallet = pwalletMain.get();

    for (auto it = vTestVector1.begin(); it != vTestVector1.end(); ++it) {
        CExtKey ekTest;

        BOOST_CHECK(0 == pwallet->ExtKeyNew32(ekTest, it->sPassphrase.c_str(), it->nHash, it->sSeed.c_str()));

        CExtKeyPair ekp(ekTest);
        CExtKey58 ek58;
        ek58.SetKey(ekp, CChainParams::EXT_SECRET_KEY_BTC);
        BOOST_CHECK(ek58.ToString() == it->sOutput);
    }
}

static const std::string strSecret1C("GzFRfngjf5aHMuAzWDZWzJ8eYqMzp29MmkCp6NgzkXFibrh45tTc");
static const std::string strSecret2C("H5hDgLvFjLcZG9jyxkUTJ28P6N5T7iMBQ79boMuaPafxXuy8hb9n");

BOOST_AUTO_TEST_CASE(stealth)
{
    CHDWallet *pwallet = pwalletMain.get();

    CStealthAddress sx;
    BOOST_CHECK(true == sx.SetEncoded("SPGyji8uZFip6H15GUfj6bsutRVLsCyBFL3P7k7T7MUDRaYU8GfwUHpfxonLFAvAwr2RkigyGfTgWMfzLAAP8KMRHq7RE8cwpEEekH"));

    CAmount nValue = 1;
    std::string strError, sNarr;

    auto locked_chain = pwallet->chain().lock();
    LockAssertion lock(::cs_main);

    // No bitfield, no narration
    std::vector<CTempRecipient> vecSend;
    CTempRecipient r;
    r.nType = OUTPUT_STANDARD;
    r.SetAmount(nValue);
    r.fSubtractFeeFromAmount = false;
    r.address = sx;
    r.sNarration = sNarr;
    vecSend.push_back(r);
    BOOST_CHECK(0 == pwallet->ExpandTempRecipients(vecSend, NULL, strError));
    BOOST_CHECK(2 == vecSend.size());
    BOOST_CHECK(34 == vecSend[1].vData.size());


    // No bitfield, with narration
    vecSend.clear();
    sNarr = "test narration";
    r.sNarration = sNarr;
    vecSend.push_back(r);
    BOOST_CHECK(0 == pwallet->ExpandTempRecipients(vecSend, NULL, strError));
    BOOST_CHECK(2 == vecSend.size());
    BOOST_REQUIRE(51 == vecSend[1].vData.size());
    BOOST_REQUIRE(vecSend[1].vData[34] == DO_NARR_CRYPT);

    CBitcoinSecret bsecret1;
    BOOST_CHECK(bsecret1.SetString(strSecret1C));
    //BOOST_CHECK(bsecret2.SetString(strSecret2C));

    CKey sScan = bsecret1.GetKey();

    CKey sShared;
    ec_point pkExtracted;
    ec_point vchEphemPK(vecSend[1].vData.begin() + 1, vecSend[1].vData.begin() + 34);
    std::vector<uint8_t> vchENarr(vecSend[1].vData.begin() + 35, vecSend[1].vData.end());


    BOOST_REQUIRE(StealthSecret(sScan, vchEphemPK, sx.spend_pubkey, sShared, pkExtracted) == 0);

    SecMsgCrypter crypter;
    crypter.SetKey(sShared.begin(), &vchEphemPK[0]);
    std::vector<uint8_t> vchNarr;
    BOOST_REQUIRE(crypter.Decrypt(&vchENarr[0], vchENarr.size(), vchNarr));
    std::string sNarrRecovered = std::string(vchNarr.begin(), vchNarr.end());
    BOOST_CHECK(sNarr == sNarrRecovered);


    // With bitfield, no narration
    vecSend.clear();
    sNarr = "";
    sx.prefix.number_bits = 5;
    sx.prefix.bitfield = 0xaaaaaaaa;
    r.address = sx;
    r.sNarration = sNarr;
    vecSend.push_back(r);
    BOOST_CHECK(0 == pwallet->ExpandTempRecipients(vecSend, NULL, strError));
    BOOST_CHECK(2 == vecSend.size());
    BOOST_REQUIRE(39 == vecSend[1].vData.size());
    BOOST_CHECK(vecSend[1].vData[34] == DO_STEALTH_PREFIX);
    uint32_t prefix, mask = SetStealthMask(sx.prefix.number_bits);
    memcpy(&prefix, &vecSend[1].vData[35], 4);

    BOOST_CHECK((prefix & mask) == (sx.prefix.bitfield & mask));


    // With bitfield, with narration
    vecSend.clear();
    sNarr = "another test narration";
    sx.prefix.number_bits = 18;
    sx.prefix.bitfield = 0xaaaaaaaa;
    r.address = sx;
    r.sNarration = sNarr;
    vecSend.push_back(r);
    BOOST_CHECK(0 == pwallet->ExpandTempRecipients(vecSend, NULL, strError));
    BOOST_CHECK(2 == vecSend.size());
    BOOST_REQUIRE(72 == vecSend[1].vData.size());

    BOOST_CHECK(vecSend[1].vData[34] == DO_STEALTH_PREFIX);
    mask = SetStealthMask(sx.prefix.number_bits);
    memcpy(&prefix, &vecSend[1].vData[35], 4);

    BOOST_CHECK((prefix & mask) == (sx.prefix.bitfield & mask));

    BOOST_CHECK(vecSend[1].vData[39] == DO_NARR_CRYPT);
    vchEphemPK.resize(33);
    memcpy(&vchEphemPK[0], &vecSend[1].vData[1], 33);

    vchENarr = std::vector<uint8_t>(vecSend[1].vData.begin() + 40, vecSend[1].vData.end());


    BOOST_REQUIRE(StealthSecret(sScan, vchEphemPK, sx.spend_pubkey, sShared, pkExtracted) == 0);

    crypter.SetKey(sShared.begin(), &vchEphemPK[0]);
    BOOST_REQUIRE(crypter.Decrypt(&vchENarr[0], vchENarr.size(), vchNarr));
    sNarrRecovered = std::string(vchNarr.begin(), vchNarr.end());
    BOOST_CHECK(sNarr == sNarrRecovered);
}

BOOST_AUTO_TEST_CASE(stealth_key_index)
{
    CHDWallet *pwallet = pwalletMain.get();

    CStealthAddress sx;
    BOOST_CHECK(sx.SetEncoded("SPGyji8uZFip6H15GUfj6bsutRVLsCyBFL3P7k7T7MUDRaYU8GfwUHpfxonLFAvAwr2RkigyGfTgWMfzLAAP8KMRHq7RE8cwpEEekH"));

    CStealthAddressIndexed sxi;
    uint32_t sxId;
    sx.ToRaw(sxi.addrRaw);
    BOOST_CHECK(pwallet->GetStealthKeyIndex(sxi, sxId));
    BOOST_CHECK(sxId == 1);


    BOOST_CHECK(sx.SetEncoded("SPGx7SrLpMcMUjJhQkMp7D8eRAxzVj34StgQdYHr9887nCNBAiUTr4eiJKunzDaBxUqTWGX1sCCJxvUH9WG1JkJw9o15Xn2JSjnpD9"));
    sx.ToRaw(sxi.addrRaw);
    BOOST_CHECK(pwallet->GetStealthKeyIndex(sxi, sxId));
    BOOST_CHECK(sxId == 2);

    BOOST_CHECK(sx.SetEncoded("SPGwdFXLfjt3yQLzVhwbQLriSBbSF3gbmBsTDtA4Sjkz5aCDvmPgw3EqT51YqbxanMzFmAUSWtvCheFvUeWc56QH7sYD4nUKVX8kz2"));
    sx.ToRaw(sxi.addrRaw);
    BOOST_CHECK(pwallet->GetStealthKeyIndex(sxi, sxId));
    BOOST_CHECK(sxId == 3);

    CStealthAddress sxOut;
    BOOST_CHECK(pwallet->GetStealthByIndex(2, sxOut));
    BOOST_CHECK(sxOut.ToString() == "SPGx7SrLpMcMUjJhQkMp7D8eRAxzVj34StgQdYHr9887nCNBAiUTr4eiJKunzDaBxUqTWGX1sCCJxvUH9WG1JkJw9o15Xn2JSjnpD9");


    BOOST_CHECK(sx.SetEncoded("SPGyji8uZFip6H15GUfj6bsutRVLsCyBFL3P7k7T7MUDRaYU8GfwUHpfxonLFAvAwr2RkigyGfTgWMfzLAAP8KMRHq7RE8cwpEEekH"));
    sx.ToRaw(sxi.addrRaw);
    BOOST_CHECK(pwallet->GetStealthKeyIndex(sxi, sxId));
    BOOST_CHECK(sxId == 1);


    CHDWalletDB wdb(pwallet->GetDBHandle(), "r+");
    uint160 hash;
    uint32_t nIndex;
    for (size_t k = 0; k < 512; ++k)
    {
        LOCK(pwallet->cs_wallet);
        pwallet->IndexStealthKey(&wdb, hash, sxi, nIndex);
    };
    BOOST_CHECK(nIndex == 515);
}

void makeNewStealthKey(CStealthAddress &sxAddr, FillableSigningProvider &keystore)
{
    InsecureNewKey(sxAddr.scan_secret, true);

    CKey spend_secret;
    InsecureNewKey(spend_secret, true);
    //sxAddr.spend_secret_id = spend_secret.GetPubKey().GetID();

    SecretToPublicKey(sxAddr.scan_secret, sxAddr.scan_pubkey);
    SecretToPublicKey(spend_secret, sxAddr.spend_pubkey);

    // verify
    CPubKey pkTemp = sxAddr.scan_secret.GetPubKey();
    BOOST_CHECK(pkTemp.size() == EC_COMPRESSED_SIZE);
    BOOST_CHECK(memcmp(&sxAddr.scan_pubkey[0], pkTemp.begin(), EC_COMPRESSED_SIZE) == 0);

    pkTemp = spend_secret.GetPubKey();
    BOOST_CHECK(pkTemp.size() == EC_COMPRESSED_SIZE);
    BOOST_CHECK(pkTemp.size() == EC_COMPRESSED_SIZE);
    BOOST_CHECK(memcmp(&sxAddr.spend_pubkey[0], pkTemp.begin(), EC_COMPRESSED_SIZE) == 0);

    keystore.AddKeyPubKey(spend_secret, pkTemp);
}

BOOST_AUTO_TEST_CASE(ext_key_index)
{
    CHDWallet *pwallet = pwalletMain.get();

    CHDWalletDB wdb(pwallet->GetDBHandle(), "r+");
    CKeyID dummy;
    uint32_t nIndex;
    for (size_t k = 0; k < 512; ++k) {
        LOCK(pwallet->cs_wallet);
        pwallet->ExtKeyNewIndex(&wdb, dummy, nIndex);
    }
    BOOST_CHECK(nIndex == 512);
}

BOOST_AUTO_TEST_CASE(test_TxOutRingCT)
{
    SetMockTime(1510000000);
    SelectParams(CBaseChainParams::TESTNET);
    CHDWallet *wallet = pwalletMain.get();

    SeedInsecureRand();
    FillableSigningProvider keystore;

    CStealthAddress sxAddr;
    makeNewStealthKey(sxAddr, keystore);

    CKey sEphem;
    CKey secretShared;
    ec_point pkSendTo;

    // Send, secret = ephem_secret, pubkey = scan_pubkey
    // NOTE: StealthSecret can fail if hash is out of range, retry with new ephemeral key
    int k, nTries = 24;
    for (k = 0; k < nTries; ++k) {
        InsecureNewKey(sEphem, true);
        if (StealthSecret(sEphem, sxAddr.scan_pubkey, sxAddr.spend_pubkey, secretShared, pkSendTo) == 0) {
            break;
        }
    }
    BOOST_CHECK_MESSAGE(k < nTries, "StealthSecret failed.");
    BOOST_CHECK(pkSendTo.size() == EC_COMPRESSED_SIZE);

    ec_point ephem_pubkey;
    CPubKey pkTemp = sEphem.GetPubKey();
    BOOST_CHECK(pkTemp.size() == EC_COMPRESSED_SIZE);
    ephem_pubkey.resize(EC_COMPRESSED_SIZE);
    memcpy(&ephem_pubkey[0], pkTemp.begin(), EC_COMPRESSED_SIZE);

    CKey secretShared_verify;
    ec_point pkSendTo_verify;

    // Receive, secret = scan_secret, pubkey = ephem_pubkey
    BOOST_CHECK(StealthSecret(sxAddr.scan_secret, ephem_pubkey, sxAddr.spend_pubkey, secretShared_verify, pkSendTo_verify) == 0);

    BOOST_CHECK(pkSendTo == pkSendTo_verify);
    BOOST_CHECK(secretShared == secretShared_verify);

    CKeyID iSpend = sxAddr.GetSpendKeyID();
    CKey kSpend;
    BOOST_CHECK(keystore.GetKey(iSpend, kSpend));
    CKey kSpendOut;
    BOOST_CHECK(StealthSharedToSecretSpend(secretShared_verify, kSpend, kSpendOut) == 0);
    pkTemp = kSpendOut.GetPubKey();
    BOOST_CHECK(CPubKey(pkSendTo) == pkTemp);

    CKey kSpendOut_test2;
    BOOST_CHECK(StealthSecretSpend(sxAddr.scan_secret, ephem_pubkey, kSpend, kSpendOut_test2) == 0);
    pkTemp = kSpendOut_test2.GetPubKey();
    BOOST_CHECK(CPubKey(pkSendTo) == pkTemp);

    BOOST_MESSAGE("----------------Setup Recipient---------------------\n");
    CTempRecipient r;
    r.nType = OUTPUT_RINGCT;
    CAmount nValue = 20*COIN;
    r.SetAmount(nValue);
    r.fSubtractFeeFromAmount = true;
    r.sEphem = sEphem;
    r.pkTo = CPubKey(pkSendTo);
    r.scriptPubKey = GetScriptForDestination(PKHash(r.pkTo));
    r.nStealthPrefix = FillStealthPrefix(sxAddr.prefix.number_bits, sxAddr.prefix.bitfield);
    r.vBlind.resize(32);
    GetStrongRandBytes(&r.vBlind[0], 32);
    BOOST_CHECK_MESSAGE(r.pkTo.IsValid(), "pubkeyto is not valid");

    {
    auto locked_chain = wallet->chain().lock();
    LockAssertion lock(::cs_main);
    LOCK(wallet->cs_wallet);

    BOOST_MESSAGE("---------------- Make RingCT Output : SetCTOutVData ---------------------\n");
    auto txout = MAKE_OUTPUT<CTxOutRingCT>();
    txout->pk = CCmpPubKey(r.pkTo);

    CPubKey pkEphem = r.sEphem.GetPubKey();
    SetCTOutVData(txout->vData, pkEphem, r);

    BOOST_MESSAGE("---------------- Make RingCT Output : AddCTData ---------------------\n");
    std::string strError;
    BOOST_CHECK_MESSAGE(wallet->AddCTData(txout.get(), r, strError) == 0, "failed to add CT Data");

    BOOST_MESSAGE("---------------- Checking RingCT Output---------------------\n");
    TxValidationState state;
    state.rct_active = true;
    BOOST_CHECK_MESSAGE(CheckAnonOutput(state, (CTxOutRingCT*)txout.get()), "failed to check ringct output");

    BOOST_MESSAGE("---------------- Serialize Transaction with No Segwit ---------------------\n");
    CMutableTransaction tx;
    tx.vpout.emplace_back(txout);
    tx.nVersion = 2|PARTICL_TXN_VERSION;
    BOOST_CHECK_MESSAGE(tx.IsParticlVersion(), "failed IsParticlVersion");

    //The peer that sends the block sets the version that the data stream will use!
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION|SERIALIZE_TRANSACTION_NO_WITNESS);
    ss << tx;

    BOOST_MESSAGE("---------------- Deserialize Transaction ---------------------\n");
    CMutableTransaction txCheck;
    ss >> txCheck;
    BOOST_CHECK_MESSAGE(!txCheck.HasWitness(), "deserialize shows witness");
    auto txout_check = txCheck.vpout.at(0);
    BOOST_CHECK_MESSAGE(txout_check->GetType() == OUTPUT_RINGCT, "deserialized output is not ringct");

    BOOST_MESSAGE("---------------- Check RingCT Output ---------------------\n");
    BOOST_CHECK_MESSAGE(!CheckAnonOutput(state, (CTxOutRingCT*)txout_check.get()), "passed check ringct output");
    }

    SetMockTime(0);
}

BOOST_AUTO_TEST_CASE(multisig_Solver1)
{
    // Tests Solver() that returns lists of keys that are
    // required to satisfy a ScriptPubKey
    //
    // Also tests IsMine() and ExtractDestination()
    //
    // Note: ExtractDestination for the multisignature transactions
    // always returns false for this release, even if you have
    // one key that would satisfy an (a|b) or 2-of-3 keys needed
    // to spend an escrow transaction.
    //
    CHDWallet keystore(m_chain.get(), WalletLocation(), WalletDatabase::CreateDummy());
    CHDWallet emptykeystore(m_chain.get(), WalletLocation(), WalletDatabase::CreateDummy());
    CHDWallet partialkeystore(m_chain.get(), WalletLocation(), WalletDatabase::CreateDummy());
    CKey key[3];
    std::vector<CTxDestination> keyaddr(3); // Wmaybe-uninitialized
    for (int i = 0; i < 3; i++) {
        key[i].MakeNewKey(true);
        AddKey(keystore, key[i]);
        keyaddr[i] = PKHash(key[i].GetPubKey());
    }
    AddKey(partialkeystore, key[0]);

    {
        std::vector<valtype> solutions;
        CScript s;
        s << ToByteVector(key[0].GetPubKey()) << OP_CHECKSIG;
        BOOST_CHECK(Solver(s, solutions) != TX_NONSTANDARD);
        BOOST_CHECK(solutions.size() == 1);
        CTxDestination addr;
        BOOST_CHECK(ExtractDestination(s, addr));
        BOOST_CHECK(addr == keyaddr[0]);
        BOOST_CHECK(keystore.IsMine(s));
        BOOST_CHECK(!emptykeystore.IsMine(s));
    }
    {
        std::vector<valtype> solutions;
        CScript s;
        s << OP_DUP << OP_HASH160 << ToByteVector(key[0].GetPubKey().GetID()) << OP_EQUALVERIFY << OP_CHECKSIG;
        BOOST_CHECK(Solver(s, solutions) != TX_NONSTANDARD);
        BOOST_CHECK(solutions.size() == 1);
        CTxDestination addr;
        BOOST_CHECK(ExtractDestination(s, addr));
        BOOST_CHECK(addr == keyaddr[0]);
        BOOST_CHECK(keystore.IsMine(s));
        BOOST_CHECK(!emptykeystore.IsMine(s));
    }
    {
        std::vector<valtype> solutions;
        CScript s;
        s << OP_2 << ToByteVector(key[0].GetPubKey()) << ToByteVector(key[1].GetPubKey()) << OP_2 << OP_CHECKMULTISIG;
        BOOST_CHECK(Solver(s, solutions) != TX_NONSTANDARD);
        BOOST_CHECK_EQUAL(solutions.size(), 4U);
        CTxDestination addr;
        BOOST_CHECK(!ExtractDestination(s, addr));
        BOOST_CHECK(keystore.m_spk_man->IsMineP2SH(s));
        BOOST_CHECK(!emptykeystore.IsMine(s));
        BOOST_CHECK(!partialkeystore.IsMine(s));
    }
    {
        std::vector<valtype> solutions;
        txnouttype whichType;
        CScript s;
        s << OP_1 << ToByteVector(key[0].GetPubKey()) << ToByteVector(key[1].GetPubKey()) << OP_2 << OP_CHECKMULTISIG;
        BOOST_CHECK(Solver(s, solutions) != TX_NONSTANDARD);
        BOOST_CHECK_EQUAL(solutions.size(), 4U);
        std::vector<CTxDestination> addrs;
        int nRequired;
        BOOST_CHECK(ExtractDestinations(s, whichType, addrs, nRequired));
        BOOST_CHECK(addrs[0] == keyaddr[0]);
        BOOST_CHECK(addrs[1] == keyaddr[1]);
        BOOST_CHECK(nRequired == 1);
        BOOST_CHECK(keystore.m_spk_man->IsMineP2SH(s));
        BOOST_CHECK(!emptykeystore.IsMine(s));
        BOOST_CHECK(!partialkeystore.IsMine(s));
    }
    {
        std::vector<valtype> solutions;
        CScript s;
        s << OP_2 << ToByteVector(key[0].GetPubKey()) << ToByteVector(key[1].GetPubKey()) << ToByteVector(key[2].GetPubKey()) << OP_3 << OP_CHECKMULTISIG;
        BOOST_CHECK(Solver(s, solutions) != TX_NONSTANDARD);
        BOOST_CHECK(solutions.size() == 5);
    }
}

BOOST_AUTO_TEST_CASE(opiscoinstake_test)
{
    SeedInsecureRand();
    CHDWallet keystoreA(m_chain.get(), WalletLocation(), WalletDatabase::CreateDummy());
    CHDWallet keystoreB(m_chain.get(), WalletLocation(), WalletDatabase::CreateDummy());

    CKey kA, kB;
    InsecureNewKey(kA, true);
    AddKey(keystoreA, kA);

    CPubKey pkA = kA.GetPubKey();
    CKeyID idA = pkA.GetID();

    InsecureNewKey(kB, true);
    AddKey(keystoreB, kB);

    CPubKey pkB = kB.GetPubKey();
    CKeyID256 idB = pkB.GetID256();

    CScript scriptSignA = CScript() << OP_DUP << OP_HASH160 << ToByteVector(idA) << OP_EQUALVERIFY << OP_CHECKSIG;
    CScript scriptSignB = CScript() << OP_DUP << OP_SHA256 << ToByteVector(idB) << OP_EQUALVERIFY << OP_CHECKSIG;

    CScript script = CScript()
        << OP_ISCOINSTAKE << OP_IF
        << OP_DUP << OP_HASH160 << ToByteVector(idA) << OP_EQUALVERIFY << OP_CHECKSIG
        << OP_ELSE
        << OP_DUP << OP_SHA256 << ToByteVector(idB) << OP_EQUALVERIFY << OP_CHECKSIG
        << OP_ENDIF;

    BOOST_CHECK(HasIsCoinstakeOp(script));
    BOOST_CHECK(script.IsPayToPublicKeyHash256_CS());

    BOOST_CHECK(!IsSpendScriptP2PKH(script));


    CScript scriptFail1 = CScript()
        << OP_ISCOINSTAKE << OP_IF
        << OP_DUP << OP_HASH160 << ToByteVector(idA) << OP_EQUALVERIFY << OP_CHECKSIG
        << OP_ELSE
        << OP_DUP << OP_HASH160 << ToByteVector(idA) << OP_EQUALVERIFY << OP_CHECKSIG
        << OP_ENDIF;
    BOOST_CHECK(IsSpendScriptP2PKH(scriptFail1));


    CScript scriptTest, scriptTestB;
    BOOST_CHECK(GetCoinstakeScriptPath(script, scriptTest));
    BOOST_CHECK(scriptTest == scriptSignA);


    BOOST_CHECK(GetNonCoinstakeScriptPath(script, scriptTest));
    BOOST_CHECK(scriptTest == scriptSignB);


    BOOST_CHECK(SplitConditionalCoinstakeScript(script, scriptTest, scriptTestB));
    BOOST_CHECK(scriptTest == scriptSignA);
    BOOST_CHECK(scriptTestB == scriptSignB);


    txnouttype whichType;
    // IsStandard should fail until chain time is >= OpIsCoinstakeTime
    BOOST_CHECK(!IsStandard(script, whichType));


    BOOST_CHECK(keystoreA.IsMine(script));
    BOOST_CHECK(keystoreB.IsMine(script));


    CAmount nValue = 100000;
    SignatureData sigdataA, sigdataB, sigdataC;

    CMutableTransaction txn;
    txn.nVersion = PARTICL_TXN_VERSION;
    txn.SetType(TXN_COINSTAKE);
    txn.nLockTime = 0;

    int nBlockHeight = 1;
    OUTPUT_PTR<CTxOutData> outData = MAKE_OUTPUT<CTxOutData>();
    outData->vData.resize(4);
    memcpy(&outData->vData[0], &nBlockHeight, 4);
    txn.vpout.push_back(outData);


    OUTPUT_PTR<CTxOutStandard> out0 = MAKE_OUTPUT<CTxOutStandard>();
    out0->nValue = nValue;
    out0->scriptPubKey = script;
    txn.vpout.push_back(out0);
    txn.vin.push_back(CTxIn(COutPoint(uint256S("d496208ea84193e0c5ed05ac708aec84dfd2474b529a7608b836e282958dc72b"), 0)));
    BOOST_CHECK(txn.IsCoinStake());

    std::vector<uint8_t> vchAmount(8);
    memcpy(&vchAmount[0], &nValue, 8);


    BOOST_CHECK(ProduceSignature(*keystoreA.GetSigningProvider(script), MutableTransactionSignatureCreator(&txn, 0, vchAmount, SIGHASH_ALL), script, sigdataA));
    BOOST_CHECK(!ProduceSignature(*keystoreB.GetSigningProvider(script), MutableTransactionSignatureCreator(&txn, 0, vchAmount, SIGHASH_ALL), script, sigdataB));


    ScriptError serror = SCRIPT_ERR_OK;
    int nFlags = STANDARD_SCRIPT_VERIFY_FLAGS;
    CScript scriptSig;
    BOOST_CHECK(VerifyScript(scriptSig, script, &sigdataA.scriptWitness, nFlags, MutableTransactionSignatureChecker(&txn, 0, vchAmount), &serror));


    txn.nVersion = PARTICL_TXN_VERSION;
    txn.SetType(TXN_STANDARD);
    BOOST_CHECK(!txn.IsCoinStake());

    // This should fail anyway as the txn changed
    BOOST_CHECK(!VerifyScript(scriptSig, script, &sigdataA.scriptWitness, nFlags, MutableTransactionSignatureChecker(&txn, 0, vchAmount), &serror));

    BOOST_CHECK(!ProduceSignature(*keystoreA.GetSigningProvider(script), MutableTransactionSignatureCreator(&txn, 0, vchAmount, SIGHASH_ALL), script, sigdataC));
    BOOST_CHECK(ProduceSignature(*keystoreB.GetSigningProvider(script), MutableTransactionSignatureCreator(&txn, 0, vchAmount, SIGHASH_ALL), script, sigdataB));

    BOOST_CHECK(VerifyScript(scriptSig, script, &sigdataB.scriptWitness, nFlags, MutableTransactionSignatureChecker(&txn, 0, vchAmount), &serror));


    CScript script_h160 = CScript()
        << OP_ISCOINSTAKE << OP_IF
        << OP_DUP << OP_HASH160 << ToByteVector(idA) << OP_EQUALVERIFY << OP_CHECKSIG
        << OP_ELSE
        << OP_HASH160 << ToByteVector(idA) << OP_EQUAL
        << OP_ENDIF;
    BOOST_CHECK(script_h160.IsPayToScriptHash_CS());


    CScript script_h256 = CScript()
        << OP_ISCOINSTAKE << OP_IF
        << OP_DUP << OP_HASH160 << ToByteVector(idA) << OP_EQUALVERIFY << OP_CHECKSIG
        << OP_ELSE
        << OP_SHA256 << ToByteVector(idB) << OP_EQUAL
        << OP_ENDIF;
    BOOST_CHECK(script_h256.IsPayToScriptHash256_CS());
}


BOOST_AUTO_TEST_SUITE_END()
