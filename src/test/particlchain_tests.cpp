// Copyright (c) 2017-2022 The Particl Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <test/util/setup_common.h>
#include <net.h>
#include <script/signingprovider.h>
#include <script/script.h>
#include <consensus/validation.h>
#include <consensus/merkle.h>
#include <consensus/tx_verify.h>
#include <key/extkey.h>
#include <pos/kernel.h>
#include <chainparams.h>
#include <blind.h>
#include <validation.h>

#include <script/sign.h>
#include <policy/policy.h>

#include <boost/test/unit_test.hpp>

bool CheckInputScripts(const CTransaction& tx, TxValidationState& state,
                       const CCoinsViewCache& inputs, unsigned int flags, bool cacheSigStore,
                       bool cacheFullScriptStore, PrecomputedTransactionData& txdata,
                       std::vector<CScriptCheck> *pvChecks, bool fAnonChecks = true) EXCLUSIVE_LOCKS_REQUIRED(cs_main);


BOOST_FIXTURE_TEST_SUITE(particlchain_tests, ParticlBasicTestingSetup)


BOOST_AUTO_TEST_CASE(oldversion_test)
{
    CBlock blk, blkOut;
    blk.nTime = 1487406900;

    CMutableTransaction txn;
    blk.vtx.push_back(MakeTransactionRef(txn));

    CDataStream ss(SER_DISK, 0);

    ss << blk;
    ss >> blkOut;

    BOOST_CHECK(blk.vtx[0]->nVersion == blkOut.vtx[0]->nVersion);
}

BOOST_AUTO_TEST_CASE(signature_test)
{
    SeedInsecureRand();
    FillableSigningProvider keystore;

    CKey k;
    InsecureNewKey(k, true);
    keystore.AddKey(k);

    CPubKey pk = k.GetPubKey();
    CKeyID id = pk.GetID();

    CMutableTransaction txn;
    txn.nVersion = PARTICL_TXN_VERSION;
    txn.nLockTime = 0;

    int nBlockHeight = 22;
    OUTPUT_PTR<CTxOutData> out0 = MAKE_OUTPUT<CTxOutData>();
    out0->vData = SetCompressedInt64(out0->vData, nBlockHeight);
    txn.vpout.push_back(out0);

    CScript script = CScript() << OP_DUP << OP_HASH160 << ToByteVector(id) << OP_EQUALVERIFY << OP_CHECKSIG;
    OUTPUT_PTR<CTxOutStandard> out1 = MAKE_OUTPUT<CTxOutStandard>();
    out1->nValue = 10000;
    out1->scriptPubKey = script;
    txn.vpout.push_back(out1);

    CMutableTransaction txn2;
    txn2.nVersion = PARTICL_TXN_VERSION;
    txn2.vin.push_back(CTxIn(txn.GetHash(), 0));

    std::vector<uint8_t> vchAmount(8);
    part::SetAmount(vchAmount, out1->nValue);

    SignatureData sigdata;
    BOOST_CHECK(ProduceSignature(keystore, MutableTransactionSignatureCreator(&txn2, 0, vchAmount, SIGHASH_ALL), script, sigdata));

    ScriptError serror = SCRIPT_ERR_OK;
    BOOST_CHECK(VerifyScript(txn2.vin[0].scriptSig, out1->scriptPubKey, &sigdata.scriptWitness, STANDARD_SCRIPT_VERIFY_FLAGS, MutableTransactionSignatureChecker(&txn2, 0, vchAmount, MissingDataBehavior::ASSERT_FAIL), &serror));
    BOOST_CHECK(serror == SCRIPT_ERR_OK);
}

BOOST_AUTO_TEST_CASE(particlchain_test)
{
    SeedInsecureRand();
    FillableSigningProvider keystore;

    CKey k;
    InsecureNewKey(k, true);
    keystore.AddKey(k);

    CPubKey pk = k.GetPubKey();
    CKeyID id = pk.GetID();

    CScript script = CScript() << OP_DUP << OP_HASH160 << ToByteVector(id) << OP_EQUALVERIFY << OP_CHECKSIG;

    CBlock blk;
    blk.nVersion = PARTICL_BLOCK_VERSION;
    blk.nTime = 1487406900;

    CMutableTransaction txn;
    txn.nVersion = PARTICL_TXN_VERSION;
    txn.SetType(TXN_COINBASE);
    txn.nLockTime = 0;
    OUTPUT_PTR<CTxOutStandard> out0 = MAKE_OUTPUT<CTxOutStandard>();
    out0->nValue = 10000;
    out0->scriptPubKey = script;
    txn.vpout.push_back(out0);


    blk.vtx.push_back(MakeTransactionRef(txn));

    bool mutated;
    blk.hashMerkleRoot = BlockMerkleRoot(blk, &mutated);
    blk.hashWitnessMerkleRoot = BlockWitnessMerkleRoot(blk, &mutated);


    CDataStream ss(SER_DISK, 0);
    ss << blk;

    CBlock blkOut;
    ss >> blkOut;

    BOOST_CHECK(blk.hashMerkleRoot == blkOut.hashMerkleRoot);
    BOOST_CHECK(blk.hashWitnessMerkleRoot == blkOut.hashWitnessMerkleRoot);
    BOOST_CHECK(blk.nTime == blkOut.nTime && blkOut.nTime == 1487406900);

    BOOST_CHECK(TXN_COINBASE == blkOut.vtx[0]->GetType());
}

BOOST_AUTO_TEST_CASE(varints)
{
    SeedInsecureRand();

    int start = InsecureRandRange(100);
    size_t size = 0;
    uint8_t c[128];
    std::vector<uint8_t> v;

    // Encode
    for (int i = start; i < 10000; i+=100) {
        size_t sz = GetSizeOfVarInt<VarIntMode::NONNEGATIVE_SIGNED>(i);
        BOOST_CHECK(sz = part::PutVarInt(c, i));
        BOOST_CHECK(0 == part::PutVarInt(v, i));
        BOOST_CHECK(0 == memcmp(c, &v[size], sz));
        size += sz;
        BOOST_CHECK(size == v.size());
    }
    for (uint64_t i = 0;  i < 100000000000ULL; i += 999999937) {
        BOOST_CHECK(0 == part::PutVarInt(v, i));
        size += GetSizeOfVarInt<VarIntMode::DEFAULT>(i);
        BOOST_CHECK(size == v.size());
    }

    // Decode
    size_t nB = 0, o = 0;
    for (int i = start; i < 10000; i+=100) {
        uint64_t j = (uint64_t)-1;
        BOOST_CHECK(0 == part::GetVarInt(v, o, j, nB));
        BOOST_CHECK_MESSAGE(i == (int)j, "decoded:" << j << " expected:" << i);
        o += nB;
    }
    for (uint64_t i = 0;  i < 100000000000ULL; i += 999999937) {
        uint64_t j = (uint64_t)-1;
        BOOST_CHECK(0 == part::GetVarInt(v, o, j, nB));
        BOOST_CHECK_MESSAGE(i == j, "decoded:" << j << " expected:" << i);
        o += nB;
    }
}

BOOST_AUTO_TEST_CASE(mixed_input_types)
{
    CMutableTransaction txn;
    txn.nVersion = PARTICL_TXN_VERSION;
    BOOST_CHECK(txn.IsParticlVersion());

    CAmount txfee;
    int nSpendHeight = 1;
    CCoinsView viewDummy;
    CCoinsViewCache inputs(&viewDummy);

    CMutableTransaction txnPrev;
    txnPrev.nVersion = PARTICL_TXN_VERSION;
    BOOST_CHECK(txnPrev.IsParticlVersion());

    CScript scriptPubKey;
    txnPrev.vpout.push_back(MAKE_OUTPUT<CTxOutStandard>(1 * COIN, scriptPubKey));
    txnPrev.vpout.push_back(MAKE_OUTPUT<CTxOutStandard>(2 * COIN, scriptPubKey));
    txnPrev.vpout.push_back(MAKE_OUTPUT<CTxOutCT>());
    txnPrev.vpout.push_back(MAKE_OUTPUT<CTxOutCT>());

    CTransaction txnPrev_c(txnPrev);
    AddCoins(inputs, txnPrev_c, 1);

    uint256 prevHash = txnPrev_c.GetHash();

    std::vector<std::pair<std::vector<int>, bool> > tests = {
        std::make_pair( (std::vector<int>) {0 }, true),
        std::make_pair( (std::vector<int>) {0, 1}, true),
        std::make_pair( (std::vector<int>) {0, 2}, false),
        std::make_pair( (std::vector<int>) {0, 1, 2}, false),
        std::make_pair( (std::vector<int>) {2}, true),
        std::make_pair( (std::vector<int>) {2, 3}, true),
        std::make_pair( (std::vector<int>) {2, 3, 1}, false),
        std::make_pair( (std::vector<int>) {-1}, true),
        std::make_pair( (std::vector<int>) {-1, -1}, true),
        std::make_pair( (std::vector<int>) {2, -1}, false),
        std::make_pair( (std::vector<int>) {0, -1}, false),
        std::make_pair( (std::vector<int>) {0, 0, -1}, false),
        std::make_pair( (std::vector<int>) {0, 2, -1}, false)
    };

    for (auto t : tests) {
        txn.vin.clear();

        for (auto ti : t.first) {
            if (ti < 0)  {
                CTxIn ai;
                ai.prevout.n = COutPoint::ANON_MARKER;
                ai.SetAnonInfo(1, 1);

                std::vector<uint8_t> vpkm, vki(33, 0);
                part::PutVarInt(vpkm, 1);
                ai.scriptWitness.stack.emplace_back(vpkm);
                ai.scriptWitness.stack.emplace_back();
                ai.scriptData.stack.emplace_back(vki);
                txn.vin.push_back(ai);
                continue;
            }
            txn.vin.push_back(CTxIn(prevHash, ti));
        }

        CTransaction tx_c(txn);
        TxValidationState state;
        bool rv = Consensus::CheckTxInputs(tx_c, state, inputs, nSpendHeight, txfee);

        if (t.second) {
            BOOST_CHECK(state.GetRejectReason() != "mixed-input-types");
        } else {
            BOOST_CHECK(!rv);
            BOOST_CHECK(state.GetRejectReason() == "mixed-input-types");
        }
    }
}

BOOST_AUTO_TEST_CASE(mixed_output_types)
{
    // When sending from plain only CT or RCT outputs are valid
    ECC_Start_Blinding();

    CAmount txfee = 2000;
    int nSpendHeight = 1;
    CCoinsView viewDummy;
    CCoinsViewCache inputs(&viewDummy);

    CMutableTransaction txnPrev;
    txnPrev.nVersion = PARTICL_TXN_VERSION;
    BOOST_CHECK(txnPrev.IsParticlVersion());

    CScript scriptPubKey;
    txnPrev.vpout.push_back(MAKE_OUTPUT<CTxOutStandard>(1 * COIN, scriptPubKey));

    CTransaction txnPrev_c(txnPrev);
    AddCoins(inputs, txnPrev_c, 1);
    uint256 prevHash = txnPrev_c.GetHash();

    CMutableTransaction txn;
    txn.nVersion = PARTICL_TXN_VERSION;
    BOOST_CHECK(txn.IsParticlVersion());
    txn.vin.push_back(CTxIn(prevHash, 0));

    OUTPUT_PTR<CTxOutData> out_fee = MAKE_OUTPUT<CTxOutData>();
    out_fee->vData.push_back(DO_FEE);
    BOOST_REQUIRE(0 == part::PutVarInt(out_fee->vData, txfee));
    txn.vpout.push_back(out_fee);

    txn.vpout.push_back(MAKE_OUTPUT<CTxOutStandard>(1 * COIN - txfee, scriptPubKey));
    txn.vpout.push_back(MAKE_OUTPUT<CTxOutCT>());
    txn.vpout.push_back(MAKE_OUTPUT<CTxOutRingCT>());

    CTransaction tx_c(txn);
    TxValidationState state;
    state.SetStateInfo(GetTime(), nSpendHeight, Params().GetConsensus(), true /* particl_mode */, false /* skip_rangeproof */);
    state.m_clamp_tx_version = true; // Using mainnet chainparams
    gArgs.ForceSetArg("-acceptanontxn", "1"); // TODO: remove
    gArgs.ForceSetArg("-acceptblindtxn", "1"); // TODO: remove
    BOOST_CHECK(!Consensus::CheckTxInputs(tx_c, state, inputs, nSpendHeight, txfee));
    BOOST_CHECK(state.GetRejectReason() == "bad-txns-plain-in-mixed-out");

    txn.vpout.pop_back();
    CTransaction tx_c2(txn);
    BOOST_CHECK(!Consensus::CheckTxInputs(tx_c2, state, inputs, nSpendHeight, txfee));
    BOOST_CHECK(state.GetRejectReason() != "bad-txns-plain-in-mixed-out");

    ECC_Stop_Blinding();
}

BOOST_AUTO_TEST_CASE(op_iscoinstake_tests)
{
    CKey k1, k2;
    InsecureNewKey(k1, true);
    InsecureNewKey(k2, true);
    CPubKey pk1 = k1.GetPubKey(), pk2 = k2.GetPubKey();
    CKeyID id1 = pk1.GetID(), id2 = pk2.GetID();

    CScript scriptOutA, scriptOutB;
    CScript scriptStake = CScript() << OP_DUP << OP_HASH160 << ToByteVector(id1) << OP_EQUALVERIFY << OP_CHECKSIG;
    CScript scriptSpend = CScript() << OP_DUP << OP_HASH160 << ToByteVector(id2) << OP_EQUALVERIFY << OP_CHECKSIG;

    CScript script = CScript() << OP_ISCOINSTAKE << OP_IF;
    script.append(scriptStake);
    script << OP_ELSE;
    script.append(scriptSpend);
    script << OP_ENDIF;

    int64_t cs_time = Params().GetConsensus().OpIsCoinstakeTime;
    TxoutType whichType;
    BOOST_CHECK(true == IsStandard(script, whichType, cs_time));

    // Test trailing script
    script << OP_DROP;
    script << CScriptNum(123);
    BOOST_CHECK(false == IsStandard(script, whichType, cs_time));

    // Test compacted cs_script
    CScript script2 = CScript() << OP_DUP << OP_HASH160;
    script2 << OP_ISCOINSTAKE << OP_IF << ToByteVector(id1);
    script2 << OP_ELSE << ToByteVector(id2) << OP_ENDIF << OP_EQUALVERIFY << OP_CHECKSIG;

    BOOST_CHECK(true == SplitConditionalCoinstakeScript(script2, scriptOutA, scriptOutB));
    BOOST_CHECK(scriptOutA == scriptStake);
    BOOST_CHECK(scriptOutB == scriptSpend);

    // Test nested ifs
    CScript script3_nested_if = CScript() << OP_1 << OP_IF << OP_RETURN << OP_ELSE << OP_IF << OP_RETURN << OP_ELSE << OP_1 << OP_RETURN << OP_ENDIF << OP_ENDIF;
    CScript script3 = CScript() << OP_ISCOINSTAKE << OP_IF;
    script3.append(script3_nested_if);
    script3 << OP_ELSE;
    script3.append(scriptSpend);
    script3 << OP_ENDIF;

    BOOST_CHECK(true == SplitConditionalCoinstakeScript(script3, scriptOutA, scriptOutB));
    BOOST_CHECK(scriptOutA == script3_nested_if);
    BOOST_CHECK(scriptOutB == scriptSpend);
}

inline static void memput_uint32_le(uint8_t *p, uint32_t v) {
    v = htole32((uint32_t) v);
    memcpy(p, &v, 4);
}

BOOST_AUTO_TEST_CASE(smsg_fees)
{
    int nSpendHeight = 1;
    CCoinsView viewDummy;
    CCoinsViewCache inputs(&viewDummy);

    CMutableTransaction txnPrev;
    txnPrev.nVersion = PARTICL_TXN_VERSION;
    BOOST_CHECK(txnPrev.IsParticlVersion());

    CScript scriptPubKey;
    txnPrev.vpout.push_back(MAKE_OUTPUT<CTxOutStandard>(1 * COIN, scriptPubKey));

    CTransaction txnPrev_c(txnPrev);
    AddCoins(inputs, txnPrev_c, 1);
    uint256 prevHash = txnPrev_c.GetHash();

    CMutableTransaction txn;
    txn.nVersion = PARTICL_TXN_VERSION;
    BOOST_CHECK(txn.IsParticlVersion());
    txn.vin.push_back(CTxIn(prevHash, 0));

    CAmount smsg_fee = 20000;
    std::vector<uint8_t> vData(1 + 24);
    vData[0] = DO_FUND_MSG;
    memset(&vData[1], 0, 20);
    memput_uint32_le(&vData[21], smsg_fee);


    OUTPUT_PTR<CTxOutData> out_smsg_fees = MAKE_OUTPUT<CTxOutData>();
    out_smsg_fees->vData = vData;
    txn.vpout.push_back(out_smsg_fees);
    txn.vpout.push_back(MAKE_OUTPUT<CTxOutStandard>(1 * COIN - smsg_fee, scriptPubKey));

    CFeeRate funding_tx_fee = CFeeRate(Params().GetConsensus().smsg_fee_funding_tx_per_k);
    size_t nBytes = GetVirtualTransactionSize(CTransaction(txn));
    CAmount txfee = funding_tx_fee.GetFee(nBytes);

    {
        CTransaction tx_c(txn);
        TxValidationState state;
        state.SetStateInfo(GetTime(), nSpendHeight, Params().GetConsensus(), true /* particl_mode */, false /* skip_rangeproof */);
        BOOST_CHECK(CheckTransaction(tx_c, state));
        BOOST_CHECK(!Consensus::CheckTxInputs(tx_c, state, inputs, nSpendHeight, txfee));
        BOOST_CHECK(state.GetRejectReason() == "bad-txns-fee-smsg");
    }

    ((CTxOutStandard*)txn.vpout.back().get())->nValue -= txfee;
    {
        CTransaction tx_c(txn);
        TxValidationState state;
        state.SetStateInfo(GetTime(), nSpendHeight, Params().GetConsensus(), true /* particl_mode */, false /* skip_rangeproof */);
        BOOST_CHECK(CheckTransaction(tx_c, state));
        BOOST_CHECK(Consensus::CheckTxInputs(tx_c, state, inputs, nSpendHeight, txfee));
    }

    txn.vpout.push_back(out_smsg_fees);
    txn.vpout.push_back(out_smsg_fees);
    {
        CTransaction tx_c(txn);
        TxValidationState state;
        state.SetStateInfo(GetTime(), nSpendHeight, Params().GetConsensus(), true /* particl_mode */, false /* skip_rangeproof */);
        BOOST_CHECK(!CheckTransaction(tx_c, state));
        BOOST_CHECK(state.GetRejectReason() == "too-many-data-outputs");
    }

    // Test multiple messages
    txn.vpout.pop_back();
    txn.vpout.pop_back();

    CAmount smsg_fee_2 = 10000;
    {
        std::vector<uint8_t> &vData = *txn.vpout[0]->GetPData();
        vData.resize(49);
        memset(&vData[25], 0, 20);
        memput_uint32_le(&vData[1 + 24 + 20], smsg_fee_2);
    }
    {
        CTransaction tx_c(txn);
        TxValidationState state;
        state.SetStateInfo(GetTime(), nSpendHeight, Params().GetConsensus(), true /* particl_mode */, false /* skip_rangeproof */);
        BOOST_CHECK(CheckTransaction(tx_c, state));
        BOOST_CHECK(!Consensus::CheckTxInputs(tx_c, state, inputs, nSpendHeight, txfee));
        BOOST_CHECK(state.GetRejectReason() == "bad-txns-fee-smsg");
    }
    nBytes = GetVirtualTransactionSize(CTransaction(txn));
    txfee = funding_tx_fee.GetFee(nBytes);
    ((CTxOutStandard*)txn.vpout[1].get())->nValue = 1 * COIN - (smsg_fee + smsg_fee_2 + txfee);
    {
        CTransaction tx_c(txn);
        TxValidationState state;
        state.SetStateInfo(GetTime(), nSpendHeight, Params().GetConsensus(), true /* particl_mode */, false /* skip_rangeproof */);
        BOOST_CHECK(CheckTransaction(tx_c, state));
        BOOST_CHECK(Consensus::CheckTxInputs(tx_c, state, inputs, nSpendHeight, txfee));
    }
}

BOOST_AUTO_TEST_CASE(coin_year_reward)
{
    BOOST_CHECK(Params().GetCoinYearReward(1529700000) == 5 * CENT);
    BOOST_CHECK(Params().GetCoinYearReward(1531832399) == 5 * CENT);
    BOOST_CHECK(Params().GetCoinYearReward(1531832400) == 4 * CENT);    // 2018-07-17 13:00:00
    BOOST_CHECK(Params().GetCoinYearReward(1563368399) == 4 * CENT);
    BOOST_CHECK(Params().GetCoinYearReward(1563368400) == 3 * CENT);    // 2019-07-17 13:00:00
    BOOST_CHECK(Params().GetCoinYearReward(1594904399) == 3 * CENT);
    BOOST_CHECK(Params().GetCoinYearReward(1594904400) == 2 * CENT);    // 2020-07-16 13:00:00

    size_t seconds_in_year = 60 * 60 * 24 * 365;
    BOOST_CHECK(Params().GetCoinYearReward(1626109199) == 2 * CENT);
    BOOST_CHECK(Params().GetCoinYearReward(1626109200) == 8 * CENT);                                // 2021-07-12 17:00:00 UTC
    BOOST_CHECK(Params().GetCoinYearReward(1626109200 + seconds_in_year) == 8 * CENT);
    BOOST_CHECK(Params().GetCoinYearReward(1626109200 + seconds_in_year * 2 - 1) == 8 * CENT);
    BOOST_CHECK(Params().GetCoinYearReward(1626109200 + seconds_in_year * 2) == 7 * CENT);          // 2023-07-12 17:00:00 UTC
    BOOST_CHECK(Params().GetCoinYearReward(1626109200 + seconds_in_year * 3) == 7 * CENT);
    BOOST_CHECK(Params().GetCoinYearReward(1626109200 + seconds_in_year * 4 - 1) == 7 * CENT);
    BOOST_CHECK(Params().GetCoinYearReward(1626109200 + seconds_in_year * 4) == 6 * CENT);          // 2025-07-11 17:00:00 UTC

    int64_t hf3_time = Params().GetConsensus().inflation_adjust_time;
    BOOST_CHECK(Params().GetCoinYearReward(hf3_time - 1) == 6 * CENT);
    auto check_rate_at_time = [&](int64_t time, CAmount expect_value, const char *expect_time_str = nullptr) {
        BOOST_CHECK_EQUAL(Params().GetCoinYearReward(time), expect_value);
        if (expect_time_str) {
            BOOST_CHECK_EQUAL(FormatISO8601DateTime(time), expect_time_str);
        }
    };
    check_rate_at_time(hf3_time - 1,                        6   * CENT);
    check_rate_at_time(hf3_time,                            3.5 * CENT,     "2026-02-01T12:00:00Z");
    check_rate_at_time(hf3_time + seconds_in_year * 1 - 1,  3.5 * CENT);
    check_rate_at_time(hf3_time + seconds_in_year * 1,      3   * CENT,     "2027-02-01T12:00:00Z");
    check_rate_at_time(hf3_time + seconds_in_year * 2,      2.5 * CENT,     "2028-02-01T12:00:00Z");
    check_rate_at_time(hf3_time + seconds_in_year * 3,      2   * CENT,     "2029-01-31T12:00:00Z");
    check_rate_at_time(hf3_time + seconds_in_year * 4,      1.5 * CENT,     "2030-01-31T12:00:00Z");
    check_rate_at_time(hf3_time + seconds_in_year * 5,      1   * CENT,     "2031-01-31T12:00:00Z");
    check_rate_at_time(hf3_time + seconds_in_year * 6,      1   * CENT,     "2032-01-31T12:00:00Z");
}

BOOST_AUTO_TEST_CASE(taproot)
{
    BOOST_CHECK(!IsOpSuccess(OP_ISCOINSTAKE));

    CScript s;
    std::vector<std::vector<unsigned char> > solutions;
    s << OP_1 << ToByteVector(uint256::ZERO);
    BOOST_CHECK_EQUAL(Solver(s, solutions), TxoutType::WITNESS_V1_TAPROOT);
    BOOST_CHECK_EQUAL(solutions.size(), 1U);
    BOOST_CHECK(solutions[0] == ToByteVector(uint256::ZERO));

    CKey k1, k2, k3;
    InsecureNewKey(k1, true);
    InsecureNewKey(k2, true);
    InsecureNewKey(k3, true);

    unsigned int flags = SCRIPT_VERIFY_P2SH;
    flags |= SCRIPT_VERIFY_DERSIG;
    flags |= SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY;
    flags |= SCRIPT_VERIFY_CHECKSEQUENCEVERIFY;
    flags |= SCRIPT_VERIFY_WITNESS;
    flags |= SCRIPT_VERIFY_NULLDUMMY;

    unsigned int flags_with_taproot = flags | SCRIPT_VERIFY_TAPROOT;

    CAmount txfee_out, txfee = 2000;
    int nSpendHeight = 1;

    // Test signing with the internal pubkey
    {
    CCoinsView viewDummy;
    CCoinsViewCache inputs(&viewDummy);

    TaprootBuilder builder;
    XOnlyPubKey xpk1{k1.GetPubKey()};
    builder.Finalize(xpk1);

    CScript tr_scriptPubKey = GetScriptForDestination(builder.GetOutput());
    CMutableTransaction txnPrev;
    txnPrev.nVersion = PARTICL_TXN_VERSION;
    BOOST_CHECK(txnPrev.IsParticlVersion());

    txnPrev.vpout.push_back(MAKE_OUTPUT<CTxOutStandard>(1 * COIN, tr_scriptPubKey));
    uint256 prevHash = txnPrev.GetHash();

    CTransaction txnPrev_c(txnPrev);
    AddCoins(inputs, txnPrev_c, 1);

    CScript tr_scriptPubKey_out = GetScriptForDestination(builder.GetOutput());
    CMutableTransaction txn;
    txn.nVersion = PARTICL_TXN_VERSION;
    txn.vin.push_back(CTxIn(prevHash, 0));
    txn.vpout.push_back(MAKE_OUTPUT<CTxOutStandard>(1 * COIN - txfee, tr_scriptPubKey_out));

    CTransaction tx_c(txn);
    TxValidationState state;
    bool rv = Consensus::CheckTxInputs(tx_c, state, inputs, nSpendHeight, txfee_out);
    BOOST_CHECK(rv);

    {
    // Without SCRIPT_VERIFY_TAPROOT prevout defaults to spendable
    LOCK(cs_main);
    PrecomputedTransactionData txdata;
    bool ret = CheckInputScripts(tx_c, state, inputs, flags, /* cacheSigStore */ false, /* cacheFullScriptStore */ false, txdata, nullptr);
    BOOST_CHECK(ret);
    }

    {
    // With SCRIPT_VERIFY_TAPROOT prevout must pass verification
    LOCK(cs_main);
    PrecomputedTransactionData txdata;
    bool ret = CheckInputScripts(tx_c, state, inputs, flags_with_taproot, /* cacheSigStore */ false, /* cacheFullScriptStore */ false, txdata, nullptr);
    BOOST_CHECK(!ret);
    }

    PrecomputedTransactionData txdata;
    std::vector<CTxOutSign> spent_outputs;
    std::vector<uint8_t> vchAmount(8);
    part::SetAmount(vchAmount, 1 * COIN);
    spent_outputs.emplace_back(vchAmount, tr_scriptPubKey_out);
    txdata.Init_vec(txn, std::move(spent_outputs), true);

    MutableTransactionSignatureCreator sig_creator(&txn, 0, vchAmount, &txdata, SIGHASH_ALL);

    FlatSigningProvider keystore;
    keystore.keys[k1.GetPubKey().GetID()] = k1;
    TaprootSpendData tr_spenddata = builder.GetSpendData();

    WitnessV1Taproot output = builder.GetOutput();
    keystore.tr_spenddata[output].Merge(builder.GetSpendData());

    SignatureData sigdata;
    std::vector<unsigned char> sig;
    bool sig_created = sig_creator.CreateSchnorrSig(keystore, sig, tr_spenddata.internal_key, nullptr, &tr_spenddata.merkle_root, SigVersion::TAPROOT);
    BOOST_CHECK(sig_created);

    txn.vin[0].scriptWitness.stack = Vector(sig);
    {
    TxValidationState state;
    CTransaction tx_c(txn);
    LOCK(cs_main);
    PrecomputedTransactionData txdata;
    bool ret = CheckInputScripts(tx_c, state, inputs, flags_with_taproot, /* cacheSigStore */ false, /* cacheFullScriptStore */ false, txdata, nullptr);
    BOOST_CHECK(ret);
    }
    }

    // Test signing a script path
    {
    CCoinsView viewDummy;
    CCoinsViewCache inputs(&viewDummy);

    TaprootBuilder builder;
    XOnlyPubKey xpk1{k1.GetPubKey()};
    XOnlyPubKey xpk2{k2.GetPubKey()};

    CScript scriptStake = CScript() << OP_ISCOINSTAKE << OP_VERIFY << ToByteVector(xpk2) << OP_CHECKSIG;
    builder.Add(0, scriptStake, TAPROOT_LEAF_TAPSCRIPT);
    builder.Finalize(xpk1);

    // Add the txn/output being spent
    CScript tr_scriptPubKey = GetScriptForDestination(builder.GetOutput());
    CMutableTransaction txnPrev;
    txnPrev.nVersion = PARTICL_TXN_VERSION;
    BOOST_CHECK(txnPrev.IsParticlVersion());
    txnPrev.vpout.push_back(MAKE_OUTPUT<CTxOutStandard>(1 * COIN, tr_scriptPubKey));
    CTransaction txnPrev_c(txnPrev);
    AddCoins(inputs, txnPrev_c, 1);

    CMutableTransaction txn;
    txn.nVersion = PARTICL_TXN_VERSION;
    txn.SetType(TXN_COINSTAKE);
    txn.nLockTime = 0;
    txn.vin.push_back(CTxIn(txnPrev.GetHash(), 0));

    int nBlockHeight = 1;
    OUTPUT_PTR<CTxOutData> outData = MAKE_OUTPUT<CTxOutData>();
    outData->vData.resize(4);
    uint32_t tmp32 = htole32(nBlockHeight);
    memcpy(&outData->vData[0], &tmp32, 4);
    txn.vpout.push_back(outData);

    txn.vpout.push_back(MAKE_OUTPUT<CTxOutStandard>(1 * COIN + txfee, tr_scriptPubKey));

    PrecomputedTransactionData txdata;
    std::vector<CTxOutSign> spent_outputs;
    std::vector<uint8_t> vchAmount(8);
    part::SetAmount(vchAmount, 1 * COIN);
    spent_outputs.emplace_back(vchAmount, tr_scriptPubKey);
    txdata.Init_vec(txn, std::move(spent_outputs), true);
    MutableTransactionSignatureCreator sig_creator(&txn, 0, vchAmount, &txdata, SIGHASH_ALL);

    FlatSigningProvider keystore;
    keystore.keys[k2.GetPubKey().GetID()] = k2;
    TaprootSpendData tr_spenddata = builder.GetSpendData();

    uint256 leaf_hash = ComputeTapleafHash(TAPROOT_LEAF_TAPSCRIPT, scriptStake);

    std::vector<unsigned char> sig;
    bool sig_created = sig_creator.CreateSchnorrSig(keystore, sig, xpk2, &leaf_hash, nullptr, SigVersion::TAPSCRIPT);
    BOOST_CHECK(sig_created);

    CScriptWitness witness;
    witness.stack.push_back(sig);
    witness.stack.push_back(std::vector<unsigned char>(scriptStake.begin(), scriptStake.end()));
    std::vector<std::vector<unsigned char> > vec_controlblocks;
    for (const auto &s : tr_spenddata.scripts[{scriptStake, TAPROOT_LEAF_TAPSCRIPT}]) {
        vec_controlblocks.push_back(s);
    }
    BOOST_CHECK(vec_controlblocks.size() == 1);
    BOOST_CHECK(vec_controlblocks[0].size() == 33);
    witness.stack.push_back(vec_controlblocks[0]);
    txn.vin[0].scriptWitness = std::move(witness);

    // Verify script can fail
    txn.SetType(TXN_COINBASE);
    BOOST_CHECK(!txn.IsCoinStake());

    {
    // Should fail as !IsCoinStake()
    TxValidationState state;
    CTransaction tx_c(txn);
    LOCK(cs_main);
    PrecomputedTransactionData txdata;
    bool ret = CheckInputScripts(tx_c, state, inputs, flags_with_taproot, /* cacheSigStore */ false, /* cacheFullScriptStore */ false, txdata, nullptr);
    BOOST_CHECK(!ret);
    BOOST_CHECK(state.GetRejectReason() == "non-mandatory-script-verify-flag (Script failed an OP_VERIFY operation)");

    // Should pass without SCRIPT_VERIFY_TAPROOT
    bool ret_without_taproot = CheckInputScripts(tx_c, state, inputs, flags, /* cacheSigStore */ false, /* cacheFullScriptStore */ false, txdata, nullptr);
    BOOST_CHECK(ret_without_taproot);
    }

    txn.nVersion = PARTICL_TXN_VERSION;
    txn.SetType(TXN_COINSTAKE);
    BOOST_CHECK(txn.IsCoinStake());
    {
    // Should pass
    TxValidationState state;
    CTransaction tx_c(txn);
    LOCK(cs_main);
    PrecomputedTransactionData txdata;
    bool ret = CheckInputScripts(tx_c, state, inputs, flags_with_taproot, /* cacheSigStore */ false, /* cacheFullScriptStore */ false, txdata, nullptr);
    BOOST_CHECK(ret);
    }
    }

    // OP_CHECKSIGADD
    {
        CCoinsView viewDummy;
        CCoinsViewCache inputs(&viewDummy);

        TaprootBuilder builder;
        XOnlyPubKey xpk1{k1.GetPubKey()};
        XOnlyPubKey xpk2{k2.GetPubKey()};
        XOnlyPubKey xpk3{k3.GetPubKey()};

        CScript scriptCheckSigAdd = CScript() << ToByteVector(xpk1) << OP_CHECKSIG << ToByteVector(xpk2) << OP_CHECKSIGADD << OP_2 << OP_NUMEQUAL;
        builder.Add(0, scriptCheckSigAdd, TAPROOT_LEAF_TAPSCRIPT);
        builder.Finalize(xpk3);

        // Add the txn/output being spent
        CScript tr_scriptPubKey = GetScriptForDestination(builder.GetOutput());
        CMutableTransaction txnPrev;
        txnPrev.nVersion = PARTICL_TXN_VERSION;
        BOOST_CHECK(txnPrev.IsParticlVersion());
        txnPrev.vpout.push_back(MAKE_OUTPUT<CTxOutStandard>(1 * COIN, tr_scriptPubKey));
        CTransaction txnPrev_c(txnPrev);
        AddCoins(inputs, txnPrev_c, 1);

        CMutableTransaction txn;
        txn.nVersion = PARTICL_TXN_VERSION;
        txn.SetType(TXN_COINSTAKE);
        txn.nLockTime = 0;
        txn.vin.push_back(CTxIn(txnPrev.GetHash(), 0));

        int nBlockHeight = 1;
        OUTPUT_PTR<CTxOutData> outData = MAKE_OUTPUT<CTxOutData>();
        outData->vData.resize(4);
        uint32_t tmp32 = htole32(nBlockHeight);
        memcpy(&outData->vData[0], &tmp32, 4);
        txn.vpout.push_back(outData);

        txn.vpout.push_back(MAKE_OUTPUT<CTxOutStandard>(1 * COIN + txfee, tr_scriptPubKey));

        PrecomputedTransactionData txdata;
        std::vector<CTxOutSign> spent_outputs;
        std::vector<uint8_t> vchAmount(8);
        part::SetAmount(vchAmount, 1 * COIN);
        spent_outputs.emplace_back(vchAmount, tr_scriptPubKey);
        txdata.Init_vec(txn, std::move(spent_outputs), true);
        MutableTransactionSignatureCreator sig_creator(&txn, 0, vchAmount, &txdata, SIGHASH_ALL);

        FlatSigningProvider keystore;
        keystore.keys[k1.GetPubKey().GetID()] = k1;
        keystore.keys[k2.GetPubKey().GetID()] = k2;
        TaprootSpendData tr_spenddata = builder.GetSpendData();

        uint256 leaf_hash = ComputeTapleafHash(TAPROOT_LEAF_TAPSCRIPT, scriptCheckSigAdd);

        std::vector<unsigned char> empty_vec, sig1, sig2;
        bool sig_created = sig_creator.CreateSchnorrSig(keystore, sig1, xpk1, &leaf_hash, nullptr, SigVersion::TAPSCRIPT);
        BOOST_CHECK(sig_created);
        sig_created = sig_creator.CreateSchnorrSig(keystore, sig2, xpk2, &leaf_hash, nullptr, SigVersion::TAPSCRIPT);
        BOOST_CHECK(sig_created);

        CScriptWitness witness;
        witness.stack.push_back(sig1); // invalid
        witness.stack.push_back(sig1);
        witness.stack.push_back(std::vector<unsigned char>(scriptCheckSigAdd.begin(), scriptCheckSigAdd.end()));
        std::vector<std::vector<unsigned char> > vec_controlblocks;
        for (const auto &s : tr_spenddata.scripts[{scriptCheckSigAdd, TAPROOT_LEAF_TAPSCRIPT}]) {
            vec_controlblocks.push_back(s);
        }
        BOOST_CHECK(vec_controlblocks.size() == 1);
        BOOST_CHECK(vec_controlblocks[0].size() == 33);
        witness.stack.push_back(vec_controlblocks[0]);
        txn.vin[0].scriptWitness = std::move(witness);

        {
        // Should fail as sig2 is invalid
        TxValidationState state;
        CTransaction tx_c(txn);
        LOCK(cs_main);
        PrecomputedTransactionData txdata;
        bool ret = CheckInputScripts(tx_c, state, inputs, flags_with_taproot, /* cacheSigStore */ false, /* cacheFullScriptStore */ false, txdata, nullptr);
        BOOST_CHECK(!ret);
        BOOST_CHECK(state.GetRejectReason() == "non-mandatory-script-verify-flag (Invalid Schnorr signature)");

        // Should pass without SCRIPT_VERIFY_TAPROOT
        bool ret_without_taproot = CheckInputScripts(tx_c, state, inputs, flags, /* cacheSigStore */ false, /* cacheFullScriptStore */ false, txdata, nullptr);
        BOOST_CHECK(ret_without_taproot);
        }

        CScriptWitness witness_fixed;
        witness_fixed.stack.push_back(sig2);
        witness_fixed.stack.push_back(sig1);
        witness_fixed.stack.push_back(std::vector<unsigned char>(scriptCheckSigAdd.begin(), scriptCheckSigAdd.end()));
        witness_fixed.stack.push_back(vec_controlblocks[0]);
        txn.vin[0].scriptWitness = std::move(witness_fixed);

        {
        TxValidationState state;
        CTransaction tx_c(txn);
        LOCK(cs_main);
        PrecomputedTransactionData txdata;
        bool ret = CheckInputScripts(tx_c, state, inputs, flags_with_taproot, /* cacheSigStore */ false, /* cacheFullScriptStore */ false, txdata, nullptr);
        BOOST_CHECK(ret);
        }
    }
}

BOOST_AUTO_TEST_SUITE_END()
