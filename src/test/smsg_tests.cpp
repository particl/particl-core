// Copyright (c) 2017-2019 The Particl Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <smsg/smessage.h>

#include <test/util/setup_common.h>
#include <net.h>
#ifdef ENABLE_WALLET
#include <wallet/hdwallet.h>
#endif
#include <xxhash/xxhash.h>

#include <boost/test/unit_test.hpp>

struct SmsgTestingSetup : public TestingSetup {
    SmsgTestingSetup() : TestingSetup(CBaseChainParams::MAIN, true) {}
};

BOOST_FIXTURE_TEST_SUITE(smsg_tests, SmsgTestingSetup)

const std::string sTestMessage = "A short test message 0123456789 !@#$%^&*()_+-=";

BOOST_AUTO_TEST_CASE(smsg_test_xxhash)
{
    XXH32_state_t *state = XXH32_createState();
    XXH32_reset(state, 1);
    XXH32_update(state, sTestMessage.data(), sTestMessage.length());
    uint32_t hash_new = XXH32_digest(state);
    BOOST_CHECK(hash_new == 474992878);
    XXH32_freeState(state);
}

BOOST_AUTO_TEST_CASE(smsg_test_ckeyId_inits_null)
{
    CKeyID k;
    BOOST_CHECK(k.IsNull());
}

#ifdef ENABLE_WALLET

void CheckValid(smsg::SecureMessage &smsg, CKeyID &kFrom, CKeyID &kTo, bool expect_pass)
{
    int rv = 0;
    BOOST_CHECK(0 == smsgModule.Encrypt(smsg, kFrom, kTo, sTestMessage));
    BOOST_CHECK(0 == smsgModule.SetHash((uint8_t*)&smsg, smsg.pPayload, smsg.nPayload));
    if (expect_pass) {
        BOOST_CHECK_MESSAGE(0 == (rv = smsgModule.Validate((uint8_t*)&smsg, smsg.pPayload, smsg.nPayload)), "Validate failed " << rv);
    } else {
        BOOST_CHECK_MESSAGE(0 != (rv = smsgModule.Validate((uint8_t*)&smsg, smsg.pPayload, smsg.nPayload)), "Validate passed " << rv);
    }

    // Reset
    delete[] smsg.pPayload;
    smsg.pPayload = nullptr;
    smsg.nPayload = 0;
}

BOOST_AUTO_TEST_CASE(smsg_test)
{
    SeedInsecureRand();

    int rv = 0;
    const int nKeys = 12;
    auto chain = interfaces::MakeChain(m_node);
    std::shared_ptr<CHDWallet> wallet = std::make_shared<CHDWallet>(chain.get(), WalletLocation(), WalletDatabase::CreateDummy());
    std::vector<CKey> keyOwn(nKeys);
    for (int i = 0; i < nKeys; i++) {
        InsecureNewKey(keyOwn[i], true);
        LOCK(wallet->cs_wallet);
        wallet->m_spk_man->AddKey(keyOwn[i]);
    }

    std::vector<CKey> keyRemote(nKeys);
    for (int i = 0; i < nKeys; i++) {
        InsecureNewKey(keyRemote[i], true);
        LOCK(wallet->cs_wallet);
        wallet->m_spk_man->AddKey(keyRemote[i]); // need pubkey
    }

    std::vector<std::shared_ptr<CWallet>> temp_vpwallets;
    BOOST_CHECK(true == smsgModule.Start(wallet, temp_vpwallets, false));

    smsg::SecureMessage smsg;
    smsg.m_ttl = 1;
    CKeyID kFrom = keyOwn[0].GetPubKey().GetID();
    CKeyID kTo = keyRemote[0].GetPubKey().GetID();
    CheckValid(smsg, kFrom, kTo, false);
    smsg.m_ttl = smsg::SMSG_MAX_FREE_TTL + 1;
    CheckValid(smsg, kFrom, kTo, false);
    smsg.m_ttl = smsg::SMSG_MAX_FREE_TTL;
    CheckValid(smsg, kFrom, kTo, true);
    smsg.m_ttl = smsg::SMSG_MIN_TTL;
    CheckValid(smsg, kFrom, kTo, true);

    CKeyID idNull;
    for (int i = 0; i < nKeys; i++) {
        smsg::SecureMessage smsg;
        smsg::MessageData msg;
        smsg.m_ttl = 1 * smsg::SMSG_SECONDS_IN_DAY;
        CKeyID kFrom = keyOwn[i].GetPubKey().GetID();
        CKeyID kTo = keyRemote[i].GetPubKey().GetID();
        CKeyID kFail = keyRemote[(i+1) % nKeys].GetPubKey().GetID();
        std::string sAddrFrom = EncodeDestination(PKHash(kFrom));
        std::string sAddrTo = EncodeDestination(PKHash(kTo));
        std::string sAddrFail = EncodeDestination(PKHash(kFail));

        bool fSendAnonymous = rand() % 3 == 0;

        BOOST_CHECK_MESSAGE(0 == (rv = smsgModule.Encrypt(smsg, fSendAnonymous ? idNull : kFrom, kTo, sTestMessage)), "SecureMsgEncrypt " << rv);

        BOOST_CHECK_MESSAGE(0 == (rv = smsgModule.SetHash((uint8_t*)&smsg, smsg.pPayload, smsg.nPayload)), "SecureMsgSetHash " << rv);

        BOOST_CHECK_MESSAGE(0 == (rv = smsgModule.Validate((uint8_t*)&smsg, smsg.pPayload, smsg.nPayload)), "SecureMsgValidate " << rv);

        BOOST_CHECK_MESSAGE(0 == (rv = smsgModule.Decrypt(false, kTo, smsg, msg)), "SecureMsgDecrypt " << rv);

        BOOST_CHECK(msg.vchMessage.size()-1 == sTestMessage.size()
            && 0 == memcmp(&msg.vchMessage[0], sTestMessage.data(), msg.vchMessage.size()-1));

        rv = smsgModule.Decrypt(false, kFail, smsg, msg);
        BOOST_CHECK_MESSAGE(smsg::SMSG_MAC_MISMATCH == rv, "SecureMsgDecrypt " << smsg::GetString(rv));
    }

    smsgModule.Shutdown();
}
#endif

BOOST_AUTO_TEST_SUITE_END()
