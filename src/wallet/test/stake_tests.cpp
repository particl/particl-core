// Copyright (c) 2017-2019 The Particl Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <wallet/hdwallet.h>
#include <wallet/coincontrol.h>
#include <interfaces/chain.h>

#include <wallet/test/hdwallet_test_fixture.h>
#include <chainparams.h>
#include <miner.h>
#include <pos/miner.h>
#include <timedata.h>
#include <coins.h>
#include <net.h>
#include <validation.h>
#include <blind.h>
#include <rpc/rpcutil.h>

#include <consensus/validation.h>

#include <chrono>
#include <thread>

#include <boost/test/unit_test.hpp>
#include <util/string.h>

struct StakeTestingSetup: public TestingSetup {
    StakeTestingSetup(const std::string& chainName = CBaseChainParams::REGTEST):
        TestingSetup(chainName, /* fParticlMode */ true)
    {
        ECC_Start_Stealth();
        ECC_Start_Blinding();

        bool fFirstRun;
        pwalletMain = std::make_shared<CHDWallet>(m_chain.get(), WalletLocation(), WalletDatabase::CreateMock());
        AddWallet(pwalletMain);
        pwalletMain->LoadWallet(fFirstRun);
        pwalletMain->Initialise();
        pwalletMain->m_chain_notifications_handler = m_chain->handleNotifications(*pwalletMain);

        m_chain_client->registerRpcs();

        SetMockTime(0);
    }

    ~StakeTestingSetup()
    {
        RemoveWallet(pwalletMain);
        pwalletMain.reset();

        mapStakeSeen.clear();
        listStakeSeen.clear();

        ECC_Stop_Stealth();
        ECC_Stop_Blinding();
    }

    std::unique_ptr<interfaces::Chain> m_chain = interfaces::MakeChain(m_node);
    std::unique_ptr<interfaces::ChainClient> m_chain_client = interfaces::MakeWalletClient(*m_chain, {});
    std::shared_ptr<CHDWallet> pwalletMain;
};

BOOST_FIXTURE_TEST_SUITE(stake_tests, StakeTestingSetup)


void StakeNBlocks(CHDWallet *pwallet, size_t nBlocks)
{
    int nBestHeight;
    size_t nStaked = 0;
    size_t k, nTries = 10000;
    for (k = 0; k < nTries; ++k) {
        {
            LOCK(cs_main);
            nBestHeight = ::ChainActive().Height();
        }

        int64_t nSearchTime = GetAdjustedTime() & ~Params().GetStakeTimestampMask(nBestHeight+1);
        if (nSearchTime <= pwallet->nLastCoinStakeSearchTime) {
            std::this_thread::sleep_for(std::chrono::milliseconds(250));
            continue;
        }

        CScript coinbaseScript;
        std::unique_ptr<CBlockTemplate> pblocktemplate(BlockAssembler(Params()).CreateNewBlock(coinbaseScript, false));
        BOOST_REQUIRE(pblocktemplate.get());

        if (pwallet->SignBlock(pblocktemplate.get(), nBestHeight+1, nSearchTime)) {
            CBlock *pblock = &pblocktemplate->block;

            if (CheckStake(pblock)) {
                nStaked++;
            }
        }

        if (nStaked >= nBlocks) {
            break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(250));
    }
    BOOST_REQUIRE(k < nTries);
    SyncWithValidationInterfaceQueue();
};

static void AddAnonTxn(CHDWallet *pwallet, CBitcoinAddress &address, CAmount amount)
{
    {
    auto locked_chain = pwallet->chain().lock();
    LOCK(pwallet->cs_wallet);
    LockAssertion lock(::cs_main);

    BOOST_REQUIRE(address.IsValid());

    std::vector<CTempRecipient> vecSend;
    std::string sError;
    CTempRecipient r;
    r.nType = OUTPUT_RINGCT;
    r.SetAmount(amount);
    r.address = address.Get();
    vecSend.push_back(r);

    CTransactionRef tx_new;
    CWalletTx wtx(pwallet, tx_new);
    CTransactionRecord rtx;
    CAmount nFee;
    CCoinControl coinControl;
    BOOST_CHECK(0 == pwallet->AddStandardInputs(*locked_chain, wtx, rtx, vecSend, true, nFee, &coinControl, sError));

    wtx.BindWallet(pwallet);
    BOOST_REQUIRE(wtx.SubmitMemoryPoolAndRelay(sError, true));
    } // cs_main
    SyncWithValidationInterfaceQueue();
}

static void DisconnectTip(CBlock &block, CBlockIndex *pindexDelete, CCoinsViewCache &view, const CChainParams &chainparams)
{
    BlockValidationState state;
    BOOST_REQUIRE(DISCONNECT_OK == DisconnectBlock(block, pindexDelete, view));
    BOOST_REQUIRE(FlushView(&view, state, true));
    BOOST_REQUIRE(::ChainstateActive().FlushStateToDisk(chainparams, state, FlushStateMode::IF_NEEDED));
    ::ChainActive().SetTip(pindexDelete->pprev);
    UpdateTip(pindexDelete->pprev, chainparams);
};

BOOST_AUTO_TEST_CASE(stake_test)
{
    SeedInsecureRand();
    CHDWallet *pwallet = pwalletMain.get();
    {
        LOCK(pwallet->cs_wallet);
        pwallet->SetLastBlockProcessed(::ChainActive().Height(), ::ChainActive().Tip()->GetBlockHash());
    }
    UniValue rv;

    std::unique_ptr<CChainParams> regtestChainParams = CreateChainParams(CBaseChainParams::REGTEST);
    const CChainParams &chainparams = *regtestChainParams;

    BOOST_REQUIRE(chainparams.GenesisBlock().GetHash() == ::ChainActive().Tip()->GetBlockHash());

    BOOST_CHECK_NO_THROW(rv = CallRPC("extkeyimportmaster tprv8ZgxMBicQKsPeK5mCpvMsd1cwyT1JZsrBN82XkoYuZY1EVK7EwDaiL9sDfqUU5SntTfbRfnRedFWjg5xkDG5i3iwd3yP7neX5F2dtdCojk4"));

    // Import the key to the last 5 outputs in the regtest genesis coinbase
    BOOST_CHECK_NO_THROW(rv = CallRPC("extkeyimportmaster tprv8ZgxMBicQKsPe3x7bUzkHAJZzCuGqN6y28zFFyg5i7Yqxqm897VCnmMJz6QScsftHDqsyWW5djx6FzrbkF9HSD3ET163z1SzRhfcWxvwL4G"));
    BOOST_CHECK_NO_THROW(rv = CallRPC("getnewextaddress lblHDKey"));

    {
        LOCK(pwallet->cs_wallet);
        CBitcoinAddress addr("pdtYqn1fBVpgRa6Am6VRRLH8fkrFr1TuDq");
        CKeyID idk;
        BOOST_CHECK(addr.GetKeyID(idk));
        BOOST_CHECK(pwallet->IsMine(idk) == ISMINE_SPENDABLE);

        const CEKAKey *pak = nullptr;
        const CEKASCKey *pasc = nullptr;
        CExtKeyAccount *pa = nullptr;
        BOOST_CHECK(pwallet->HaveKey(idk, pak, pasc, pa));
        BOOST_REQUIRE(pa);
        BOOST_REQUIRE(pak);
        BOOST_CHECK(pak->nParent == 1);
        BOOST_CHECK(pak->nKey == 1);
        BOOST_CHECK(!pasc);

        CEKAKey ak;
        CKey key;
        CKeyID idStealth;
        BOOST_CHECK(pwallet->GetKey(idk, key, pa, ak, idStealth));
        BOOST_CHECK(idk == key.GetPubKey().GetID());
    }

    {
        LOCK2(cs_main, pwallet->cs_wallet);
        const auto bal = pwallet->GetBalance();
        BOOST_REQUIRE(bal.m_mine_trusted == 12500000000000);
    }
    BOOST_REQUIRE(::ChainActive().Tip()->nMoneySupply == 12500000000000);

    StakeNBlocks(pwallet, 2);
    BOOST_REQUIRE(::ChainActive().Tip()->nMoneySupply == 12500000079274);

    CBlockIndex *pindexDelete = ::ChainActive().Tip();
    BOOST_REQUIRE(pindexDelete);

    CBlock block;
    BOOST_REQUIRE(ReadBlockFromDisk(block, pindexDelete, chainparams.GetConsensus()));

    const CTxIn &txin = block.vtx[0]->vin[0];

    {
    LOCK(cs_main);
    CCoinsViewCache &view = ::ChainstateActive().CoinsTip();
    const Coin &coin = view.AccessCoin(txin.prevout);
    BOOST_REQUIRE(coin.IsSpent());


    DisconnectTip(block, pindexDelete, view, chainparams);

    BOOST_REQUIRE(pindexDelete->pprev->GetBlockHash() == ::ChainActive().Tip()->GetBlockHash());

    const Coin &coin2 = view.AccessCoin(txin.prevout);
    BOOST_REQUIRE(!coin2.IsSpent());
    }

    BOOST_CHECK(::ChainActive().Height() == pindexDelete->nHeight - 1);
    BOOST_CHECK(::ChainActive().Tip()->GetBlockHash() == pindexDelete->pprev->GetBlockHash());
    BOOST_REQUIRE(::ChainActive().Tip()->nMoneySupply == 12500000039637);


    // Reconnect block
    {
        BlockValidationState state;
        std::shared_ptr<const CBlock> pblock = std::make_shared<const CBlock>(block);
        BOOST_REQUIRE(ActivateBestChain(state, chainparams, pblock));

        LOCK(cs_main);
        CCoinsViewCache &view = ::ChainstateActive().CoinsTip();
        const Coin &coin = view.AccessCoin(txin.prevout);
        BOOST_REQUIRE(coin.IsSpent());
        BOOST_REQUIRE(::ChainActive().Tip()->nMoneySupply == 12500000079274);
    }

    CKey kRecv;
    InsecureNewKey(kRecv, true);

    bool fSubtractFeeFromAmount = false;
    CAmount nAmount = 10000;
    CTransactionRef tx_new;

    // Parse Bitcoin address
    CScript scriptPubKey = GetScriptForDestination(PKHash(kRecv.GetPubKey()));

    // Create and send the transaction
    CAmount nFeeRequired;
    std::string strError;
    std::vector<CRecipient> vecSend;
    int nChangePosRet = -1;
    CRecipient recipient = {scriptPubKey, nAmount, fSubtractFeeFromAmount};
    vecSend.push_back(recipient);

    CCoinControl coinControl;
    {
        auto locked_chain = pwallet->chain().lock();
        BOOST_CHECK(pwallet->CreateTransaction(*locked_chain, vecSend, tx_new, nFeeRequired, nChangePosRet, strError, coinControl));
    }
    {
        pwallet->SetBroadcastTransactions(true);
        mapValue_t mapValue;
        pwallet->CommitTransaction(tx_new, std::move(mapValue), {} /* orderForm */);
    }

    StakeNBlocks(pwallet, 1);

    CBlock blockLast;
    BOOST_REQUIRE(ReadBlockFromDisk(blockLast, ::ChainActive().Tip(), chainparams.GetConsensus()));

    BOOST_REQUIRE(blockLast.vtx.size() == 2);
    BOOST_REQUIRE(blockLast.vtx[1]->GetHash() == tx_new->GetHash());

    {
        uint256 tipHash = ::ChainActive().Tip()->GetBlockHash();
        uint256 prevTipHash = ::ChainActive().Tip()->pprev->GetBlockHash();

        // Disconnect last block
        CBlockIndex *pindexDelete = ::ChainActive().Tip();
        BOOST_REQUIRE(pindexDelete);

        CBlock block;
        BOOST_REQUIRE(ReadBlockFromDisk(block, pindexDelete, chainparams.GetConsensus()));

        {
        LOCK(cs_main);
        CCoinsViewCache &view = ::ChainstateActive().CoinsTip();
        DisconnectTip(block, pindexDelete, view, chainparams);
        }


        BOOST_CHECK(prevTipHash == ::ChainActive().Tip()->GetBlockHash());


        {
            LOCK(cs_main);

            // Reduce the reward
            RegtestParams().SetCoinYearReward(1 * CENT);
            BOOST_CHECK(Params().GetCoinYearReward(0) == 1 * CENT);

            BlockValidationState state;
            CCoinsViewCache view(&::ChainstateActive().CoinsTip());
            BOOST_REQUIRE(false == ConnectBlock(block, state, pindexDelete, view, chainparams, false));

            BOOST_CHECK(state.IsInvalid());
            BOOST_CHECK(state.GetRejectReason() == "bad-cs-amount");
            BOOST_CHECK(prevTipHash == ::ChainActive().Tip()->GetBlockHash());

            // restore the reward
            RegtestParams().SetCoinYearReward(2 * CENT);
            BOOST_CHECK(Params().GetCoinYearReward(0) == 2 * CENT);

            // block should connect now
            BlockValidationState clearstate;
            CCoinsViewCache &clearview = ::ChainstateActive().CoinsTip();
            BOOST_REQUIRE(ConnectBlock(block, clearstate, pindexDelete, clearview, chainparams, false));

            BOOST_CHECK(!clearstate.IsInvalid());
            BOOST_REQUIRE(FlushView(&clearview, state, false));
            BOOST_REQUIRE(::ChainstateActive().FlushStateToDisk(chainparams, clearstate, FlushStateMode::IF_NEEDED));
            ::ChainActive().SetTip(pindexDelete);
            UpdateTip(pindexDelete, chainparams);

            BOOST_CHECK(tipHash == ::ChainActive().Tip()->GetBlockHash());
            BOOST_CHECK(::ChainActive().Tip()->nMoneySupply == 12500000153511);
        }
    }

    BOOST_CHECK_NO_THROW(rv = CallRPC("getnewextaddress lblTestKey"));
    std::string extaddr = part::StripQuotes(rv.write());

    BOOST_CHECK(pwallet->GetBalance().m_mine_trusted + pwallet->GetStaked() == 12500000108911);

    {
        BOOST_CHECK_NO_THROW(rv = CallRPC("getnewstealthaddress"));
        std::string sSxAddr = part::StripQuotes(rv.write());

        CBitcoinAddress address(sSxAddr);


        AddAnonTxn(pwallet, address, 10 * COIN);
        AddAnonTxn(pwallet, address, 20 * COIN);

        StakeNBlocks(pwallet, 2);
        CCoinControl coinControl;
        BOOST_CHECK(30 * COIN == pwallet->GetAvailableAnonBalance(&coinControl));

        BOOST_CHECK(::ChainActive().Tip()->nAnonOutputs == 4);

        for (size_t i = 0; i < 2; ++i) {
            LOCK(cs_main);
            // Disconnect last block
            uint256 prevTipHash = ::ChainActive().Tip()->pprev->GetBlockHash();
            CBlockIndex *pindexDelete = ::ChainActive().Tip();
            BOOST_REQUIRE(pindexDelete);

            CBlock block;
            BOOST_REQUIRE(ReadBlockFromDisk(block, pindexDelete, chainparams.GetConsensus()));

            CCoinsViewCache &view = ::ChainstateActive().CoinsTip();
            DisconnectTip(block, pindexDelete, view, chainparams);

            BOOST_CHECK(prevTipHash == ::ChainActive().Tip()->GetBlockHash());
        }

        BOOST_CHECK(::ChainActive().Tip()->nAnonOutputs == 0);
        BOOST_CHECK(::ChainActive().Tip()->nMoneySupply == 12500000153511);
    }
}

BOOST_AUTO_TEST_SUITE_END()
