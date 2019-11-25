// Copyright (c) 2012-2019 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <wallet/test/hdwallet_test_fixture.h>
#include <bench/bench.h>
#include <wallet/hdwallet.h>
#include <wallet/coincontrol.h>
#include <interfaces/chain.h>

#include <validation.h>
#include <blind.h>
#include <rpc/rpcutil.h>
#include <timedata.h>
#include <miner.h>
#include <pos/miner.h>

struct TimingTestingSetup: public TestingSetup {
    TimingTestingSetup(const std::string& chainName = CBaseChainParams::REGTEST):
        TestingSetup(chainName, true)
    {
        ECC_Start_Stealth();
        ECC_Start_Blinding();

        m_chain_client->registerRpcs();
    }

    ~TimingTestingSetup()
    {
        ECC_Stop_Stealth();
        ECC_Stop_Blinding();
    }

    std::unique_ptr<interfaces::Chain> m_chain = interfaces::MakeChain(m_node);
    std::unique_ptr<interfaces::ChainClient> m_chain_client = interfaces::MakeWalletClient(*m_chain, {});
};

std::string StripQuotes(std::string s)
{
    // Strip double quotes from start and/or end of string
    size_t len = s.length();
    if (len < 2) {
        if (len > 0 && s[0] == '"') {
            s = s.substr(1, len - 1);
        }
        return s;
    }

    if (s[0] == '"') {
        if (s[len-1] == '"') {
            s = s.substr(1, len - 2);
        } else {
            s = s.substr(1, len - 1);
        }
    } else
    if (s[len-1] == '"') {
        s = s.substr(0, len - 2);
    }
    return s;
};

CTransactionRef CreateTxn(CHDWallet *pwallet, CBitcoinAddress &address, CAmount amount, int type_in, int type_out, int nRingSize = 5)
{
    auto locked_chain = pwallet->chain().lock();
    LOCK(pwallet->cs_wallet);
    LockAssertion lock(::cs_main);

    assert(address.IsValid());

    std::vector<CTempRecipient> vecSend;
    std::string sError;
    CTempRecipient r;
    r.nType = type_out;
    r.SetAmount(amount);
    r.address = address.Get();
    vecSend.push_back(r);

    CTransactionRef tx_new;
    CWalletTx wtx(pwallet, tx_new);
    CTransactionRecord rtx;
    CAmount nFee;
    CCoinControl coinControl;
    if (type_in == OUTPUT_STANDARD) {
        int result = pwallet->AddStandardInputs(*locked_chain, wtx, rtx, vecSend, true, nFee, &coinControl, sError);
        std::cout << sError << std::endl;
        assert(0 == result);
    } else
    if (type_in == OUTPUT_CT) {
        int result = pwallet->AddBlindedInputs(*locked_chain, wtx, rtx, vecSend, true, nFee, &coinControl, sError);
        std::cout << sError << std::endl;
        assert(0 == result);
    } else {
        int nInputsPerSig = 1;
        int result = pwallet->AddAnonInputs(*locked_chain, wtx, rtx, vecSend, true, nRingSize, nInputsPerSig, nFee, &coinControl, sError);
        std::cout << sError << std::endl;
        assert(0 == result);
    }
    return wtx.tx;
}

static void AddAnonTxn(CHDWallet *pwallet, CBitcoinAddress &address, CAmount amount, OutputTypes output_type)
{
    {
    auto locked_chain = pwallet->chain().lock();
    LOCK(pwallet->cs_wallet);
    LockAssertion lock(::cs_main);

    assert(address.IsValid());

    std::vector<CTempRecipient> vecSend;
    std::string sError;
    CTempRecipient r;
    r.nType = output_type;
    r.SetAmount(amount);
    r.address = address.Get();
    vecSend.push_back(r);

    CTransactionRef tx_new;
    CWalletTx wtx(pwallet, tx_new);
    CTransactionRecord rtx;
    CAmount nFee;
    CCoinControl coinControl;
    assert(0 == pwallet->AddStandardInputs(*locked_chain, wtx, rtx, vecSend, true, nFee, &coinControl, sError));

    wtx.BindWallet(pwallet);
    assert(wtx.SubmitMemoryPoolAndRelay(sError, true));
    } // cs_main
    SyncWithValidationInterfaceQueue();
}

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
        assert(pblocktemplate.get());

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
    assert(k < nTries);
    SyncWithValidationInterfaceQueue();
};

static void WalletTiming(benchmark::State& state, const std::string type, const bool owned)
{
    TimingTestingSetup test{};
    
    uint64_t wallet_creation_flags = 0;
    SecureString passphrase;
    std::string error;
    std::vector<std::string> warnings;

    WalletLocation location_a("a");
    std::shared_ptr<CHDWallet> pwallet_a = std::static_pointer_cast<CHDWallet>(CWallet::CreateWalletFromFile(*test.m_chain.get(), location_a, error, warnings, wallet_creation_flags));
    std::cout << error << std::endl;
    assert(pwallet_a.get());
    pwallet_a->Initialise();
    AddWallet(pwallet_a);

    WalletLocation location_b("b");
    std::shared_ptr<CHDWallet> pwallet_b = std::static_pointer_cast<CHDWallet>(CWallet::CreateWalletFromFile(*test.m_chain.get(), location_b, error, warnings, wallet_creation_flags));
    assert(pwallet_b.get());
    pwallet_b->Initialise();
    AddWallet(pwallet_b);

    {
        LOCK(pwallet_a->cs_wallet);
        pwallet_a->SetLastBlockProcessed(::ChainActive().Height(), ::ChainActive().Tip()->GetBlockHash());
    }
    {
        LOCK(pwallet_b->cs_wallet);
        pwallet_b->SetLastBlockProcessed(::ChainActive().Height(), ::ChainActive().Tip()->GetBlockHash());
    }

    std::string from_address_type, to_address_type;
    OutputTypes from_tx_type, to_tx_type;

    std::string from = type.substr(0, type.find("->"));
    std::string to = type.substr(type.find("->") + 2);

    UniValue rv;

    CallRPC("extkeyimportmaster tprv8ZgxMBicQKsPeK5mCpvMsd1cwyT1JZsrBN82XkoYuZY1EVK7EwDaiL9sDfqUU5SntTfbRfnRedFWjg5xkDG5i3iwd3yP7neX5F2dtdCojk4", "a");
    CallRPC("extkeyimportmaster \"expect trouble pause odor utility palace ignore arena disorder frog helmet addict\"", "b");

    if (from == "plain") {
        from_address_type = "getnewaddress";
        from_tx_type = OUTPUT_STANDARD;
    } else if (from == "blind") {
        from_address_type = "getnewstealthaddress";
        from_tx_type = OUTPUT_CT;
    } else if (from == "anon") {
        from_address_type = "getnewstealthaddress";
        from_tx_type = OUTPUT_RINGCT;
    }

    if (to == "plain") {
        to_address_type = "getnewaddress";
        to_tx_type = OUTPUT_STANDARD;
    } else if (to == "blind") {
        to_address_type = "getnewstealthaddress";
        to_tx_type = OUTPUT_CT;
    } else if (to == "anon") {
        to_address_type = "getnewstealthaddress";
        to_tx_type = OUTPUT_RINGCT;
    }
    
    rv = CallRPC(from_address_type, "a");
    CBitcoinAddress addr_a(StripQuotes(rv.write()));

    rv = CallRPC(to_address_type, "b");
    CBitcoinAddress addr_b(StripQuotes(rv.write()));

    if (from == "anon" || from == "blind") {
        AddAnonTxn(pwallet_a.get(), addr_a, 1 * COIN, from == "anon" ? OUTPUT_RINGCT : OUTPUT_CT);
        AddAnonTxn(pwallet_a.get(), addr_a, 1 * COIN, from == "anon" ? OUTPUT_RINGCT : OUTPUT_CT);
        AddAnonTxn(pwallet_a.get(), addr_a, 1 * COIN, from == "anon" ? OUTPUT_RINGCT : OUTPUT_CT);
        AddAnonTxn(pwallet_a.get(), addr_a, 1 * COIN, from == "anon" ? OUTPUT_RINGCT : OUTPUT_CT);
        AddAnonTxn(pwallet_a.get(), addr_a, 1 * COIN, from == "anon" ? OUTPUT_RINGCT : OUTPUT_CT);

        StakeNBlocks(pwallet_a.get(), 2);
    }

    CTransactionRef tx = CreateTxn(pwallet_a.get(), owned ? addr_b : addr_a, 1000, from_tx_type, to_tx_type);
    
    CWalletTx::Confirmation confirm;
    LOCK(cs_main);
    LOCK(pwallet_b.get()->cs_wallet);

    while (state.KeepRunning()) {
        pwallet_b.get()->AddToWalletIfInvolvingMe(tx, confirm, true);
    }

    RemoveWallet(pwallet_a);
    pwallet_a.reset();

    RemoveWallet(pwallet_b);
    pwallet_b.reset();
}

static void WalletTimingPlainPlainNotOwned(benchmark::State& state) { WalletTiming(state, "plain->plain", false); }
static void WalletTimingPlainPlainOwned(benchmark::State& state) { WalletTiming(state, "plain->plain", true); }
static void WalletTimingPlainBlindNotOwned(benchmark::State& state) { WalletTiming(state, "plain->blind", false); }
static void WalletTimingPlainBlindOwned(benchmark::State& state) { WalletTiming(state, "plain->blind", true); }
static void WalletTimingPlainAnonNotOwned(benchmark::State& state) { WalletTiming(state, "plain->anon", false); }
static void WalletTimingPlainAnonOwned(benchmark::State& state) { WalletTiming(state, "plain->anon", true); }

static void WalletTimingBlindPlainNotOwned(benchmark::State& state) { WalletTiming(state, "blind->plain", false); }
static void WalletTimingBlindPlainOwned(benchmark::State& state) { WalletTiming(state, "blind->plain", true); }
static void WalletTimingBlindBlindNotOwned(benchmark::State& state) { WalletTiming(state, "blind->blind", false); }
static void WalletTimingBlindBlindOwned(benchmark::State& state) { WalletTiming(state, "blind->blind", true); }
static void WalletTimingBlindAnonNotOwned(benchmark::State& state) { WalletTiming(state, "blind->anon", false); }
static void WalletTimingBlindAnonOwned(benchmark::State& state) { WalletTiming(state, "blind->anon", true); }

static void WalletTimingAnonPlainNotOwned(benchmark::State& state) { WalletTiming(state, "anon->plain", false); }
static void WalletTimingAnonPlainOwned(benchmark::State& state) { WalletTiming(state, "anon->plain", true); }
static void WalletTimingAnonBlindNotOwned(benchmark::State& state) { WalletTiming(state, "anon->blind", false); }
static void WalletTimingAnonBlindOwned(benchmark::State& state) { WalletTiming(state, "anon->blind", true); }
static void WalletTimingAnonAnonNotOwned(benchmark::State& state) { WalletTiming(state, "anon->anon", false); }
static void WalletTimingAnonAnonOwned(benchmark::State& state) { WalletTiming(state, "anon->anon", true); }


BENCHMARK(WalletTimingPlainPlainNotOwned, 100);
BENCHMARK(WalletTimingPlainPlainOwned, 100);
BENCHMARK(WalletTimingPlainBlindNotOwned, 100);
BENCHMARK(WalletTimingPlainBlindOwned, 100);
// BENCHMARK(WalletTimingPlainAnonNotOwned, 100);
// BENCHMARK(WalletTimingPlainAnonOwned, 100);

BENCHMARK(WalletTimingBlindPlainNotOwned, 100);
BENCHMARK(WalletTimingBlindPlainOwned, 100);
BENCHMARK(WalletTimingBlindBlindNotOwned, 100);
BENCHMARK(WalletTimingBlindBlindOwned, 100);
BENCHMARK(WalletTimingBlindAnonNotOwned, 100);
BENCHMARK(WalletTimingBlindAnonOwned, 100);


BENCHMARK(WalletTimingAnonPlainNotOwned, 100);
BENCHMARK(WalletTimingAnonPlainOwned, 100);
BENCHMARK(WalletTimingAnonBlindNotOwned, 100);
BENCHMARK(WalletTimingAnonBlindOwned, 100);
BENCHMARK(WalletTimingAnonAnonNotOwned, 100);
BENCHMARK(WalletTimingAnonAnonOwned, 100);
