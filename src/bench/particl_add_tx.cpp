// Copyright (c) 2017-2019 The Particl Core developers
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
#include <rpc/blockchain.h>
#include <timedata.h>
#include <miner.h>
#include <pos/miner.h>
#include <util/string.h>

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
        assert(0 == pwallet->AddStandardInputs(*locked_chain, wtx, rtx, vecSend, true, nFee, &coinControl, sError));
    } else
    if (type_in == OUTPUT_CT) {
        assert(0 == pwallet->AddBlindedInputs(*locked_chain, wtx, rtx, vecSend, true, nFee, &coinControl, sError));
    } else {
        int nInputsPerSig = 1;
        assert(0 == pwallet->AddAnonInputs(*locked_chain, wtx, rtx, vecSend, true, nRingSize, nInputsPerSig, nFee, &coinControl, sError));
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

static void AddTx(benchmark::State& state, const std::string from, const std::string to, const bool owned)
{
    ECC_Start_Stealth();
    ECC_Start_Blinding();

    std::unique_ptr<interfaces::Chain> m_chain = interfaces::MakeChain(*g_rpc_node);
    std::unique_ptr<interfaces::ChainClient> m_chain_client = interfaces::MakeWalletClient(*m_chain, {});
    m_chain_client->registerRpcs();

    uint64_t wallet_creation_flags = WALLET_FLAG_BLANK_WALLET;
    SecureString passphrase;
    std::string error;
    std::vector<std::string> warnings;

    WalletLocation location_a("a");
    std::shared_ptr<CHDWallet> pwallet_a = std::static_pointer_cast<CHDWallet>(CWallet::CreateWalletFromFile(*m_chain.get(), location_a, error, warnings, wallet_creation_flags));
    assert(pwallet_a.get());
    pwallet_a->Initialise();
    AddWallet(pwallet_a);

    WalletLocation location_b("b");
    std::shared_ptr<CHDWallet> pwallet_b = std::static_pointer_cast<CHDWallet>(CWallet::CreateWalletFromFile(*m_chain.get(), location_b, error, warnings, wallet_creation_flags));
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
    OutputTypes from_tx_type = OUTPUT_NULL;
    OutputTypes to_tx_type = OUTPUT_NULL;

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

    assert(from_tx_type != OUTPUT_NULL);
    assert(to_tx_type != OUTPUT_NULL);

    rv = CallRPC(from_address_type, "a");
    CBitcoinAddress addr_a(part::StripQuotes(rv.write()));

    rv = CallRPC(to_address_type, "b");
    CBitcoinAddress addr_b(part::StripQuotes(rv.write()));

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

    ECC_Stop_Stealth();
    ECC_Stop_Blinding();
}

static void ParticlAddTxPlainPlainNotOwned(benchmark::State& state) { AddTx(state, "plain", "plain", false); }
static void ParticlAddTxPlainPlainOwned(benchmark::State& state) { AddTx(state, "plain", "plain", true); }
static void ParticlAddTxPlainBlindNotOwned(benchmark::State& state) { AddTx(state, "plain", "blind", false); }
static void ParticlAddTxPlainBlindOwned(benchmark::State& state) { AddTx(state, "plain", "blind", true); }
// static void ParticlAddTxPlainAnonNotOwned(benchmark::State& state) { AddTx(state, "plain", "anon", false); }
// static void ParticlAddTxPlainAnonOwned(benchmark::State& state) { AddTx(state, "plain", "anon", true); }

static void ParticlAddTxBlindPlainNotOwned(benchmark::State& state) { AddTx(state, "blind", "plain", false); }
static void ParticlAddTxBlindPlainOwned(benchmark::State& state) { AddTx(state, "blind", "plain", true); }
static void ParticlAddTxBlindBlindNotOwned(benchmark::State& state) { AddTx(state, "blind", "blind", false); }
static void ParticlAddTxBlindBlindOwned(benchmark::State& state) { AddTx(state, "blind", "blind", true); }
static void ParticlAddTxBlindAnonNotOwned(benchmark::State& state) { AddTx(state, "blind", "anon", false); }
static void ParticlAddTxBlindAnonOwned(benchmark::State& state) { AddTx(state, "blind", "anon", true); }

static void ParticlAddTxAnonPlainNotOwned(benchmark::State& state) { AddTx(state, "anon", "plain", false); }
static void ParticlAddTxAnonPlainOwned(benchmark::State& state) { AddTx(state, "anon", "plain", true); }
static void ParticlAddTxAnonBlindNotOwned(benchmark::State& state) { AddTx(state, "anon", "blind", false); }
static void ParticlAddTxAnonBlindOwned(benchmark::State& state) { AddTx(state, "anon", "blind", true); }
static void ParticlAddTxAnonAnonNotOwned(benchmark::State& state) { AddTx(state, "anon", "anon", false); }
static void ParticlAddTxAnonAnonOwned(benchmark::State& state) { AddTx(state, "anon", "anon", true); }

BENCHMARK(ParticlAddTxPlainPlainNotOwned, 100);
BENCHMARK(ParticlAddTxPlainPlainOwned, 100);
BENCHMARK(ParticlAddTxPlainBlindNotOwned, 100);
BENCHMARK(ParticlAddTxPlainBlindOwned, 100);
// BENCHMARK(ParticlAddTxPlainAnonNotOwned, 100);
// BENCHMARK(ParticlAddTxPlainAnonOwned, 100);

BENCHMARK(ParticlAddTxBlindPlainNotOwned, 100);
BENCHMARK(ParticlAddTxBlindPlainOwned, 100);
BENCHMARK(ParticlAddTxBlindBlindNotOwned, 100);
BENCHMARK(ParticlAddTxBlindBlindOwned, 100);
BENCHMARK(ParticlAddTxBlindAnonNotOwned, 100);
BENCHMARK(ParticlAddTxBlindAnonOwned, 100);

BENCHMARK(ParticlAddTxAnonPlainNotOwned, 100);
BENCHMARK(ParticlAddTxAnonPlainOwned, 100);
BENCHMARK(ParticlAddTxAnonBlindNotOwned, 100);
BENCHMARK(ParticlAddTxAnonBlindOwned, 100);
BENCHMARK(ParticlAddTxAnonAnonNotOwned, 100);
BENCHMARK(ParticlAddTxAnonAnonOwned, 100);
