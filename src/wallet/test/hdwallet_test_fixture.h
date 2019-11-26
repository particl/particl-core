// Copyright (c) 2017-2019 The Particl Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef PARTICL_WALLET_TEST_HDWALLET_TEST_FIXTURE_H
#define PARTICL_WALLET_TEST_HDWALLET_TEST_FIXTURE_H

#include <test/util/setup_common.h>
#include <interfaces/chain.h>

class CHDWallet;

/** Testing setup and teardown for wallet.
 */
struct HDWalletTestingSetup: public TestingSetup {
    explicit HDWalletTestingSetup(const std::string& chainName = CBaseChainParams::MAIN);
    ~HDWalletTestingSetup();

    std::unique_ptr<interfaces::Chain> m_chain = interfaces::MakeChain(m_node);
    std::unique_ptr<interfaces::ChainClient> m_chain_client = interfaces::MakeWalletClient(*m_chain, {});
    std::shared_ptr<CHDWallet> pwalletMain;
};

#endif // PARTICL_WALLET_TEST_HDWALLET_TEST_FIXTURE_H

