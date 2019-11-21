// Copyright (c) 2017 The Particl Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_WALLET_RPCHDWALLET_H
#define BITCOIN_WALLET_RPCHDWALLET_H

#include <memory>
#include <vector>

namespace interfaces {
class Chain;
class Handler;
}

void RegisterHDWalletRPCCommands(interfaces::Chain& chain, std::vector<std::unique_ptr<interfaces::Handler>>& handlers);

#endif //BITCOIN_WALLET_RPCHDWALLET_H
