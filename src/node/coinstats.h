// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2019 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_NODE_COINSTATS_H
#define BITCOIN_NODE_COINSTATS_H

#include <amount.h>
#include <uint256.h>

#include <cstdint>

class CCoinsView;

struct CCoinsStats
{
    int nHeight;
    uint256 hashBlock;
    uint64_t nTransactions;
    uint64_t nTransactionOutputs;
    uint64_t nBogoSize;
    uint256 hashSerialized;
    uint64_t nDiskSize;
    CAmount nTotalAmount;
    uint64_t nBlindTransactionOutputs;

    //! The number of coins contained.
    uint64_t coins_count{0};

    CCoinsStats() : nHeight(0), nTransactions(0), nTransactionOutputs(0), nBogoSize(0), nDiskSize(0), nTotalAmount(0), nBlindTransactionOutputs(0) {}
};

//! Calculate statistics about the unspent transaction output set
bool GetUTXOStats(CCoinsView* view, CCoinsStats& stats);

#endif // BITCOIN_NODE_COINSTATS_H
