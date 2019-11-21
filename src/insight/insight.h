// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_INSIGHT_INSIGHT_H
#define BITCOIN_INSIGHT_INSIGHT_H

#include <threadsafety.h>

#include <amount.h>
#include <sync.h>
#include <stdint.h>
#include <vector>
#include <string>
#include <utility>

extern CCriticalSection cs_main;

extern bool fAddressIndex;
extern bool fSpentIndex;
extern bool fTimestampIndex;

class CTxOutBase;
class CScript;
class uint256;
struct CAddressIndexKey;
struct CAddressUnspentKey;
struct CAddressUnspentValue;
struct CSpentIndexKey;
struct CSpentIndexValue;

bool ExtractIndexInfo(const CScript *pScript, int &scriptType, std::vector<uint8_t> &hashBytes);
bool ExtractIndexInfo(const CTxOutBase *out, int &scriptType, std::vector<uint8_t> &hashBytes, CAmount &nValue, const CScript *&pScript);

/** Functions for insight block explorer */
bool GetTimestampIndex(const unsigned int &high, const unsigned int &low, const bool fActiveOnly, std::vector<std::pair<uint256, unsigned int> > &hashes);
bool GetSpentIndex(CSpentIndexKey &key, CSpentIndexValue &value);
bool HashOnchainActive(const uint256 &hash) EXCLUSIVE_LOCKS_REQUIRED(cs_main);
bool GetAddressIndex(uint256 addressHash, int type,
                     std::vector<std::pair<CAddressIndexKey, CAmount> > &addressIndex,
                     int start = 0, int end = 0);
bool GetAddressUnspent(uint256 addressHash, int type,
                       std::vector<std::pair<CAddressUnspentKey, CAddressUnspentValue> > &unspentOutputs);

bool getAddressFromIndex(const int &type, const uint256 &hash, std::string &address);

#endif // BITCOIN_INSIGHT_INSIGHT_H
