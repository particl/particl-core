// Copyright (c) 2017-2019 The Particl Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <wallet/hdwallettypes.h>

int CTransactionRecord::InsertOutput(COutputRecord &r)
{
    for (size_t i = 0; i < vout.size(); ++i) {
        if (vout[i].n == r.n) {
            return 0; // duplicate
        }

        if (vout[i].n < r.n) {
            continue;
        }

        vout.insert(vout.begin() + i, r);
        return 1;
    }
    vout.push_back(r);
    return 1;
};

bool CTransactionRecord::EraseOutput(uint16_t n)
{
    for (size_t i = 0; i < vout.size(); ++i) {
        if (vout[i].n != n) {
            continue;
        }

        vout.erase(vout.begin() + i);
        return true;
    }
    return false;
};

COutputRecord *CTransactionRecord::GetOutput(int n)
{
    // vout is always in order by asc n
    for (auto &r : vout) {
        if (r.n > n) {
            return nullptr;
        }
        if (r.n == n) {
            return &r;
        }
    }
    return nullptr;
};

const COutputRecord *CTransactionRecord::GetOutput(int n) const
{
    // vout is always in order by asc n
    for (const auto &r : vout) {
        if (r.n > n) {
            return nullptr;
        }
        if (r.n == n) {
            return &r;
        }
    }
    return nullptr;
};

const COutputRecord *CTransactionRecord::GetChangeOutput() const
{
    for (const auto &r : vout) {
        if (r.nFlags & ORF_CHANGE) {
            return &r;
        }
    }
    return nullptr;
};
