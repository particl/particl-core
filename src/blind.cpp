// Copyright (c) 2017-2021 The Particl Core developers
// Distributed under the MIT/X11 software license, see the accompanying
// file license.txt or http://www.opensource.org/licenses/mit-license.php.

#include <blind.h>

#include <assert.h>
#include <secp256k1_rangeproof.h>

#include <support/allocators/secure.h>
#include <random.h>
#include <util/system.h>
#include <serialize.h>
#include <streams.h>
#include <version.h>

#include <common/bloom.h>
#include <chain/ct_tainted.h>
#include <chain/tx_blacklist.h>
#include <chain/tx_whitelist.h>
#include <set>


secp256k1_context *secp256k1_ctx_blind = nullptr;
secp256k1_scratch_space *blind_scratch = nullptr;
secp256k1_bulletproof_generators *blind_gens = nullptr;

static CBloomFilter ct_tainted_filter;
static std::set<uint256> ct_whitelist;
static std::set<int64_t> rct_whitelist;
static std::set<int64_t> rct_blacklist;
static std::set<int64_t> rct_whitelist2;

static int CountLeadingZeros(uint64_t nValueIn)
{
    int nZeros = 0;

    for (size_t i = 0; i < 64; ++i, nValueIn >>= 1) {
        if ((nValueIn & 1)) {
            break;
        }
        nZeros++;
    }

    return nZeros;
}

static int CountTrailingZeros(uint64_t nValueIn)
{
    int nZeros = 0;

    uint64_t mask = ((uint64_t)1) << 63;
    for (size_t i = 0; i < 64; ++i, nValueIn <<= 1) {
        if ((nValueIn & mask)) {
            break;
        }
        nZeros++;
    }

    return nZeros;
}

static int64_t ipow(int64_t base, int exp)
{
    int64_t result = 1;
    while (exp) {
        if (exp & 1) {
            result *= base;
        }
        exp >>= 1;
        base *= base;
    }
    return result;
}


int SelectRangeProofParameters(uint64_t nValueIn, uint64_t &minValue, int &exponent, int &nBits)
{
    int nLeadingZeros = CountLeadingZeros(nValueIn);
    int nTrailingZeros = CountTrailingZeros(nValueIn);

    size_t nBitsReq = 64 - nLeadingZeros - nTrailingZeros;

    nBits = 32;

    // TODO: output rangeproof parameters should depend on the parameters of the inputs
    // TODO: drop low value bits to fee

    if (nValueIn == 0) {
        exponent = GetRandInt(5);
        if (GetRandInt(10) == 0) { // sometimes raise the exponent
            nBits += GetRandInt(5);
        }
        return 0;
    }


    uint64_t nTest = nValueIn;
    size_t nDiv10; // max exponent
    for (nDiv10 = 0; nTest % 10 == 0; nDiv10++, nTest /= 10) ;


    // TODO: how to pick best?

    int eMin = nDiv10 / 2;
    exponent = eMin;
    if (nDiv10-eMin > 0) {
        exponent += GetRandInt(nDiv10-eMin);
    }

    nTest = nValueIn / ipow(10, exponent);

    nLeadingZeros = CountLeadingZeros(nTest);
    nTrailingZeros = CountTrailingZeros(nTest);

    nBitsReq = 64 - nTrailingZeros;


    if (nBitsReq > 32) {
        nBits = nBitsReq;
    }

    // make multiple of 4
    while (nBits < 63 && nBits % 4 != 0) {
        nBits++;
    }

    return 0;
}

int GetRangeProofInfo(const std::vector<uint8_t> &vRangeproof, int &rexp, int &rmantissa, CAmount &min_value, CAmount &max_value)
{
    if (vRangeproof.size() > 500 && vRangeproof.size() < 1000) { // v2
        rexp = -1;
        rmantissa = -1;
        min_value = 0;
        max_value = 0x7FFFFFFFFFFFFFFFl; // largest signed
        return true;
    }
    return (!(secp256k1_rangeproof_info(secp256k1_ctx_blind,
        &rexp, &rmantissa, (uint64_t*) &min_value, (uint64_t*) &max_value,
        vRangeproof.data(), vRangeproof.size()) == 1));
}

void LoadRCTBlacklist(const int64_t indices[], size_t num_indices)
{
    rct_blacklist = std::set<int64_t>(indices, indices + num_indices);
    LogPrintf("RCT blacklist size %d\n", rct_blacklist.size());
}

void LoadRCTWhitelist(const int64_t indices[], size_t num_indices, int list_id)
{
    switch (list_id) {
        case 1:
            rct_whitelist = std::set<int64_t>(indices, indices + num_indices);
            LogPrintf("RCT whitelist size %d\n", rct_whitelist.size());
            break;
        case 2:
            rct_whitelist2 = std::set<int64_t>(indices, indices + num_indices);
            LogPrintf("RCT whitelist2 size %d\n", rct_whitelist2.size());
            break;
        default:
            LogPrintf("Error: Unknown RCT whitelist %d\n", list_id);
            break;
    }
}

void LoadCTWhitelist(const unsigned char *data, size_t data_length)
{
    assert(data_length % 32 == 0);

    ct_whitelist.clear();
    for (size_t i = 0; i < data_length; i += 32) {
        ct_whitelist.insert(uint256(&data[i], 32));
    }
    LogPrintf("CT whitelist size %d\n", ct_whitelist.size());
}

void LoadCTTaintedFilter(const unsigned char *data, size_t data_length)
{
    CDataStream stream(Span<const unsigned char>(data, data_length), SER_NETWORK, PROTOCOL_VERSION);
    stream >> ct_tainted_filter;
}

void LoadBlindedOutputFilters()
{
    LoadCTTaintedFilter(ct_tainted_filter_data, ct_tainted_filter_data_len);
    LoadCTWhitelist(tx_whitelist_data, tx_whitelist_data_len);
    LoadRCTWhitelist(anon_index_whitelist, anon_index_whitelist_size, 1);
    LoadRCTBlacklist(anon_index_blacklist, anon_index_blacklist_size);
    LoadRCTWhitelist(anon_index_whitelist2, anon_index_whitelist2_size, 2);
}

bool IsFrozenBlindOutput(const uint256 &txid)
{
    if (ct_tainted_filter.contains(txid)) {
        return !ct_whitelist.count(txid);
    }
    return false;
}

bool IsBlacklistedAnonOutput(int64_t anon_index)
{
    return rct_blacklist.count(anon_index);
}

bool IsWhitelistedAnonOutput(int64_t anon_index, int64_t time, const Consensus::Params &consensus_params)
{
    if (time >= consensus_params.exploit_fix_3_time &&
        rct_whitelist2.count(anon_index)) {
        return true;
    }
    return rct_whitelist.count(anon_index);
}

void ECC_Start_Blinding()
{
    assert(secp256k1_ctx_blind == nullptr);

    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    assert(ctx != nullptr);

    {
        // Pass in a random blinding seed to the secp256k1 context.
        std::vector<unsigned char, secure_allocator<unsigned char> > vseed(32);
        GetRandBytes(vseed.data(), 32);
        bool ret = secp256k1_context_randomize(ctx, vseed.data());
        assert(ret);
    }

    secp256k1_ctx_blind = ctx;

    blind_scratch = secp256k1_scratch_space_create(secp256k1_ctx_blind, 1024 * 1024);
    assert(blind_scratch);
    blind_gens = secp256k1_bulletproof_generators_create(secp256k1_ctx_blind, &secp256k1_generator_const_g, 128);
    assert(blind_gens);
}

void ECC_Stop_Blinding()
{
    secp256k1_bulletproof_generators_destroy(secp256k1_ctx_blind, blind_gens);
    secp256k1_scratch_space_destroy(secp256k1_ctx_blind, blind_scratch);

    secp256k1_context *ctx = secp256k1_ctx_blind;
    secp256k1_ctx_blind = nullptr;

    if (ctx) {
        secp256k1_context_destroy(ctx);
    }
}
