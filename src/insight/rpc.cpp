// Copyright (c) 2018-2019 The Particl Core developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <rpc/server.h>
#include <rpc/util.h>
#include <rpc/blockchain.h>

#include <util/strencodings.h>
#include <insight/insight.h>
#include <insight/csindex.h>
#include <index/txindex.h>
#include <validation.h>
#include <txmempool.h>
#include <key_io.h>
#include <core_io.h>
#include <script/standard.h>

#include <univalue.h>

#include <boost/thread/thread.hpp> // boost::thread::interrupt

static bool GetIndexKey(const CTxDestination &dest, uint256 &hashBytes, int &type) {
    if (dest.type() == typeid(PKHash)) {
        const PKHash &id = boost::get<PKHash>(dest);
        memcpy(hashBytes.begin(), id.begin(), 20);
        type = ADDR_INDT_PUBKEY_ADDRESS;
        return true;
    }
    if (dest.type() == typeid(ScriptHash)) {
        const ScriptHash& id = boost::get<ScriptHash>(dest);
        memcpy(hashBytes.begin(), id.begin(), 20);
        type = ADDR_INDT_SCRIPT_ADDRESS;
        return true;
    }
    if (dest.type() == typeid(CKeyID256)) {
        const CKeyID256& id = boost::get<CKeyID256>(dest);
        memcpy(hashBytes.begin(), id.begin(), 32);
        type = ADDR_INDT_PUBKEY_ADDRESS_256;
        return true;
    }
    if (dest.type() == typeid(CScriptID256)) {
        const CScriptID256& id = boost::get<CScriptID256>(dest);
        memcpy(hashBytes.begin(), id.begin(), 32);
        type = ADDR_INDT_SCRIPT_ADDRESS_256;
        return true;
    }
    if (dest.type() == typeid(WitnessV0KeyHash)) {
        const WitnessV0KeyHash& id = boost::get<WitnessV0KeyHash>(dest);
        memcpy(hashBytes.begin(), id.begin(), 20);
        type = ADDR_INDT_WITNESS_V0_KEYHASH;
        return true;
    }
    if (dest.type() == typeid(WitnessV0ScriptHash)) {
        const WitnessV0ScriptHash& id = boost::get<WitnessV0ScriptHash>(dest);
        memcpy(hashBytes.begin(), id.begin(), 32);
        type = ADDR_INDT_WITNESS_V0_SCRIPTHASH;
        return true;
    }
    type = ADDR_INDT_UNKNOWN;
    return false;
}

bool getAddressesFromParams(const UniValue& params, std::vector<std::pair<uint256, int> > &addresses)
{
    if (params[0].isStr()) {
        auto dest = DecodeDestination(params[0].get_str());
        uint256 hashBytes;
        int type = 0;
        if (!GetIndexKey(dest, hashBytes, type)) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid address");
        }
        addresses.push_back(std::make_pair(hashBytes, type));
    } else
    if (params[0].isObject()) {
        UniValue addressValues = find_value(params[0].get_obj(), "addresses");
        if (!addressValues.isArray()) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Addresses is expected to be an array");
        }

        std::vector<UniValue> values = addressValues.getValues();
        for (std::vector<UniValue>::iterator it = values.begin(); it != values.end(); ++it) {
            auto dest = DecodeDestination(it->get_str());
            uint256 hashBytes;
            int type = 0;
            if (!GetIndexKey(dest, hashBytes, type)) {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid address");
            }
            addresses.push_back(std::make_pair(hashBytes, type));
        }
    } else {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid address");
    }

    return true;
}

bool heightSort(std::pair<CAddressUnspentKey, CAddressUnspentValue> a,
                std::pair<CAddressUnspentKey, CAddressUnspentValue> b)
{
    return a.second.blockHeight < b.second.blockHeight;
}

bool timestampSort(std::pair<CMempoolAddressDeltaKey, CMempoolAddressDelta> a,
                   std::pair<CMempoolAddressDeltaKey, CMempoolAddressDelta> b)
{
    return a.second.time < b.second.time;
}

UniValue getaddressmempool(const JSONRPCRequest& request)
{
            RPCHelpMan{"getaddressmempool",
                "\nReturns all mempool deltas for an address (requires addressindex to be enabled).\n",
                {
                    {"addresses", RPCArg::Type::ARR, RPCArg::Optional::NO, "A json array with addresses.\n",
                        {
                            {"address", RPCArg::Type::STR, RPCArg::Optional::NO, "The base58check encoded address."},
                        },
                    },
                },
                RPCResult{
            "[\n"
            "  {\n"
            "    \"address\"  (string) The base58check encoded address\n"
            "    \"txid\"  (string) The related txid\n"
            "    \"index\"  (number) The related input or output index\n"
            "    \"satoshis\"  (number) The difference of satoshis\n"
            "    \"timestamp\"  (number) The time the transaction entered the mempool (seconds)\n"
            "    \"prevtxid\"  (string) The previous txid (if spending)\n"
            "    \"prevout\"  (string) The previous transaction output index (if spending)\n"
            "  }\n"
            "]\n"
                },
                RPCExamples{
            HelpExampleCli("getaddressmempool", "'{\"addresses\": [\"Pb7FLL3DyaAVP2eGfRiEkj4U8ZJ3RHLY9g\"]}'") +
            "\nAs a JSON-RPC call\n"
            + HelpExampleRpc("getaddressmempool", "{\"addresses\": [\"Pb7FLL3DyaAVP2eGfRiEkj4U8ZJ3RHLY9g\"]}")
                },
        }.Check(request);

    if (!fAddressIndex) {
        throw JSONRPCError(RPC_MISC_ERROR, "Address index is not enabled.");
    }

    std::vector<std::pair<uint256, int> > addresses;
    if (!getAddressesFromParams(request.params, addresses)) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid address");
    }

    std::vector<std::pair<CMempoolAddressDeltaKey, CMempoolAddressDelta> > indexes;
    if (!mempool.getAddressIndex(addresses, indexes)) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "No information available for address");
    }

    std::sort(indexes.begin(), indexes.end(), timestampSort);

    UniValue result(UniValue::VARR);

    for (std::vector<std::pair<CMempoolAddressDeltaKey, CMempoolAddressDelta> >::iterator it = indexes.begin();
         it != indexes.end(); it++) {

        std::string address;
        if (!getAddressFromIndex(it->first.type, it->first.addressBytes, address)) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Unknown address type");
        }

        UniValue delta(UniValue::VOBJ);
        delta.pushKV("address", address);
        delta.pushKV("txid", it->first.txhash.GetHex());
        delta.pushKV("index", (int)it->first.index);
        delta.pushKV("satoshis", it->second.amount);
        delta.pushKV("timestamp", it->second.time);
        if (it->second.amount < 0) {
            delta.pushKV("prevtxid", it->second.prevhash.GetHex());
            delta.pushKV("prevout", (int)it->second.prevout);
        }
        result.push_back(delta);
    }

    return result;
}

UniValue getaddressutxos(const JSONRPCRequest& request)
{
        RPCHelpMan{"getaddressutxos",
                "\nReturns all unspent outputs for an address (requires addressindex to be enabled).\n",
                {
                    {"addresses", RPCArg::Type::ARR, RPCArg::Optional::NO, "A json array with addresses.\n",
                        {
                            {"address", RPCArg::Type::STR, RPCArg::Optional::NO, "The base58check encoded address."},
                        },
                    },
                    {"chainInfo", RPCArg::Type::BOOL, /* default */ "false", "Include chain info in results, only applies if start and end specified."},
                },
                RPCResult{
            "[\n"
            "  {\n"
            "    \"address\"  (string) The address base58check encoded\n"
            "    \"txid\"  (string) The output txid\n"
            "    \"height\"  (number) The block height\n"
            "    \"outputIndex\"  (number) The output index\n"
            "    \"script\"  (strin) The script hex encoded\n"
            "    \"satoshis\"  (number) The number of satoshis of the output\n"
            "  }\n"
            "]\n"
                },
                RPCExamples{
            HelpExampleCli("getaddressutxos", "'{\"addresses\": [\"Pb7FLL3DyaAVP2eGfRiEkj4U8ZJ3RHLY9g\"]}'") +
            "\nAs a JSON-RPC call\n"
            + HelpExampleRpc("getaddressutxos", "{\"addresses\": [\"Pb7FLL3DyaAVP2eGfRiEkj4U8ZJ3RHLY9g\"]}")
                },
        }.Check(request);

    if (!fAddressIndex) {
        throw JSONRPCError(RPC_MISC_ERROR, "Address index is not enabled.");
    }

    bool includeChainInfo = false;
    if (request.params[0].isObject()) {
        UniValue chainInfo = find_value(request.params[0].get_obj(), "chainInfo");
        if (chainInfo.isBool()) {
            includeChainInfo = chainInfo.get_bool();
        }
    }

    std::vector<std::pair<uint256, int> > addresses;
    if (!getAddressesFromParams(request.params, addresses)) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid address");
    }

    std::vector<std::pair<CAddressUnspentKey, CAddressUnspentValue> > unspentOutputs;
    for (std::vector<std::pair<uint256, int> >::iterator it = addresses.begin(); it != addresses.end(); it++) {
        if (!GetAddressUnspent(it->first, it->second, unspentOutputs)) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "No information available for address");
        }
    }

    std::sort(unspentOutputs.begin(), unspentOutputs.end(), heightSort);

    UniValue utxos(UniValue::VARR);

    for (std::vector<std::pair<CAddressUnspentKey, CAddressUnspentValue> >::const_iterator it=unspentOutputs.begin(); it!=unspentOutputs.end(); it++) {
        UniValue output(UniValue::VOBJ);
        std::string address;
        if (!getAddressFromIndex(it->first.type, it->first.hashBytes, address)) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Unknown address type");
        }

        output.pushKV("address", address);
        output.pushKV("txid", it->first.txhash.GetHex());
        output.pushKV("outputIndex", (int)it->first.index);
        output.pushKV("script", HexStr(it->second.script.begin(), it->second.script.end()));
        output.pushKV("satoshis", it->second.satoshis);
        output.pushKV("height", it->second.blockHeight);
        utxos.push_back(output);
    }

    if (includeChainInfo) {
        UniValue result(UniValue::VOBJ);
        result.pushKV("utxos", utxos);

        LOCK(cs_main);
        result.pushKV("hash", ::ChainActive().Tip()->GetBlockHash().GetHex());
        result.pushKV("height", (int)::ChainActive().Height());
        return result;
    } else {
        return utxos;
    }
}

UniValue getaddressdeltas(const JSONRPCRequest& request)
{
            RPCHelpMan{"getaddressdeltas",
                "\nReturns all changes for an address (requires addressindex to be enabled).\n",
                {
                    {"addresses", RPCArg::Type::ARR, RPCArg::Optional::NO, "A json array with addresses.\n",
                        {
                            {"address", RPCArg::Type::STR, RPCArg::Optional::NO, "The base58check encoded address."},
                        },
                    },
                    {"start", RPCArg::Type::NUM, /* default */ "0", "The start block height."},
                    {"end", RPCArg::Type::NUM, /* default */ "0", "The end block height."},
                    {"chainInfo", RPCArg::Type::BOOL, /* default */ "false", "Include chain info in results, only applies if start and end specified."},
                },
                RPCResult{
            "[\n"
            "  {\n"
            "    \"satoshis\"  (number) The difference of satoshis\n"
            "    \"txid\"  (string) The related txid\n"
            "    \"index\"  (number) The related input or output index\n"
            "    \"height\"  (number) The block height\n"
            "    \"address\"  (string) The base58check encoded address\n"
            "  }\n"
            "]\n"
                },
                RPCExamples{
            HelpExampleCli("getaddressdeltas", "'{\"addresses\": [\"Pb7FLL3DyaAVP2eGfRiEkj4U8ZJ3RHLY9g\"]}'") +
            "\nAs a JSON-RPC call\n"
            + HelpExampleRpc("getaddressdeltas", "{\"addresses\": [\"Pb7FLL3DyaAVP2eGfRiEkj4U8ZJ3RHLY9g\"]}")
                },
        }.Check(request);

    if (!fAddressIndex) {
        throw JSONRPCError(RPC_MISC_ERROR, "Address index is not enabled.");
    }

    UniValue startValue = find_value(request.params[0].get_obj(), "start");
    UniValue endValue = find_value(request.params[0].get_obj(), "end");

    UniValue chainInfo = find_value(request.params[0].get_obj(), "chainInfo");
    bool includeChainInfo = false;
    if (chainInfo.isBool()) {
        includeChainInfo = chainInfo.get_bool();
    }

    int start = 0;
    int end = 0;

    if (startValue.isNum() && endValue.isNum()) {
        start = startValue.get_int();
        end = endValue.get_int();
        if (start <= 0 || end <= 0) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Start and end is expected to be greater than zero");
        }
        if (end < start) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "End value is expected to be greater than start");
        }
    }

    std::vector<std::pair<uint256, int> > addresses;

    if (!getAddressesFromParams(request.params, addresses)) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid address");
    }

    std::vector<std::pair<CAddressIndexKey, CAmount> > addressIndex;

    for (std::vector<std::pair<uint256, int> >::iterator it = addresses.begin(); it != addresses.end(); it++) {
        if (start > 0 && end > 0) {
            if (!GetAddressIndex(it->first, it->second, addressIndex, start, end)) {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "No information available for address");
            }
        } else {
            if (!GetAddressIndex(it->first, it->second, addressIndex)) {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "No information available for address");
            }
        }
    }

    UniValue deltas(UniValue::VARR);

    for (std::vector<std::pair<CAddressIndexKey, CAmount> >::const_iterator it=addressIndex.begin(); it!=addressIndex.end(); it++) {
        std::string address;
        if (!getAddressFromIndex(it->first.type, it->first.hashBytes, address)) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Unknown address type");
        }

        UniValue delta(UniValue::VOBJ);
        delta.pushKV("satoshis", it->second);
        delta.pushKV("txid", it->first.txhash.GetHex());
        delta.pushKV("index", (int)it->first.index);
        delta.pushKV("blockindex", (int)it->first.txindex);
        delta.pushKV("height", it->first.blockHeight);
        delta.pushKV("address", address);
        deltas.push_back(delta);
    }

    UniValue result(UniValue::VOBJ);

    if (includeChainInfo && start > 0 && end > 0) {
        LOCK(cs_main);

        if (start > ::ChainActive().Height() || end > ::ChainActive().Height()) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Start or end is outside chain range");
        }

        CBlockIndex* startIndex = ::ChainActive()[start];
        CBlockIndex* endIndex = ::ChainActive()[end];

        UniValue startInfo(UniValue::VOBJ);
        UniValue endInfo(UniValue::VOBJ);

        startInfo.pushKV("hash", startIndex->GetBlockHash().GetHex());
        startInfo.pushKV("height", start);

        endInfo.pushKV("hash", endIndex->GetBlockHash().GetHex());
        endInfo.pushKV("height", end);

        result.pushKV("deltas", deltas);
        result.pushKV("start", startInfo);
        result.pushKV("end", endInfo);

        return result;
    } else {
        return deltas;
    }
}

UniValue getaddressbalance(const JSONRPCRequest& request)
{
            RPCHelpMan{"getaddressbalance",
                "\nReturns the balance for an address(es) (requires addressindex to be enabled).\n",
                {
                    {"addresses", RPCArg::Type::ARR, RPCArg::Optional::NO, "A json array with addresses.\n",
                        {
                            {"address", RPCArg::Type::STR, RPCArg::Optional::NO, "The base58check encoded address."},
                        },
                    },
                },
                RPCResult{
            "{\n"
            "  \"balance\"  (string) The current balance in satoshis\n"
            "  \"received\"  (string) The total number of satoshis received (including change)\n"
            "}\n"
                },
                RPCExamples{
            HelpExampleCli("getaddressbalance", "'{\"addresses\": [\"Pb7FLL3DyaAVP2eGfRiEkj4U8ZJ3RHLY9g\"]}'") +
            "\nAs a JSON-RPC call\n"
            + HelpExampleRpc("getaddressbalance", "{\"addresses\": [\"Pb7FLL3DyaAVP2eGfRiEkj4U8ZJ3RHLY9g\"]}")
                },
        }.Check(request);

    if (!fAddressIndex) {
        throw JSONRPCError(RPC_MISC_ERROR, "Address index is not enabled.");
    }

    std::vector<std::pair<uint256, int> > addresses;

    if (!getAddressesFromParams(request.params, addresses)) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid address");
    }

    std::vector<std::pair<CAddressIndexKey, CAmount> > addressIndex;

    for (std::vector<std::pair<uint256, int> >::iterator it = addresses.begin(); it != addresses.end(); it++) {
        if (!GetAddressIndex(it->first, it->second, addressIndex)) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "No information available for address");
        }
    }

    CAmount balance = 0;
    CAmount received = 0;

    for (std::vector<std::pair<CAddressIndexKey, CAmount> >::const_iterator it=addressIndex.begin(); it!=addressIndex.end(); it++) {
        if (it->second > 0) {
            received += it->second;
        }
        balance += it->second;
    }

    UniValue result(UniValue::VOBJ);
    result.pushKV("balance", balance);
    result.pushKV("received", received);

    return result;
}

UniValue getaddresstxids(const JSONRPCRequest& request)
{
            RPCHelpMan{"getaddresstxids",
                "\nReturns the txids for an address(es) (requires addressindex to be enabled).\n",
                {
                    {"addresses", RPCArg::Type::ARR, RPCArg::Optional::NO, "A json array with addresses.\n",
                        {
                            {"address", RPCArg::Type::STR, RPCArg::Optional::NO, "The base58check encoded address."},
                        },
                    },
                    {"start", RPCArg::Type::NUM, /* default */ "0", "The start block height."},
                    {"end", RPCArg::Type::NUM, /* default */ "0", "The end block height."},
                },
                RPCResult{
            "[\n"
            "  \"transactionid\"  (string) The transaction id\n"
            "  ,...\n"
            "]\n"
                },
                RPCExamples{
            HelpExampleCli("getaddresstxids", "'{\"addresses\": [\"Pb7FLL3DyaAVP2eGfRiEkj4U8ZJ3RHLY9g\"]}'") +
            "\nAs a JSON-RPC call\n"
            + HelpExampleRpc("getaddresstxids", "{\"addresses\": [\"Pb7FLL3DyaAVP2eGfRiEkj4U8ZJ3RHLY9g\"]}")
                },
        }.Check(request);

    if (!fAddressIndex) {
        throw JSONRPCError(RPC_MISC_ERROR, "Address index is not enabled.");
    }

    std::vector<std::pair<uint256, int> > addresses;

    if (!getAddressesFromParams(request.params, addresses)) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid address");
    }

    int start = 0;
    int end = 0;
    if (request.params[0].isObject()) {
        UniValue startValue = find_value(request.params[0].get_obj(), "start");
        UniValue endValue = find_value(request.params[0].get_obj(), "end");
        if (startValue.isNum() && endValue.isNum()) {
            start = startValue.get_int();
            end = endValue.get_int();
        }
    }

    std::vector<std::pair<CAddressIndexKey, CAmount> > addressIndex;

    for (std::vector<std::pair<uint256, int> >::iterator it = addresses.begin(); it != addresses.end(); it++) {
        if (start > 0 && end > 0) {
            if (!GetAddressIndex(it->first, it->second, addressIndex, start, end)) {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "No information available for address");
            }
        } else {
            if (!GetAddressIndex(it->first, it->second, addressIndex)) {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "No information available for address");
            }
        }
    }

    std::set<std::pair<int, std::string> > txids;
    UniValue result(UniValue::VARR);

    for (std::vector<std::pair<CAddressIndexKey, CAmount> >::const_iterator it=addressIndex.begin(); it!=addressIndex.end(); it++) {
        int height = it->first.blockHeight;
        std::string txid = it->first.txhash.GetHex();

        if (addresses.size() > 1) {
            txids.insert(std::make_pair(height, txid));
        } else {
            if (txids.insert(std::make_pair(height, txid)).second) {
                result.push_back(txid);
            }
        }
    }

    if (addresses.size() > 1) {
        for (std::set<std::pair<int, std::string> >::const_iterator it=txids.begin(); it!=txids.end(); it++) {
            result.push_back(it->second);
        }
    }

    return result;
}

UniValue getspentinfo(const JSONRPCRequest& request)
{
            RPCHelpMan{"getspentinfo",
                "\nReturns the txid and index where an output is spent.\n",
                {
                    {"inputs", RPCArg::Type::OBJ, RPCArg::Optional::NO, "",
                        {
                            {"txid", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The hex string of the txid."},
                            {"index", RPCArg::Type::NUM, RPCArg::Optional::NO, "The output number."},
                        },
                    },
                },
                RPCResult{
            "{\n"
            "  \"txid\"   (string) The transaction id\n"
            "  \"index\"  (number) The spending input index\n"
            "  \"height\" (number) The height of the block containing the spending tx\n"
            "}\n"
                },
                RPCExamples{
            HelpExampleCli("getspentinfo", "'{\"txid\": \"0437cd7f8525ceed2324359c2d0ba26006d92d856a9c20fa0241106ee5a597c9\", \"index\": 0}'") +
            "\nAs a JSON-RPC call\n"
            + HelpExampleRpc("getspentinfo", "{\"txid\": \"0437cd7f8525ceed2324359c2d0ba26006d92d856a9c20fa0241106ee5a597c9\", \"index\": 0}")
                },
        }.Check(request);

    UniValue txidValue = find_value(request.params[0].get_obj(), "txid");
    UniValue indexValue = find_value(request.params[0].get_obj(), "index");

    if (!txidValue.isStr() || !indexValue.isNum()) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid txid or index");
    }

    uint256 txid = ParseHashV(txidValue, "txid");
    int outputIndex = indexValue.get_int();

    CSpentIndexKey key(txid, outputIndex);
    CSpentIndexValue value;

    if (!GetSpentIndex(key, value)) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Unable to get spent info");
    }

    UniValue obj(UniValue::VOBJ);
    obj.pushKV("txid", value.txid.GetHex());
    obj.pushKV("index", (int)value.inputIndex);
    obj.pushKV("height", value.blockHeight);

    return obj;
}

static void AddAddress(CScript *script, UniValue &uv)
{
    if (script->IsPayToScriptHash()) {
        std::vector<unsigned char> hashBytes(script->begin()+2, script->begin()+22);
        uv.pushKV("address", EncodeDestination(ScriptHash(uint160(hashBytes))));
    } else
    if (script->IsPayToPublicKeyHash()) {
        std::vector<unsigned char> hashBytes(script->begin()+3, script->begin()+23);
        uv.pushKV("address", EncodeDestination(PKHash(uint160(hashBytes))));
    } else
    if (script->IsPayToScriptHash256()) {
        std::vector<unsigned char> hashBytes(script->begin()+2, script->begin()+34);
        uv.pushKV("address", EncodeDestination(CScriptID256(uint256(hashBytes))));
    } else
    if (script->IsPayToPublicKeyHash256()) {
        std::vector<unsigned char> hashBytes(script->begin()+3, script->begin()+35);
        uv.pushKV("address", EncodeDestination(CKeyID256(uint256(hashBytes))));
    }
}

static UniValue blockToDeltasJSON(const CBlock& block, const CBlockIndex* blockindex)
{
    UniValue result(UniValue::VOBJ);
    result.pushKV("hash", block.GetHash().GetHex());
    int confirmations = -1;
    // Only report confirmations if the block is on the main chain
    if (::ChainActive().Contains(blockindex)) {
        confirmations = ::ChainActive().Height() - blockindex->nHeight + 1;
    } else {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Block is an orphan");
    }
    result.pushKV("confirmations", confirmations);
    result.pushKV("size", (int)::GetSerializeSize(block, PROTOCOL_VERSION));
    result.pushKV("height", blockindex->nHeight);
    result.pushKV("version", block.nVersion);
    result.pushKV("merkleroot", block.hashMerkleRoot.GetHex());
    result.pushKV("witnessmerkleroot", block.hashWitnessMerkleRoot.GetHex());

    UniValue deltas(UniValue::VARR);

    for (unsigned int i = 0; i < block.vtx.size(); i++) {
        const CTransaction &tx = *(block.vtx[i]);
        const uint256 txhash = tx.GetHash();

        UniValue entry(UniValue::VOBJ);
        entry.pushKV("txid", txhash.GetHex());
        entry.pushKV("index", (int)i);

        UniValue inputs(UniValue::VARR);

        if (!tx.IsCoinBase()) {

            for (size_t j = 0; j < tx.vin.size(); j++) {
                const CTxIn input = tx.vin[j];

                UniValue delta(UniValue::VOBJ);

                CSpentIndexValue spentInfo;
                CSpentIndexKey spentKey(input.prevout.hash, input.prevout.n);

                if (GetSpentIndex(spentKey, spentInfo)) {
                    std::string address;
                    if (!getAddressFromIndex(spentInfo.addressType, spentInfo.addressHash, address)) {
                        continue;
                    }
                    delta.pushKV("address", address);
                    delta.pushKV("satoshis", -1 * spentInfo.satoshis);
                    delta.pushKV("index", (int)j);
                    delta.pushKV("prevtxid", input.prevout.hash.GetHex());
                    delta.pushKV("prevout", (int)input.prevout.n);

                    inputs.push_back(delta);
                } else {
                    throw JSONRPCError(RPC_INTERNAL_ERROR, "Spent information not available");
                }
            }
        }

        entry.pushKV("inputs", inputs);

        UniValue outputs(UniValue::VARR);

        for (unsigned int k = 0; k < tx.vpout.size(); k++) {
            const CTxOutBase *out = tx.vpout[k].get();

            UniValue delta(UniValue::VOBJ);

            delta.pushKV("index", (int)k);

            switch (out->GetType())
            {
                case OUTPUT_STANDARD:
                    {
                    delta.pushKV("type", "standard");
                    CTxOutStandard *s = (CTxOutStandard*) out;
                    delta.pushKV("satoshis", s->nValue);
                    AddAddress(&s->scriptPubKey, delta);
                    }
                    break;
                case OUTPUT_CT:
                    {
                    CTxOutCT *s = (CTxOutCT*) out;
                    delta.pushKV("type", "blind");
                    delta.pushKV("valueCommitment", HexStr(&s->commitment.data[0], &s->commitment.data[0]+33));
                    AddAddress(&s->scriptPubKey, delta);
                    }
                    break;
                case OUTPUT_RINGCT:
                    {
                    CTxOutRingCT *s = (CTxOutRingCT*) out;
                    delta.pushKV("type", "anon");
                    delta.pushKV("pubkey", HexStr(s->pk.begin(), s->pk.end()));
                    delta.pushKV("valueCommitment", HexStr(&s->commitment.data[0], &s->commitment.data[0]+33));
                    }
                    break;
                default:
                    continue;
                    break;
            };

            outputs.push_back(delta);
        }

        entry.pushKV("outputs", outputs);
        deltas.push_back(entry);

    }
    result.pushKV("deltas", deltas);
    PushTime(result, "time", block.GetBlockTime());
    PushTime(result, "mediantime", blockindex->GetMedianTimePast());
    result.pushKV("nonce", (uint64_t)block.nNonce);
    result.pushKV("bits", strprintf("%08x", block.nBits));
    result.pushKV("difficulty", GetDifficulty(blockindex));
    result.pushKV("chainwork", blockindex->nChainWork.GetHex());

    if (blockindex->pprev)
        result.pushKV("previousblockhash", blockindex->pprev->GetBlockHash().GetHex());
    CBlockIndex *pnext = ::ChainActive().Next(blockindex);
    if (pnext)
        result.pushKV("nextblockhash", pnext->GetBlockHash().GetHex());
    return result;
}

static UniValue getblockdeltas(const JSONRPCRequest& request)
{
    RPCHelpMan{"getblockdeltas",
        "\nReturns block deltas.\n",
        {
            {"blockhash", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The block hash"},
        },
        RPCResults{},
        RPCExamples{
        HelpExampleCli("getblockdeltas", "\"00000000c937983704a73af28acdec37b049d214adbda81d7e2a3dd146f6ed09\"") +
        "\nAs a JSON-RPC call\n"
        + HelpExampleRpc("getblockdeltas", "\"00000000c937983704a73af28acdec37b049d214adbda81d7e2a3dd146f6ed09\"")
        },
    }.Check(request);

    LOCK(cs_main);

    std::string strHash = request.params[0].get_str();
    uint256 hash(uint256S(strHash));

    if (::BlockIndex().count(hash) == 0) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Block not found");
    }

    CBlock block;
    CBlockIndex* pblockindex = ::BlockIndex()[hash];

    if (fHavePruned && !(pblockindex->nStatus & BLOCK_HAVE_DATA) && pblockindex->nTx > 0) {
        throw JSONRPCError(RPC_INTERNAL_ERROR, "Block not available (pruned data)");
    }

    if (!ReadBlockFromDisk(block, pblockindex, Params().GetConsensus())) {
        throw JSONRPCError(RPC_INTERNAL_ERROR, "Can't read block from disk");
    }

    return blockToDeltasJSON(block, pblockindex);
}

static UniValue getblockhashes(const JSONRPCRequest& request)
{
            RPCHelpMan{"getblockhashes",
                "\nReturns array of hashes of blocks within the timestamp range provided.\n",
                {
                    {"high", RPCArg::Type::NUM, RPCArg::Optional::NO, "The newer block timestamp."},
                    {"low", RPCArg::Type::NUM, RPCArg::Optional::NO, "The older block timestamp."},
                    {"options", RPCArg::Type::OBJ, /* default */ "", "",
                        {
                            {"noOrphans", RPCArg::Type::BOOL, /* default */ "false", "Only include blocks on the main chain."},
                            {"logicalTimes", RPCArg::Type::BOOL, /* default */ "false", "Include logical timestamps with hashes."},
                        },
                        "options"},
                },
                RPCResult{
            "[\n"
            "  \"hash\"         (string) The block hash\n"
            "]\n"
            "[\n"
            "  {\n"
            "    \"blockhash\": (string) The block hash\n"
            "    \"logicalts\": (numeric) The logical timestamp\n"
            "  }\n"
            "]\n"
                },
                RPCExamples{
            HelpExampleCli("getblockhashes", "1231614698 1231024505 '{\"noOrphans\":false, \"logicalTimes\":true}'") +
            "\nAs a JSON-RPC call\n"
            + HelpExampleRpc("getblockhashes", "1231614698, 1231024505")
                },
        }.Check(request);

    unsigned int high = request.params[0].get_int();
    unsigned int low = request.params[1].get_int();
    bool fActiveOnly = false;
    bool fLogicalTS = false;

    if (request.params.size() > 2) {
        if (request.params[2].isObject()) {
            UniValue noOrphans = find_value(request.params[2].get_obj(), "noOrphans");
            UniValue returnLogical = find_value(request.params[2].get_obj(), "logicalTimes");

            if (noOrphans.isBool()) {
                fActiveOnly = noOrphans.get_bool();
            }

            if (returnLogical.isBool()) {
                fLogicalTS = returnLogical.get_bool();
            }
        }
    }

    std::vector<std::pair<uint256, unsigned int> > blockHashes;

    if (fActiveOnly) {
        LOCK(cs_main);
    }

    if (!GetTimestampIndex(high, low, fActiveOnly, blockHashes)) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "No information available for block hashes");
    }

    UniValue result(UniValue::VARR);

    for (std::vector<std::pair<uint256, unsigned int> >::const_iterator it=blockHashes.begin(); it!=blockHashes.end(); it++) {
        if (fLogicalTS) {
            UniValue item(UniValue::VOBJ);
            item.pushKV("blockhash", it->first.GetHex());
            item.pushKV("logicalts", (int)it->second);
            result.push_back(item);
        } else {
            result.push_back(it->first.GetHex());
        }
    }

    return result;
}

UniValue gettxoutsetinfobyscript(const JSONRPCRequest& request)
{
            RPCHelpMan{"gettxoutsetinfobyscript",
                "\nReturns statistics about the unspent transaction output set per script type.\n"
                "This call may take some time.\n",
                {
                },
                RPCResult{
            "{\n"
            "  \"height\":n,     (numeric) The current block height (index)\n"
            "  \"bestblock\": \"hex\",   (string) the best block hash hex\n"
            "}\n"
                },
                RPCExamples{
            HelpExampleCli("gettxoutsetinfobyscript", "") +
            "\nAs a JSON-RPC call\n"
            + HelpExampleRpc("gettxoutsetinfobyscript", "")
                },
        }.Check(request);

    UniValue ret(UniValue::VOBJ);

    int nHeight;
    uint256 hashBlock;

    std::unique_ptr<CCoinsViewCursor> pcursor;
    {
        LOCK(cs_main);
        ::ChainstateActive().ForceFlushStateToDisk();
        pcursor = std::unique_ptr<CCoinsViewCursor>(::ChainstateActive().CoinsDB().Cursor());
        assert(pcursor);
        hashBlock = pcursor->GetBestBlock();
        nHeight = ::BlockIndex().find(hashBlock)->second->nHeight;
    }

    class PerScriptTypeStats {
    public:
        int64_t nPlain = 0;
        int64_t nBlinded = 0;
        int64_t nPlainValue = 0;

        UniValue ToUV()
        {
            UniValue ret(UniValue::VOBJ);
            ret.pushKV("num_plain", nPlain);
            ret.pushKV("num_blinded", nBlinded);
            ret.pushKV("total_amount", ValueFromAmount(nPlainValue));
            return ret;
        }
    };

    PerScriptTypeStats statsPKH;
    PerScriptTypeStats statsSH;
    PerScriptTypeStats statsCSPKH;
    PerScriptTypeStats statsCSSH;
    PerScriptTypeStats statsOther;

    uint256 prevkey;
    while (pcursor->Valid()) {
        boost::this_thread::interruption_point();
        COutPoint key;
        Coin coin;
        if (pcursor->GetKey(key) && pcursor->GetValue(coin)) {
            PerScriptTypeStats *ps = &statsOther;
            if (coin.out.scriptPubKey.IsPayToPublicKeyHash())
                ps = &statsPKH;
            else if (coin.out.scriptPubKey.IsPayToScriptHash())
                ps = &statsSH;
            else if (coin.out.scriptPubKey.IsPayToPublicKeyHash256_CS())
                ps = &statsCSPKH;
            else if (coin.out.scriptPubKey.IsPayToScriptHash256_CS() || coin.out.scriptPubKey.IsPayToScriptHash_CS() )
                ps = &statsCSSH;

            if (coin.nType == OUTPUT_STANDARD) {
                ps->nPlain++;
                ps->nPlainValue += coin.out.nValue;
            } else
            if (coin.nType == OUTPUT_CT) {
                ps->nBlinded++;
            }
        } else {
            throw JSONRPCError(RPC_INTERNAL_ERROR, "Unable to read UTXO set");
        }
        pcursor->Next();
    }

    ret.pushKV("height", (int64_t)nHeight);
    ret.pushKV("bestblock", hashBlock.GetHex());
    ret.pushKV("paytopubkeyhash", statsPKH.ToUV());
    ret.pushKV("paytoscripthash", statsSH.ToUV());
    ret.pushKV("coldstake_paytopubkeyhash", statsCSPKH.ToUV());
    ret.pushKV("coldstake_paytoscripthash", statsCSSH.ToUV());
    ret.pushKV("other", statsOther.ToUV());

    return ret;
}

static void pushScript(UniValue &uv, const std::string &name, const CScript *script)
{
    if (!script) {
        return;
    }

    UniValue uvs(UniValue::VOBJ);
    uvs.pushKV("hex", HexStr(script->begin(), script->end()));

    CTxDestination dest_stake, dest_spend;
    if (script->StartsWithICS()) {
        CScript spend_script, stake_script;
        if (SplitConditionalCoinstakeScript(*script, stake_script, spend_script)) {
            ExtractDestination(stake_script, dest_stake);
            ExtractDestination(spend_script, dest_spend);
        }
    } else {
        ExtractDestination(*script, dest_spend);
    }
    if (dest_stake.type() != typeid(CNoDestination)) {
        uvs.pushKV("stakeaddr", EncodeDestination(dest_stake));
    }
    if (dest_spend.type() != typeid(CNoDestination)) {
        uvs.pushKV("spendaddr", EncodeDestination(dest_spend));
    }
    uv.pushKV(name, uvs);
}

UniValue getblockreward(const JSONRPCRequest& request)
{
            RPCHelpMan{"getblockreward",
                "\nReturns the blockreward for block at height.\n",
                {
                    {"height", RPCArg::Type::NUM, RPCArg::Optional::NO, "The chain height of the block."},
                },
                RPCResult{
            "{\n"
            "  \"blockhash\" : \"id\",     (id) The hash of the block.\n"
            "  \"coinstake\" : \"id\",     (id) The hash of the coinstake transaction.\n"
            "  \"blocktime\" : n,          (id) The time of the block.\n"
            "  \"stakereward\" : n,      (numeric) The stake reward portion, newly minted coin.\n"
            "  \"blockreward\" : n,      (numeric) The block reward, value paid to staker, including fees.\n"
            "  \"foundationreward\" : n, (numeric) The accumulated foundation reward payout, if any.\n"
            "  \"kernelscript\" :\n"
            "  {\n"
            "    \"hex\" : \"str\",          (str) The script from the kernel output.\n"
            "    \"stakeaddr\" : \"str\",    (str) The stake address, if output script is coldstake.\n"
            "    \"spendaddr\" : \"str\",    (str) The spend address.\n"
            "  }\n"
            "  \"outputs\" :\n"
            "  [\n"
            "    \"script\" : {\n"
            "      \"hex\" : \"str\",          (str) The script from the kernel output.\n"
            "      \"stakeaddr\" : \"str\",    (str) The stake address, if output script is coldstake.\n"
            "      \"spendaddr\" : \"str\",    (str) The spend address.\n"
            "    }\n"
            "    \"value\" : n,          (numeric) The value of the output.\n"
            "  ]\n"
            "}\n"
                },
                RPCExamples{
            HelpExampleCli("getblockreward", "1000") +
            "\nAs a JSON-RPC call\n"
            + HelpExampleRpc("getblockreward", "1000")
                },
        }.Check(request);

    RPCTypeCheck(request.params, {UniValue::VNUM});

    if (!g_txindex) {
        throw JSONRPCError(RPC_MISC_ERROR, "Requires -txindex enabled");
    }

    int nHeight = request.params[0].get_int();
    if (nHeight < 0 || nHeight > ::ChainActive().Height()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Block height out of range");
    }

    LOCK(cs_main);

    CBlockIndex *pblockindex = ::ChainActive()[nHeight];

    CAmount stake_reward = 0;
    if (pblockindex->pprev) {
        stake_reward = Params().GetProofOfStakeReward(pblockindex->pprev, 0);
    }

    CBlock block;
    if (!ReadBlockFromDisk(block, pblockindex, Params().GetConsensus())) {
        throw JSONRPCError(RPC_MISC_ERROR, "Block not found on disk");
    }

    const DevFundSettings *devfundconf = Params().GetDevFundSettings(pblockindex->GetBlockTime());
    CScript devFundScriptPubKey;
    if (devfundconf) {
        CTxDestination dest = DecodeDestination(devfundconf->sDevFundAddresses);
        devFundScriptPubKey = GetScriptForDestination(dest);
    }

    const auto &tx = block.vtx[0];

    UniValue outputs(UniValue::VARR);
    CAmount value_out = 0, value_in = 0, value_foundation = 0;
    for (const auto &txout : tx->vpout) {
        if (!txout->IsStandardOutput()) {
            continue;
        }

        UniValue output(UniValue::VOBJ);
        pushScript(output, "script", txout->GetPScriptPubKey());
        output.pushKV("value", ValueFromAmount(txout->GetValue()));
        outputs.push_back(output);

        if (devfundconf && *txout->GetPScriptPubKey() == devFundScriptPubKey) {
            value_foundation += txout->GetValue();
            continue;
        }

        value_out += txout->GetValue();
    }

    CScript kernel_script;
    int n = -1;
    for (const auto& txin : tx->vin) {
        n++;
        if (txin.IsAnonInput()) {
            continue;
        }

        CBlockIndex *blockindex = nullptr;
        CTransactionRef tx_prev;
        uint256 hashBlock;
        if (!GetTransaction(txin.prevout.hash, tx_prev, Params().GetConsensus(), hashBlock, blockindex)) {
            throw JSONRPCError(RPC_MISC_ERROR, "Transaction not found on disk");
        }
        if (txin.prevout.n > tx_prev->GetNumVOuts()) {
            throw JSONRPCError(RPC_MISC_ERROR, "prevout not found on disk");
        }
        value_in += tx_prev->vpout[txin.prevout.n]->GetValue();
        if (n == 0) {
            kernel_script = *tx_prev->vpout[txin.prevout.n]->GetPScriptPubKey();
        }
    }

    CAmount block_reward = value_out - value_in;

    UniValue rv(UniValue::VOBJ);
    rv.pushKV("blockhash", pblockindex->GetBlockHash().ToString());
    if (tx->IsCoinStake()) {
        rv.pushKV("coinstake", tx->GetHash().ToString());
    }

    rv.pushKV("blocktime", pblockindex->GetBlockTime());
    rv.pushKV("stakereward", ValueFromAmount(stake_reward));
    rv.pushKV("blockreward", ValueFromAmount(block_reward));

    if (value_foundation > 0) {
        rv.pushKV("foundationreward", ValueFromAmount(value_foundation));
    }

    if (tx->IsCoinStake()) {
        pushScript(rv, "kernelscript", &kernel_script);
    }
    rv.pushKV("outputs", outputs);

    return rv;
}

UniValue listcoldstakeunspent(const JSONRPCRequest& request)
{
            RPCHelpMan{"listcoldstakeunspent",
                "\nReturns the unspent outputs of \"stakeaddress\" at height.\n",
                {
                    {"stakeaddress", RPCArg::Type::STR, RPCArg::Optional::NO, "The stakeaddress to filter outputs by."},
                    {"height", RPCArg::Type::NUM, /* default */ "", "The block height to return outputs for, -1 for current height."},
                    {"options", RPCArg::Type::OBJ, /* default */ "", "",
                        {
                            {"mature_only", RPCArg::Type::BOOL, /* default */ "false", "Return only outputs stakeable at height."},
                            {"all_staked", RPCArg::Type::BOOL, /* default */ "false", "Ignore maturity check for outputs of coinstake transactions."},
                            {"show_outpoints", RPCArg::Type::BOOL, /* default */ "false", "Display txid and index per output."},
                        },
                        "options"},
                },
                RPCResult{
            "[\n"
            " {\n"
            "  \"height\" : n,           (numeric) The height the output was staked into the chain.\n"
            "  \"value\" : n,            (numeric) The value of the output.\n"
            "  \"addrspend\" : \"addr\",   (string) The spending address of the output\n"
            " } ...\n"
            "]\n"
                },
                RPCExamples{
            HelpExampleCli("listcoldstakeunspent", "\"Pb7FLL3DyaAVP2eGfRiEkj4U8ZJ3RHLY9g\" 1000") +
            "\nAs a JSON-RPC call\n"
            + HelpExampleRpc("listcoldstakeunspent", "\"Pb7FLL3DyaAVP2eGfRiEkj4U8ZJ3RHLY9g\", 1000")
                },
            }.Check(request);

    RPCTypeCheck(request.params, {UniValue::VSTR, UniValue::VNUM}, true);

    if (!g_txindex) {
        throw JSONRPCError(RPC_MISC_ERROR, "Requires -txindex enabled");
    }
    if (!g_txindex->m_cs_index) {
        throw JSONRPCError(RPC_MISC_ERROR, "Requires -csindex enabled");
    }

    ColdStakeIndexLinkKey seek_key;
    CTxDestination stake_dest = DecodeDestination(request.params[0].get_str(), true);
    if (stake_dest.type() == typeid(PKHash)) {
        seek_key.m_stake_type = TX_PUBKEYHASH;
        PKHash id = boost::get<PKHash>(stake_dest);
        memcpy(seek_key.m_stake_id.begin(), id.begin(), 20);
    } else
    if (stake_dest.type() == typeid(CKeyID256)) {
        seek_key.m_stake_type = TX_PUBKEYHASH256;
        seek_key.m_stake_id = boost::get<CKeyID256>(stake_dest);
    } else {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Unrecognised stake address type.");
    }

    CDBWrapper &db = g_txindex->GetDB();

    LOCK(cs_main);

    int height = !request.params[1].isNull() ? request.params[1].get_int() : -1;
    if (height == -1) {
        height = ::ChainActive().Tip()->nHeight;
    }

    bool mature_only = false;
    bool all_staked = false;
    bool show_outpoints = false;
    if (request.params[2].isObject()) {
        const UniValue &options = request.params[2];
        RPCTypeCheck(options, {UniValue::VBOOL, UniValue::VBOOL}, true);
        if (options["mature_only"].isBool()) {
            mature_only = options["mature_only"].get_bool();
        }
        if (options["all_staked"].isBool()) {
            all_staked = options["all_staked"].get_bool();
        }
        if (options["show_outpoints"].isBool()) {
            show_outpoints = options["show_outpoints"].get_bool();
        }
    }

    UniValue rv(UniValue::VARR);

    std::unique_ptr<CDBIterator> it(db.NewIterator());
    it->Seek(std::make_pair(DB_TXINDEX_CSLINK, seek_key));

    int min_kernel_depth = Params().GetStakeMinConfirmations();
    std::pair<char, ColdStakeIndexLinkKey> key;
    while (it->Valid() && it->StartsWith(DB_TXINDEX_CSLINK) && it->GetKey(key)) {
        ColdStakeIndexLinkKey &lk = key.second;

        if (key.first != DB_TXINDEX_CSLINK
            || lk.m_stake_id != seek_key.m_stake_id
            || (int)lk.m_height > height)
            break;

        std::vector <ColdStakeIndexOutputKey> oks;
        ColdStakeIndexOutputValue ov;
        UniValue output(UniValue::VOBJ);

        if (it->GetValue(oks)) {
            for (const auto &ok : oks) {
                if (db.Read(std::make_pair(DB_TXINDEX_CSOUTPUT, ok), ov)
                    && (ov.m_spend_height == -1 || ov.m_spend_height > height)) {

                    if (mature_only
                        && (!all_staked || !(ov.m_flags & CSI_FROM_STAKE))) {
                        int depth = height - lk.m_height;
                        int depth_required = std::min(min_kernel_depth-1, (int)(height / 2));
                        if (depth < depth_required) {
                            continue;
                        }
                    }

                    UniValue output(UniValue::VOBJ);
                    output.pushKV("height", (int)lk.m_height);
                    output.pushKV("value", ov.m_value);

                    if (show_outpoints) {
                        output.pushKV("txid", ok.m_txnid.ToString());
                        output.pushKV("n", ok.m_n);
                    }

                    switch (lk.m_spend_type) {
                        case TX_PUBKEYHASH: {
                            PKHash idk;
                            memcpy(idk.begin(), lk.m_spend_id.begin(), 20);
                            output.pushKV("addrspend", EncodeDestination(idk));
                            }
                            break;
                        case TX_PUBKEYHASH256:
                            output.pushKV("addrspend", EncodeDestination(lk.m_spend_id));
                            break;
                        case TX_SCRIPTHASH: {
                            ScriptHash ids;
                            memcpy(ids.begin(), lk.m_spend_id.begin(), 20);
                            output.pushKV("addrspend", EncodeDestination(ids));
                            }
                            break;
                        case TX_SCRIPTHASH256: {
                            CScriptID256 ids;
                            memcpy(ids.begin(), lk.m_spend_id.begin(), 32);
                            output.pushKV("addrspend", EncodeDestination(ids));
                            }
                            break;
                        default:
                            output.pushKV("addrspend", "unknown_type");
                            break;
                    }

                    rv.push_back(output);
                }
            }
        }
        it->Next();
    }

    return rv;
}

UniValue getindexinfo(const JSONRPCRequest& request)
{
            RPCHelpMan{"getindexinfo",
                "\nReturns an object of enabled indices.\n",
                {
                },
                RPCResult{
            "{\n"
            "  \"txindex\": xxx             (bool) Is the txindex enabled.\n"
            "  \"addressindex\": xxx        (bool) Is the addressindex enabled.\n"
            "  \"spentindex\":  xxx         (bool) Is the spentindex enabled.\n"
            "  \"timestampindex\":  xxx     (bool) Is the timestampindex enabled.\n"
            "  \"coldstakeindex\":  xxx     (bool) Is the coldstakeindex enabled.\n"
            "}\n"
                },
                RPCExamples{
            HelpExampleCli("getindexinfo", "") +
            "\nAs a JSON-RPC call\n"
            + HelpExampleRpc("getindexinfo", "")
                },
        }.Check(request);

    UniValue ret(UniValue::VOBJ);

    ret.pushKV("txindex", (bool) g_txindex);
    ret.pushKV("addressindex", fAddressIndex);
    ret.pushKV("spentindex", fSpentIndex);
    ret.pushKV("timestampindex", fTimestampIndex);
    ret.pushKV("coldstakeindex", (bool) (g_txindex && g_txindex->m_cs_index));

    return ret;
}

static const CRPCCommand commands[] =
{ //  category              name                      actor (function)         argNames
  //  --------------------- ------------------------  -----------------------  ----------
    /* Address index */
    { "addressindex",       "getaddressmempool",      &getaddressmempool,      {"addresses"} },
    { "addressindex",       "getaddressutxos",        &getaddressutxos,        {"addresses"} },
    { "addressindex",       "getaddressdeltas",       &getaddressdeltas,       {"addresses"} },
    { "addressindex",       "getaddresstxids",        &getaddresstxids,        {"addresses"} },
    { "addressindex",       "getaddressbalance",      &getaddressbalance,      {"addresses"} },

    /* Blockchain */
    { "blockchain",         "getspentinfo",           &getspentinfo,           {"inputs"} },
    { "blockchain",         "getblockdeltas",         &getblockdeltas,         {} },
    { "blockchain",         "getblockhashes",         &getblockhashes,         {"high","low","options"} },
    { "blockchain",         "gettxoutsetinfobyscript",&gettxoutsetinfobyscript,{} },
    { "blockchain",         "getblockreward",         &getblockreward,         {"height"} },

    { "csindex",            "listcoldstakeunspent",   &listcoldstakeunspent,   {"stakeaddress","height","options"} },

    { "blockchain",         "getindexinfo",           &getindexinfo,           {} },
};

void RegisterInsightRPCCommands(CRPCTable &tableRPC)
{
    for (unsigned int vcidx = 0; vcidx < ARRAYLEN(commands); vcidx++)
        tableRPC.appendCommand(commands[vcidx].name, &commands[vcidx]);
}
