// Copyright (c) 2017-2019 The Particl Core developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <rpc/server.h>
#include <rpc/util.h>

#include <validation.h>
#include <txdb.h>


static bool IsDigits(const std::string &str)
{
    return str.length() && std::all_of(str.begin(), str.end(), ::isdigit);
};

UniValue anonoutput(const JSONRPCRequest &request)
{
            RPCHelpMan{"anonoutput",
                "\nReturns an anon output at index or by publickey hex.\n"
                "If no output is provided returns the last index.\n",
                {
                    {"output", RPCArg::Type::STR, /* default */ "", "Output to view, specified by index or hex of publickey."},
                },
                RPCResult{
            "{\n"
            "  \"index\" : num,                 (numeric) Position in chain of anon output.\n"
            "  \"publickey\" : \"hex\",           (string)\n"
            "  \"txnhash\" : \"hex\",             (string)\n"
            "  \"n\" : num,                     (numeric)\n"
            "  \"blockheight\" : num,           (numeric)\n"
            "}\n"
                },
                RPCExamples{
            HelpExampleCli("anonoutput", "\"1\"")
            + HelpExampleRpc("anonoutput", "\"2\"")
            },
        }.Check(request);

    UniValue result(UniValue::VOBJ);

    if (request.params.size() == 0) {
        LOCK(cs_main);
        result.pushKV("lastindex", (int)::ChainActive().Tip()->nAnonOutputs);
        return result;
    }

    std::string sIn = request.params[0].get_str();

    int64_t nIndex;
    if (IsDigits(sIn)) {
        if (!ParseInt64(sIn, &nIndex)) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid index");
        }
    } else {
        if (!IsHex(sIn)) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, sIn+" is not a hexadecimal or decimal string.");
        }
        std::vector<uint8_t> vIn = ParseHex(sIn);

        CCmpPubKey pk(vIn.begin(), vIn.end());

        if (!pk.IsValid()) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, sIn+" is not a valid compressed public key.");
        }

        if (!pblocktree->ReadRCTOutputLink(pk, nIndex)) {
            throw JSONRPCError(RPC_MISC_ERROR, "Output not indexed.");
        }
    };

    CAnonOutput ao;
    if (!pblocktree->ReadRCTOutput(nIndex, ao)) {
        throw JSONRPCError(RPC_MISC_ERROR, "Unknown index.");
    }

    result.pushKV("index", (int)nIndex);
    result.pushKV("publickey", HexStr(ao.pubkey.begin(), ao.pubkey.end()));
    result.pushKV("txnhash", ao.outpoint.hash.ToString());
    result.pushKV("n", (int)ao.outpoint.n);
    result.pushKV("blockheight", ao.nBlockHeight);

    return result;
};

static const CRPCCommand commands[] =
{ //  category              name                      actor (function)         argNames
  //  --------------------- ------------------------  -----------------------  ----------
    { "anon",               "anonoutput",             &anonoutput,             {"output"} },
};

void RegisterAnonRPCCommands(CRPCTable &tableRPC)
{
    for (unsigned int vcidx = 0; vcidx < ARRAYLEN(commands); vcidx++)
        tableRPC.appendCommand(commands[vcidx].name, &commands[vcidx]);
}
