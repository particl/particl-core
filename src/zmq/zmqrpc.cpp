// Copyright (c) 2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <zmq/zmqrpc.h>

#include <rpc/server.h>
#include <rpc/util.h>
#include <zmq/zmqabstractnotifier.h>
#include <zmq/zmqnotificationinterface.h>

#include <util/strencodings.h>

#include <univalue.h>

int GetNewZMQKeypair(char *server_public_key, char *server_secret_key)
{
    return zmq_curve_keypair(server_public_key, server_secret_key);
}

namespace {

UniValue getzmqnotifications(const JSONRPCRequest& request)
{
            RPCHelpMan{"getzmqnotifications",
                "\nReturns information about the active ZeroMQ notifications.\n",
                {},
                RPCResult{
            "[\n"
            "  {                        (json object)\n"
            "    \"type\": \"pubhashtx\",   (string) Type of notification\n"
            "    \"address\": \"...\",      (string) Address of the publisher\n"
            "    \"hwm\": n                 (numeric) Outbound message high water mark\n"
            "  },\n"
            "  ...\n"
            "]\n"
                },
                RPCExamples{
                    HelpExampleCli("getzmqnotifications", "")
            + HelpExampleRpc("getzmqnotifications", "")
                },
            }.Check(request);

    UniValue result(UniValue::VARR);
    if (g_zmq_notification_interface != nullptr) {
        for (const auto* n : g_zmq_notification_interface->GetActiveNotifiers()) {
            UniValue obj(UniValue::VOBJ);
            obj.pushKV("type", n->GetType());
            obj.pushKV("address", n->GetAddress());
            obj.pushKV("hwm", n->GetOutboundMessageHighWaterMark());
            result.push_back(obj);
        }
    }

    return result;
}

UniValue getnewzmqserverkeypair(const JSONRPCRequest& request)
{
            RPCHelpMan{"getnewzmqserverkeypair",
                "\nReturns a newly generated server keypair for use with zmq.\n",
                {},
                RPCResults{},
                RPCExamples{""},
            }.Check(request);

    char server_public_key[41], server_secret_key[41];
    if (0 != GetNewZMQKeypair(server_public_key, server_secret_key)) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "zmq_curve_keypair failed.");
    }

    UniValue obj(UniValue::VOBJ);
    obj.pushKV("server_secret_key", server_secret_key);
    obj.pushKV("server_public_key", server_public_key);

    std::string sBase64 = EncodeBase64((uint8_t*)server_secret_key, 40);
    obj.pushKV("server_secret_key_b64", sBase64);

    return obj;
}

const CRPCCommand commands[] =
{ //  category              name                                actor (function)                argNames
  //  -----------------     ------------------------            -----------------------         ----------
    { "zmq",                "getzmqnotifications",              &getzmqnotifications,           {} },
    { "zmq",                "getnewzmqserverkeypair",           &getnewzmqserverkeypair,        {} },
};

} // anonymous namespace

void RegisterZMQRPCCommands(CRPCTable& t)
{
    for (const auto& c : commands) {
        t.appendCommand(c.name, &c);
    }
}
