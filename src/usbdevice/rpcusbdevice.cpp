// Copyright (c) 2018-2019 The Particl Core developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <usbdevice/usbdevice.h>
#include <rpc/server.h>
#include <rpc/util.h>
#include <rpc/rawtransaction_util.h>
#include <util/strencodings.h>
#include <key_io.h>
#include <key/extkey.h>
#include <chainparams.h>
#include <validation.h>
#include <core_io.h>
#include <primitives/transaction.h>
#include <policy/policy.h>
#include <script/script.h>
#include <script/script_error.h>
#include <script/sign.h>
#include <script/signingprovider.h>
#include <script/standard.h>
#include <txmempool.h>

#ifdef ENABLE_WALLET
#include <wallet/hdwallet.h>
#include <wallet/rpcwallet.h>
#endif

#include <univalue.h>

#include <memory>

static std::vector<uint32_t> GetPath(std::vector<uint32_t> &vPath, const UniValue &path, const UniValue &defaultpath)
{
    // Pass empty string as defaultpath to drop defaultpath and use path as full path
    std::string sPath;
    if (path.isStr()) {
        sPath = path.get_str();
    } else
    if (path.isNum()) {
        sPath = strprintf("%d", path.get_int());
    } else {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Unknown \"path\" type.");
    }

    if (defaultpath.isNull()) {
        sPath = GetDefaultAccountPath() + "/" + sPath;
    } else
    if (path.isNum()) {
        sPath = strprintf("%d", defaultpath.get_int()) + "/" + sPath;
    } else
    if (defaultpath.isStr()) {
        if (!defaultpath.get_str().empty()) {
            sPath = defaultpath.get_str() + "/" + sPath;
        }
    } else {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Unknown \"defaultpath\" type.");
    }

    int rv;
    if ((rv = ExtractExtKeyPath(sPath, vPath)) != 0) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("Bad path: %s.", ExtKeyGetString(rv)));
    }

    return vPath;
};

static usb_device::CUSBDevice *SelectDevice(std::vector<std::unique_ptr<usb_device::CUSBDevice> > &vDevices)
{
    std::string sError;
    usb_device::CUSBDevice *rv = SelectDevice(vDevices, sError);
    if (!rv) {
        throw JSONRPCError(RPC_INTERNAL_ERROR, sError);
    }
    return rv;
};

static UniValue deviceloadmnemonic(const JSONRPCRequest &request)
{
            RPCHelpMan{"deviceloadmnemonic",
                "\nStart mnemonic loader.\n",
                {
                    {"wordcount", RPCArg::Type::NUM, /* default */ "12", "Word count of mnemonic."},
                    {"pinprotection", RPCArg::Type::BOOL, /* default */ "false", "Make the new account the default account for the wallet."},
                },
                RPCResults{},
                RPCExamples{
            HelpExampleCli("deviceloadmnemonic", "")
            + HelpExampleRpc("deviceloadmnemonic", "")
                },
            }.Check(request);

    std::vector<std::unique_ptr<usb_device::CUSBDevice> > vDevices;
    usb_device::CUSBDevice *pDevice = SelectDevice(vDevices);

    uint32_t wordcount = 12;
    if (request.params.size() > 0) {
        std::string s = request.params[0].get_str();
        if (s.length() && !ParseUInt32(s, &wordcount)) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "wordcount invalid number.");
        }
    }

    bool pinprotection = false;
    if (request.params.size() > 1) {
        if(request.params[1].get_str() == "true") {
            pinprotection = true;
        }
    }

    UniValue result(UniValue::VOBJ);
    std::string sError;
    if (0 == pDevice->LoadMnemonic(wordcount, pinprotection, sError)) {
        result.pushKV("complete", "Device loaded");
    } else {
        result.pushKV("error", sError);
    }

    return result;
};

static UniValue devicebackup(const JSONRPCRequest &request)
{
            RPCHelpMan{"devicebackup",
                "\nStart device backup mnemonic generator.\n",
                {
                },
                RPCResults{},
                RPCExamples{
            HelpExampleCli("devicebackup", "")
            + HelpExampleRpc("devicebackup", "")
                },
            }.Check(request);

    std::vector<std::unique_ptr<usb_device::CUSBDevice> > vDevices;
    usb_device::CUSBDevice *pDevice = SelectDevice(vDevices);

    UniValue result(UniValue::VOBJ);
    std::string sError;
    if (0 == pDevice->Backup(sError)) {
        result.pushKV("complete", "Device backed up");
    } else {
        result.pushKV("error", sError);
    }

    return result;
};

static UniValue listdevices(const JSONRPCRequest &request)
{
            RPCHelpMan{"listdevices",
                "\nList connected hardware devices.\n",
                {
                },
                RPCResult{
            "{\n"
            "  \"vendor\"           (string) USB vendor string.\n"
            "  \"product\"          (string) USB product string.\n"
            "  \"firmwareversion\"  (string) Detected firmware version of device, if possible.\n"
            "}\n"
                },
                RPCExamples{
            HelpExampleCli("listdevices", "") +
            "\nAs a JSON-RPC call\n"
            + HelpExampleRpc("listdevices", "")
                },
            }.Check(request);

    std::vector<std::unique_ptr<usb_device::CUSBDevice> > vDevices;
    ListAllDevices(vDevices);

    UniValue result(UniValue::VARR);

    for (size_t i = 0; i < vDevices.size(); ++i) {
        usb_device::CUSBDevice *device = vDevices[i].get();
        UniValue obj(UniValue::VOBJ);
        obj.pushKV("vendor", device->pType->cVendor);
        obj.pushKV("product", device->pType->cProduct);
        obj.pushKV("serialno", device->cSerialNo);

        std::string sValue, sError;
        if (0 == device->GetFirmwareVersion(sValue, sError)) {
            obj.pushKV("firmwareversion", sValue);
        } else {
            obj.pushKV("error", sError);
#ifndef WIN32
#ifndef MAC_OSX
            obj.pushKV("tip", "Have you set udev rules?");
#endif
#endif
        }

        result.push_back(obj);
    }

    return result;
};

static UniValue promptunlockdevice(const JSONRPCRequest &request)
{
            RPCHelpMan{"promptunlockdevice",
                "\nPrompt an unlock for the hardware device.\n",
                {
                },
                RPCResult{
            "{\n"
            "  \"sent\"           (boolean) whether prompting the unlock was successful.\n"
            "}\n"
                },
                RPCExamples{
            HelpExampleCli("promptunlockdevice", "") +
            "\nAs a JSON-RPC call\n"
            + HelpExampleRpc("promptunlockdevice", "")
                },
            }.Check(request);

    std::vector<std::unique_ptr<usb_device::CUSBDevice> > vDevices;
    usb_device::CUSBDevice *pDevice = SelectDevice(vDevices);

    UniValue result(UniValue::VOBJ);
    std::string sError;
    if (0 != pDevice->PromptUnlock(sError)) {
        throw JSONRPCError(RPC_INTERNAL_ERROR, sError);
    }

    result.pushKV("sent", true);

    return result;
};

static UniValue unlockdevice(const JSONRPCRequest &request)
{
            RPCHelpMan{"unlockdevice",
                "\nList connected hardware devices.\n",
                {
                    {"passphrase", RPCArg::Type::STR, /* default */ "", "Passphrase to unlock the device."},
                    {"pin", RPCArg::Type::NUM, /* default */ "", "PIN to unlock the device."},
                },
                RPCResult{
            "{\n"
            "  \"unlocked\"           (boolean) will be true when unlocked else error is thrown.\n"
            "}\n"
                },
                RPCExamples{
            HelpExampleCli("unlockdevice", "\"mysecretpassword\" 1687") +
            "\nAs a JSON-RPC call\n"
            + HelpExampleRpc("unlockdevice", "\"mysecretpassword\" 1687")
                },
            }.Check(request);

    std::string passphraseword, pin, sError;
    if (!request.params[0].isNull()) {
        passphraseword = request.params[0].get_str();
    }
    if (!request.params[1].isNull()) {
        pin = request.params[1].get_str();
    }
    if (!pin.length() && !passphraseword.length()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Neither a pin nor a passphraseword was provided.");
    }

    std::vector<std::unique_ptr<usb_device::CUSBDevice> > vDevices;
    ListAllDevices(vDevices);

    UniValue result(UniValue::VOBJ);

    if (vDevices.size() > 1) {
        throw JSONRPCError(RPC_INTERNAL_ERROR, "Too many hardware devices connected.");
    }
    if (vDevices.size() != 1) {
        throw JSONRPCError(RPC_INTERNAL_ERROR, "No hardware devices connected.");
    }

    usb_device::CUSBDevice *device = vDevices[0].get();
    if (0 != device->Unlock(pin, passphraseword, sError)) {
        throw JSONRPCError(RPC_INTERNAL_ERROR, sError);
    }

    result.pushKV("unlocked", true);

    return result;
};

static UniValue getdeviceinfo(const JSONRPCRequest &request)
{
            RPCHelpMan{"getdeviceinfo",
                "\nGet information from connected hardware device.\n",
                {
                },
                RPCResult{
            "{\n"
            "}\n"
                },
                RPCExamples{
            HelpExampleCli("getdeviceinfo", "") +
            "\nAs a JSON-RPC call\n"
            + HelpExampleRpc("getdeviceinfo", "")
                },
            }.Check(request);

    std::vector<std::unique_ptr<usb_device::CUSBDevice> > vDevices;
    usb_device::CUSBDevice *pDevice = SelectDevice(vDevices);

    UniValue info(UniValue::VOBJ);
    std::string sError;
    if (0 != pDevice->GetInfo(info, sError)) {
        info.pushKV("error", sError);
    }

    return info;
};

static UniValue getdevicepublickey(const JSONRPCRequest &request)
{
            RPCHelpMan{"getdevicepublickey",
                "\nGet the public key and address at \"path\" from a hardware device.\n",
                {
                    {"path", RPCArg::Type::STR, RPCArg::Optional::NO, "The path to the key to sign with.\n"
            "                           The full path is \"accountpath\"/\"path\"."},
                    {"accountpath", RPCArg::Type::STR, /* default */ GetDefaultAccountPath(), "Account path, set to empty string to ignore."},
                },
                RPCResult{
            "{\n"
            "  \"publickey\"        (string) The derived public key at \"path\".\n"
            "  \"address\"          (string) The address of \"publickey\".\n"
            "  \"path\"             (string) The full path of \"publickey\".\n"
            "}\n"
                },
                RPCExamples{
            "Get the first public key of external chain:\n"
            + HelpExampleCli("getdevicepublickey", "\"0/0\"")
            + "Get the first public key of internal chain of testnet account:\n"
            + HelpExampleCli("getdevicepublickey", "\"1/0\" \"44h/1h/0h\"") +
            "\nAs a JSON-RPC call\n"
            + HelpExampleRpc("getdevicepublickey", "\"0/0\"")
                },
            }.Check(request);

    std::vector<uint32_t> vPath;
    GetPath(vPath, request.params[0], request.params[1]);

    std::vector<std::unique_ptr<usb_device::CUSBDevice> > vDevices;
    usb_device::CUSBDevice *pDevice = SelectDevice(vDevices);

    std::string sError;
    CPubKey pk;
    if (0 != pDevice->GetPubKey(vPath, pk, sError)) {
        throw JSONRPCError(RPC_INTERNAL_ERROR, strprintf("GetPubKey failed %s.", sError));
    }

    std::string sPath;
    if (0 != PathToString(vPath, sPath)) {
        sPath = "error";
    }

    UniValue rv(UniValue::VOBJ);
    rv.pushKV("publickey", HexStr(pk));
    rv.pushKV("address", CBitcoinAddress(PKHash(pk)).ToString());
    rv.pushKV("path", sPath);

    return rv;
};

static UniValue getdevicexpub(const JSONRPCRequest &request)
{
            RPCHelpMan{"getdevicexpub",
                "\nGet the extended public key at \"path\" from a hardware device.\n",
                {
                    {"path", RPCArg::Type::STR, RPCArg::Optional::NO, "The path to the key to sign with.\n"
            "                           The full path is \"accountpath\"/\"path\"."},
                    {"accountpath", RPCArg::Type::STR, /* default */ GetDefaultAccountPath(), "Account path, set to empty string to ignore."},
                },
                RPCResult{
            "\"address\"              (string) The particl extended public key\n"
                },
                RPCExamples{
            HelpExampleCli("getdevicexpub", "\"0\"") +
            "\nAs a JSON-RPC call\n"
            + HelpExampleRpc("getdevicexpub", "\"0\"")
                },
            }.Check(request);

    std::vector<uint32_t> vPath;
    GetPath(vPath, request.params[0], request.params[1]);

    std::vector<std::unique_ptr<usb_device::CUSBDevice> > vDevices;
    usb_device::CUSBDevice *pDevice = SelectDevice(vDevices);

    std::string sError;
    CExtPubKey ekp;
    if (0 != pDevice->GetXPub(vPath, ekp, sError)) {
        throw JSONRPCError(RPC_INTERNAL_ERROR, strprintf("GetXPub failed %s.", sError));
    }

    return CBitcoinExtPubKey(ekp).ToString();
};

static UniValue devicesignmessage(const JSONRPCRequest &request)
{
            RPCHelpMan{"devicesignmessage",
                "\nSign a message with the key at \"path\" on a hardware device.\n",
                {
                    {"path", RPCArg::Type::STR, RPCArg::Optional::NO, "The path to the key to sign with.\n"
            "                           The full path is \"accountpath\"/\"path\"."},
                    {"message", RPCArg::Type::STR, RPCArg::Optional::NO, "The message to sign for."},
                    {"accountpath", RPCArg::Type::STR, /* default */ GetDefaultAccountPath(), "Account path, set to empty string to ignore."},
                },
                RPCResult{
            "\"signature\"          (string) The signature of the message encoded in base 64\n"
                },
                RPCExamples{
            "Sign with the first key of external chain:\n"
            + HelpExampleCli("devicesignmessage", "\"0/0\" \"my message\"") +
            "\nAs a JSON-RPC call\n"
            + HelpExampleRpc("devicesignmessage", "\"0/0\", \"my message\"")
                },
            }.Check(request);

    std::vector<uint32_t> vPath;
    GetPath(vPath, request.params[0], request.params[2]);

    std::vector<std::unique_ptr<usb_device::CUSBDevice> > vDevices;
    usb_device::CUSBDevice *pDevice = SelectDevice(vDevices);

    if (!request.params[1].isStr()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Bad message.");
    }

    std::string sError, sMessage = request.params[1].get_str();
    std::vector<uint8_t> vchSig;
    if (0 != pDevice->SignMessage(vPath, sMessage, vchSig, sError)) {
        throw JSONRPCError(RPC_INTERNAL_ERROR, strprintf("SignMessage failed %s.", sError));
    }

    return EncodeBase64(vchSig.data(), vchSig.size());
};

static UniValue devicesignrawtransaction(const JSONRPCRequest &request)
{
    #ifdef ENABLE_WALLET
    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
    CHDWallet *const pwallet = GetParticlWallet(wallet.get());
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }
    #endif

            RPCHelpMan{"devicesignrawtransaction",
                "\nSign inputs for raw transaction (serialized, hex-encoded).\n"
                "The second optional argument (may be null) is an array of previous transaction outputs that\n"
                "this transaction depends on but may not yet be in the block chain.\n"
                "The third optional argument (may be null) is an array of bip44 paths\n"
                "that, if given, will be the only keys derived to sign the transaction.\n",
                {
                    {"hexstring", RPCArg::Type::STR, RPCArg::Optional::NO, "The transaction hex string."},
                    {"prevtxs", RPCArg::Type::ARR, /* default */ "", "A json array of previous dependent transaction outputs",
                        {
                            {"", RPCArg::Type::OBJ, RPCArg::Optional::NO, "",
                                {
                                    {"txid", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The transaction id"},
                                    {"vout", RPCArg::Type::NUM, RPCArg::Optional::NO, "The output number"},
                                    {"scriptPubKey", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "script key"},
                                    {"redeemScript", RPCArg::Type::STR_HEX, /* default */ "", "(required for P2SH or P2WSH)"},
                                    {"amount", RPCArg::Type::AMOUNT, RPCArg::Optional::NO, "The amount spent"},
                                },
                            },
                        },
                    },
                    {"paths", RPCArg::Type::ARR, /* default */ "", "A json array of key paths for signing",
                        {
                            {"path", RPCArg::Type::STR, RPCArg::Optional::NO, "bip44 path."},
                        },
                    },
                    {"sighashtype", RPCArg::Type::STR, /* default */ "ALL", "The signature hash type. Must be one of\n"
            "       \"ALL\"\n"
            "       \"NONE\"\n"
            "       \"SINGLE\"\n"
            "       \"ALL|ANYONECANPAY\"\n"
            "       \"NONE|ANYONECANPAY\"\n"
            "       \"SINGLE|ANYONECANPAY\""},
                    {"accountpath", RPCArg::Type::STR, /* default */ GetDefaultAccountPath(), "Account path, set to empty string to ignore."},
                },
                RPCResult{
            "{\n"
            "  \"hex\" : \"value\",           (string) The hex-encoded raw transaction with signature(s)\n"
            "  \"complete\" : true|false,   (boolean) If the transaction has a complete set of signatures\n"
            "  \"errors\" : [                 (json array of objects) Script verification errors (if there are any)\n"
            "    {\n"
            "      \"txid\" : \"hash\",           (string) The hash of the referenced, previous transaction\n"
            "      \"vout\" : n,                (numeric) The index of the output to spent and used as input\n"
            "      \"scriptSig\" : \"hex\",       (string) The hex-encoded signature script\n"
            "      \"sequence\" : n,            (numeric) Script sequence number\n"
            "      \"error\" : \"text\"           (string) Verification or signing error related to the input\n"
            "    }\n"
            "    ,...\n"
            "  ]\n"
            "}\n"
                },
                RPCExamples{
            HelpExampleCli("devicesignrawtransaction", "\"myhex\"") +
            "\nAs a JSON-RPC call\n"
            + HelpExampleRpc("devicesignrawtransaction", "\"myhex\"")
                },
            }.Check(request);

#ifdef ENABLE_WALLET
    LOCK2(cs_main, pwallet ? &pwallet->cs_wallet : nullptr);
#else
    LOCK(cs_main);
#endif
    RPCTypeCheck(request.params, {UniValue::VSTR, UniValue::VARR, UniValue::VARR, UniValue::VSTR, UniValue::VSTR}, true);

    CMutableTransaction mtx;
    if (!DecodeHexTx(mtx, request.params[0].get_str(), true)) {
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "TX decode failed");
    }

    std::vector<std::unique_ptr<usb_device::CUSBDevice> > vDevices;
    usb_device::CUSBDevice *pDevice = SelectDevice(vDevices);

    // TODO check root id on wallet and device match


    // Fetch previous transactions (inputs):
    CCoinsView viewDummy;
    CCoinsViewCache view(&viewDummy);
    {
        LOCK(mempool.cs);
        CCoinsViewCache &viewChain = ::ChainstateActive().CoinsTip();
        CCoinsViewMemPool viewMempool(&viewChain, mempool);
        view.SetBackend(viewMempool); // temporarily switch cache backend to db+mempool view

        for (const CTxIn& txin : mtx.vin) {
            view.AccessCoin(txin.prevout); // Load entries from viewChain into view; can fail.
        }

        view.SetBackend(viewDummy); // switch back to avoid locking mempool for too long
    }


    bool fGivenKeys = false;
    usb_device::CPathKeyStore tempKeystore;
    if (!request.params[2].isNull()) {
        fGivenKeys = true;
        UniValue paths = request.params[2].get_array();
        for (unsigned int idx = 0; idx < paths.size(); idx++) {
            usb_device::CPathKey pathkey;
            GetPath(pathkey.vPath, paths[idx], request.params[4]);

            std::string sError;
            if (0 != pDevice->GetPubKey(pathkey.vPath, pathkey.pk, sError)) {
                throw JSONRPCError(RPC_INTERNAL_ERROR, strprintf("Device GetPubKey failed %s.", sError));
            }

            tempKeystore.AddKey(pathkey);
        }
    }

    // Add previous txouts given in the RPC call:
    if (!request.params[1].isNull()) {
        UniValue prevTxs = request.params[1].get_array();
        for (unsigned int idx = 0; idx < prevTxs.size(); idx++) {
            const UniValue& p = prevTxs[idx];
            if (!p.isObject()) {
                throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "expected object with {\"txid'\",\"vout\",\"scriptPubKey\"}");
            }

            UniValue prevOut = p.get_obj();

            RPCTypeCheckObj(prevOut,
                {
                    {"txid", UniValueType(UniValue::VSTR)},
                    {"vout", UniValueType(UniValue::VNUM)},
                    {"scriptPubKey", UniValueType(UniValue::VSTR)},
                });

            uint256 txid = ParseHashO(prevOut, "txid");

            int nOut = find_value(prevOut, "vout").get_int();
            if (nOut < 0) {
                throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "vout must be positive");
            }

            COutPoint out(txid, nOut);
            std::vector<unsigned char> pkData(ParseHexO(prevOut, "scriptPubKey"));
            CScript scriptPubKey(pkData.begin(), pkData.end());

            {
            const Coin& coin = view.AccessCoin(out);

            if (coin.nType != OUTPUT_STANDARD && coin.nType != OUTPUT_CT) {
                throw JSONRPCError(RPC_MISC_ERROR, strprintf("Bad input type: %d", coin.nType));
            }

            if (!coin.IsSpent() && coin.out.scriptPubKey != scriptPubKey) {
                std::string err("Previous output scriptPubKey mismatch:\n");
                err = err + ScriptToAsmStr(coin.out.scriptPubKey) + "\nvs:\n"+
                    ScriptToAsmStr(scriptPubKey);
                throw JSONRPCError(RPC_DESERIALIZATION_ERROR, err);
            }
            Coin newcoin;
            newcoin.out.scriptPubKey = scriptPubKey;
            newcoin.out.nValue = 0;
            if (prevOut.exists("amount")) {
                newcoin.out.nValue = AmountFromValue(find_value(prevOut, "amount"));
            }
            newcoin.nHeight = 1;
            view.AddCoin(out, std::move(newcoin), true);
            }

            // if redeemScript given and not using the local wallet (private keys
            // given), add redeemScript to the tempKeystore so it can be signed:
            if (fGivenKeys && (scriptPubKey.IsPayToScriptHashAny(mtx.IsCoinStake()))) {
                RPCTypeCheckObj(prevOut,
                    {
                        {"txid", UniValueType(UniValue::VSTR)},
                        {"vout", UniValueType(UniValue::VNUM)},
                        {"scriptPubKey", UniValueType(UniValue::VSTR)},
                        {"redeemScript", UniValueType(UniValue::VSTR)},
                    });
                UniValue v = find_value(prevOut, "redeemScript");
                if (!v.isNull()) {
                    std::vector<unsigned char> rsData(ParseHexV(v, "redeemScript"));
                    CScript redeemScript(rsData.begin(), rsData.end());
                    tempKeystore.AddCScript(redeemScript);
                }
            }
        }
    }

#ifdef ENABLE_WALLET
    const FillableSigningProvider& keystore = ((fGivenKeys || !pwallet) ? (FillableSigningProvider&)tempKeystore : (const FillableSigningProvider&)*static_cast<const FillableSigningProvider*>(pwallet->GetSigningProvider()));
#else
    const FillableSigningProvider& keystore = tempKeystore;
#endif

    int nHashType = SIGHASH_ALL;
    if (!request.params[3].isNull()) {
        static std::map<std::string, int> mapSigHashValues = {
            {std::string("ALL"), int(SIGHASH_ALL)},
            {std::string("ALL|ANYONECANPAY"), int(SIGHASH_ALL|SIGHASH_ANYONECANPAY)},
            {std::string("NONE"), int(SIGHASH_NONE)},
            {std::string("NONE|ANYONECANPAY"), int(SIGHASH_NONE|SIGHASH_ANYONECANPAY)},
            {std::string("SINGLE"), int(SIGHASH_SINGLE)},
            {std::string("SINGLE|ANYONECANPAY"), int(SIGHASH_SINGLE|SIGHASH_ANYONECANPAY)},
        };
        std::string strHashType = request.params[3].get_str();
        if (mapSigHashValues.count(strHashType)) {
            nHashType = mapSigHashValues[strHashType];
        } else {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid sighash param");
        }
    }

    bool fHashSingle = ((nHashType & ~SIGHASH_ANYONECANPAY) == SIGHASH_SINGLE);

    // Script verification errors
    UniValue vErrors(UniValue::VARR);

    // Use CTransaction for the constant parts of the
    // transaction to avoid rehashing.
    const CTransaction txConst(mtx);

    // Prepare transaction
    int prep = pDevice->PrepareTransaction(mtx, view, keystore, nHashType);
    if (0 != prep) {
        throw JSONRPCError(RPC_INTERNAL_ERROR, strprintf("PrepareTransaction failed with code %d.", prep));
    }

    if (!pDevice->sError.empty()) {
        pDevice->Close();
        UniValue entry(UniValue::VOBJ);
        entry.pushKV("error", pDevice->sError);
        vErrors.push_back(entry);
        UniValue result(UniValue::VOBJ);
        result.pushKV("hex", EncodeHexTx(CTransaction(mtx)));
        if (!vErrors.empty()) {
            result.pushKV("errors", vErrors);
        }
        return result;
    }

    // Sign what we can:
    for (unsigned int i = 0; i < mtx.vin.size(); i++) {
        CTxIn& txin = mtx.vin[i];
        const Coin& coin = view.AccessCoin(txin.prevout);
        if (coin.IsSpent()) {
            TxInErrorToJSON(txin, vErrors, "Input not found or already spent");
            continue;
        }
        if (coin.nType != OUTPUT_STANDARD && coin.nType != OUTPUT_CT) {
            pDevice->Close();
            throw JSONRPCError(RPC_MISC_ERROR, strprintf("Bad input type: %d", coin.nType));
        }

        std::vector<uint8_t> vchAmount(8);
        CScript prevPubKey = coin.out.scriptPubKey;
        CAmount amount = coin.out.nValue;
        memcpy(vchAmount.data(), &amount, 8);
        SignatureData sigdata = DataFromTransaction(mtx, i, vchAmount, prevPubKey);

        // Only sign SIGHASH_SINGLE if there's a corresponding output:
        if (!fHashSingle || (i < mtx.GetNumVOuts())) {
            pDevice->sError.clear();
            ProduceSignature(keystore, usb_device::DeviceSignatureCreator(pDevice, &mtx, i, vchAmount, nHashType), prevPubKey, sigdata);

            if (!pDevice->sError.empty()) {
                UniValue entry(UniValue::VOBJ);
                entry.pushKV("error", pDevice->sError);
                vErrors.push_back(entry);
                pDevice->sError.clear();
            }
        }

        UpdateInput(txin, sigdata);

        ScriptError serror = SCRIPT_ERR_OK;
        if (!VerifyScript(txin.scriptSig, prevPubKey, &txin.scriptWitness, STANDARD_SCRIPT_VERIFY_FLAGS, TransactionSignatureChecker(&txConst, i, vchAmount), &serror)) {
            if (serror == SCRIPT_ERR_INVALID_STACK_OPERATION) {
                // Unable to sign input and verification failed (possible attempt to partially sign).
                TxInErrorToJSON(txin, vErrors, "Unable to sign input, invalid stack size (possibly missing key)");
            } else {
                TxInErrorToJSON(txin, vErrors, ScriptErrorString(serror));
            }
        }
    }

    pDevice->Close();

    bool fComplete = vErrors.empty();

    UniValue result(UniValue::VOBJ);
    result.pushKV("hex", EncodeHexTx(CTransaction(mtx)));
    result.pushKV("complete", fComplete);
    if (!vErrors.empty()) {
        result.pushKV("errors", vErrors);
    }

    return result;
};

#ifdef ENABLE_WALLET
static UniValue initaccountfromdevice(const JSONRPCRequest &request)
{
    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
    CHDWallet *const pwallet = GetParticlWallet(wallet.get());
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp))
        return NullUniValue;

            RPCHelpMan{"initaccountfromdevice",
                "\nInitialise an extended key account from a hardware device." +
                HelpRequiringPassphrase(pwallet) + "\n",
                {
                    {"label", RPCArg::Type::STR, /* default */ "", "A label for the account."},
                    {"path", RPCArg::Type::STR, /* default */ "", "The path to derive the key from (default=\""+GetDefaultAccountPath()+"\")."},
                    {"makedefault", RPCArg::Type::BOOL, /* default */ "true", "Make the new account the default account for the wallet."},
                    {"scan_chain_from", RPCArg::Type::NUM, /* default */ "0", "Timestamp, scan the chain for incoming txns only on blocks after time, negative number to skip."},
                    {"initstealthchain", RPCArg::Type::BOOL, /* default */ "true", "Prepare the account to generate stealthaddresses (default=true).\n"
            "                           The hardware device will need to sign a fake transaction to use as the seed for the scan chain."},
                },
                RPCResult{
            "{\n"
            "  \"extkey\"           (string) The derived extended public key at \"path\".\n"
            "  \"path\"             (string) The full path used to derive the account.\n"
            "}\n"
                },
                RPCExamples{
            HelpExampleCli("initaccountfromdevice", "\"new_acc\" \"44h/1h/0h\" false") +
            "\nAs a JSON-RPC call\n"
            + HelpExampleRpc("initaccountfromdevice", "\"new_acc\"")
                },
            }.Check(request);

    RPCTypeCheck(request.params, {UniValue::VSTR, UniValue::VSTR, UniValue::VBOOL, UniValue::VNUM}, true);

    // Make sure the results are valid at least up to the most recent block
    // the user could have gotten from another RPC command prior to now
    pwallet->BlockUntilSyncedToCurrentChain();

    EnsureWalletIsUnlocked(pwallet);

    std::vector<std::unique_ptr<usb_device::CUSBDevice> > vDevices;
    usb_device::CUSBDevice *pDevice = SelectDevice(vDevices);

    std::string sLabel;
    if (request.params[0].isStr()) {
        sLabel = request.params[0].get_str();
    }

    std::vector<uint32_t> vPath;
    if (request.params[1].isStr() && request.params[1].get_str().size()) {
        UniValue emptyStr(UniValue::VSTR);
        GetPath(vPath, request.params[1], emptyStr);
    } else {
        std::string sPath = GetDefaultAccountPath();
        int rv;
        if ((rv = ExtractExtKeyPath(sPath, vPath)) != 0) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("Bad path: %s.", ExtKeyGetString(rv)));
        }
    }

    bool fMakeDefault = request.params[2].isBool() ? request.params[2].get_bool() : true;
    int64_t nScanFrom = request.params[3].isNum() ? request.params[3].get_int64() : 0;
    bool fInitStealth = request.params[4].isBool() ? request.params[4].get_bool() : true;

    WalletRescanReserver reserver(pwallet);
    if (!reserver.reserve()) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Wallet is currently rescanning. Abort existing rescan or wait.");
    }

    std::string sError;
    CExtPubKey ekp;
    if (0 != pDevice->GetXPub(vPath, ekp, sError)) {
        throw JSONRPCError(RPC_INTERNAL_ERROR, strprintf("GetXPub failed %s.", sError));
    }

    CKeyID idAccount = ekp.pubkey.GetID();

    {
        LOCK(pwallet->cs_wallet);
        CHDWalletDB wdb(pwallet->GetDBHandle(), "r+");

        CStoredExtKey checkSEA;
        if (wdb.ReadExtKey(idAccount, checkSEA)) {
            throw JSONRPCError(RPC_INTERNAL_ERROR, "Account already exists in db.");
        }


        CStoredExtKey *sekAccount = new CStoredExtKey();
        sekAccount->nFlags |= EAF_ACTIVE | EAF_IN_ACCOUNT | EAF_HARDWARE_DEVICE;
        sekAccount->kp = CExtKeyPair(ekp);
        sekAccount->SetPath(vPath); // EKVT_PATH

        std::vector<uint8_t> vData;
        CExtKeyAccount *sea = new CExtKeyAccount();
        sea->sLabel = sLabel;
        sea->nFlags |= EAF_ACTIVE | EAF_HARDWARE_DEVICE;
        sea->mapValue[EKVT_CREATED_AT] = SetCompressedInt64(vData, GetTime());
        vData.clear();
        PushUInt32(vData, pDevice->pType->nVendorId);
        PushUInt32(vData, pDevice->pType->nProductId);
        sea->mapValue[EKVT_HARDWARE_DEVICE] = vData;
        sea->InsertChain(sekAccount);

        CExtPubKey epExternal, epInternal;
        uint32_t nExternal, nInternal;
        if (sekAccount->DeriveNextKey(epExternal, nExternal, false) != 0
            || sekAccount->DeriveNextKey(epInternal, nInternal, false) != 0) {
            sea->FreeChains();
            throw JSONRPCError(RPC_INTERNAL_ERROR, "Could not derive account chain keys.");
        }

        std::vector<uint32_t> vChainPath;
        vChainPath.push_back(vPath.back()); // make relative to key before account
        CStoredExtKey *sekExternal = new CStoredExtKey();
        sekExternal->kp = CExtKeyPair(epExternal);
        vChainPath.push_back(nExternal);
        sekExternal->SetPath(vChainPath);
        sekExternal->nFlags |= EAF_ACTIVE | EAF_RECEIVE_ON | EAF_IN_ACCOUNT | EAF_HARDWARE_DEVICE;
        sekExternal->mapValue[EKVT_KEY_TYPE] = SetChar(vData, EKT_EXTERNAL);
        sea->InsertChain(sekExternal);
        sea->nActiveExternal = sea->NumChains();

        CStoredExtKey *sekInternal = new CStoredExtKey();
        sekInternal->kp = CExtKeyPair(epInternal);
        vChainPath.pop_back();
        vChainPath.push_back(nInternal);
        sekInternal->SetPath(vChainPath);
        sekInternal->nFlags |= EAF_ACTIVE | EAF_RECEIVE_ON | EAF_IN_ACCOUNT | EAF_HARDWARE_DEVICE;
        sekInternal->mapValue[EKVT_KEY_TYPE] = SetChar(vData, EKT_INTERNAL);
        sea->InsertChain(sekInternal);
        sea->nActiveInternal = sea->NumChains();

        if (fInitStealth) {
            // Generate a chain to use for generating scan secrets
            // Use a signed message as the seed so the scan chain is deterministic.
            // In this way if the wallet is locked it's not possible to regenerate the private key to the scan chain.

            std::string msg = "Scan chain secret seed";
            std::vector<uint8_t> vchSig;
            std::vector<uint32_t> vSigPath;
            if (!pwallet->GetFullChainPath(sea, sea->nActiveExternal, vSigPath)) {
                sea->FreeChains();
                throw JSONRPCError(RPC_INTERNAL_ERROR, "GetFullChainPath failed.");
            }

            vSigPath.push_back(0);
            uiInterface.NotifyWaitingForDevice(false);
            if (0 != pDevice->SignMessage(vSigPath, msg, vchSig, sError)) {
                sea->FreeChains();
                uiInterface.NotifyWaitingForDevice(true);
                throw JSONRPCError(RPC_INTERNAL_ERROR, strprintf("Could not generate scan chain seed from signed message %s.", sError));
            }
            uiInterface.NotifyWaitingForDevice(true);
            vchSig.insert(vchSig.end(), sekExternal->kp.pubkey.begin(), sekExternal->kp.pubkey.end());

            CExtKey evStealthScan;
            evStealthScan.SetSeed(vchSig.data(), vchSig.size());

            CStoredExtKey *sekStealthScan = new CStoredExtKey();
            sekStealthScan->kp = CExtKeyPair(evStealthScan);
            vSigPath.clear();
            // sekStealthScan isn't on the account chain
            sekStealthScan->nFlags |= EAF_ACTIVE | EAF_IN_ACCOUNT;
            sekStealthScan->mapValue[EKVT_KEY_TYPE] = SetChar(vData, EKT_STEALTH_SCAN);
            sea->InsertChain(sekStealthScan);
            uint32_t nStealthScanChain = sea->NumChains();


            // Step over hardened chain 1 (stealth v1 chain)
            sekAccount->SetCounter(1, true);

            CExtPubKey epStealthSpend;
            uint32_t nStealthSpend = WithHardenedBit(CHAIN_NO_STEALTH_SPEND);
            vPath.push_back(nStealthSpend);
            if (0 != pDevice->GetXPub(vPath, epStealthSpend, sError)) {
                sea->FreeChains();
                throw JSONRPCError(RPC_INTERNAL_ERROR, strprintf("GetXPub failed %s.", sError));
            }
            vPath.pop_back();

            CStoredExtKey *sekStealthSpend = new CStoredExtKey();
            sekStealthSpend->kp = CExtKeyPair(epStealthSpend);
            vChainPath.pop_back();
            vChainPath.push_back(nStealthSpend);
            sekStealthSpend->SetPath(vChainPath);
            sekStealthSpend->nFlags |= EAF_ACTIVE | EAF_IN_ACCOUNT | EAF_HARDWARE_DEVICE;
            sekStealthSpend->mapValue[EKVT_KEY_TYPE] = SetChar(vData, EKT_STEALTH_SPEND);
            sea->InsertChain(sekStealthSpend);
            uint32_t nStealthSpendChain = sea->NumChains();

            sea->mapValue[EKVT_STEALTH_SCAN_CHAIN] = SetCompressedInt64(vData, nStealthScanChain);
            sea->mapValue[EKVT_STEALTH_SPEND_CHAIN] = SetCompressedInt64(vData, nStealthSpendChain);
        }

        if (!wdb.TxnBegin()) {
            throw std::runtime_error("TxnBegin failed.");
        }

        if (0 != pwallet->ExtKeySaveAccountToDB(&wdb, idAccount, sea)) {
            sea->FreeChains();
            wdb.TxnAbort();
            throw JSONRPCError(RPC_INTERNAL_ERROR, "DB Write failed.");
        }

        if (0 != pwallet->ExtKeyAddAccountToMaps(idAccount, sea)) {
            sea->FreeChains();
            wdb.TxnAbort();
            throw JSONRPCError(RPC_INTERNAL_ERROR, "ExtKeyAddAccountToMaps failed.");
        }

        CKeyID idOldDefault = pwallet->idDefaultAccount;
        if (fMakeDefault) {
            CKeyID idNewDefaultAccount = sea->GetID();
            int rv;
            if (0 != (rv = pwallet->ExtKeySetDefaultAccount(&wdb, idNewDefaultAccount))) {
                pwallet->ExtKeyRemoveAccountFromMapsAndFree(sea);
                wdb.TxnAbort();
                throw JSONRPCError(RPC_INTERNAL_ERROR, strprintf("ExtKeySetDefaultAccount failed, %s.", ExtKeyGetString(rv)));
            }
        }
        if (!pwallet->UnsetWalletFlagRV(&wdb, WALLET_FLAG_BLANK_WALLET)) {
            throw JSONRPCError(RPC_INTERNAL_ERROR, "UnsetWalletFlag failed.");
        }
        if (!wdb.TxnCommit()) {
            pwallet->idDefaultAccount = idOldDefault;
            pwallet->ExtKeyRemoveAccountFromMapsAndFree(sea);
            throw JSONRPCError(RPC_INTERNAL_ERROR, "TxnCommit failed.");
        }
    }

    if (nScanFrom >= 0) {
        pwallet->RescanFromTime(nScanFrom, reserver, true /* update */);
        pwallet->MarkDirty();
        auto locked_chain = pwallet->chain().lock();
        LOCK(pwallet->cs_wallet);
        pwallet->ReacceptWalletTransactions();
    }

    std::string sPath;
    if (0 != PathToString(vPath, sPath)) {
        sPath = "error";
    }
    UniValue result(UniValue::VOBJ);

    result.pushKV("extkey", CBitcoinExtPubKey(ekp).ToString());
    result.pushKV("path", sPath);
    result.pushKV("scanfrom", nScanFrom);

    return result;
};


static UniValue devicegetnewstealthaddress(const JSONRPCRequest &request)
{
    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
    CHDWallet *const pwallet = GetParticlWallet(wallet.get());
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

            RPCHelpMan{"devicegetnewstealthaddress",
                "\nReturns a new Particl stealth address for receiving payments." +
                    HelpRequiringPassphrase(pwallet) + "\n",
                {
                    {"label", RPCArg::Type::STR, /* default */ "", "If \"label\" is specified the new address will be added to the address book."},
                    {"num_prefix_bits", RPCArg::Type::NUM, /* default */ "0", "If specified and > 0, the stealth address is created with a prefix."},
                    {"prefix_num", RPCArg::Type::NUM, /* default */ "", "If prefix_num is not specified the prefix will be selected deterministically.\n"
            "           prefix_num can be specified in base2, 10 or 16, for base 2 prefix_num must begin with 0b, 0x for base16.\n"
            "           A 32bit integer will be created from prefix_num and the least significant num_prefix_bits will become the prefix.\n"
            "           A stealth address created without a prefix will scan all incoming stealth transactions, irrespective of transaction prefixes.\n"
            "           Stealth addresses with prefixes will scan only incoming stealth transactions with a matching prefix."},
                    {"bech32", RPCArg::Type::BOOL, /* default */ "true", "Use Bech32 encoding."},
                },
                RPCResult{
            "\"address\"              (string) The new particl stealth address\n"
                },
                RPCExamples{
             HelpExampleCli("devicegetnewstealthaddress", "\"lblTestSxAddrPrefix\" 3 \"0b101\"") +
            "\nAs a JSON-RPC call\n"
            + HelpExampleRpc("devicegetnewstealthaddress", "\"lblTestSxAddrPrefix\", 3, \"0b101\"")
                },
            }.Check(request);

    EnsureWalletIsUnlocked(pwallet);


    std::string sError, sLabel;
    if (request.params.size() > 0) {
        sLabel = request.params[0].get_str();
    }

    uint32_t num_prefix_bits = 0;
    if (request.params.size() > 1) {
        std::string s = request.params[1].get_str();
        if (s.length() && !ParseUInt32(s, &num_prefix_bits)) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "num_prefix_bits invalid number.");
        }
    }

    if (num_prefix_bits > 32) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "num_prefix_bits must be <= 32.");
    }

    std::string sPrefix_num;
    if (request.params.size() > 2)
        sPrefix_num = request.params[2].get_str();

    bool fBech32 = request.params.size() > 3 ? request.params[3].get_bool() : true;


    CEKAStealthKey akStealth;
    CStealthAddress sxAddr;
    {
        LOCK(pwallet->cs_wallet);

        ExtKeyAccountMap::iterator mi = pwallet->mapExtAccounts.find(pwallet->idDefaultAccount);
        if (mi == pwallet->mapExtAccounts.end()) {
            throw JSONRPCError(RPC_INTERNAL_ERROR, "Unknown account.");
        }

        CExtKeyAccount *sea = mi->second;
        uint64_t nScanChain, nSpendChain;
        CStoredExtKey *sekScan = nullptr, *sekSpend = nullptr;
        mapEKValue_t::iterator mvi = sea->mapValue.find(EKVT_STEALTH_SCAN_CHAIN);
        if (mvi != sea->mapValue.end()) {
            GetCompressedInt64(mvi->second, nScanChain);
            sekScan = sea->GetChain(nScanChain);
        }
        if (!sekScan) {
            throw JSONRPCError(RPC_INTERNAL_ERROR, "Unknown stealth scan chain.");
        }

        mvi = sea->mapValue.find(EKVT_STEALTH_SPEND_CHAIN);
        if (mvi != sea->mapValue.end()) {
            GetCompressedInt64(mvi->second, nSpendChain);
            sekSpend = sea->GetChain(nSpendChain);
        }
        if (!sekSpend) {
            throw JSONRPCError(RPC_INTERNAL_ERROR, "Unknown stealth spend chain.");
        }

        uint32_t nSpendGenerated = sekSpend->nHGenerated;

        std::vector<uint32_t> vSpendPath;
        if (!pwallet->GetFullChainPath(sea, nSpendChain, vSpendPath)) {
            throw JSONRPCError(RPC_INTERNAL_ERROR, "GetFullChainPath failed.");
        }
        vSpendPath.push_back(WithHardenedBit(nSpendGenerated));

        std::vector<std::unique_ptr<usb_device::CUSBDevice> > vDevices;
        usb_device::CUSBDevice *pDevice = SelectDevice(vDevices);

        CPubKey pkSpend;
        if (0 != pDevice->GetPubKey(vSpendPath, pkSpend, sError)) {
            throw JSONRPCError(RPC_INTERNAL_ERROR, strprintf("Device GetPubKey failed %s.", sError));
        }

        sekSpend->nHGenerated = nSpendGenerated+1;


        CKey kScan;
        uint32_t nScanOut;
        if (0 != sekScan->DeriveNextKey(kScan, nScanOut, true)) {
            throw JSONRPCError(RPC_INTERNAL_ERROR, "Derive failed.");
        }

        uint32_t nPrefixBits = num_prefix_bits;
        uint32_t nPrefix = 0;
        const char *pPrefix = sPrefix_num.empty() ? nullptr : sPrefix_num.c_str();
        if (pPrefix) {
            if (!ExtractStealthPrefix(pPrefix, nPrefix)) {
                throw JSONRPCError(RPC_INTERNAL_ERROR, "ExtractStealthPrefix failed.");
            }
        } else
        if (nPrefixBits > 0) {
            // If pPrefix is null, set nPrefix from the hash of kScan
            uint8_t tmp32[32];
            CSHA256().Write(kScan.begin(), 32).Finalize(tmp32);
            memcpy(&nPrefix, tmp32, 4);
        }

        uint32_t nMask = SetStealthMask(nPrefixBits);
        nPrefix = nPrefix & nMask;
        akStealth = CEKAStealthKey(nScanChain, nScanOut, kScan, nSpendChain, WithHardenedBit(nSpendGenerated), pkSpend, nPrefixBits, nPrefix);
        akStealth.sLabel = sLabel;

        if (0 != akStealth.SetSxAddr(sxAddr)) {
            throw JSONRPCError(RPC_INTERNAL_ERROR, "SetSxAddr failed.");
        }

        CKeyID idAccount = sea->GetID();
        CHDWalletDB wdb(pwallet->GetDBHandle(), "r+");

        if (!wdb.TxnBegin()) {
            throw JSONRPCError(RPC_INTERNAL_ERROR, "TxnBegin failed.");
        }

        if (0 != pwallet->SaveStealthAddress(&wdb, sea, akStealth, fBech32)) {
            wdb.TxnAbort();
            pwallet->ExtKeyRemoveAccountFromMapsAndFree(idAccount);
            pwallet->ExtKeyLoadAccount(&wdb, idAccount);
            throw JSONRPCError(RPC_INTERNAL_ERROR, "SaveStealthAddress failed.");
        }

        if (!wdb.TxnCommit()) {
            throw JSONRPCError(RPC_INTERNAL_ERROR, "TxnCommit failed.");
        }
    }

    pwallet->AddressBookChangedNotify(sxAddr, CT_NEW);

    return sxAddr.ToString(fBech32);
};
#endif

static const CRPCCommand commands[] =
{ //  category              name                            actor (function)            argNames
  //  --------------------- ------------------------        -----------------------     ----------
    { "usbdevice",          "deviceloadmnemonic",           &deviceloadmnemonic,        {"wordcount", "pinprotection"} },
    { "usbdevice",          "devicebackup",                 &devicebackup,              {} },
    { "usbdevice",          "listdevices",                  &listdevices,               {} },
    { "usbdevice",          "promptunlockdevice",           &promptunlockdevice,        {} },
    { "usbdevice",          "unlockdevice",                 &unlockdevice,              {"passphrase", "pin"} },
    { "usbdevice",          "getdeviceinfo",                &getdeviceinfo,             {} },
    { "usbdevice",          "getdevicepublickey",           &getdevicepublickey,        {"path","accountpath"} },
    { "usbdevice",          "getdevicexpub",                &getdevicexpub,             {"path","accountpath"} },
    { "usbdevice",          "devicesignmessage",            &devicesignmessage,         {"path","message","accountpath"} },
    { "usbdevice",          "devicesignrawtransaction",     &devicesignrawtransaction,  {"hexstring","prevtxs","privkeypaths","sighashtype","accountpath"} }, /* uses wallet if enabled */
#ifdef ENABLE_WALLET
    { "usbdevice",          "initaccountfromdevice",        &initaccountfromdevice,     {"label","path","makedefault","scan_chain_from","initstealthchain"} },
    { "usbdevice",          "devicegetnewstealthaddress",   &devicegetnewstealthaddress,{"label","num_prefix_bits","prefix_num","bech32"} },
#endif
};

void RegisterUSBDeviceRPC(CRPCTable &t)
{
    for (unsigned int vcidx = 0; vcidx < ARRAYLEN(commands); vcidx++)
        t.appendCommand(commands[vcidx].name, &commands[vcidx]);
}
