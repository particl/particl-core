// Copyright (c) 2018-2019 The Particl Core developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <usbdevice/trezordevice.h>

#include <chainparams.h>
#include <coins.h>
#include <pubkey.h>
#include <key_io.h>
#include <base58.h>
#include <usbdevice/usbwrapper.h>
#include <util/strencodings.h>
#include <util/system.h>
#include <shutdown.h>
#include <univalue.h>

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#include <usbdevice/trezor/messages-bitcoin.pb.h>
#include <usbdevice/trezor/messages-management.pb.h>
#include <usbdevice/trezor/messages.pb.h>
#pragma GCC diagnostic pop

namespace usb_device {

int CTrezorDevice::Open()
{
    if (!pType) {
        return 1;
    }

    if (webusb_init()) {
        return 1;
    }

    if (!(handle = webusb_open_path(cPath))) {
        webusb_exit();
        return 1;
    }

    return 0;
};

int CTrezorDevice::Close()
{
    if (handle) {
        webusb_close(handle);
    }
    handle = nullptr;

    webusb_exit();
    return 0;
};

int CTrezorDevice::WriteV1(uint16_t msg_type, std::vector<uint8_t>& vec)
{
    static const size_t BUFFER_LEN = 64;
    uint8_t buffer[BUFFER_LEN];
    size_t msg_len = vec.size();
    size_t wrote = 0;

    do {
        size_t i = 0;
#ifdef WIN32
        //buffer[i++] = 0; // Report ID
#endif
        buffer[i++] = '?';

        if (wrote == 0) {
            buffer[i++] = '#';
            buffer[i++] = '#';

            buffer[i++] = (msg_type >> 8) & 0xFF;
            buffer[i++] = (msg_type & 0xFF);

            buffer[i++] = (msg_len >> 24) & 0xFF;
            buffer[i++] = (msg_len >> 16) & 0xFF;
            buffer[i++] = (msg_len >> 8) & 0xFF;
            buffer[i++] = msg_len & 0xFF;
        }

        size_t put = std::min(msg_len - wrote, BUFFER_LEN - i);
        memcpy(buffer + i, vec.data() + wrote, put);
        if (i + put < BUFFER_LEN) {
            memset(buffer + i + put, 0, BUFFER_LEN - (i + put));
        }
        int result = webusb_write(handle, buffer, BUFFER_LEN);
        if (result < 0) {
            return result;
        }
        wrote += put;
    } while (wrote < msg_len);

    return 0;
};

static int ReadWithTimeoutV1(webusb_device* handle, uint16_t& msg_type, std::vector<uint8_t>& vec, int timeout)
{
    static const size_t BUFFER_LEN = 64;
    uint8_t buffer[BUFFER_LEN];

    size_t result = webusb_read_timeout(handle, buffer, BUFFER_LEN, timeout);
    if (result < 9) {
        return result;
    }
    if (buffer[0] != '?' || buffer[1] != '#' || buffer[2] != '#') {
        return -1;
    }

    msg_type = buffer[3] << 8;
    msg_type += buffer[4];

    size_t len_full = buffer[5] << 24;
    len_full += buffer[6] << 16;
    len_full += buffer[7] << 8;
    len_full += buffer[8];

    vec.resize(len_full);

    size_t get = std::min(len_full, BUFFER_LEN - 9);
    memcpy(vec.data(), buffer + 9, get);
    size_t read = get;

    while (read < len_full) {
        int result = webusb_read_timeout(handle, buffer, BUFFER_LEN, timeout);
        if (result < 1) {
            return result;
        }
        if (buffer[0] != '?') {
            return -1;
        }
        size_t get = std::min(len_full - read, BUFFER_LEN - 1);
        memcpy(vec.data() + read, buffer + 1, get);
        read += get;
    }

    return 0;
};

int CTrezorDevice::ReadV1(uint16_t& msg_type, std::vector<uint8_t>& vec)
{
    return ReadWithTimeoutV1(handle, msg_type, vec, 60000);
};

int CTrezorDevice::OpenIfUnlocked(std::string& sError)
{
    hw::trezor::messages::management::GetFeatures msg_in;
    hw::trezor::messages::management::Features msg_out;

    std::vector<uint8_t> vec_in, vec_out;

    if (0 != Open()) {
        return errorN(1, sError, __func__, "Failed to open device.");
    }

    // Send an initialize message, which clears the Trezor
    // of any previous actions that were ungoing.
    hw::trezor::messages::management::Initialize msg_init;
    std::vector<uint8_t> vec_init;
    vec_init.resize(msg_init.ByteSize());
    if (!msg_init.SerializeToArray(vec_init.data(), vec_init.size())) {
        Close();
        return errorN(1, sError, __func__, "SerializeToArray for Initialize failed.");
    }

    if (0 != WriteV1(hw::trezor::messages::MessageType_Initialize, vec_init)) {
        Close();
        return errorN(1, sError, __func__, "WriteV1 for Initialize failed.");
    }

    uint16_t msg_type_out = 0;
    if (0 != ReadV1(msg_type_out, vec_out)) {
        Close();
        return errorN(1, sError, __func__, "ReadV1 failed.");
    }

    if (hw::trezor::messages::MessageType_Features != msg_type_out) {
        Close();
        return errorN(1, sError, __func__, "ReadV1 did not return Features message, instead msg_type_out=%u.", msg_type_out);
    }

    Close();

    if (!msg_out.ParseFromArray(vec_out.data(), vec_out.size())) {
        return errorN(1, sError, __func__, "ParseFromArray failed.");
    }

    bool passphrase_protection = msg_out.passphrase_protection();
    LogPrintf("%s: Device passphrase protection status = %b.\n", __func__, passphrase_protection);
    if (passphrase_protection) {
        bool unlocked = (msg_out.passphrase_cached());
        LogPrintf("%s: Device passphrase unlocked status = %b.\n", __func__, unlocked);

        if (!unlocked) {
            return errorN(1, sError, __func__, "Device is not unlocked, please use devicepromptunlock and deviceunlock.");
        }
    }

    bool pin_protection = msg_out.pin_protection();
    LogPrintf("%s: Device pin protection status = %b.\n", __func__, pin_protection);
    if (pin_protection) {
        bool unlocked = (msg_out.pin_cached());
        LogPrintf("%s: Device pin unlocked status = %b.\n", __func__, unlocked);

        if (!unlocked) {
            return errorN(1, sError, __func__, "Device is not unlocked, please use devicepromptunlock and deviceunlock.");
        }
    }

    return Open();
};

int CTrezorDevice::GetFirmwareVersion(std::string& sFirmware, std::string& sError)
{
    hw::trezor::messages::management::GetFeatures msg_in;
    hw::trezor::messages::management::Features msg_out;

    std::vector<uint8_t> vec_in, vec_out;

    vec_in.resize(msg_in.ByteSize());

    if (!msg_in.SerializeToArray(vec_in.data(), vec_in.size())) {
        return errorN(1, sError, __func__, "SerializeToArray failed.");
    }

    if (0 != Open()) {
        return errorN(1, sError, __func__, "Failed to open device.");
    }

    if (0 != WriteV1(hw::trezor::messages::MessageType_GetFeatures, vec_in)) {
        Close();
        return errorN(1, sError, __func__, "WriteV1 failed.");
    }

    uint16_t msg_type_out = 0;
    if (0 != ReadV1(msg_type_out, vec_out)) {
        Close();
        return errorN(1, sError, __func__, "ReadV1 failed.");
    }

    Close();

    if (!msg_out.ParseFromArray(vec_out.data(), vec_out.size())) {
        return errorN(1, sError, __func__, "ParseFromArray failed.");
    }

    sFirmware = strprintf("%d.%d.%d", msg_out.major_version(), msg_out.minor_version(), msg_out.patch_version());

    return 0;
};

int CTrezorDevice::GetInfo(UniValue& info, std::string& sError)
{
    hw::trezor::messages::management::GetFeatures msg_in;
    hw::trezor::messages::management::Features msg_out;

    std::vector<uint8_t> vec_in, vec_out;

    vec_in.resize(msg_in.ByteSize());

    if (!msg_in.SerializeToArray(vec_in.data(), vec_in.size())) {
        return errorN(1, sError, __func__, "SerializeToArray failed.");
    }

    if (0 != Open()) {
        return errorN(1, sError, __func__, "Failed to open device.");
    }

    if (0 != WriteV1(hw::trezor::messages::MessageType_GetFeatures, vec_in)) {
        Close();
        return errorN(1, sError, __func__, "WriteV1 failed.");
    }

    uint16_t msg_type_out = 0;
    if (0 != ReadV1(msg_type_out, vec_out)) {
        Close();
        return errorN(1, sError, __func__, "ReadV1 failed.");
    }

    Close();

    if (!msg_out.ParseFromArray(vec_out.data(), vec_out.size())) {
        return errorN(1, sError, __func__, "ParseFromArray failed.");
    }

    info.pushKV("device_id", msg_out.device_id());
    info.pushKV("initialized", msg_out.initialized());
    info.pushKV("firmware_present", msg_out.firmware_present());
    info.pushKV("pin_protection", msg_out.pin_protection());
    info.pushKV("pin_cached", msg_out.pin_cached());
    info.pushKV("passphrase_protection", msg_out.passphrase_protection());
    info.pushKV("passphrase_cached", msg_out.passphrase_cached());

    return 0;
};

int CTrezorDevice::GetPubKey(const std::vector<uint32_t>& vPath, CPubKey& pk, std::string& sError)
{
    hw::trezor::messages::bitcoin::GetPublicKey msg_in;
    hw::trezor::messages::bitcoin::PublicKey msg_out;

    for (const auto i : vPath) {
        msg_in.add_address_n(i);
    }

    std::vector<uint8_t> vec_in, vec_out;

    vec_in.resize(msg_in.ByteSize());

    if (!msg_in.SerializeToArray(vec_in.data(), vec_in.size())) {
        return errorN(1, sError, __func__, "SerializeToArray failed.");
    }

    int opened = OpenIfUnlocked(sError);
    if (0 !=  opened){
        return opened;
    }

    if (0 != WriteV1(hw::trezor::messages::MessageType_GetPublicKey, vec_in)) {
        Close();
        return errorN(1, sError, __func__, "WriteV1 failed.");
    }

    uint16_t msg_type_out = hw::trezor::messages::MessageType_PublicKey;
    if (0 != ReadV1(msg_type_out, vec_out)) {
        Close();
        return errorN(1, sError, __func__, "ReadV1 failed.");
    }

    Close();

    if (!msg_out.ParseFromArray(vec_out.data(), vec_out.size())) {
        return errorN(1, sError, __func__, "ParseFromArray failed.");
    }

    size_t lenPubkey = msg_out.node().public_key().size();
    pk.Set(&msg_out.node().public_key().c_str()[0], &msg_out.node().public_key().c_str()[lenPubkey]);

    return 0;
};

int CTrezorDevice::GetXPub(const std::vector<uint32_t>& vPath, CExtPubKey& ekp, std::string& sError)
{
    if (vPath.size() < 1 || vPath.size() > 10) {
        return errorN(1, sError, __func__, _("Path depth out of range.").c_str());
    }
    size_t lenPath = vPath.size();

    hw::trezor::messages::bitcoin::GetPublicKey msg_in;
    hw::trezor::messages::bitcoin::PublicKey msg_out;

    for (const auto i : vPath) {
        msg_in.add_address_n(i);
    }

    uint16_t msg_type_out;
    std::vector<uint8_t> vec_in, vec_out;

    vec_in.resize(msg_in.ByteSize());

    if (!msg_in.SerializeToArray(vec_in.data(), vec_in.size())) {
        return errorN(1, sError, __func__, "SerializeToArray failed.");
    }

    int opened = OpenIfUnlocked(sError);
    if (0 !=  opened){
        return opened;
    }

    if (0 != WriteV1(hw::trezor::messages::MessageType_GetPublicKey, vec_in)) {
        Close();
        return errorN(1, sError, __func__, "WriteV1 failed.");
    }

    if (0 != ReadV1(msg_type_out, vec_out)) {
        Close();
        return errorN(1, sError, __func__, "ReadV1 failed.");
    }

    if (hw::trezor::messages::MessageType_PublicKey != msg_type_out) {
        Close();
        return errorN(1, sError, __func__, "ReadV1 did not return PublicKey message, instead msg_type_out=%u.", msg_type_out);
    }

    Close();

    if (!msg_out.ParseFromArray(vec_out.data(), vec_out.size())) {
        return errorN(1, sError, __func__, "ParseFromArray failed.");
    }

    if (vPath.back() != msg_out.node().child_num() || lenPath != msg_out.node().depth()) {
        return errorN(1, sError, __func__, "Mismatched key returned.");
    }

    ekp.nDepth = msg_out.node().depth();
    uint32_t fingerprint = bswap_32(msg_out.node().fingerprint()); // bswap_32 still necessary when system is big endian?
    memcpy(ekp.vchFingerprint, ((uint8_t*)&fingerprint), 4);
    ekp.nChild = msg_out.node().child_num();
    assert(msg_out.node().chain_code().size() == 32);
    memcpy(ekp.chaincode, msg_out.node().chain_code().data(), 32);

    size_t lenPubkey = msg_out.node().public_key().size();
    ekp.pubkey.Set(&msg_out.node().public_key().c_str()[0], &msg_out.node().public_key().c_str()[lenPubkey]);

    if (lenPubkey == 65 && !ekp.pubkey.Compress()) {
        return errorN(1, sError, __func__, "Pubkey compression failed.");
    }

    return 0;
};

int CTrezorDevice::SignMessage(const std::vector<uint32_t>& vPath, const std::string& sMessage, std::vector<uint8_t>& vchSig, std::string& sError)
{
    if (vPath.size() < 1 || vPath.size() > 10) {
        return errorN(1, sError, __func__, _("Path depth out of range.").c_str());
    }

    hw::trezor::messages::bitcoin::SignMessage msg_in;
    hw::trezor::messages::bitcoin::MessageSignature msg_out;

    for (const auto i : vPath) {
        msg_in.add_address_n(i);
    }

    msg_in.set_coin_name("Bitcoin");
    msg_in.set_message(sMessage);

    std::vector<uint8_t> vec_in, vec_out;

    vec_in.resize(msg_in.ByteSize());

    if (!msg_in.SerializeToArray(vec_in.data(), vec_in.size())) {
        return errorN(1, sError, __func__, "SerializeToArray failed.");
    }

    int opened = OpenIfUnlocked(sError);
    if (0 !=  opened){
        return opened;
    }

    if (0 != WriteV1(hw::trezor::messages::MessageType_SignMessage, vec_in)) {
        Close();
        return errorN(1, sError, __func__, "WriteV1 failed.");
    }

    uint16_t msg_type_out = hw::trezor::messages::MessageType_ButtonRequest;
    if (0 != ReadV1(msg_type_out, vec_out)) {
        Close();
        return errorN(1, sError, __func__, "ReadV1 failed.");
    }

    hw::trezor::messages::common::ButtonAck msg_in1;
    vec_in.resize(msg_in1.ByteSize());

    if (0 != WriteV1(hw::trezor::messages::MessageType_ButtonAck, vec_in)) {
        Close();
        return errorN(1, sError, __func__, "WriteV1 failed.");
    }

    msg_type_out = hw::trezor::messages::MessageType_MessageSignature;
    if (0 != ReadV1(msg_type_out, vec_out)) {
        Close();
        return errorN(1, sError, __func__, "ReadV1 failed.");
    }

    Close();

    if (!msg_out.ParseFromArray(vec_out.data(), vec_out.size())) {
        return errorN(1, sError, __func__, "ParseFromArray failed.");
    }

    size_t lenSignature = msg_out.signature().size();
    vchSig.resize(lenSignature);

    memcpy(&vchSig[0], msg_out.signature().c_str(), lenSignature);

    return 0;
};

int CTrezorDevice::PrepareTransaction(CMutableTransaction& mtx, const CCoinsViewCache& view, const CKeyStore& keystore, int nHashType)
{
    int opened = OpenIfUnlocked(sError);
    if (0 !=  opened){
        return opened;
    }

    bool fHashSingle = ((nHashType & ~SIGHASH_ANYONECANPAY) == SIGHASH_SINGLE);

    m_preparing = true;
    for (unsigned int i = 0; i < mtx.vin.size(); i++) {
        CTxIn& txin = mtx.vin[i];
        const Coin& coin = view.AccessCoin(txin.prevout);
        if (coin.IsSpent() || coin.nType != OUTPUT_STANDARD) {
            continue;
        }

        std::vector<uint8_t> vchAmount(8);
        CScript prevPubKey = coin.out.scriptPubKey;
        CAmount amount = coin.out.nValue;
        memcpy(vchAmount.data(), &amount, 8);

        m_cache[i] = SignData(prevPubKey, nHashType, vchAmount);
        SignatureData sigdata = DataFromTransaction(mtx, i, vchAmount, prevPubKey);

        // Only sign SIGHASH_SINGLE if there's a corresponding output:
        if (!fHashSingle || (i < mtx.GetNumVOuts())) {
            ProduceSignature(keystore, DeviceSignatureCreator(this, &mtx, i, vchAmount, nHashType), prevPubKey, sigdata);
        }
    }

    m_preparing = false;

    return CompleteTransaction(&mtx);
};

int CTrezorDevice::SignTransaction(const std::vector<uint32_t>& vPath, const std::vector<uint8_t>& vSharedSecret, const CMutableTransaction* tx, int nIn, const CScript& scriptCode, int hashType, const std::vector<uint8_t>& amount, SigVersion sigversion, std::vector<uint8_t>& vchSig, std::string& sError)
{
    if (m_preparing) {
        m_cache[nIn] = SignData(vPath, vSharedSecret, scriptCode, hashType, amount, sigversion);
    } else {
        const auto& ci = m_cache.find(nIn);
        if (ci != m_cache.end()) {
            vchSig = ci->second.m_signature;
        }
    }

    return 0;
};

int CTrezorDevice::CompleteTransaction(CMutableTransaction* tx)
{
    hw::trezor::messages::bitcoin::SignTx msg_in;
    hw::trezor::messages::bitcoin::TxRequest req;
    uint16_t msg_type_out = 0;

    msg_in.set_outputs_count(tx->vpout.size());
    msg_in.set_inputs_count(tx->vin.size());
    msg_in.set_coin_name(GetCoinName());
    msg_in.set_version(tx->nVersion);
    msg_in.set_lock_time(tx->nLockTime);

    std::vector<uint8_t> vec_in, vec_out, serialised_tx;

    vec_in.resize(msg_in.ByteSize());

    if (!msg_in.SerializeToArray(vec_in.data(), vec_in.size())) {
        return errorN(1, sError, __func__, "SerializeToArray failed.");
    }

    if (0 != WriteV1(hw::trezor::messages::MessageType_SignTx, vec_in)) {
        return errorN(1, sError, __func__, "WriteV1 failed.");
    }

    for (;;) {
        if (0 != ReadV1(msg_type_out, vec_out)) {
            return errorN(1, sError, __func__, "ReadV1 failed.");
        }

        if (msg_type_out == hw::trezor::messages::MessageType_Failure) {
            hw::trezor::messages::common::Failure msg_fail;
            if (!msg_fail.ParseFromArray(vec_out.data(), vec_out.size())) {
                return errorN(1, sError, __func__, "ParseFromArray failed.");
            }
            return errorN(1, sError, __func__, "Dongle error %u %s.", msg_fail.code(), msg_fail.message());
        } else if (msg_type_out == hw::trezor::messages::MessageType_ButtonRequest) {
            hw::trezor::messages::common::ButtonAck msg;
            vec_in.resize(msg.ByteSize());
            if (!msg.SerializeToArray(vec_in.data(), vec_in.size())) {
                return errorN(1, sError, __func__, "SerializeToArray failed.");
            }
            if (0 != WriteV1(hw::trezor::messages::MessageType_ButtonAck, vec_in)) {
                return errorN(1, sError, __func__, "WriteV1 failed.");
            }
            continue;
        } else if (msg_type_out != hw::trezor::messages::MessageType_TxRequest) {
            return errorN(1, "%s: Unknown return type, msg_type_out=%u.", __func__, msg_type_out);
        }

        if (!req.ParseFromArray(vec_out.data(), vec_out.size())) {
            return errorN(1, sError, __func__, "ParseFromArray failed.");
        }

        if (req.has_serialized()) {
            const auto& msg_serialized = req.serialized();
            if (msg_serialized.has_serialized_tx()) {
                std::string s = msg_serialized.serialized_tx();
                serialised_tx.insert(serialised_tx.end(), s.begin(), s.end());
            }

            if (msg_serialized.has_signature()) {
                size_t i = msg_serialized.signature_index();

                std::string signature = msg_serialized.signature();

                const auto& ci = m_cache.find(i);
                if (ci == m_cache.end()) {
                    return errorN(1, sError, __func__, "No information for input %d.", i);
                }

                auto& cache_sig = ci->second.m_signature;
                cache_sig.resize(signature.size() + 1);
                memcpy(cache_sig.data(), signature.data(), signature.size());
                cache_sig[signature.size()] = ci->second.m_hashType;
            }
        }

        hw::trezor::messages::bitcoin::TxAck msg;
        if (req.request_type() == hw::trezor::messages::bitcoin::TxRequest::TXINPUT) {
            const auto msg_tx = msg.mutable_tx();
            uint32_t i = req.details().request_index();

            if (i >= tx->vin.size()) {
                return errorN(1, sError, __func__, "Requested input %d out of range.", i);
            }
            auto msg_input = msg_tx->add_inputs();

            const auto& ci = m_cache.find(i);
            if (ci == m_cache.end()) {
                return errorN(1, sError, __func__, "No information for input %d.", i);
            }
            const auto& txin = tx->vin[i];

            for (const auto i : ci->second.m_path) {
                msg_input->add_address_n(i);
            }

            if (ci->second.m_shared_secret.size() == 32) {
                const std::vector<uint8_t>& shared_secret = ci->second.m_shared_secret;
                std::string s(shared_secret.begin(), shared_secret.end());
                msg_input->set_particl_shared_secret(s);
            }

            std::string hash;
            hash.resize(32);
            for (size_t k = 0; k < 32; ++k) {
                hash[k] = *(txin.prevout.hash.begin() + (31 - k));
            }

            msg_input->set_prev_hash(hash);
            msg_input->set_prev_index(txin.prevout.n);

            msg_input->set_sequence(txin.nSequence);
            msg_input->set_script_type(hw::trezor::messages::bitcoin::SPENDWITNESS);
            if (ci->second.m_amount.size() != 8) {
                return errorN(1, sError, __func__, "Non-standard amount size for input %d.", i);
            }
            int64_t amount;
            memcpy(&amount, ci->second.m_amount.data(), 8);
            msg_input->set_amount(amount);
        } else if (req.request_type() == hw::trezor::messages::bitcoin::TxRequest::TXOUTPUT) {
            const auto msg_tx = msg.mutable_tx();
            uint32_t i = req.details().request_index();
            if (i >= tx->vpout.size()) {
                return errorN(1, sError, __func__, "Requested output %d out of range.", i);
            }
            auto msg_output = msg_tx->add_outputs();

            if (tx->vpout[i]->IsType(OUTPUT_STANDARD)) {
                CTxDestination address;
                const CScript* pscript = tx->vpout[i]->GetPScriptPubKey();
                if (!pscript) {
                    return errorN(1, sError, __func__, "GetPScriptPubKey failed.");
                }

                if (pscript->StartsWithICS()) {
                    CScript scriptA, scriptB;
                    if (!SplitConditionalCoinstakeScript(*pscript, scriptA, scriptB)) {
                        return errorN(1, sError, __func__, "Output %d, failed to split script.", i);
                    }
                    CTxDestination addrStake, addrSpend;
                    if (!ExtractDestination(scriptA, addrStake)) {
                        return errorN(1, sError, __func__, "ExtractDestination failed.");
                    }
                    if (!ExtractDestination(scriptB, addrSpend)) {
                        return errorN(1, sError, __func__, "ExtractDestination failed.");
                    }
                    if (addrStake.type() != typeid(PKHash) || addrSpend.type() != typeid(CKeyID256)) {
                        return errorN(1, sError, __func__, "Unsupported coldstake script types.");
                    }
                    PKHash idStake = boost::get<PKHash>(addrStake);
                    CKeyID256 idSpend = boost::get<CKeyID256>(addrSpend);

                    // Construct joined address, p2pkh prefix +2
                    std::vector<uint8_t> addr_raw(53);
                    addr_raw[0] = Params().Base58Prefix(CChainParams::PUBKEY_ADDRESS)[0] + 2;
                    memcpy(&addr_raw[1], idStake.begin(), 20);
                    memcpy(&addr_raw[21], idSpend.begin(), 32);
                    msg_output->set_address(EncodeBase58Check(addr_raw));
                } else {
                    if (!ExtractDestination(*pscript, address)) {
                        return errorN(1, sError, __func__, "ExtractDestination failed.");
                    }
                    msg_output->set_address(EncodeDestination(address));
                }

                msg_output->set_amount(tx->vpout[i]->GetValue());
                msg_output->set_script_type(hw::trezor::messages::bitcoin::TxAck::TransactionType::TxOutputType::PAYTOADDRESS);
            } else if (tx->vpout[i]->IsType(OUTPUT_DATA)) {
                CTxOutData* txd = (CTxOutData*)tx->vpout[i].get();
                std::string s(txd->vData.begin(), txd->vData.end());
                msg_output->set_op_return_data(s);
                msg_output->set_amount(0);
                msg_output->set_script_type(hw::trezor::messages::bitcoin::TxAck::TransactionType::TxOutputType::PAYTOPARTICLDATA);
            } else {
                return errorN(1, sError, __func__, "Unknown type of output %d.", i);
            }
        } else if (req.request_type() == hw::trezor::messages::bitcoin::TxRequest::TXFINISHED) {
            if (LogAcceptCategory(BCLog::HDWALLET)) {
                LogPrintf("%s: Debug, serialised_tx %s.\n", __func__, HexStr(serialised_tx));
            }
            break;
        } else {
            LogPrintf("%s: Unknown request_type.\n", __func__);
            break;
        }

        vec_in.resize(msg.ByteSize());
        if (!msg.SerializeToArray(vec_in.data(), vec_in.size())) {
            return errorN(1, sError, __func__, "SerializeToArray failed.");
        }

        if (0 != WriteV1(hw::trezor::messages::MessageType_TxAck, vec_in)) {
            return errorN(1, sError, __func__, "WriteV1 failed.");
        }
    }

    return 0;
};

std::string CTrezorDevice::GetCoinName()
{
    return Params().NetworkIDString() == "main" ? "Particl" : "Particl Testnet";
};

int CTrezorDevice::LoadMnemonic(uint32_t wordcount, bool pinprotection, std::string& sError)
{
    hw::trezor::messages::management::RecoveryDevice msg_in;
    uint16_t msg_type_out = 0;

    msg_in.set_type(hw::trezor::messages::management::RecoveryDevice_RecoveryDeviceType_RecoveryDeviceType_Matrix);
    msg_in.set_word_count(wordcount);
    msg_in.set_pin_protection(pinprotection);

    std::vector<uint8_t> vec_in, vec_out;

    vec_in.resize(msg_in.ByteSize());

    if (!msg_in.SerializeToArray(vec_in.data(), vec_in.size())) {
        return errorN(1, sError, __func__, "SerializeToArray failed.");
    }

    int opened = OpenIfUnlocked(sError);
    if (0 !=  opened){
        return opened;
    }

    if (0 != WriteV1(hw::trezor::messages::MessageType_RecoveryDevice, vec_in)) {
        Close();
        return errorN(1, sError, __func__, "WriteV1 failed.");
    }


    for (;;) {
        if (0 != ReadV1(msg_type_out, vec_out)) {
            Close();
            return errorN(1, sError, __func__, "ReadV1 failed.");
        }

        if (msg_type_out == hw::trezor::messages::MessageType_Failure) {
            hw::trezor::messages::common::Failure msg_fail;
            if (!msg_fail.ParseFromArray(vec_out.data(), vec_out.size())) {
                Close();
                return errorN(1, sError, __func__, "ParseFromArray failed.");
            }
            Close();
            return errorN(1, sError, __func__, "Dongle error %s.", msg_fail.message());
        }

        if (msg_type_out == hw::trezor::messages::MessageType_ButtonRequest) {
            hw::trezor::messages::common::ButtonAck msg;
            vec_in.resize(msg.ByteSize());
            if (!msg.SerializeToArray(vec_in.data(), vec_in.size())) {
                Close();
                return errorN(1, sError, __func__, "SerializeToArray failed.");
            }
            if (0 != WriteV1(hw::trezor::messages::MessageType_ButtonAck, vec_in)) {
                Close();
                return errorN(1, sError, __func__, "WriteV1 failed.");
            }
        }
        if (msg_type_out == hw::trezor::messages::MessageType_Success) {
            break;
        }
    }
    Close();

    return 0;
};

int CTrezorDevice::Backup(std::string& sError)
{
    hw::trezor::messages::management::BackupDevice msg_in;
    uint16_t msg_type_out = 0;

    std::vector<uint8_t> vec_in, vec_out;

    vec_in.resize(msg_in.ByteSize());

    if (!msg_in.SerializeToArray(vec_in.data(), vec_in.size())) {
        return errorN(1, sError, __func__, "SerializeToArray failed.");
    }

    int opened = OpenIfUnlocked(sError);
    if (0 !=  opened){
        return opened;
    }

    if (0 != WriteV1(hw::trezor::messages::MessageType_BackupDevice, vec_in)) {
        Close();
        return errorN(1, sError, __func__, "WriteV1 failed.");
    }

    for (;;) {
        if (0 != ReadV1(msg_type_out, vec_out)) {
            Close();
            return errorN(1, sError, __func__, "ReadV1 failed.");
        }

        if (msg_type_out == hw::trezor::messages::MessageType_Failure) {
            hw::trezor::messages::common::Failure msg_fail;
            if (!msg_fail.ParseFromArray(vec_out.data(), vec_out.size())) {
                Close();
                return errorN(1, sError, __func__, "ParseFromArray failed.");
            }
            Close();
            return errorN(1, sError, __func__, "Dongle error %s.", msg_fail.message());
        }

        if (msg_type_out == hw::trezor::messages::MessageType_ButtonRequest) {
            hw::trezor::messages::common::ButtonAck msg;
            vec_in.resize(msg.ByteSize());
            if (!msg.SerializeToArray(vec_in.data(), vec_in.size())) {
                Close();
                return errorN(1, sError, __func__, "SerializeToArray failed.");
            }
            if (0 != WriteV1(hw::trezor::messages::MessageType_ButtonAck, vec_in)) {
                Close();
                return errorN(1, sError, __func__, "WriteV1 failed.");
            }
        }
        if (msg_type_out == hw::trezor::messages::MessageType_Success) {
            break;
        }
    }
    Close();

    return 0;
};

int CTrezorDevice::PromptUnlock(std::string& sError)
{
    LogPrintf("%s: started\n", std::string(__func__));
    hw::trezor::messages::management::Ping msg_in;
    std::vector<uint8_t> vec_in;
    msg_in.set_passphrase_protection(true);
    msg_in.set_pin_protection(true);

    uint16_t msg_type_out = 0;
    std::vector<uint8_t> vec_out;

    if (0 != Open()) {
        return errorN(1, sError, __func__, "Failed to open device.");
    }

    vec_in.resize(msg_in.ByteSize());
    if (!msg_in.SerializeToArray(vec_in.data(), vec_in.size())) {
        Close();
        return errorN(1, sError, __func__, "SerializeToArray failed.");
    }

    if (0 != WriteV1(hw::trezor::messages::MessageType_Ping, vec_in)) {
        Close();
        return errorN(1, sError, __func__, "WriteV1 failed.");
    }

    if (0 != ReadV1(msg_type_out, vec_out)) {
        Close();
        return errorN(1, sError, __func__, "ReadV1 failed.");
    }

    Close();

    if (msg_type_out == hw::trezor::messages::MessageType_PinMatrixRequest
        || msg_type_out == hw::trezor::messages::MessageType_PassphraseRequest
        || msg_type_out == hw::trezor::messages::MessageType_Success) {
            return 0;
    } else {
        return errorN(1, sError, __func__, "Unexpected response from prompting unlock.");
    }

}

int CTrezorDevice::Unlock(std::string pin, std::string passphraseword, std::string &sError)
{
    int unlocked = 1;
    if(pin.size() > 0) {
        hw::trezor::messages::common::PinMatrixAck msg_in;
        msg_in.set_pin(pin);

        std::vector<uint8_t> vec_pin;
        vec_pin.resize(msg_in.ByteSize());

        if (!msg_in.SerializeToArray(vec_pin.data(), vec_pin.size())) {
            return errorN(1, sError, __func__, "SerializeToArray failed.");
        }

        unlocked = GenericUnlock(&vec_pin, hw::trezor::messages::MessageType_PinMatrixAck);
        if (0 < unlocked) {
            return errorN(1, sError, __func__, "Failed to send unlock PIN to device.");
        }
    }

    if (passphraseword.size() > 0) {
        hw::trezor::messages::common::PassphraseAck msg_in;
        msg_in.set_passphrase(passphraseword);

        std::vector<uint8_t> vec_pass;
        vec_pass.resize(msg_in.ByteSize());

        if (!msg_in.SerializeToArray(vec_pass.data(), vec_pass.size())) {
            return errorN(1, sError, __func__, "SerializeToArray failed.");
        }

        unlocked = GenericUnlock(&vec_pass, hw::trezor::messages::MessageType_PassphraseAck);
        if (0 != unlocked) {
            return errorN(1, sError, __func__, "Failed to send unlock passphrase to device.");
        }
    } else if (unlocked == -1) {
        return errorN(1, sError, __func__, "Device needs passphrase to unlock.");
    }

    return 0;
};

int CTrezorDevice::GenericUnlock(std::vector<uint8_t>* vec_in, uint16_t msg_type_in) {
    uint16_t msg_type_out = 0;
    std::vector<uint8_t> vec_out;

    if (0 != Open()) {
        return errorN(1, sError, __func__, "Failed to open device.");
    }

    if (0 != WriteV1(msg_type_in, *vec_in)) {
        Close();
        return errorN(1, sError, __func__, "WriteV1 failed.");
    }

    if (0 != ReadV1(msg_type_out, vec_out)) {
        Close();
        return errorN(1, sError, __func__, "ReadV1 failed.");
    }

    Close();

    LogPrintf("%s: received msg type out = %d\n", std::string(__func__), msg_type_out);

    if (msg_type_out == hw::trezor::messages::MessageType_PassphraseRequest){
        return -1;
    }

    if (msg_type_out == hw::trezor::messages::MessageType_Failure){
        return errorN(1, sError, __func__, "Unlocking returned failure.");
    }

    return 0;
};

} // namespace usb_device
