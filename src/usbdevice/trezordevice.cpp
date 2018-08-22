// Copyright (c) 2018 The Particl Core developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <usbdevice/trezordevice.h>

#include <hidapi/hidapi.h>
#include <stdio.h>
#include <inttypes.h>
#include <util.h>
#include <pubkey.h>
#include <crypto/common.h>
#include <utilstrencodings.h>
#include <univalue.h>
#include <chainparams.h>
#include <validation.h>

#ifdef ENABLE_WALLET
#include <wallet/hdwallet.h>
#endif

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#include <usbdevice/trezor/messages.pb.h>
#include <usbdevice/trezor/messages-management.pb.h>
#include <usbdevice/trezor/messages-bitcoin.pb.h>
#pragma GCC diagnostic pop

namespace usb_device {

int CTrezorDevice::Open()
{
    if (!pType) {
        return 1;
    }

    if (hid_init()) {
        return 1;
    }

    if (!(handle = hid_open_path(cPath))) {
        hid_exit();
        return 1;
    }

    return 0;
};

int CTrezorDevice::Close()
{
    if (handle) {
        hid_close(handle);
    }
    handle = nullptr;

    hid_exit();
    return 0;
};

static int WriteV1(hid_device *handle, uint16_t msg_type, std::vector<uint8_t> &vec)
{
    static const size_t BUFFER_LEN = 64;
    uint8_t buffer[BUFFER_LEN];
    size_t msg_len = vec.size();
    size_t wrote = 0;

    do {
        size_t i = 0;
#ifdef WIN32
        buffer[i++] = 0; // Report ID
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
        int result = hid_write(handle, buffer, BUFFER_LEN);
        if (result < 0) {
            return result;
        }
        wrote += put;
    } while (wrote < msg_len);

    return 0;
};

static int ReadV1(hid_device *handle, uint16_t &msg_type, std::vector<uint8_t> &vec)
{
    static const size_t BUFFER_LEN = 64;
    uint8_t buffer[BUFFER_LEN];

    size_t result = hid_read_timeout(handle, buffer, BUFFER_LEN, 60000);
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
        int result = hid_read_timeout(handle, buffer, BUFFER_LEN, 60000);
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

int CTrezorDevice::GetFirmwareVersion(std::string &sFirmware, std::string &sError)
{
    GetFeatures msg_in;
    Features msg_out;

    std::vector<uint8_t> vec_in, vec_out;

    vec_in.resize(msg_in.ByteSize());

    if (!msg_in.SerializeToArray(vec_in.data(), vec_in.size())) {
        return errorN(1, sError, __func__, "SerializeToArray failed.");
    }

    if (0 != Open()) {
        return errorN(1, sError, __func__, "Failed to open device.");
    }

    if (0 != WriteV1(handle, MessageType_GetFeatures, vec_in)) {
        Close();
        return errorN(1, sError, __func__, "WriteV1 failed.");
    }

    uint16_t msg_type_out = 0;
    if (0 != ReadV1(handle, msg_type_out, vec_out)) {
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

int CTrezorDevice::GetPubKey(const std::vector<uint32_t> &vPath, CPubKey &pk, std::string &sError)
{
    message::GetPublicKey msg_in;
    message::PublicKey msg_out;

    std::vector<uint8_t> vec_in, vec_out;

    vec_in.resize(msg_in.ByteSize());

    if (!msg_in.SerializeToArray(vec_in.data(), vec_in.size())) {
        return errorN(1, sError, __func__, "SerializeToArray failed.");
    }

    if (0 != Open()) {
        return errorN(1, sError, __func__, "Failed to open device.");
    }

    if (0 != WriteV1(handle, MessageType_GetPublicKey, vec_in)) {
        Close();
        return errorN(1, sError, __func__, "WriteV1 failed.");
    }

    uint16_t msg_type_out = MessageType_PublicKey;
    if (0 != ReadV1(handle, msg_type_out, vec_out)) {
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

int CTrezorDevice::GetXPub(const std::vector<uint32_t> &vPath, CExtPubKey &ekp, std::string &sError)
{
    if (vPath.size() < 1 || vPath.size() > 10) {
        return errorN(1, sError, __func__, _("Path depth out of range.").c_str());
    }
    size_t lenPath = vPath.size();

    message::GetPublicKey msg_in;
    message::PublicKey msg_out;

    std::vector<uint8_t> vec_in, vec_out;

    vec_in.resize(msg_in.ByteSize());

    if (!msg_in.SerializeToArray(vec_in.data(), vec_in.size())) {
        return errorN(1, sError, __func__, "SerializeToArray failed.");
    }

    if (0 != Open()) {
        return errorN(1, sError, __func__, "Failed to open device.");
    }

    if (0 != WriteV1(handle, MessageType_GetPublicKey, vec_in)) {
        Close();
        return errorN(1, sError, __func__, "WriteV1 failed.");
    }

    uint16_t msg_type_out = MessageType_PublicKey;
    if (0 != ReadV1(handle, msg_type_out, vec_out)) {
        Close();
        return errorN(1, sError, __func__, "ReadV1 failed.");
    }

    Close();

    if (!msg_out.ParseFromArray(vec_out.data(), vec_out.size())) {
        return errorN(1, sError, __func__, "ParseFromArray failed.");
    }

    ekp.nDepth = lenPath;
    ekp.nChild = vPath.back();

    size_t lenPubkey = msg_out.node().public_key().size();
    ekp.pubkey.Set(&msg_out.node().public_key().c_str()[0], &msg_out.node().public_key().c_str()[lenPubkey]);

    if (lenPubkey == 65 && !ekp.pubkey.Compress()) {
        return errorN(1, sError, __func__, "Pubkey compression failed.");
    }
    //version[4] | depth[1] | parent_fingerprint[4] | index[4] | chain_code[32] | serialized_key[65]
    memcpy(ekp.vchFingerprint, &msg_out.xpub().c_str()[5], 4);
    memcpy(ekp.chaincode, &msg_out.xpub().c_str()[13], 32);

    return 0;
};

int CTrezorDevice::SignMessage(const std::vector<uint32_t> &vPath, const std::string &sMessage, std::vector<uint8_t> &vchSig, std::string &sError)
{
    if (vPath.size() < 1 || vPath.size() > 10) {
        return errorN(1, sError, __func__, _("Path depth out of range.").c_str());
    }

    message::SignMessage msg_in;
    message::MessageSignature msg_out;

    msg_in.set_coin_name("Bitcoin");
    msg_in.set_message(sMessage);

    std::vector<uint8_t> vec_in, vec_out;

    vec_in.resize(msg_in.ByteSize());

    if (!msg_in.SerializeToArray(vec_in.data(), vec_in.size())) {
        return errorN(1, sError, __func__, "SerializeToArray failed.");
    }

    if (0 != Open()) {
        return errorN(1, sError, __func__, "Failed to open device.");
    }

    if (0 != WriteV1(handle, MessageType_SignMessage, vec_in)) {
        Close();
        return errorN(1, sError, __func__, "WriteV1 failed.");
    }

    uint16_t msg_type_out = MessageType_ButtonRequest;
    if (0 != ReadV1(handle, msg_type_out, vec_out)) {
        Close();
        return errorN(1, sError, __func__, "ReadV1 failed.");
    }

    ButtonAck msg_in1;
    vec_in.resize(msg_in1.ByteSize());

    if (0 != WriteV1(handle, MessageType_ButtonAck, vec_in)) {
        Close();
        return errorN(1, sError, __func__, "WriteV1 failed.");
    }

    msg_type_out = MessageType_MessageSignature;
    if (0 != ReadV1(handle, msg_type_out, vec_out)) {
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

message::TxAck resp;
message::TxAck_TransactionType txn;

int CTrezorDevice::PrepareTransaction(const CMutableTransaction *tx, const CCoinsViewCache &view)
{
    if (!handle) {
        return errorN(1, sError, __func__, "Device not open.");
    }

    message::SignTx msg_in;

    msg_in.set_coin_name("Bitcoin");
    msg_in.set_inputs_count(tx->vin.size());
    msg_in.set_outputs_count(tx->vout.size());

    std::vector<uint8_t> vec_in, vec_out;

    vec_in.resize(msg_in.ByteSize());

    if (!msg_in.SerializeToArray(vec_in.data(), vec_in.size())) {
        return errorN(1, sError, __func__, "SerializeToArray failed.");
    }

    if (0 != WriteV1(handle, MessageType_SignTx, vec_in)) {
        Close();
        return errorN(1, sError, __func__, "WriteV1 failed.");
    }

    uint16_t msg_type_out = MessageType_TxRequest;

	for (size_t i = 0; i < tx->vin.size(); ++i) {
		if (0 != ReadV1(handle, msg_type_out, vec_out)) {
			Close();
			return errorN(1, sError, __func__, "ReadV1 failed.");
		}

		const auto &txin = tx->vin[i];
		const Coin &coin = view.AccessCoin(txin.prevout);

        if (coin.IsSpent()) {
            return errorN(1, sError, __func__, _("Input %d not found or already spent").c_str(), i);
        }

        const CScript &scriptCode = coin.out.scriptPubKey;

		message::TxAck_TransactionType_TxInputType *input = txn.add_inputs();

		input->set_prev_hash(txin.prevout.hash.begin(), 32);
		input->set_prev_index(txin.prevout.n);
		input->set_amount(coin.out.nValue);
		input->set_sequence(txin.nSequence);
		//scriptCode

		resp.set_allocated_tx(&txn);

		vec_in.clear();
		vec_in.resize(resp.ByteSize());

		if (!resp.SerializeToArray(vec_in.data(), vec_in.size())) {
			return errorN(1, sError, __func__, "SerializeToArray failed.");
		}

	    if (0 != WriteV1(handle, MessageType_TxAck, vec_in)) {
	        Close();
	        return errorN(1, sError, __func__, "WriteV1 failed.");
	    }
	}
	//vin_meta
	//vout
	//sign

    return 0;
};

int CTrezorDevice::SignTransaction(const std::vector<uint32_t> &vPath, const std::vector<uint8_t> &vSharedSecret, const CMutableTransaction *tx,
    int nIn, const CScript &scriptCode, int hashType, const std::vector<uint8_t>& amount, SigVersion sigversion,
    std::vector<uint8_t> &vchSig, std::string &sError)
{
	return 0;
};

} // usb_device
