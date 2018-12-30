// Copyright (c) 2018 The Particl Core developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef PARTICL_USBDEVICE_TREZORDEVICE_H
#define PARTICL_USBDEVICE_TREZORDEVICE_H

#include <usbdevice/usbdevice.h>


namespace usb_device {

typedef struct webusb_device webusb_device;

class CTrezorDevice : public CUSBDevice
{
private:
    class SignData
    {
    public:
        SignData() {};
        SignData(const CScript &scriptCode, int hashType, const std::vector<uint8_t> &amount)
            : m_scriptCode(scriptCode), m_hashType(hashType), m_amount(amount) {};
        SignData(const std::vector<uint32_t> &path, const std::vector<uint8_t> &shared_secret,
                 const CScript &scriptCode, int hashType, const std::vector<uint8_t> &amount, SigVersion sigversion)
            : m_path(path), m_shared_secret(shared_secret),
              m_scriptCode(scriptCode), m_hashType(hashType), m_amount(amount), m_sigversion(sigversion) {};
        std::vector<uint32_t> m_path;
        std::vector<uint8_t> m_shared_secret;
        CScript m_scriptCode;
        int m_hashType = 0;
        std::vector<uint8_t> m_amount;
        SigVersion m_sigversion = SigVersion::BASE;
        std::vector<uint8_t> m_signature;
    };

    std::string GetCoinName();
public:
    CTrezorDevice(const DeviceType *pType_, const char *cPath_, const char *cSerialNo_, int nInterface_)
        : CUSBDevice(pType_, cPath_, cSerialNo_, nInterface_) {};

    int Open() override;
    int Close() override;

    int GetFirmwareVersion(std::string &sFirmware, std::string &sError) override;
    int GetInfo(UniValue &info, std::string &sError) override;

    int GetPubKey(const std::vector<uint32_t> &vPath, CPubKey &pk, std::string &sError) override;
    int GetXPub(const std::vector<uint32_t> &vPath, CExtPubKey &ekp, std::string &sError) override;

    int SignMessage(const std::vector<uint32_t> &vPath, const std::string &sMessage, std::vector<uint8_t> &vchSig, std::string &sError) override;

    int PrepareTransaction(CMutableTransaction &tx, const CCoinsViewCache &view, const CKeyStore &keystore, int nHashType) override;

    int SignTransaction(const std::vector<uint32_t> &vPath, const std::vector<uint8_t> &vSharedSecret, const CMutableTransaction *tx,
        int nIn, const CScript &scriptCode, int hashType, const std::vector<uint8_t> &amount, SigVersion sigversion,
        std::vector<uint8_t> &vchSig, std::string &sError) override;

    int CompleteTransaction(CMutableTransaction *tx);

    int LoadMnemonic(uint32_t wordcount, bool pinprotection, std::string &sError) override;
    int Backup(std::string &sError) override;

    int OpenAsUnlocked() override;
    int CloseAndReadWhenUnlocked(uint16_t msg_type_out_awaited, uint16_t &msg_type_out, std::vector<uint8_t> &vec_out) override;
    int Unlock(std::string pin, std::string passphraseword, std::string &sError) override;
    int GenericUnlock(std::vector<uint8_t>* msg_in, uint16_t msg_type_in) override;

    bool m_preparing = false;
    std::map<int, SignData> m_cache;

protected:
    webusb_device *handle = nullptr;
};

} // usb_device

#endif // PARTICL_USBDEVICE_TREZORDEVICE_H
