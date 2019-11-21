// Copyright (c) 2018-2019 The Particl Core developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef PARTICL_USBDEVICE_DEBUGDEVICE_H
#define PARTICL_USBDEVICE_DEBUGDEVICE_H

#include <usbdevice/usbdevice.h>
#include <key/extkey.h>

#include <memory>

namespace usb_device {

class CDebugDevice : public CUSBDevice
{
public:
    CDebugDevice();

    int GetFirmwareVersion(std::string &sFirmware, std::string &sError) override;
    int GetInfo(UniValue &info, std::string &sError) override;

    int GetPubKey(const std::vector<uint32_t> &vPath, CPubKey &pk, std::string &sError) override;
    int GetXPub(const std::vector<uint32_t> &vPath, CExtPubKey &ekp, std::string &sError) override;

    int SignMessage(const std::vector<uint32_t> &vPath, const std::string &sMessage, std::vector<uint8_t> &vchSig, std::string &sError) override;

    int SignTransaction(const std::vector<uint32_t> &vPath, const std::vector<uint8_t> &vSharedSecret, const CMutableTransaction *tx,
        int nIn, const CScript &scriptCode, int hashType, const std::vector<uint8_t> &amount, SigVersion sigversion,
        std::vector<uint8_t> &vchSig, std::string &sError) override;

    CExtKey ekv;
};

} // usb_device

#endif // PARTICL_USBDEVICE_DEBUGDEVICE_H
