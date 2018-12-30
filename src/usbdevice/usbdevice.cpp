// Copyright (c) 2018 The Particl Core developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <usbdevice/usbdevice.h>

#include <usbdevice/debugdevice.h>
#include <usbdevice/ledgerdevice.h>
#include <usbdevice/trezordevice.h>
#include <usbdevice/usbwrapper.h>

#include <hidapi/hidapi.h>

#include <stdio.h>
#include <inttypes.h>
#include <univalue.h>
#include <chainparams.h>

#ifdef ENABLE_WALLET
#include <wallet/hdwallet.h>
#endif

#include <google/protobuf/stubs/common.h>

namespace usb_device {

const DeviceType usbDeviceTypes[] = {
    DeviceType(0xffff, 0x0001, "Debug", "Device", USBDEVICE_DEBUG),
    DeviceType(0x2c97, 0x0001, "Ledger", "Nano S", USBDEVICE_LEDGER_NANO_S),
    //DeviceType(0x534c, 0x0001, "Trezor", "One", USBDEVICE_TREZOR_ONE),
};

const DeviceType webusbDeviceTypes[] = {
    DeviceType(0x1209, 0x53c1, "Trezor", "One", USBDEVICE_TREZOR_ONE),
};

void ShutdownHardwareIntegration()
{
    // Safe to call ShutdownProtobufLibrary multiple times
    google::protobuf::ShutdownProtobufLibrary();
}

int CUSBDevice::GetFirmwareVersion(std::string &sFirmware, std::string &sError)
{
    sFirmware = "no_device";
    return 0;
};

int CUSBDevice::GetInfo(UniValue &info, std::string &sError)
{
    info.pushKV("error", "no_device");
    return 0;
};

static bool MatchLedgerInterface(struct hid_device_info *cur_dev)
{
#ifdef MAC_OSX
    return cur_dev->usage_page == 0xffa0;
#endif
#ifdef WIN32
    return cur_dev->usage_page == 0xffa0;
#endif
    return cur_dev->interface_number == 0;
}

static bool MatchTrezorInterface(struct hid_device_info *cur_dev)
{
#ifdef MAC_OSX
    return cur_dev->usage_page == 0xff00;
#endif
#ifdef WIN32
    return cur_dev->usage_page == 0xff00;
#endif
    return cur_dev->interface_number == 0;
}

void ListHIDDevices(std::vector<std::unique_ptr<CUSBDevice> > &vDevices)
{
    if (Params().NetworkIDString() == "regtest") {
        vDevices.push_back(std::unique_ptr<CUSBDevice>(new CDebugDevice()));
        return;
    }

    struct hid_device_info *devs, *cur_dev;

    if (hid_init()) {
        return;
    }

    devs = hid_enumerate(0x0, 0x0);
    cur_dev = devs;
    while (cur_dev) {
        for (const auto &type : usbDeviceTypes) {
            if (cur_dev->vendor_id != type.nVendorId
                || cur_dev->product_id != type.nProductId) {
                continue;
            }

            if (type.type == USBDEVICE_LEDGER_NANO_S
                && MatchLedgerInterface(cur_dev)) {
                char mbs[128];
                wcstombs(mbs, cur_dev->serial_number, sizeof(mbs));
                std::unique_ptr<CUSBDevice> device(new CLedgerDevice(&type, cur_dev->path, mbs, cur_dev->interface_number));
                vDevices.push_back(std::move(device));
            } else
            if (type.type == USBDEVICE_TREZOR_ONE
                && MatchTrezorInterface(cur_dev)) {
                char mbs[128];
                wcstombs(mbs, cur_dev->serial_number, sizeof(mbs));
                std::unique_ptr<CUSBDevice> device(new CTrezorDevice(&type, cur_dev->path, mbs, cur_dev->interface_number));
                vDevices.push_back(std::move(device));
            }
        }
        cur_dev = cur_dev->next;
    }
    hid_free_enumeration(devs);

    hid_exit();

    return;
};

void ListWebUSBDevices(std::vector<std::unique_ptr<CUSBDevice> > &vDevices)
{
    struct webusb_device_info *devs, *cur_dev;
    if (webusb_init()) {
        return;
    }

    devs = webusb_enumerate(0x0, 0x0);
    cur_dev = devs;
    while (cur_dev) {
        for (const auto &type : webusbDeviceTypes) {
            if (cur_dev->vendor_id != type.nVendorId
                || cur_dev->product_id != type.nProductId) {
                continue;
            }

            if (type.type == USBDEVICE_TREZOR_ONE
                && cur_dev->interface_number == 0) {
                char mbs[128];
                wcstombs(mbs, cur_dev->serial_number, sizeof(mbs));
                std::unique_ptr<CUSBDevice> device(new CTrezorDevice(&type, cur_dev->path, mbs, cur_dev->interface_number));
                vDevices.push_back(std::move(device));
            }
        }
        cur_dev = cur_dev->next;
    }
    webusb_free_enumeration(devs);

    webusb_exit();

    return;
};

void ListAllDevices(std::vector<std::unique_ptr<CUSBDevice> > &vDevices)
{
    if (Params().NetworkIDString() == "regtest") {
        vDevices.push_back(std::unique_ptr<CUSBDevice>(new CDebugDevice()));
        return;
    }

    ListHIDDevices(vDevices);
    ListWebUSBDevices(vDevices);

    return;
};

CUSBDevice *SelectDevice(std::vector<std::unique_ptr<CUSBDevice> > &vDevices, std::string &sError)
{
    if (Params().NetworkIDString() == "regtest") {
        vDevices.push_back(std::unique_ptr<CUSBDevice>(new CDebugDevice()));
        return vDevices[0].get();
    }

    ListAllDevices(vDevices);
    if (vDevices.size() < 1) {
        sError = "No device found.";
        return nullptr;
    }
    if (vDevices.size() > 1) { // TODO: Select device
        sError = "Multiple devices found.";
        return nullptr;
    }

    return vDevices[0].get();
};

DeviceSignatureCreator::DeviceSignatureCreator(CUSBDevice *pDeviceIn, const CMutableTransaction *txToIn,
    unsigned int nInIn, const std::vector<uint8_t> &amountIn, int nHashTypeIn)
    : BaseSignatureCreator(), txTo(txToIn), nIn(nInIn), nHashType(nHashTypeIn), amount(amountIn), checker(txTo, nIn, amountIn), pDevice(pDeviceIn)
{
};

bool DeviceSignatureCreator::CreateSig(const SigningProvider &provider, std::vector<unsigned char> &vchSig, const CKeyID &keyid, const CScript &scriptCode, SigVersion sigversion) const
{
    if (!pDevice) {
        return false;
    }

    //uint256 hash = SignatureHash(scriptCode, *txTo, nIn, nHashType, amount, sigversion);
    const CHDWallet *pw = dynamic_cast<const CHDWallet*>(&provider);
    if (pw) {
        const CEKAKey *pak = nullptr;
        const CEKASCKey *pasc = nullptr;
        CExtKeyAccount *pa = nullptr;
        if (!pw->HaveKey(keyid, pak, pasc, pa) || !pa) {
            return false;
        }

        std::vector<uint32_t> vPath;
        std::vector<uint8_t> vSharedSecret;
        if (pak) {
            if (!pw->GetFullChainPath(pa, pak->nParent, vPath)) {
                return error("%s: GetFullAccountPath failed.", __func__);
            }

            vPath.push_back(pak->nKey);
        } else
        if (pasc) {
            AccStealthKeyMap::const_iterator miSk = pa->mapStealthKeys.find(pasc->idStealthKey);
            if (miSk == pa->mapStealthKeys.end()) {
                return error("%s: CEKASCKey Stealth key not found.", __func__);
            }
            if (!pw->GetFullChainPath(pa, miSk->second.akSpend.nParent, vPath)) {
                return error("%s: GetFullAccountPath failed.", __func__);
            }

            vPath.push_back(miSk->second.akSpend.nKey);
            vSharedSecret.resize(32);
            memcpy(vSharedSecret.data(), pasc->sShared.begin(), 32);
        } else {
            return error("%s: HaveKey error.", __func__);
        }
        if (0 != pDevice->SignTransaction(vPath, vSharedSecret, txTo, nIn, scriptCode, nHashType, amount, sigversion, vchSig, pDevice->sError)) {
            return error("%s: SignTransaction failed.", __func__);
        }
        return true;
    }

    const CPathKeyStore *pks = dynamic_cast<const CPathKeyStore*>(&provider);
    if (pks) {
        CPathKey pathkey;
        if (!pks->GetKey(keyid, pathkey)) {
            return false;
        }

        std::vector<uint8_t> vSharedSecret;
        if (0 != pDevice->SignTransaction(pathkey.vPath, vSharedSecret, txTo, nIn, scriptCode, nHashType, amount, sigversion, vchSig, pDevice->sError)) {
            return error("%s: SignTransaction failed.", __func__);
        }
        return true;
    }

    return false;
};

} // usb_device
