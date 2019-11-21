// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2018 The Bitcoin Core developers
// Copyright (c) 2017-2019 The Particl Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_SCRIPT_ISMINE_H
#define BITCOIN_SCRIPT_ISMINE_H

/** IsMine() return codes */
enum isminetype : uint8_t
{
    ISMINE_NO               = 0,
    ISMINE_WATCH_ONLY_      = 1 << 0,
    ISMINE_SPENDABLE        = 1 << 1,
    ISMINE_USED             = 1 << 2,
    ISMINE_HARDWARE_DEVICE  = 1 << 6, // Private key is on external device
    ISMINE_WATCH_COLDSTAKE  = 1 << 7,
    ISMINE_WATCH_ONLY       = ISMINE_WATCH_ONLY_ | ISMINE_WATCH_COLDSTAKE,
    ISMINE_ALL              = ISMINE_WATCH_ONLY | ISMINE_SPENDABLE,
    ISMINE_ALL_USED         = ISMINE_ALL | ISMINE_USED,
    ISMINE_ENUM_ELEMENTS,
};


#endif // BITCOIN_SCRIPT_ISMINE_H
