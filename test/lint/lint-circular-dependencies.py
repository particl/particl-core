#!/usr/bin/env python3
#
# Copyright (c) 2020-2022 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
#
# Check for circular dependencies

import glob
import os
import re
import subprocess
import sys

EXPECTED_CIRCULAR_DEPENDENCIES = (
    "chainparamsbase -> util/system -> chainparamsbase",
    "node/blockstorage -> validation -> node/blockstorage",
    "index/coinstatsindex -> node/coinstats -> index/coinstatsindex",
    "policy/fees -> txmempool -> policy/fees",
    "qt/addresstablemodel -> qt/walletmodel -> qt/addresstablemodel",
    "qt/recentrequeststablemodel -> qt/walletmodel -> qt/recentrequeststablemodel",
    "qt/sendcoinsdialog -> qt/walletmodel -> qt/sendcoinsdialog",
    "qt/transactiontablemodel -> qt/walletmodel -> qt/transactiontablemodel",
    "wallet/fees -> wallet/wallet -> wallet/fees",
    "wallet/wallet -> wallet/walletdb -> wallet/wallet",
    "node/coinstats -> validation -> node/coinstats",
    # Particl
    "anon -> txmempool -> anon",
    "anon -> validation -> anon",
    "consensus/tx_verify -> validation -> consensus/tx_verify",
    "insight/insight -> txdb -> insight/insight",
    "insight/insight -> txmempool -> insight/insight",
    "insight/insight -> validation -> insight/insight",
    "key/extkey -> key_io -> key/extkey",
    "key/stealth -> key_io -> key/stealth",
    "pos/kernel -> validation -> pos/kernel",
    "pos/miner -> wallet/hdwallet -> pos/miner",
    "smsg/db -> smsg/smessage -> smsg/db",
    "smsg/smessage -> validation -> smsg/smessage",
    "txdb -> validation -> txdb",
    "usbdevice/debugdevice -> usbdevice/usbdevice -> usbdevice/debugdevice",
    "usbdevice/ledgerdevice -> usbdevice/usbdevice -> usbdevice/ledgerdevice",
    "usbdevice/trezordevice -> usbdevice/usbdevice -> usbdevice/trezordevice",
    "usbdevice/usbdevice -> wallet/hdwallet -> usbdevice/usbdevice",
    "wallet/hdwallet -> wallet/hdwalletdb -> wallet/hdwallet",
    "wallet/hdwallet -> wallet/wallet -> wallet/hdwallet",
    "wallet/hdwallet -> wallet/receive -> wallet/hdwallet",
    "wallet/hdwallet -> wallet/spend -> wallet/hdwallet",
    "key/extkey -> key_io -> script/standard -> key/extkey",
    "key/stealth -> key_io -> script/standard -> key/stealth",
    "smsg/smessage -> wallet/hdwallet -> smsg/smessage",
    "net_processing -> smsg/smessage -> wallet/hdwallet -> pos/kernel -> node/transaction -> net_processing",
    "net_processing -> smsg/smessage -> node/context -> net_processing",
    "net_processing -> smsg/smessage -> net_processing",
    "net_processing -> validation -> net_processing",
    "consensus/tx_verify -> validation -> txmempool -> consensus/tx_verify",
)

CODE_DIR = "src"


def main():
    circular_dependencies = []
    exit_code = 0
    os.chdir(
        CODE_DIR
    )  # We change dir before globbing since glob.glob's root_dir option is only available in Python 3.10

    # Using glob.glob since subprocess.run's globbing won't work without shell=True
    files = []
    for path in ["*", "*/*", "*/*/*"]:
        for extension in ["h", "cpp"]:
            files.extend(glob.glob(f"{path}.{extension}"))

    command = ["python3", "../contrib/devtools/circular-dependencies.py", *files]
    dependencies_output = subprocess.run(
        command,
        stdout=subprocess.PIPE,
        universal_newlines=True,
    )

    for dependency_str in dependencies_output.stdout.rstrip().split("\n"):
        circular_dependencies.append(
            re.sub("^Circular dependency: ", "", dependency_str)
        )

    # Check for an unexpected dependencies
    for dependency in circular_dependencies:
        if dependency not in EXPECTED_CIRCULAR_DEPENDENCIES:
            exit_code = 1
            print(
                f'A new circular dependency in the form of "{dependency}" appears to have been introduced.\n',
                file=sys.stderr,
            )

    # Check for missing expected dependencies
    for expected_dependency in EXPECTED_CIRCULAR_DEPENDENCIES:
        if expected_dependency not in circular_dependencies:
            exit_code = 1
            print(
                f'Good job! The circular dependency "{expected_dependency}" is no longer present.',
            )
            print(
                f"Please remove it from EXPECTED_CIRCULAR_DEPENDENCIES in {__file__}",
            )
            print(
                "to make sure this circular dependency is not accidentally reintroduced.\n",
            )

    sys.exit(exit_code)


if __name__ == "__main__":
    main()
