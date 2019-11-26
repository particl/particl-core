Next Major Version
==============

- Added Czech bip39 wordlist.
- No default account wallet warning is silenced if wallet was intentionally created empty.


0.19.0.1
==============

- rpc: Add coinstakeinfo option to getblock.


0.18.1.x
==============
- wallet: Fix missing low amount error string.


0.18.1.6
==============
- Fixed crash when rescanning a watchonly account.
- Fixed errors when calling the mnemonic rpc function concurrently.
- Fixed crash when initaccountfromdevice is called before setting udev rules.
- Added udev rule hint to Qt gui if initaccountfromdevice fails.
- Creating a stealth address from the Qt gui works if the wallet was initialised with a hardware device.
- Added moneysupply and anonoutputs to getblockheader rpc output.


0.18.1.5
==============

- rpc: smsgsend accepts a coincontrol parameter.
- Fixed infinite loop bug in AddStandardInputs when sum of specified inputs is too low.
- Fixed bug preventing outputs received with extkey addresses from hardware linked wallets being spent.
- rpc: importstealthaddress can import watchonly stealth addresses.
- rpc: smsgzmqpush resends zmq smsg notifications.
- Fixed bug causing wallet unlock to freeze.


0.18.1.4
==============

- Stealth address lookahead when rescanning an uncrypted or unlocked wallet.
- RingCT send options are saved by the Qt gui.
- SMSG can listen for incoming messages on multiple wallets.


0.18.1.3
==============

- Log source of change address, allow p2wpkh changeaddresses.
- rpc: smsggetfeerate cmd will display target rate if passed a negative height.
- rpc: smsg cmd can export full message.
- rpc: Add smsgpeers command.
- net: Enable per message received byte counters for smsg.
- rpc: smsgscanbuckets will skip expired messages.
- rpc: Added smsgdumpprivkey command.
- Relaxed smsg anti-spam constraint to allow backdated free messages if they pass the current difficulty.


0.18.1.2
==============

- Improved fee estimation.


0.18.1.1
==============

- Don't include paid smsg fees for fee estimates.
- Fixed rescanblockchain needing to be run after clearwallettransactions to find anon-tx spends.
- SMSG is incompatible with earlier releases, new bucket dir and db prefixes prevent collisions with existing data.
  - Changed SMSG days retention to ttl in seconds.
  - Listen for anon messages is set to false by default.
  - Moved some smsgsend arguments to an options object
  - New parameter ttl_is_seconds for smsgsend, if true interprets days_retention as seconds
  - New min ttl of 1 hour, max 31 days for paid and 14 for free


0.18.1.0
==============

- clearbanned rpc cmd clears persistent DOS counters too.
- Added segwit scripts to insight.


0.18.0.12
==============

- Merged Bitcoin 0.18.1 backports.
- Fixed help text for createsignaturewith commands.
- Added 'pubkey' to output of extkey info extended-secret-key.
- Fixed help text for getspentinfo.
- Enabled segwit addresses in Particl mode for easier integrations.
- Raised minimum peer version to 90009.


0.18.0.11
==============

- Fixed regression causing unloadwallet to fail.
- Added smsggetinfo RPC command to display SMSG related information.
- Added smsgsetwallet RPC command to switch the active SMSG wallet without disabling SMSG.
- Unloading the active SMSG wallet will leave SMSG enabled.
- Fixed DOS vulnerability.
- Fixed rpc cmd filtertransactions filtering by type.


0.18.0.10
==============

- Fixed avoidpartialspends.
- Testnet fork scheduled for 2019-07-01 12:00:00 UTC
  - Enable variable difficulty for smsg free messages.
- Mainnet fork scheduled for 2019.07.16-12:00:00 UTC
  - Enable bulletproof rangeproofs.
  - Enable RingCT transactions.
  - Enable variable fee rate for smsg paid messages.
  - Enable variable difficulty for smsg free messages.


0.18.0.9
==============

- pruneorphanedblocks shows shutdown warning if not in test mode.
- Fixed Qt 'Request payment' button greyed out after importing mnemonic.


0.18.0.8
==============

- Fixed issue where clearing the rewardaddress requires a restart.
- Fixed regression where disablewallet required nosmsg also.
- Fixed getrawtransaction failing where scripts are nonstandard with OP_ISCOINSTAKE.
- New balance category for immature anon coin.


0.18.0.7
==============

- Fixed regression causing wallet catch-up rescan to never trigger.
- New checkpoints.


0.18.0.6 rc2
==============

- Fixed regression when sending all blind to part.


0.18.0.6 rc1
==============

SMSG won't connect to nodes running a version below 0.18.0.6

- Fixed failure when sending all blind to part.
- smsgbuckets: Add total only mode
- SMSG: Difficulty can be adjusted by stakers.
- SMSG: Messages can be created and imported without being transmitted.
- SMSG: Messages can be sent without being stored to the outbox.


0.18.0.5 rc1
==============

0.18.0.3 or above required for testnet fork at 2019-02-16 12:00:00 UTC.

- filtertransactions: Display fee when type is 'internal_transfer'.
- promptunlockdevice and unlockdevice added for Trezor hardware wallet.
- signmessage / verifymessage: Add sign and verify using 256bit addresses.
- Wallet won't search smsg for unknown pubkeys when sending.
- New rewindrangeproof rpc command.
- Fixed initial block download issues.
- Converted contrib/linearize.
- Updated DNS seeds.
- New checkpoint data.
- New branding.


0.18.0.4 Alpha
==============
For Testnet.

0.18.0.3 or above required for testnet fork at 2019-02-16 12:00:00 UTC.

- Fixed lockunspent crash in market tests.


0.18.0.3 Alpha
==============
For Testnet.

0.18.0.3 or above required for testnet fork at 2019-02-16 12:00:00 UTC.

- Enables variable smsg fee after fork.
- Enables bullet proof range proofs after fork.
- Enables p2sh in coldstake spend script after fork.



0.17.1.4
==============
For mainnet only.

0.17.1.2 or above required for mainnet fork at 2019-03-01 12:00:00 UTC.

- Fixed initial block download issues.
- Updated DNS seeds.
- New checkpoint data.


0.17.1.3
==============
For mainnet only.

0.17.1.2 or above required for mainnet fork at 2019-03-01 12:00:00 UTC.

- Removed smsg fee limit, allowing larger messages to be valid for more
  time.


0.17.1.2
==============
For mainnet only.

0.17.1.2 or above required for mainnet fork at 2019-03-01 12:00:00 UTC.

- This release will enable paid secure messaging on mainnet after fork
  scheduled for 2019-03-01 12:00:00 UTC.
