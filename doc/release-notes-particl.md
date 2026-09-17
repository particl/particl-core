
23.2.12
==============

- Hardened anon transaction input validation.
- secp256k1: Invalid commitments are rejected when loaded.


23.2.11
==============

- Hardened blinded commitment validation.
- New checkpoints.


23.2.10
==============

- Improve smsg message size validation.
- New checkpoints.


23.2.9
==============

- Hard Fork
  - 2026-02-01 12:00:00 UTC
  - Reduce stake reward to 3.5% of moneysupply.
  - Remove forced treasury fund donation stake split.
  - Disable frozen blinded spends below 200 PART.
- New checkpoints.


23.2.8
==============

- smsg: Fix found messages counter when scanning files.
- rpc: Add master path override to extkeyimport master.
- qt: Disable 'Make Blank Wallet' option in Particl mode.
- smsg: Add plaintext format version 2 option.
  - Only affects decrpted messages, the encrypted messages are still compatible with older nodes.
- smsg: Add RPC methods for remote address management.
- smsg rpc:
  - Added parameter to smsggetdifficulty to return difficulty in compact target form.
- New checkpoints.


23.2.7
==============

- Fixed segfault with getblock verbosity > 2
- New checkpoints.


23.2.6
==============

- Transactions with blinded inputs are marked in the TXDB.
  - Enables the wallet to detect blinded transaction type_in without txindex.
- rpc:
  - gettransaction shows total amount for tx records.
  - gettransaction shows type_in field.
  - gettransaction for fee for tx records shown once instead of in details.
  - filtertransactions total amount now includes fee for sent txns.
    - Matches gettransaction for mapwallet transactions.
  - extkeyimportmaster will fail to import to a wallet with an active account without setting the replaceaccount parameter.
  - debugwallet can detect and repair missing blind input flags.
- New checkpoints.
- Merged BTC 23.2


23.1.5
==============

- wallet: Fix missing blinding factor bug.
- hardware devices: Temporarily disable Ledger Nano S Plus support.


23.1.4
==============

- rpc: Fix listunspentblind filter by address
- wallet: Fix disabling recscan for importaccount command
- wallet: Locked blinded outputs are processed in order when unlocked.
  - Should make the onlyinstance option obsolete.
- rpc: debugwallet added some output for a locked wallet if no parameters provided.
- New checkpoints.
- Merged BTC 23.1


23.0.3
==============

- qt: Fix crash when retreiving record transaction descriptions.
- wallet: Fix walletpassphrasechange after encryptwallet without restarting.


23.0.2
==============

- Coincontrol allow_other_inputs defaults to true
  - Added allow_other_inputs to smsg rpc functions which accept a coincontrol parameter.


23.0.1
==============

- rpc: devicesignrawtransactionwithwallet is split out of devicesignrawtransaction.
  - Workaround for wallet context only provided for wallet rpc commands.


22.0.2
==============

- rpc: signrawtransactionwithkey accepts tapscript spending data.


22.0.1
==============

- script: Remove timelocked script signing.


0.21.2.10
==============

- rpc: Added pending_depth to getcoldstakinginfo
  - getbalances staked shows immature coins unspendable before maturing after 100 blocks (COINBASE_MATURITY)
  - getcoldstakinginfo pending_depth shows coins unstakable until after 225 blocks (nStakeMinConfirmations)
- rpc: Added minstakeabledepth to getstakinginfo
- wallet: Only mark anon/blind tx outputs as change if wallet owns inputs.


0.21.2.9
==============

- smsg: The smsgdb is periodically compacted.
- smsg: Added pagination to smsginbox and smsgoutbox.
- smsg: Shutdown smsgdb even if smsg is not initialised.


0.21.2.8
==============

- wallet: Fix regression summing balances after fully importing watchonly stealthaddress.
- net: Restore automatic banning.  Ban peer if misbehaviour score is 2x limit.


0.21.2.7
==============

- wallet: Fix receiving anon txns on locked wallet and new address.
- wallet: Fix passing anon_ring_size parameter to fundrawtransactionfrom.


0.21.2.6
==============

- wallet:
  - Add minimum and maximumAmount to fundrawtransactionfrom and sendtypeto
  - Add includeWatching option to sendtypeto
- qt: Fixed empty qr popup when trying to create stealth address from locked wallet.
- smsg: Stores best block and runs rebuild rollingindices on startup if out of sync.


0.21.2.5
==============

- Scheduled fork for 2022-02-01 17:00:00 UTC.
  - Raised protocol version to 90035
- Fixed chain syncing issue.
- qt: Include immature anon balance in overview total.
- New checkpoints.


0.21.2.4
==============

- wallet will record txns with blinded outputs to known addresses.


0.21.2.3
==============

- rpc: New command getposdifficulty, returns the network weight at block heights.
- qt: Disable balance type combo boxes on the send dialog when wallet is linked to a hardware wallet.


0.21.1.2
==============

- Merged Bitcoin 0.21.1.
- New argument -checkpeerheight
  - Can disable peer height for initial-block-download status and staking.
- Wallet tracks anon watchonly transactions.
- dumpprivkey: Dumps keys for stealth addresses.
- getaddressinfo: Shows stealth address public keys.
- fundrawtransactionfrom:
  - Can add anon inputs.
  - Can sign txns.
  - Accepts data for candidate inputs
    - Anon inputs must exist in the chain as the pubkey index is required by the ringsig.
- rewindrangeproof: Accepts nonce directly
- Raised protocol version to 90034
  - Must be greater than protocol version of 0.19


0.21.0.1
==============

- Fixed gettransaction verbose output missing for wallet record txns.
- Exclude watchonly records from filtertransactions unless requested.


0.20.1.1
==============

- Added Czech bip39 wordlist.
- No default account wallet warning is silenced if wallet was intentionally created empty.
- Enable blockchain pruning.
  - Requires a rolling index for chain reorgs and paid smsg validation.
  - On the first run the rolling indices will be initialised.
  - If you later run an older release use the -rebuildrollingindices flag to manually rebuild the indices again.
- Added support for watchonly blinded outputs
  - New 'blind_watchonly_visible' option for coincontrol on sendtypeto command.
  - When 'blind_watchonly_visible' is set blinded outputs sent to stealth addresses can be uncovered with the scan secret only.
    - Nonce is calculated as ECDH(ephem_secret + tweak, scan_public_key) and recovered with ECDH(scan_secret_key, ephem_public_key + G * tweak)


0.19.2.20
==============

- Raised min protocol version to 90014
- Disable p2sh-p2wpkh addresses.
- qt: 'Import Chain' defaults to disabled.
- wallet, qt: Default ring size set to 12 to match Particl Desktop.
- wallet: Fix BTC segwit address path and label in getaddressinfo.
- rpc: Fix bug in filtertransactions hiding txns with watchonly inputs and spendable outputs.
- qt: Fix missing anon outputs in coincontrol.


0.19.2.19
==============

- qt: Fix abandon transaction button greyed out for record txns.
- Backported taproot validation.
- New checkpoints.


0.19.2.18
==============

- qt: Include immature anon balance in overview total.
- rpc: Use WordToType in fundrawtransactionfrom.
- rpc: smsgdebug dumpids path is hardcoded and will skip expired smsges by default.
- New checkpoints.
- Scheduled hardfork:
  - Mainnet: 2022-02-01 17 UTC
  - Testnet: 2022-01-01 17 UTC


0.19.2.17
==============

- smsg: Prefer selecting confirmed inputs for funding txns.
- net: Ignore smsg for peers with connection type one shot or feeler.
- smsg: Fund multiple messages per txn.
  - Sent messages can be stashed in db for later bulk funding.
- rpc: gettransaction and filtertransactions can display smsg funding info.
- rpc: Fixed sendtypeto with show_hex set.
- insight: Spent index should update even if addressindex can't.
- insight: Add PayToTimeLockedScriptHash to addressindex.
- wallet: Fix changepos return value for anon and blind txns off by one.
- rpc: New getlockedbalances command.
- rpc: fundrawtransactionfrom can set the public key used for the change output.
- rpc: verifyrawtransaction
  - Checks transaction outputs.
  - spendheight can be specified.
- Fixed fundrawtransactionfrom witnessstack


0.19.2.16
==============

- Limited automatic rollbackrctindex to one attempt.
- wallet: listunspentanon default minimum output value set to 1sat.
  - Excludes 0 value change outputs.
- Fixed VerifyDB at -checklevel=4


0.19.2.15
==============

- index: Fix issue when cs index best block is set and the index best block is not.
- validation: Fix chain sync error after incomplete shutdown.
  - Block height is stored for newly added RCT keyimages, rollback removes > chain height.
  - New rollbackrctindex command to manually trigger rct index rollback to chain tip.
- New checkpoints.


0.19.2.14
==============

- wallet: Add ability receive on loose extkey chains.
  - receive_on must be active for chain.
    - See feature_part_extkey test.
  - New track-only mode, won't save keys or transactions, only updates child key counter.
- rpc: New getblockhashafter command.
  - Returns first block at or after provided time.
- Fix abandoning coinstakes with descendants.
  - Avoid assert when disconnecting a spent coinstake tx


0.19.2.13
==============

- Fixed RPC escaping in qt.
  - Solves issue with quotes in mnemonic passwords.
- rpc: Include null votes in votehistory current/future results.
- qt: Disable balance type combo boxes on the send dialog when wallet is hardware linked.
- smsg: Fix duplicate tx entry when funding paid smsg.
- wallet: sendtypeto accepts an extkey as stakeaddress.
- wallet: Fixed multiple provisional derivations from the same extkey.
- rpc: extkey options can set num_derives and num_derives_hardened.
- Raised min protocol version to 90013
- hardware: Updated Trezor integration.


0.19.2.12
==============

- Hardfork scheduled at 2021-07-12 17:00:00 UTC
- Raised protocol version to 90013
- Raised min protocol version to 90012
- Add -lookuptorcontrolhost option, disabled by default.
- extkeyimportmaster rpc command has new options parameter:
  - Can adjust default lookahead sizes and create extkeys before the initial scan.
- Fixed bug where dust output converted to change was added to the fee before subfee was processed.
- Added new PID for Ledger Nano X (4015).
- listunspentanon: New show_pubkeys option.
- New wallet command getkeyimage returns keyimage for pubkey if owned.
- New command checkkeyimage checks if keyimage is spent in the chain.
- See hardware device outputs as watch-only if not compiled with usbdevice.


0.19.2.11
==============

- Fix bug preventing syncing chain from genesis.


0.19.2.10
==============

- Add show_anon_spends option to filtertransactions.
- Remove spurious "ExtractDestination failed" log messages.
- Add show_change option to filtertransactions.
- Transaction record format changed.
  - Owned anon prevouts stored in vin, new vkeyimages attribute.
  - Breaks backwards compatibility, to downgrade run `debugwallet {\"downgrade_wallet\":true}`.
- Improved filtertransactions total amount for internal_transfer with anon inputs.
- Display blocktime if < timereceived.
- SaveStealthAddress updates counters.
  - If wallet rescans lookahead removal code would remove existing stealth addresses.
- debugwallet inputs moved to a json object, new options:
  - downgrade_wallets: Downgrade wallet formatfor previous releases.
  - list_frozen_outputs: List all spendable and unspendable frozen blinded outputs.
  - spend_frozen_output: Spends the largest spendable frozen blinded output, after next hard fork.
  - trace_frozen_outputs: Dumps amounts, blinding values and optionally spent anon keys to aid in validating frozen outputs.
    - See: https://github.com/tecnovert/particl_debug_scripts/blob/main/trace_frozen.py
  - detects missing anon spends.
- New insight -balancesindex
  - New rpc command: getblockbalances
  - balancesindex tracks the amount of plain coin sent to and from blind and anon.
  - Coins can move between anon and blind but the sums should match.
- New walletsettings stakingoptions minstakeablevalue option.
  - Wallet won't try stake outputs with values lower than.
- New walletsettings other minownedvalue option.
  - Wallet won't track outputs with values lower than.
- setvote will clear all vote settings when all parameters are set to 0.
- votehistory, new include_future parameter.
  - If current_only and include_future are true, future scheduled votes will be displayed.
- Fixed bug in wallet stealth address lookahead when rescanning.
- deriverangekeys
  - Can derive and save stealth addresses.
  - Added shortcut for internal chain.
- liststealthaddresses: New verbose parameter displays key paths and count of received addresses.
- sendtypeto: New stakeaddress parameter on output, avoids buildscript step when sending to coldstaking scripts.
- trace_frozen_outputs traces blacklisted outputs.


0.19.2.5
==============

- Allow anon and blinded transaction on testnet.
- filtertransactions can display blinding factors.
- New mainnet checkpoint.


0.19.2.4
==============

- Emergency hardfork release
- Disables anon and blind transactions


0.19.2.3
==============

- Merged Bitcoin 0.19.2 backports.
- New checkpoints.
- Fix smsginbox hex encoding bug.
- Tighten IsStandard() check to fail on trailing script.
- Re-enable win32 gitian build.


0.19.1.2
==============

- Fixed walletsettings stakelimit display.
- Fixed createwallet not adding new wallet to staking threads.
- Fixed bug where sending from qt fails from wallet with empty name when multiple wallets are loaded.
- Fixed inconsistent txn records displayed in qt after loading another wallet
- Added rpc function to change dev fund settings in regtest.
- wallet: List locked maprecord txns in ListCoins()
- wallet: p2sh change address works when coldstakingaddress is set.
- qt: Added tooltips for anon options, display in spend confirm dialog.


0.19.1.1
==============

- Merged Bitcoin 0.19.1 backports.
- Added generatemnemonic command to particl-wallet.
- Qt receiving addresses table displays relative paths.
- Qt receiving addresses page can verify an address on a hardware device.
  - Window -> Receiving addresses, right click on address -> Verify Address On Hardware Wallet
- Path of change address is sent to ledger hardware devices.


0.19.0.1
==============

- rpc: Add coinstakeinfo option to getblock.


0.18.1.8
==============

- Fixed walletsettings stakelimit display.
- Fixed createwallet not adding new wallet to staking threads.
- Fixed bug where sending from qt fails from wallet with empty name when multiple wallets are loaded.
- Fixed inconsistent txn records displayed in qt after loading another wallet
- Added rpc function to change dev fund settings in regtest.
- wallet: p2sh change address works when coldstakingaddress is set.
- qt: Added tooltips for anon options, display in spend confirm dialog.


0.18.1.7
==============

- wallet: Fix missing low amount error string.
- hardware devices: Add ID for Ledger Nano S firmware 1.6


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
