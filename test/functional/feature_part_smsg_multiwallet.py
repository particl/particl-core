#!/usr/bin/env python3
# Copyright (c) 2019 The Particl Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

import time

from test_framework.test_particl import ParticlTestFramework, connect_nodes_bi
from test_framework.authproxy import JSONRPCException


class SmsgMultiWalletTest(ParticlTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True  # Don't copy from cache
        self.num_nodes = 3
        self.extra_args = [ ['-debug', '-reservebalance=10000000'] for i in range(self.num_nodes) ]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def setup_network(self, split=False):
        self.add_nodes(self.num_nodes, extra_args=self.extra_args)
        self.start_nodes()
        connect_nodes_bi(self.nodes, 0, 1)
        connect_nodes_bi(self.nodes, 0, 2)

    def run_test(self):
        nodes = self.nodes

        nodes[0].extkeyimportmaster('abandon baby cabbage dad eager fabric gadget habit ice kangaroo lab absorb')
        assert(nodes[0].getwalletinfo()['total_balance'] == 100000)

        nodes[1].extkeyimportmaster('pact mammal barrel matrix local final lecture chunk wasp survey bid various book strong spread fall ozone daring like topple door fatigue limb olympic', '', 'true')
        nodes[1].getnewextaddress('lblExtTest')
        nodes[1].rescanblockchain()
        assert(nodes[1].getwalletinfo()['total_balance'] == 25000)

        nodes[2].extkeyimportmaster(nodes[2].mnemonic('new')['master'])

        address1 = nodes[1].getnewaddress()
        nodes[1].smsgaddlocaladdress(address1)
        nodes[2].smsgaddaddress(address1, nodes[1].smsglocalkeys()['wallet_keys'][0]['public_key'])

        nodes[2].createwallet('wallet_2')
        w1 = nodes[2].get_wallet_rpc('')
        w2 = nodes[2].get_wallet_rpc('wallet_2')
        w2.extkeyimportmaster(nodes[2].mnemonic('new')['master'])
        w2.encryptwallet('qwerty234')

        smsg_info = nodes[2].smsggetinfo()
        assert(len(smsg_info['enabled_wallets']) == 2)

        address2_1 = w1.getnewaddress()
        address2_1_info = w1.getaddressinfo(address2_1)
        address2_2 = w2.getnewaddress()
        address2_2_info = w2.getaddressinfo(address2_2)
        nodes[2].smsgaddlocaladdress(address2_1)
        nodes[2].smsgaddlocaladdress(address2_2)

        addr2_1_sx = w1.getnewstealthaddress()
        dest2_3 = w1.derivefromstealthaddress(addr2_1_sx)
        dest2_3 = w1.derivefromstealthaddress(addr2_1_sx, dest2_3['ephemeral_pubkey'])
        pubkey2_3 = dest2_3['pubkey']
        privkey2_3 = dest2_3['privatekey']
        address2_3 = dest2_3['address']
        nodes[2].smsgimportprivkey(privkey2_3, 'smsg test address2_3')

        nodes[1].smsgaddaddress(address2_1, address2_1_info['pubkey'])
        nodes[1].smsgaddaddress(address2_2, address2_2_info['pubkey'])
        nodes[1].smsgaddaddress(address2_3, pubkey2_3)

        nodes[1].smsgsend(address1, address2_1, 'test 1')
        nodes[1].smsgsend(address1, address2_2, 'test 2')
        nodes[1].smsgsend(address1, address2_3, 'test 3')

        i = 0
        for i in range(20):
            ro = nodes[2].smsginbox()
            if len(ro['messages']) > 1:
                break
            time.sleep(1)
        assert(i < 19)

        assert(len(ro['messages']) == 2)

        w2.walletpassphrase('qwerty234', 30)

        i = 0
        for i in range(20):
            ro = nodes[2].smsginbox()
            if len(ro['messages']) > 0:
                break
            time.sleep(1)
        assert(i < 19)

        assert(len(ro['messages']) == 1)

        self.log.info('Test smsgsend with coincontrol')
        w2.walletlock()
        nodes[1].sendtoaddress(address2_2, 0.0001)  # Too small
        for i in range(5):
            nodes[1].sendtoaddress(address2_2, 1.0)

        self.sync_all()
        self.stakeBlocks(1)

        plain_unspent = w2.listunspent()
        assert(len(plain_unspent) == 6)

        for i in range(len(plain_unspent)):
            if plain_unspent[i]['amount'] < 1.0:
                cantspend = plain_unspent[i]
        spend = plain_unspent[2]
        if spend['amount'] < 1.0:
            spend = plain_unspent[3]

        nodes[2].smsgsetwallet('wallet_2')
        smsg_info = nodes[2].smsggetinfo()
        assert(smsg_info['active_wallet'] == 'wallet_2')

        coincontrol = {'inputs': [{'tx': spend['txid'], 'n': spend['vout']}]}
        sendoptions = {}
        msg = 'paid msg from locked wallet spending output {} {}'.format(spend['txid'], spend['vout'])

        # Fail sending from a locked wallet
        try:
            ro = nodes[2].smsgsend(address2_2, address1, msg, True, 6, False, sendoptions, coincontrol)
            raise AssertionError('Should have failed.')
        except JSONRPCException as e:
            assert('Wallet locked' in e.error['message'])

        # Allow testing fees from a locked wallet - if address isn't in a locked wallet
        ro = nodes[2].smsgsend(address2_3, address1, msg, True, 6, True, sendoptions, coincontrol)
        assert(ro['result'] == 'Not Sent.')
        assert(ro['fee'] > 0.00137)

        # Check funding fails if coincontrol inputs are too low
        coincontrol = {'inputs': [{'tx': cantspend['txid'], 'n': cantspend['vout']}]}
        ro = nodes[2].smsgsend(address2_3, address1, msg, True, 6, True, sendoptions, coincontrol)
        assert('Insufficient funds' in ro['error'])

        # Pass if allowed to pick extra outputs
        ro = nodes[2].smsgsend(address2_3, address1, msg, True, 6, True, sendoptions)
        assert(ro['fee'] > 0.00137)

        # Should send if unlocked
        w2.walletpassphrase('qwerty234', 30)
        coincontrol = {'inputs': [{'tx': spend['txid'], 'n': spend['vout']}]}
        send_receipt = nodes[2].smsgsend(address2_2, address1, msg, True, 6, False, sendoptions, coincontrol)
        assert(send_receipt['result'] == 'Sent.')
        assert(send_receipt['fee'] > 0.00137)

        fund_tx = nodes[2].getrawtransaction(send_receipt['txid'], True)
        assert(len(fund_tx['vin']) == 1)
        assert(fund_tx['vin'][0]['txid'] == spend['txid'])
        assert(fund_tx['vin'][0]['vout'] == spend['vout'])

        self.sync_all()
        self.stakeBlocks(1)

        for i in range(20):
            ro = nodes[1].smsginbox()
            if len(ro['messages']) > 0:
                break
            time.sleep(1)
        assert(i < 19)

        assert(len(ro['messages']) == 1)
        assert(ro['messages'][0]['text'] == msg)

        self.log.info('Done.')


if __name__ == '__main__':
    SmsgMultiWalletTest().main()
