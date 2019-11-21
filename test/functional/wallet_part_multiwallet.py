#!/usr/bin/env python3
# Copyright (c) 2019 The Particl Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

from test_framework.test_particl import ParticlTestFramework, connect_nodes_bi


class MultiWalletTest(ParticlTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 3
        self.extra_args = [ ['-debug','-noacceptnonstdtxn','-reservebalance=10000000'] for i in range(self.num_nodes)]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def setup_network(self, split=False):
        self.add_nodes(self.num_nodes, extra_args=self.extra_args)
        self.start_nodes()

        connect_nodes_bi(self.nodes, 0, 1)
        connect_nodes_bi(self.nodes, 0, 2)
        self.sync_all()

    def run_test(self):
        nodes = self.nodes

        nodes[0].extkeyimportmaster('abandon baby cabbage dad eager fabric gadget habit ice kangaroo lab absorb')
        assert(nodes[0].getwalletinfo()['total_balance'] == 100000)
        nodes[1].extkeyimportmaster('pact mammal barrel matrix local final lecture chunk wasp survey bid various book strong spread fall ozone daring like topple door fatigue limb olympic', '', 'true')
        nodes[1].getnewextaddress('lblExtTest')
        nodes[1].rescanblockchain()
        assert(nodes[1].getwalletinfo()['total_balance'] == 25000)
        nodes[2].extkeyimportmaster('sección grito médula hecho pauta posada nueve ebrio bruto buceo baúl mitad')

        self.log.info('Check loaded wallets rescan any missed blocks')

        nodes[2].createwallet('wallet_2')
        assert(len(nodes[2].listwallets()) == 2)

        w1 = nodes[2].get_wallet_rpc('')
        w2 = nodes[2].get_wallet_rpc('wallet_2')
        w2.extkeyimportmaster('sección grito médula hecho pauta posada nueve ebrio bruto buceo baúl mitad')

        addr = w1.getnewaddress()
        nodes[0].sendtoaddress(addr, 1000)
        self.stakeBlocks(1)
        assert(w1.getwalletinfo()['total_balance'] == 1000)
        assert(w2.getwalletinfo()['total_balance'] == 1000)

        nodes[2].unloadwallet('wallet_2')
        assert(len(nodes[2].listwallets()) == 1)

        nodes[2].sendtoaddress(nodes[1].getnewaddress(), 100)

        self.sync_all()
        self.stakeBlocks(1)

        nodes[2].loadwallet('wallet_2')
        w1 = nodes[2].get_wallet_rpc('')
        w2 = nodes[2].get_wallet_rpc('wallet_2')

        assert(w1.getwalletinfo()['total_balance'] < 900)
        assert(w1.getwalletinfo()['total_balance'] == w2.getwalletinfo()['total_balance'])

        ro = nodes[2].getblockstats(nodes[2].getblockchaininfo()['blocks'])
        assert(ro['height'] == 2)

        self.log.info('createwallet with passphrase')

        nodes[2].createwallet('wallet_3', False, False, 'password_abc')
        w3 = nodes[2].get_wallet_rpc('wallet_3')
        ro = w3.getwalletinfo()
        assert('hdseedid' in ro)
        assert(ro['encryptionstatus'] == 'Locked')


if __name__ == '__main__':
    MultiWalletTest().main()
