#!/usr/bin/env python3
# Copyright (c) 2018-2019 The Particl Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

from test_framework.test_particl import ParticlTestFramework, connect_nodes_bi


class WalletParticlUnloadSpentTest(ParticlTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 2
        self.extra_args = [ ['-debug', '-noacceptnonstdtxn', '-reservebalance=10000000'] for i in range(self.num_nodes)]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def setup_network(self, split=False):
        self.add_nodes(self.num_nodes, extra_args=self.extra_args)
        self.start_nodes()
        connect_nodes_bi(self.nodes, 0, 1)

    def run_test(self):
        nodes = self.nodes

        nodes[0].extkeyimportmaster('abandon baby cabbage dad eager fabric gadget habit ice kangaroo lab absorb')
        assert(nodes[0].getwalletinfo()['total_balance'] == 100000)

        ro = nodes[0].walletsettings('unloadspent', {'mode':1, 'mindepth':2})
        assert(ro['unloadspent']['mode'] == 1)
        assert(ro['unloadspent']['mindepth'] == 2)

        ro = nodes[1].extkey('importaccount', nodes[0].extkey('account', 'default', 'true')['epkey'])
        ro = nodes[1].extkey('setdefaultaccount', ro['account_id'])

        w0 = nodes[0].getwalletinfo()
        w1 = nodes[1].getwalletinfo()

        assert(w0['total_balance'] == w1['watchonly_total_balance'])
        assert(w0['txcount'] == w1['txcount'])

        self.stakeBlocks(40)

        w0 = nodes[0].getwalletinfo()
        w1 = nodes[1].getwalletinfo()
        assert(w0['total_balance'] == w1['watchonly_total_balance'])
        assert(w0['txcount'] < w1['txcount'])

        d0 = nodes[0].debugwallet()
        d1 = nodes[1].debugwallet()
        assert(d0['mapWallet_size'] + d0['m_collapsed_txns_size'] == d1['mapWallet_size'])
        assert(d1['m_collapsed_txns_size'] == 0)

        self.log.info('Test node restart')
        self.stop_node(0)
        self.start_node(0, self.extra_args[0])

        ro = nodes[0].walletsettings('unloadspent')
        assert(ro['unloadspent']['mode'] == 1)
        assert(ro['unloadspent']['mindepth'] == 2)



if __name__ == '__main__':
    WalletParticlUnloadSpentTest().main()
