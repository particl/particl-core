#!/usr/bin/env python3
# Copyright (c) 2014-2015 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

#
# Test txindex generation and fetching
#

from test_framework.test_particl import ParticlTestFramework
from test_framework.util import connect_nodes, assert_equal


class TxIndexTest(ParticlTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 4
        self.extra_args = [
            # Nodes 0/1 are "wallet" nodes
            ['-debug',],
            ['-debug','-txindex'],
            # Nodes 2/3 are used for testing
            ['-debug','-txindex'],
            ['-debug','-txindex'],]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def setup_network(self):
        self.add_nodes(self.num_nodes, extra_args=self.extra_args)
        self.start_nodes()

        connect_nodes(self.nodes[0], 1)
        connect_nodes(self.nodes[0], 2)
        connect_nodes(self.nodes[0], 3)

        self.sync_all()

    def run_test(self):

        nodes = self.nodes

        # Stop staking
        for i in range(len(nodes)):
            nodes[i].reservebalance(True, 10000000)

        nodes[0].extkeyimportmaster('abandon baby cabbage dad eager fabric gadget habit ice kangaroo lab absorb')
        assert(nodes[0].getwalletinfo()['total_balance'] == 100000)


        print('Testing transaction index...')

        nodes[1].extkeyimportmaster('graine article givre hublot encadrer admirer stipuler capsule acajou paisible soutirer organe')
        addr1 = nodes[1].getnewaddress()

        txid = nodes[0].sendtoaddress(addr1, 5)

        # Check verbose raw transaction results
        verbose = self.nodes[0].getrawtransaction(txid, 1)
        assert(len(verbose['vout']) == 2)

        str0 = self.dumpj(verbose['vout'][0])
        str1 = self.dumpj(verbose['vout'][1])
        if addr1 in str0:
            assert_equal(verbose['vout'][0]['valueSat'], 500000000)
            assert_equal(verbose['vout'][0]['value'], 5)
        elif addr1 in str1:
            assert_equal(verbose['vout'][1]['valueSat'], 500000000)
            assert_equal(verbose['vout'][1]['value'], 5)
        else:
            assert(False)

        ro = nodes[0].gettxoutsetinfobyscript()
        assert(ro['height'] == 0)
        assert(ro['paytopubkeyhash']['num_plain'] == 15)

        print('Passed\n')


if __name__ == '__main__':
    TxIndexTest().main()
