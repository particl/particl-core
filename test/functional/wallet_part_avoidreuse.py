#!/usr/bin/env python3
# Copyright (c) 2019 The Particl Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

from test_framework.test_particl import ParticlTestFramework, isclose, connect_nodes_bi
from test_framework.util import assert_equal


class WalletParticlAvoidReuseTest(ParticlTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 4
        self.extra_args = [ ['-debug', '-noacceptnonstdtxn', '-reservebalance=10000000'] for i in range(self.num_nodes)]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def setup_network(self, split=False):
        self.add_nodes(self.num_nodes, extra_args=self.extra_args)
        self.start_nodes()
        connect_nodes_bi(self.nodes, 0, 1)
        connect_nodes_bi(self.nodes, 0, 2)
        connect_nodes_bi(self.nodes, 0, 3)

    def run_test(self):
        nodes = self.nodes

        nodes[0].extkeyimportmaster('abandon baby cabbage dad eager fabric gadget habit ice kangaroo lab absorb')
        assert(nodes[0].getwalletinfo()['total_balance'] == 100000)
        nodes[1].extkeyimportmaster('pact mammal barrel matrix local final lecture chunk wasp survey bid various book strong spread fall ozone daring like topple door fatigue limb olympic', '', 'true')
        nodes[1].getnewextaddress('lblExtTest')
        nodes[1].rescanblockchain()
        assert(nodes[1].getwalletinfo()['total_balance'] == 25000)
        nodes[2].extkeyimportmaster('sección grito médula hecho pauta posada nueve ebrio bruto buceo baúl mitad')
        nodes[3].extkeyimportmaster('sección grito médula hecho pauta posada nueve ebrio bruto buceo baúl mitad')

        nodes[0].setwalletflag('avoid_reuse')
        nodes[1].setwalletflag('avoid_reuse')
        nodes[2].setwalletflag('avoid_reuse')

        assert_equal(nodes[0].getwalletinfo()["avoid_reuse"], True)
        assert_equal(nodes[1].getwalletinfo()["avoid_reuse"], True)
        assert_equal(nodes[2].getwalletinfo()["avoid_reuse"], True)
        assert_equal(nodes[3].getwalletinfo()["avoid_reuse"], False)

        addr_plain = nodes[2].getnewaddress()
        nodes[1].sendtoaddress(addr_plain, 1)

        self.sync_all()
        nodes[1].sendtoaddress(addr_plain, 2)

        self.sync_all()
        self.stakeBlocks(1)
        assert(isclose(nodes[2].getbalances()['mine']['trusted'], 3.0))

        nodes[2].sendtoaddress(nodes[1].getnewaddress(), 0.5)
        print(nodes[2].getbalances()['mine']['trusted'])
        assert(isclose(nodes[2].getbalances()['mine']['trusted'], 2.499464))

        nodes[1].sendtoaddress(addr_plain, 3)
        self.sync_all()
        self.stakeBlocks(1)

        assert(len(nodes[2].listunspent()) == 2)
        assert(isclose(nodes[2].getbalances()['mine']['trusted'], 2.499464))

        assert(len(nodes[3].listunspent()) == 2)
        assert(isclose(nodes[3].getbalances()['mine']['trusted'], 5.499464))


if __name__ == '__main__':
    WalletParticlAvoidReuseTest().main()
