#!/usr/bin/env python3
# Copyright (c) 2017-2019 The Particl Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

from test_framework.test_particl import ParticlTestFramework, isclose, connect_nodes_bi


class WalletParticlWatchOnlyTest(ParticlTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 3
        self.extra_args = [ ['-debug','-reservebalance=10000000'] for i in range(self.num_nodes)]

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

        addr = 'pcwP4hTtaMb7n4urszBTsgxWLdNLU4yNGz'
        nodes[1].importaddress(addr, addr, True)

        ro = nodes[1].getaddressinfo(addr)
        assert(ro['ismine'] == False)
        assert(ro['iswatchonly'] == True)

        assert(isclose(nodes[1].getwalletinfo()['watchonly_balance'], 10000.0))
        assert(len(nodes[1].filtertransactions({'include_watchonly': True})) == 1)

        ro = nodes[2].extkey('importaccount', nodes[0].extkey('account', 'default', 'true')['epkey'])
        nodes[2].extkey('setdefaultaccount', ro['account_id'])

        w0 = nodes[0].getwalletinfo()
        w2 = nodes[2].getwalletinfo()

        assert(w0['total_balance'] == w2['watchonly_total_balance'])
        assert(w0['txcount'] == w2['txcount'])

        sxaddr0 = nodes[0].getnewstealthaddress()
        sxaddrs = nodes[0].liststealthaddresses(True)
        addr_info = nodes[0].getaddressinfo(sxaddr0)
        scan_vk = sxaddrs[0]['Stealth Addresses'][0]['Scan Secret']
        spend_pk = sxaddrs[0]['Stealth Addresses'][0]['spend_public_key']
        spend_vk = sxaddrs[0]['Stealth Addresses'][0]['Spend Secret']
        ro = nodes[2].importstealthaddress(scan_vk, spend_pk)
        assert(ro['stealth_address'] == sxaddr0)
        assert(ro['watchonly'] == True)
        ro = nodes[2].getaddressinfo(sxaddr0)
        assert(ro['ismine'] == False)
        assert(ro['iswatchonly'] == True)

        txid = nodes[0].sendtoaddress(sxaddr0, 1.0)
        self.stakeBlocks(1)

        w0 = nodes[0].getwalletinfo()
        w2 = nodes[2].getwalletinfo()

        assert(w0['total_balance'] == w2['watchonly_total_balance'])
        assert(w0['txcount'] == w2['txcount'])

        nodes[2].importstealthaddress(scan_vk, spend_vk)
        ro = nodes[2].getaddressinfo(sxaddr0)
        assert(ro['ismine'] == True)
        assert(ro['iswatchonly'] == False)

        nodes[2].rescanblockchain(0)


if __name__ == '__main__':
    WalletParticlWatchOnlyTest().main()
