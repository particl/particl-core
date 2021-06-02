#!/usr/bin/env python3
# Copyright (c) 2017-2021 The Particl Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

from test_framework.test_particl import ParticlTestFramework, connect_nodes_bi
from test_framework.util import assert_raises_rpc_error
from test_framework.messages import COIN



class AnonTest(ParticlTestFramework):
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

        self.import_genesis_coins_a(nodes[0])
        txnHashes = []

        nodes[1].extkeyimportmaster('drip fog service village program equip minute dentist series hawk crop sphere olympic lazy garbage segment fox library good alley steak jazz force inmate')
        sxAddrTo1_1 = nodes[1].getnewstealthaddress('lblsx11')
        assert(sxAddrTo1_1 == 'TetbYTGv5LiqyFiUD3a5HHbpSinQ9KiRYDGAMvRzPfz4RnHMbKGAwDr1fjLGJ5Eqg1XDwpeGyqWMiwdK3qM3zKWjzHNpaatdoHVzzA')

        sxAddrTo0_1 = nodes[0].getnewstealthaddress('lblsx01')

        txnHashes.append(nodes[0].sendparttoanon(sxAddrTo1_1, 1, '', '', False, 'node0 -> node1 p->a'))
        txnHashes.append(nodes[0].sendparttoblind(sxAddrTo0_1, 1000, '', '', False, 'node0 -> node0 p->b'))
        txnHashes.append(nodes[0].sendblindtoanon(sxAddrTo1_1, 100, '', '', False, 'node0 -> node1 b->a 1'))
        txnHashes.append(nodes[0].sendblindtoanon(sxAddrTo1_1, 100, '', '', False, 'node0 -> node1 b->a 2'))
        txnHashes.append(nodes[0].sendblindtoanon(sxAddrTo1_1, 100, '', '', False, 'node0 -> node1 b->a 3'))
        txnHashes.append(nodes[0].sendblindtoanon(sxAddrTo1_1, 10, '', '', False, 'node0 -> node1 b->a 4'))

        for k in range(5):
            txnHash = nodes[0].sendparttoanon(sxAddrTo1_1, 10, '', '', False, 'node0 -> node1 p->a')
            txnHashes.append(txnHash)
        for k in range(10):
            txnHash = nodes[0].sendblindtoanon(sxAddrTo1_1, 10, '', '', False, 'node0 -> node1 b->a')
            txnHashes.append(txnHash)

        for h in txnHashes:
            assert(self.wait_for_mempool(nodes[1], h))

        assert('node0 -> node1 b->a 4' in self.dumpj(nodes[1].listtransactions('*', 100)))
        assert('node0 -> node1 b->a 4' in self.dumpj(nodes[0].listtransactions('*', 100)))

        self.stakeBlocks(2)

        block1_hash = nodes[1].getblockhash(1)
        ro = nodes[1].getblock(block1_hash)
        for txnHash in txnHashes:
            assert(txnHash in ro['tx'])

        txnHash = nodes[1].sendanontoanon(sxAddrTo0_1, 1, '', '', False, 'node1 -> node0 a->a')
        txnHashes = [txnHash,]

        assert(self.wait_for_mempool(nodes[0], txnHash))
        self.stakeBlocks(1)

        ro = nodes[1].getblock(nodes[1].getblockhash(3))
        for txnHash in txnHashes:
            assert(txnHash in ro['tx'])

        assert(nodes[1].anonoutput()['lastindex'] == 28)

        txnHashes.clear()
        txnHashes.append(nodes[1].sendanontoanon(sxAddrTo0_1, 101, '', '', False, 'node1 -> node0 a->a', 5, 1))
        txnHashes.append(nodes[1].sendanontoanon(sxAddrTo0_1, 0.1, '', '', False, '', 5, 2))

        assert(nodes[1].getwalletinfo()['anon_balance'] > 10)

        outputs = [{'address': sxAddrTo0_1, 'amount': 10, 'subfee': True},]
        ro = nodes[1].sendtypeto('anon', 'part', outputs, 'comment_to', 'comment_from', 4, 32, True)
        assert(ro['bytes'] > 0)

        txnHashes.append(nodes[1].sendtypeto('anon', 'part', outputs))
        txnHashes.append(nodes[1].sendtypeto('anon', 'anon', [{'address': sxAddrTo1_1, 'amount': 1},]))

        for txhash in txnHashes:
            assert(self.wait_for_mempool(nodes[0], txhash))

        self.log.info('Test filtertransactions with type filter')
        ro = nodes[1].filtertransactions({'type': 'anon', 'count': 20, 'show_anon_spends': True, 'show_change': True})
        assert(len(ro) > 2)
        foundTx = 0
        for t in ro:
            if t['txid'] == txnHashes[-1]:
                foundTx += 1
                assert(t['amount'] == t['fee'])
            elif t['txid'] == txnHashes[-2]:
                foundTx += 1
                assert('anon_inputs' in t)
                assert(t['amount'] < -9.9 and t['amount'] > -10.0)
                n_standard = 0
                n_anon = 0
                for to in t['outputs']:
                    if to['type'] == 'standard':
                        n_standard += 1
                    elif to['type'] == 'anon':
                        n_anon += 1
                        assert(to['is_change'] == 'true')
                assert(n_standard == 1)
                assert(n_anon > 0)
                assert(t['type_in'] == 'anon')
            if t['txid'] == txnHashes[-3]:
                foundTx += 1
                assert(t['outputs'][0]['type'] == 'anon')
            if foundTx > 2:
                break
        assert(foundTx > 2)

        self.log.info('Test unspent with address filter')
        unspent_filtered = nodes[1].listunspentanon(1, 9999, [sxAddrTo1_1])
        assert(unspent_filtered[0]['label'] == 'lblsx11')

        self.log.info('Test permanent lockunspent')

        unspent = nodes[1].listunspentanon()
        assert(nodes[1].lockunspent(False, [unspent[0]], True) == True)
        assert(nodes[1].lockunspent(False, [unspent[1]], True) == True)
        assert(len(nodes[1].listlockunspent()) == 2)
        # Restart node
        self.sync_all()
        self.stop_node(1)
        self.start_node(1, self.extra_args[1])
        connect_nodes_bi(self.nodes, 0, 1)
        assert(len(nodes[1].listlockunspent()) == 2)
        assert(len(nodes[1].listunspentanon()) < len(unspent))
        assert(nodes[1].lockunspent(True, [unspent[0]]) == True)
        assert_raises_rpc_error(-8, 'Invalid parameter, expected locked output', nodes[1].lockunspent, True, [unspent[0]])

        assert(len(nodes[1].listunspentanon()) == len(unspent)-1)
        assert(nodes[1].lockunspent(True) == True)
        assert(len(nodes[1].listunspentanon()) == len(unspent))
        assert(nodes[1].lockunspent(True) == True)

        ro = nodes[2].getblockstats(nodes[2].getblockchaininfo()['blocks'])
        assert(ro['height'] == 3)

        self.log.info('Test recover from mnemonic')
        # Txns currently in the mempool will be reprocessed in the next block
        self.stakeBlocks(1)
        wi_1 = nodes[1].getwalletinfo()

        nodes[1].createwallet('test_import')
        w1_2 = nodes[1].get_wallet_rpc('test_import')
        w1_2.extkeyimportmaster('drip fog service village program equip minute dentist series hawk crop sphere olympic lazy garbage segment fox library good alley steak jazz force inmate')
        w1_2.getnewstealthaddress('lblsx11')
        w1_2.rescanblockchain(0)
        wi_1_2 = w1_2.getwalletinfo()
        assert(wi_1_2['anon_balance'] == wi_1['anon_balance'])

        nodes[1].createwallet('test_import_locked')
        w1_3 = nodes[1].get_wallet_rpc('test_import_locked')
        w1_3.encryptwallet('test')

        assert_raises_rpc_error(-13, 'Error: Wallet locked, please enter the wallet passphrase with walletpassphrase first.', w1_3.filtertransactions, {'show_blinding_factors': True})
        assert_raises_rpc_error(-13, 'Error: Wallet locked, please enter the wallet passphrase with walletpassphrase first.', w1_3.filtertransactions, {'show_anon_spends': True})

        w1_3.walletpassphrase('test', 30)

        # Skip initial rescan by passing -1 as scan_chain_from
        w1_3.extkeyimportmaster('drip fog service village program equip minute dentist series hawk crop sphere olympic lazy garbage segment fox library good alley steak jazz force inmate',
            '', False, 'imported key', 'imported acc', -1)
        w1_3.getnewstealthaddress('lblsx11')
        w1_3.walletsettings('other', {'onlyinstance': False})
        w1_3.walletlock()
        assert(w1_3.getwalletinfo()['encryptionstatus'] == 'Locked')
        w1_3.rescanblockchain(0)

        w1_3.walletpassphrase('test', 30)

        wi_1_3 = w1_3.getwalletinfo()
        assert(wi_1_3['anon_balance'] == wi_1['anon_balance'])

        self.log.info('Test subfee edge case')
        unspents = nodes[0].listunspent()
        total_input = int(unspents[0]['amount'] * COIN) + int(unspents[1]['amount'] * COIN)
        total_output = total_input - 1

        coincontrol = {'test_mempool_accept': True, 'show_hex': True, 'show_fee': True, 'inputs': [{'tx': unspents[0]['txid'],'n': unspents[0]['vout']}, {'tx': unspents[1]['txid'],'n': unspents[1]['vout']}]}
        outputs = [{'address': sxAddrTo0_1, 'amount': '%i.%08i' % (total_output // COIN, total_output % COIN), 'narr': '', 'subfee' : True},]
        tx = nodes[0].sendtypeto('part', 'anon', outputs, 'comment', 'comment-to', 5, 1, False, coincontrol)
        assert(total_input == int(tx['fee'] * COIN) + int(tx['outputs_fee'][sxAddrTo0_1]))
        assert(tx['mempool-allowed'] == True)


if __name__ == '__main__':
    AnonTest().main()
