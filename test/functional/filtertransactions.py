#!/usr/bin/env python3
# Copyright (c) 2017 The Particl Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

from test_framework.test_particl import ParticlTestFramework
from test_framework.test_particl import isclose
from test_framework.util import *
from test_framework.address import *

import json

class FilterTransactionsTest(ParticlTestFramework):
    def __init__(self):
        super().__init__()
        self.setup_clean_chain = True
        self.num_nodes = 3
        self.extra_args = [ [ '-debug' ] for i in range(self.num_nodes) ]

    def setup_network(self, split=False):
        self.nodes = self.start_nodes(self.num_nodes, self.options.tmpdir, self.extra_args)
        connect_nodes_bi(self.nodes, 0, 1)
        connect_nodes_bi(self.nodes, 0, 2)
        connect_nodes_bi(self.nodes, 1, 2)
        self.is_network_split = False
        self.sync_all()

    def run_test(self):
        nodes = self.nodes

        # import keys for node wallets
        nodes[0].extkeyimportmaster('abandon baby cabbage dad eager fabric gadget habit ice kangaroo lab absorb')
        nodes[1].extkeyimportmaster('drip fog service village program equip minute dentist series hawk crop sphere olympic lazy garbage segment fox library good alley steak jazz force inmate')
        nodes[2].extkeyimportmaster('sección grito médula hecho pauta posada nueve ebrio bruto buceo baúl mitad')

        # create addresses
        selfAddress    = nodes[0].getnewaddress('self')
        selfAddress2   = nodes[0].getnewaddress('self2')
        selfStealth    = nodes[0].getnewstealthaddress('stealth')
        selfSpending   = nodes[0].getnewaddress('spending', 'false', 'false', 'true')
        selfExternal   = nodes[0].getnewextaddress('external')
        targetAddress  = nodes[1].getnewaddress('target')
        targetStealth  = nodes[1].getnewstealthaddress('taret stealth')
        targetExternal = nodes[1].getnewextaddress('target external')
        stakingAddress = nodes[2].getnewaddress('staking')
        
        # simple PART transaction
        nodes[0].sendtoaddress(targetAddress, 10)
        self.sync_all()
        nodes[1].sendtoaddress(selfAddress, 8)

        # PART to BLIND
        nodes[0].sendparttoblind(
            selfStealth,          # address
            20,                   # amount
            '',                   # ?
            '',                   # ?
            False,                # substract fee
            'node0 -> node0 p->b' # narrative
        )

        # PART to ANON
        nodes[0].sendparttoanon(
            targetStealth,        # address
            20,                   # amount
            '',                   # ?
            '',                   # ?
            False,                # substract fee
            'node0 -> node1 p->a' # narrative
        )

        # several outputs
        nodes[0].sendtypeto(
            'part',               # type in
            'part',               # type out
            [                     # outputs
                {
                    'address':    selfAddress,
                    'amount':     1,
                    'narr':       'output 1'
                },
                {
                    'address':    selfAddress2,
                    'amount':     2,
                    'narr':       'output 2'
                }
            ]
        )

        # cold staking: watchonly
        script = nodes[0].buildscript(
            {
                'recipe':        'ifcoinstake',
                'addrstake':     stakingAddress,
                'addrspend':     selfSpending
            }
        )
        nodes[0].sendtypeto(
            'part',              # type in
            'part',              # type out
            [                    # outputs
                {
                    'address':   'script',
                    'amount':    200,
                    'script':    script['hex'],
                    'narr':      'activating cold staking'
                }
            ]
        )
        txid = nodes[0].sendtoaddress(selfSpending, 100)
        nodes[0].sendtypeto(
            'part',              # type in
            'part',              # type out
            [                    # outputs
                {
                    'address':   targetAddress,
                    'amount':    7,
                    'narr':      'watchonly transaction'
                }
            ],
            '',                  # comment
            '',                  # comment_to
            0,                   # ring size
            0,                   # inputs per sig
            False,               # test fee
            {                    # coincontrol
                'changeaddress': selfAddress,
                'inputs':        [{ 'tx': txid, 'n': 1 }],
                'replaceable':   False,
                'conf_target':   1,
                'estimate_mode': 'CONSERVATIVE'
            }
        )
        
        ro = nodes[0].scanchain()
        self.stakeBlocks(1)
        self.sync_all()
        
        # ro = nodes[0].filtertransactions({'count': 20})
        # print(json.dumps(ro, indent=4, default=self.jsonDecimal))

        #
        # general
        #
        
        # without argument
        ro = nodes[0].filtertransactions()
        assert(len(ro) == 10)
        
        # too much arguments
        try:
            nodes[0].filtertransactions('foo', 'bar')
            assert(False)
        except JSONRPCException as e:
            assert('filtertransactions' in e.error['message'])

        #
        # count
        #

        # count: 0 => JSONRPCException
        try:
            nodes[0].filtertransactions({ 'count': 0 })
            assert(False)
        except JSONRPCException as e:
            assert('Invalid count' in e.error['message'])

        # count: -1 => JSONRPCException
        try:
            nodes[0].filtertransactions({ 'count': -1 })
            assert(False)
        except JSONRPCException as e:
            assert('Invalid count' in e.error['message'])

        # count: 1
        ro = nodes[0].filtertransactions({ 'count': 1 })
        assert(len(ro) == 1)

        #
        # skip
        #

        # skip: -1 => JSONRPCException
        try:
            nodes[0].filtertransactions({ 'skip': -1 })
            assert(False)
        except JSONRPCException as e:
            assert('Invalid skip' in e.error['message'])

        # skip = count => no entry
        ro = nodes[0].filtertransactions({ 'count': 50 })
        ro = nodes[0].filtertransactions({ 'skip': len(ro) })
        assert(len(ro) == 0)

        # skip == count - 1 => one entry
        ro = nodes[0].filtertransactions({ 'count': 50 })
        ro = nodes[0].filtertransactions({ 'skip': len(ro) - 1 })
        assert(len(ro) == 1)

        # skip: 1
        ro = nodes[0].filtertransactions({ 'category': 'send', 'skip': 1 })
        assert(float(ro[0]['amount']) == -20.0)

        #
        # include_watchonly
        #

        ro = nodes[2].filtertransactions({ 'watchonly': False })
        assert(len(ro) == 0)
        ro = nodes[2].filtertransactions({ 'watchonly': True })
        assert(len(ro) == 1)

        #
        # search
        #

        queries = [
            [targetAddress, 2],
            [selfStealth,   1],
            ['70000',       1]
        ]

        for query in queries:
            ro = nodes[0].filtertransactions({ 'search': query[0] })
            assert(len(ro) == query[1])

        #
        # category
        #
        
        # 'orphan' transactions
        # 'immature' transactions
        # 'orphaned_stake' transactions

        categories = [
            ['internal_transfer', 4],
            ['coinbase',          1],
            ['send',              3],
            ['receive',           1],
            ['stake',             0]
        ]

        for category in categories:
            ro = nodes[0].filtertransactions({ 'category': category[0] })
            for t in ro:
                assert(t['category'] == category[0])
            if (category[0] != 'stake'):
                assert(len(ro) == category[1])
        
        # category 'all'
        length = len(nodes[0].filtertransactions())
        ro = nodes[0].filtertransactions({ 'category': 'all' })
        assert(len(ro) == length)
        
        # invalid transaction category
        try:
            ro = nodes[0].filtertransactions({ 'category': 'invalid' })
            assert(False)
        except JSONRPCException as e:
            assert('Invalid category' in e.error['message'])

        #
        # sort
        #
        
        sortings = [
            [ 'time',          'desc' ],
            [ 'address',        'asc' ],
            [ 'category',       'asc' ],
            [ 'amount',        'desc' ],
            [ 'confirmations', 'desc' ],
            [ 'txid',           'asc' ]
        ]
        
        for sorting in sortings:
            ro = nodes[0].filtertransactions({ 'sort': sorting[0] })
            prev = None
            for t in ro:
                if "address" not in t:
                    t["address"] = t["outputs"][0]["address"]
                if t["amount"] < 0:
                    t["amount"] = -t["amount"]
                if prev is not None:
                    if sorting[1] == 'asc':
                        assert(t[sorting[0]] >= prev[sorting[0]])
                    if sorting[1] == 'desc':
                        assert(t[sorting[0]] <= prev[sorting[0]])
                prev = t

        # invalid sort
        try:
            ro = nodes[0].filtertransactions({ 'sort': 'invalid' })
            assert(False)
        except JSONRPCException as e:
            assert('Invalid sort' in e.error['message'])

if __name__ == '__main__':
    FilterTransactionsTest().main()
