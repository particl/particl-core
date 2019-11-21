#!/usr/bin/env python3
# Copyright (c) 2017-2019 The Particl Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

from decimal import Decimal

from test_framework.test_particl import ParticlTestFramework, isclose, connect_nodes_bi
from test_framework.util import satoshi_round
from test_framework.authproxy import JSONRPCException


class MultiSigTest(ParticlTestFramework):
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

        ro = nodes[0].extkeyimportmaster('abandon baby cabbage dad eager fabric gadget habit ice kangaroo lab absorb')
        assert(ro['account_id'] == 'aaaZf2qnNr5T7PWRmqgmusuu5ACnBcX2ev')
        assert(nodes[0].getwalletinfo()['total_balance'] == 100000)

        addrs = []
        pubkeys = []

        ro = nodes[0].getnewaddress()
        addrs.append(ro)
        pubkeys.append(nodes[0].getaddressinfo(ro)['pubkey'])

        ro = nodes[0].getnewaddress()
        addrs.append(ro)
        pubkeys.append(nodes[0].getaddressinfo(ro)['pubkey'])

        nodes[1].extkeyimportmaster('drip fog service village program equip minute dentist series hawk crop sphere olympic lazy garbage segment fox library good alley steak jazz force inmate')
        nodes[2].extkeyimportmaster(nodes[2].mnemonic('new', '', 'french')['mnemonic'])

        ro = nodes[1].getnewaddress()
        addrs.append(ro)
        pubkeys.append(nodes[1].getaddressinfo(ro)['pubkey'])

        ro = nodes[2].getnewaddress()
        addrs.append(ro)
        pubkeys.append(nodes[2].getaddressinfo(ro)['pubkey'])


        v = [addrs[0], addrs[1], pubkeys[2]]
        msAddr = nodes[0].addmultisigaddress(2, v)['address']

        ro = nodes[0].getaddressinfo(msAddr)
        assert(ro['isscript'] == True)
        scriptPubKey = ro['scriptPubKey']
        redeemScript = ro['hex']


        mstxid = nodes[0].sendtoaddress(msAddr, 10)
        hexfund = nodes[0].gettransaction(mstxid)['hex']
        ro = nodes[0].decoderawtransaction(hexfund)

        fundscriptpubkey = ''
        fundoutid = -1
        for vout in ro['vout']:
            if not isclose(vout['value'], 10.0):
                continue

            fundoutid = vout['n']
            fundscriptpubkey = vout['scriptPubKey']['hex']
        assert(fundoutid >= 0), "fund output not found"


        addrTo = nodes[2].getnewaddress()

        inputs = [{
            "txid":mstxid,
            "vout":fundoutid,
            "scriptPubKey":fundscriptpubkey,
            "redeemScript":redeemScript,
            "amount":10.0,
            }]

        outputs = {addrTo:2, msAddr:7.99}

        hexRaw = nodes[0].createrawtransaction(inputs, outputs)

        vk0 = nodes[0].dumpprivkey(addrs[0])
        signkeys = [vk0,]
        hexRaw1 = nodes[0].signrawtransactionwithkey(hexRaw, signkeys, inputs)['hex']

        vk1 = nodes[0].dumpprivkey(addrs[1])
        signkeys = [vk1,]
        hexRaw2 = nodes[0].signrawtransactionwithkey(hexRaw1, signkeys, inputs)['hex']

        txnid_spendMultisig = nodes[0].sendrawtransaction(hexRaw2)


        self.stakeBlocks(1)
        block1_hash = nodes[0].getblockhash(1)
        ro = nodes[0].getblock(block1_hash)
        assert(txnid_spendMultisig in ro['tx'])


        msAddr256 = nodes[0].addmultisigaddress(2, v, "", False, True)['address']
        ro = nodes[0].getaddressinfo(msAddr256)
        assert(ro['isscript'] == True)

        msAddr256 = nodes[0].addmultisigaddress(2, v, "", True, True)['address']
        assert(msAddr256 == "tpj1vtll9wnsd7dxzygrjp2j5jr5tgrjsjmj3vwjf7vf60f9p50g5ddqmasmut")

        ro = nodes[0].getaddressinfo(msAddr256)
        assert(ro['isscript'] == True)
        scriptPubKey = ro['scriptPubKey']
        redeemScript = ro['hex']

        mstxid2 = nodes[0].sendtoaddress(msAddr256, 9)
        hexfund = nodes[0].gettransaction(mstxid2)['hex']
        ro = nodes[0].decoderawtransaction(hexfund)

        fundscriptpubkey = ''
        fundoutid = -1
        for vout in ro['vout']:
            if not isclose(vout['value'], 9.0):
                continue
            fundoutid = vout['n']
            fundscriptpubkey = vout['scriptPubKey']['hex']
            assert('OP_SHA256' in vout['scriptPubKey']['asm'])
        assert(fundoutid >= 0), "fund output not found"


        inputs = [{
            "txid":mstxid2,
            "vout":fundoutid,
            "scriptPubKey":fundscriptpubkey,
            "redeemScript":redeemScript,
            "amount":9.0, # Must specify amount
            }]

        addrTo = nodes[2].getnewaddress()
        outputs = {addrTo:2, msAddr256:6.99}

        hexRaw = nodes[0].createrawtransaction(inputs, outputs)

        vk0 = nodes[0].dumpprivkey(addrs[0])
        signkeys = [vk0,]
        hexRaw1 = nodes[0].signrawtransactionwithkey(hexRaw, signkeys, inputs)['hex']

        vk1 = nodes[0].dumpprivkey(addrs[1])
        signkeys = [vk1,]
        hexRaw2 = nodes[0].signrawtransactionwithkey(hexRaw1, signkeys, inputs)['hex']

        txnid_spendMultisig2 = nodes[0].sendrawtransaction(hexRaw2)

        self.stakeBlocks(1)
        block2_hash = nodes[0].getblockhash(2)
        ro = nodes[0].getblock(block2_hash)
        assert(txnid_spendMultisig2 in ro['tx'])

        ro = nodes[0].getaddressinfo(msAddr)
        scriptPubKey = ro['scriptPubKey']
        redeemScript = ro['hex']

        opts = {"recipe":"abslocktime","time":946684800,"addr":msAddr}
        scriptTo = nodes[0].buildscript(opts)['hex']

        outputs = [{'address':'script', 'amount':8, 'script':scriptTo},]
        mstxid3 = nodes[0].sendtypeto('part', 'part', outputs)

        hexfund = nodes[0].gettransaction(mstxid3)['hex']
        ro = nodes[0].decoderawtransaction(hexfund)

        fundscriptpubkey = ''
        fundoutid = -1
        for vout in ro['vout']:
            if not isclose(vout['value'], 8.0):
                continue
            fundoutid = vout['n']
            fundscriptpubkey = vout['scriptPubKey']['hex']
            assert('OP_CHECKLOCKTIMEVERIFY' in vout['scriptPubKey']['asm'])
        assert(fundoutid >= 0), "fund output not found"


        inputs = [{
            "txid":mstxid3,
            "vout":fundoutid,
            "scriptPubKey":fundscriptpubkey,
            "redeemScript":redeemScript,
            "amount":8.0, # Must specify amount
            }]

        addrTo = nodes[2].getnewaddress()
        outputs = {addrTo:2, msAddr:5.99}
        locktime = 946684801

        hexRaw = nodes[0].createrawtransaction(inputs, outputs, locktime)

        vk0 = nodes[0].dumpprivkey(addrs[0])
        signkeys = [vk0,]
        hexRaw1 = nodes[0].signrawtransactionwithkey(hexRaw, signkeys, inputs)['hex']

        vk1 = nodes[0].dumpprivkey(addrs[1])
        signkeys = [vk1,]
        hexRaw2 = nodes[0].signrawtransactionwithkey(hexRaw1, signkeys, inputs)['hex']

        txnid_spendMultisig3 = nodes[0].sendrawtransaction(hexRaw2)

        self.stakeBlocks(1)
        block3_hash = nodes[0].getblockhash(3)
        ro = nodes[0].getblock(block3_hash)
        assert(txnid_spendMultisig3 in ro['tx'])


        self.log.info("Coldstake script")

        stakeAddr = nodes[0].getnewaddress()
        addrTo = nodes[0].getnewaddress()

        opts = {"recipe":"ifcoinstake","addrstake":stakeAddr,"addrspend":msAddr}
        scriptTo = nodes[0].buildscript(opts)['hex']

        outputs = [{ 'address':'script', 'amount':1, 'script':scriptTo }]
        txFundId = nodes[0].sendtypeto('part', 'part', outputs)
        hexfund = nodes[0].gettransaction(txFundId)['hex']

        ro = nodes[0].decoderawtransaction(hexfund)
        for vout in ro['vout']:
            if not isclose(vout['value'], 1.0):
                continue
            fundoutn = vout['n']
            fundscriptpubkey = vout['scriptPubKey']['hex']
            assert('OP_ISCOINSTAKE' in vout['scriptPubKey']['asm'])
        assert(fundoutn >= 0), "fund output not found"

        ro = nodes[0].getaddressinfo(msAddr)
        assert(ro['isscript'] == True)
        scriptPubKey = ro['scriptPubKey']
        redeemScript = ro['hex']

        inputs = [{
            'txid': txFundId,
            'vout': fundoutn,
            'scriptPubKey': fundscriptpubkey,
            'redeemScript': redeemScript,
            'amount': 1.0,
            }]

        outputs = {addrTo:0.99}
        hexRaw = nodes[0].createrawtransaction(inputs, outputs)

        sig0 = nodes[0].createsignaturewithwallet(hexRaw, inputs[0], addrs[0])
        sig1 = nodes[0].createsignaturewithwallet(hexRaw, inputs[0], addrs[1])


        self.log.info('Test createsignaturewithwallet without providing prevout details')
        outpoint_only = { 'txid': txFundId, 'vout': fundoutn }
        sig1_check1 = nodes[0].createsignaturewithwallet(hexRaw, outpoint_only, addrs[1])
        assert(sig1 == sig1_check1)
        addr1_privkey = nodes[0].dumpprivkey(addrs[1])
        sig1_check2 = nodes[0].createsignaturewithkey(hexRaw, inputs[0], addr1_privkey)
        assert(sig1 == sig1_check2)
        try:
            sig1_check3 = nodes[0].createsignaturewithkey(hexRaw, outpoint_only, addr1_privkey)
            assert(False), 'createsignaturewithkey passed with no redeemscript'
        except JSONRPCException as e:
            assert('"redeemScript" is required' in e.error['message'])
        outpoint_only['redeemScript'] = redeemScript
        sig1_check3 = nodes[0].createsignaturewithkey(hexRaw, outpoint_only, addr1_privkey)
        assert(sig1 == sig1_check3)


        witnessStack = [
            "",
            sig0,
            sig1,
            redeemScript,
        ]
        hexRawSigned = nodes[0].tx([hexRaw,'witness=0:'+ ':'.join(witnessStack)])

        ro = nodes[0].verifyrawtransaction(hexRawSigned)
        assert(ro['complete'] == True)

        ro = nodes[0].signrawtransactionwithwallet(hexRaw)
        assert(ro['complete'] == True)
        assert(ro['hex'] == hexRawSigned)

        txid = nodes[0].sendrawtransaction(hexRawSigned)

        self.stakeBlocks(1)
        block4_hash = nodes[0].getblockhash(4)
        ro = nodes[0].getblock(block4_hash)
        assert(txid in ro['tx'])


        self.log.info("Test combinerawtransaction")
        unspent0 = nodes[0].listunspent()
        unspent2 = nodes[2].listunspent()

        inputs = [unspent0[0], unspent2[0]]
        outputs = {nodes[0].getnewaddress() : satoshi_round(unspent0[0]['amount'] + unspent2[0]['amount'] - Decimal(0.1))}
        rawtx = nodes[0].createrawtransaction(inputs, outputs)

        rawtx0 = nodes[0].signrawtransactionwithwallet(rawtx)
        assert(rawtx0['complete'] == False)

        rawtx2 = nodes[2].signrawtransactionwithwallet(rawtx0['hex']) # Keeps signature from node0
        assert(rawtx2['complete'])

        rawtx2 = nodes[2].signrawtransactionwithwallet(rawtx)
        assert(rawtx2['complete'] == False)

        rawtx_complete = nodes[0].combinerawtransaction([rawtx0['hex'], rawtx2['hex']])
        nodes[0].sendrawtransaction(rawtx_complete)


if __name__ == '__main__':
    MultiSigTest().main()
