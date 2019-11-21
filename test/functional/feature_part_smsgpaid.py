#!/usr/bin/env python3
# Copyright (c) 2017-2019 The Particl Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

import time
import json
import binascii

from test_framework.test_particl import (
    ParticlTestFramework,
    isclose,
    getIndexAtProperty,
)
from test_framework.util import assert_raises_rpc_error, connect_nodes, sync_mempools
from test_framework.authproxy import JSONRPCException


class SmsgPaidTest(ParticlTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 3
        self.extra_args = [ ['-debug','-noacceptnonstdtxn','-reservebalance=10000000'] for i in range(self.num_nodes) ]
        self.extra_args[2].append('-disablewallet')

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def setup_network(self, split=False):
        self.add_nodes(self.num_nodes, extra_args=self.extra_args)
        self.start_nodes()
        connect_nodes(self.nodes[0], 1)
        connect_nodes(self.nodes[0], 2)

        self.sync_all()

    def run_test(self):
        tmpdir = self.options.tmpdir
        nodes = self.nodes

        nodes[0].extkeyimportmaster(nodes[0].mnemonic('new')['master'])
        nodes[1].extkeyimportmaster('abandon baby cabbage dad eager fabric gadget habit ice kangaroo lab absorb')

        address0 = nodes[0].getnewaddress()  # Will be different each run
        address1 = nodes[1].getnewaddress()
        assert(address1 == 'pX9N6S76ZtA5BfsiJmqBbjaEgLMHpt58it')

        sx_addr0 = nodes[0].getnewstealthaddress()
        nodes[1].sendtypeto('part', 'part', [{'address':sx_addr0, 'amount':20},])

        ro = nodes[0].smsglocalkeys()
        assert(len(ro['wallet_keys']) == 0)

        ro = nodes[0].smsgaddlocaladdress(address0)
        assert('Receiving messages enabled for address' in ro['result'])

        ro = nodes[0].smsglocalkeys()
        assert(len(ro['wallet_keys']) == 1)

        ro = nodes[1].smsgaddaddress(address0, ro['wallet_keys'][0]['public_key'])
        assert(ro['result'] == 'Public key added to db.')


        text_1 = "['data':'test','value':1]"
        ro = nodes[1].smsgsend(address1, address0, text_1, True, 4, True)
        assert(ro['result'] == 'Not Sent.')
        assert(isclose(ro['fee'], 0.00086600))


        ro = nodes[1].smsgsend(address1, address0, text_1, True, 4)
        assert(ro['result'] == 'Sent.')

        self.stakeBlocks(1, nStakeNode=1)
        for i in range(20):
            nodes[0].sendtypeto('part', 'anon', [{'address':sx_addr0, 'amount':0.5},])
        self.waitForSmsgExchange(1, 1, 0)

        ro = nodes[0].smsginbox()
        assert(len(ro['messages']) == 1)
        assert(ro['messages'][0]['text'] == text_1)

        self.log.info('Test smsgimportprivkey and smsgdumpprivkey')
        test_privkey = '7pHSJFY1tNwi6d68UttGzB8YnXq2wFWrBVoadLv4Y6ekJD3L1iKs'
        address0_1 = 'pasdoMwEn35xQUXFvsChWAQjuG8rEKJQW9'
        nodes[0].smsgimportprivkey(test_privkey, 'smsg test key')
        assert(nodes[0].smsgdumpprivkey(address0_1) == test_privkey)

        text_2 = "['data':'test','value':2]"
        ro = nodes[0].smsglocalkeys()
        assert(len(ro['smsg_keys']) == 1)
        assert(ro['smsg_keys'][0]['address'] == address0_1)

        ro = nodes[1].smsgaddaddress(address0_1, ro['smsg_keys'][0]['public_key'])
        assert(ro['result'] == 'Public key added to db.')

        ro = nodes[1].smsgsend(address1, address0_1, text_2, True, 4)
        assert(ro['result'] == 'Sent.')

        self.stakeBlocks(1, nStakeNode=1)
        self.waitForSmsgExchange(2, 1, 0)

        ro = nodes[0].smsginbox()
        assert(len(ro['messages']) == 1)
        assert(ro['messages'][0]['text'] == text_2)

        nodes[0].encryptwallet('qwerty234')
        time.sleep(2)

        ro = nodes[0].getwalletinfo()
        assert(ro['encryptionstatus'] == 'Locked')

        localkeys0 = nodes[0].smsglocalkeys()
        assert(len(localkeys0['smsg_keys']) == 1)
        assert(len(localkeys0['wallet_keys']) == 1)
        assert(localkeys0['smsg_keys'][0]['address'] == address0_1)
        assert(localkeys0['wallet_keys'][0]['address'] == address0)

        text_3 = "['data':'test','value':3]"
        ro = nodes[0].smsglocalkeys()
        assert(len(ro['smsg_keys']) == 1)
        assert(ro['smsg_keys'][0]['address'] == address0_1)

        ro = nodes[1].smsgsend(address1, address0, 'Non paid msg')
        assert(ro['result'] == 'Sent.')

        ro = nodes[1].smsgsend(address1, address0_1, text_3, True, 4)
        assert(ro['result'] == 'Sent.')
        assert(len(ro['txid']) == 64)

        self.sync_all()
        self.stakeBlocks(1, nStakeNode=1)
        self.waitForSmsgExchange(4, 1, 0)

        msgid = ro['msgid']
        for i in range(5):
            try:
                ro = nodes[1].smsg(msgid)
                assert(ro['location'] == 'outbox')
                break
            except Exception as e:
                time.sleep(1)
        assert(ro['text'] == text_3)
        assert(ro['from'] == address1)
        assert(ro['to'] == address0_1)

        ro = nodes[0].walletpassphrase("qwerty234", 300)
        ro = nodes[0].smsginbox()
        assert(len(ro['messages']) == 2)
        flat = self.dumpj(ro)
        assert('Non paid msg' in flat)
        assert(text_3 in flat)

        ro = nodes[0].walletlock()

        ro = nodes[0].smsginbox("all")
        assert(len(ro['messages']) == 4)
        flat = self.dumpj(ro)
        assert(flat.count('Wallet is locked') == 2)


        ro = nodes[0].smsg(msgid)
        assert(ro['read'] == True)

        ro = nodes[0].smsg(msgid, {'setread':False})
        assert(ro['read'] == False)

        ro = nodes[0].smsg(msgid, {'delete':True})
        assert(ro['operation'] == 'Deleted')

        try:
            ro = nodes[0].smsg(msgid)
            assert(False), 'Read deleted msg.'
        except:
            pass

        ro = nodes[0].smsggetpubkey(address0_1)
        assert(ro['publickey'] == 'h2UfzZxbhxQPcXDfYTBRGSC7GM77qrLjhtqcmfAnAia9')


        filepath = tmpdir+'/sendfile.txt'
        msg = b"msg in file\0after null sep"
        with open(filepath, 'wb', encoding=None) as fp:
            fp.write(msg)

        sendoptions = {'fromfile': True}
        ro = nodes[1].smsgsend(address1, address0_1, filepath, True, 4, False, sendoptions)
        assert(ro['result'] == 'Sent.')
        msgid = ro['msgid']

        sendoptions = {'decodehex': True}
        ro = nodes[1].smsgsend(address1, address0_1, binascii.hexlify(msg).decode("utf-8"), True, 4, False, sendoptions)
        msgid2 = ro['msgid']
        self.stakeBlocks(1, nStakeNode=1)

        for i in range(5):
            try:
                ro = nodes[1].smsg(msgid, {'encoding':'hex'})
                assert(ro['location'] == 'outbox')
                break
            except:
                time.sleep(1)
        assert(msg == bytes.fromhex(ro['hex'][:-2]))  # Extra null byte gets tacked on

        for i in range(5):
            try:
                ro = nodes[1].smsg(msgid2, {'encoding':'hex'})
                assert(ro['location'] == 'outbox')
                break
            except:
                time.sleep(1)
        assert(msg == bytes.fromhex(ro['hex'][:-2]))
        assert(ro['daysretention'] == 4)


        ro = nodes[0].smsgoptions('list', True)
        assert(len(ro['options']) == 3)
        assert(len(ro['options'][0]['description']) > 0)

        ro = nodes[0].smsgoptions('set', 'newAddressAnon', 'false')
        assert('newAddressAnon = false' in json.dumps(ro))


        addr = nodes[0].getnewaddress('smsg test')
        pubkey = nodes[0].getaddressinfo(addr)['pubkey']
        ro = nodes[1].smsgaddaddress(addr, pubkey)
        assert('Public key added to db' in json.dumps(ro))

        # Wait for sync
        i = 0
        for i in range(10):
            ro = nodes[0].smsginbox('all')
            if len(ro['messages']) >= 5:
                break
            time.sleep(1)
        assert(i < 10)


        self.log.info('Test filtering')
        ro = nodes[0].smsginbox('all', "'vAlue':2")
        assert(len(ro['messages']) == 1)

        ro = nodes[1].smsgoutbox('all', "'vAlue':2")
        assert(len(ro['messages']) == 1)


        self.log.info('Test clear and rescan')
        ro = nodes[0].smsginbox('clear')
        assert('Deleted 5 messages' in ro['result'])

        ro = nodes[0].walletpassphrase("qwerty234", 300)
        ro = nodes[0].smsgscanbuckets()
        assert('Scan Buckets Completed' in ro['result'])

        ro = nodes[0].smsginbox('all')
        # Recover 5 + 1 dropped msg
        assert(len(ro['messages']) == 6)


        self.log.info('Test smsglocalkeys')
        addr = nodes[0].getnewaddress()

        ro = nodes[0].smsglocalkeys('recv','+', addr)
        assert('Address not found' in ro['result'])
        ro = nodes[0].smsglocalkeys('anon', '+', addr)
        assert('Address not found' in ro['result'])

        ro = nodes[0].smsgaddlocaladdress(addr)
        assert('Receiving messages enabled for address' in ro['result'])

        ro = nodes[0].smsglocalkeys('recv',  '-',addr)
        assert('Receive off' in ro['key'])
        assert(addr in ro['key'])

        ro = nodes[0].smsglocalkeys('anon', '-',addr)
        assert('Anon off' in ro['key'])
        assert(addr in ro['key'])

        ro = nodes[0].smsglocalkeys('all')

        n = getIndexAtProperty(ro['wallet_keys'], 'address', addr)
        assert(ro['wallet_keys'][n]['receive'] == '0')
        assert(ro['wallet_keys'][n]['anon'] == '0')

        self.log.info('Test smsgpurge')
        ro = nodes[0].smsg(msgid, {'encoding':'hex'})
        assert(ro['msgid'] == msgid)

        nodes[0].smsgpurge(msgid)

        try:
            nodes[0].smsg(msgid, {'encoding':'hex'})
            assert(False), 'Purged message in inbox'
        except JSONRPCException as e:
            assert('Unknown message id' in e.error['message'])

        ro = nodes[0].smsgbuckets()
        assert(int(ro['total']['numpurged']) == 1)
        # Sum all buckets
        num_messages = 0
        num_active = 0
        for b in ro['buckets']:
            num_messages += int(b['no. messages'])
            num_active += int(b['active messages'])
        assert(num_messages == num_active + 1)


        self.log.info('Test listunspent include_immature')
        without_immature = nodes[1].listunspent()

        with_immature = nodes[1].listunspent(query_options={'include_immature':True})
        assert(len(with_immature) > len(without_immature))


        self.log.info('Test encoding options')
        options = {'encoding': 'hex'}
        ro = nodes[0].smsginbox('all', '', options)
        assert(len(ro['messages']) == 5)
        for msg in ro['messages']:
            assert('hex' in msg)
        options = {'encoding': 'text'}
        ro = nodes[0].smsginbox('all', '', options)
        assert(len(ro['messages']) == 5)
        for msg in ro['messages']:
            assert('text' in msg)
        options = {'encoding': 'none'}
        ro = nodes[0].smsginbox('all', '', options)
        assert(len(ro['messages']) == 5)
        for msg in ro['messages']:
            assert('text' not in msg)
            assert('hex' not in msg)

        self.log.info('Test disablewallet')
        assert('SMSG' in self.dumpj(nodes[2].getnetworkinfo()['localservicesnames']))
        assert_raises_rpc_error(-32601, 'Method not found', nodes[2].getwalletinfo)
        for i in range(20):
            if nodes[0].smsgbuckets('total')['total']['messages'] != nodes[2].smsgbuckets('total')['total']['messages']:
                time.sleep(0.5)
                continue
            break
        assert(nodes[0].smsgbuckets('total')['total']['messages'] == nodes[2].smsgbuckets('total')['total']['messages'])

        self.log.info('Test smsggetinfo and smsgsetwallet')
        ro = nodes[0].smsggetinfo()
        assert(ro['enabled'] is True)
        assert(ro['active_wallet'] == '')
        assert_raises_rpc_error(-1, 'Wallet not found: "abc"', nodes[0].smsgsetwallet, 'abc')
        nodes[0].smsgsetwallet()
        ro = nodes[0].smsggetinfo()
        assert(ro['enabled'] is True)
        assert(ro['active_wallet'] == 'Not set.')
        nodes[0].createwallet('new_wallet')
        assert(len(nodes[0].listwallets()) == 2)
        nodes[0].smsgsetwallet('new_wallet')
        ro = nodes[0].smsggetinfo()
        assert(ro['enabled'] is True)
        assert(ro['active_wallet'] == 'new_wallet')
        nodes[0].smsgdisable()
        ro = nodes[0].smsggetinfo()
        assert(ro['enabled'] is False)
        nodes[0].smsgenable()
        ro = nodes[0].smsggetinfo()
        assert(ro['enabled'] is True)

        self.log.info('Test funding from RCT balance')
        nodes[1].smsginbox()  # Clear inbox
        ro = nodes[1].smsgaddlocaladdress(address1)
        assert('Receiving messages enabled for address' in ro['result'])

        msg = 'Test funding from RCT balance'
        sendoptions = {'fund_from_rct': True, 'rct_ring_size': 6}
        sent_msg = nodes[0].smsgsend(address0, address1, msg, True, 4, False, sendoptions)
        assert(sent_msg['result'] == 'Sent.')
        fund_tx = nodes[0].getrawtransaction(sent_msg['txid'], True)
        assert(fund_tx['vin'][0]['type'] == 'anon')

        ro = nodes[0].smsgoutbox('all', '', {'sending': True})
        assert(ro['messages'][0]['msgid'] == sent_msg['msgid'])

        sync_mempools([nodes[0], nodes[1]])
        self.stakeBlocks(1, nStakeNode=1)
        i = 0
        for i in range(20):
            ro = nodes[1].smsginbox()
            if len(ro['messages']) > 0:
                break
            time.sleep(1)
        assert(i < 19)
        assert(msg == ro['messages'][0]['text'])

        ro = nodes[0].smsgoutbox('all', '', {'sending': True})
        assert(len(ro['messages']) == 0)


if __name__ == '__main__':
    SmsgPaidTest().main()
