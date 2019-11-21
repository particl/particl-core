#!/usr/bin/env python3
# Copyright (c) 2016-2018 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test RPC commands for signing and verifying messages."""

from test_framework.test_particl import ParticlTestFramework
from test_framework.util import assert_equal

class SignMessagesTest(ParticlTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1
        self.extra_args = [[]]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def setup_network(self, split=False):
        self.add_nodes(self.num_nodes, extra_args=self.extra_args)
        self.start_nodes()

    def run_test(self):
        self.nodes[0].extkeyimportmaster('abandon baby cabbage dad eager fabric gadget habit ice kangaroo lab absorb')

        message = 'This is just a test message'

        self.log.info('test signing with priv_key')
        priv_key = '7shnesmjFcQZoxXCsNV55v7hrbQMtBfMNscuBkYrLa1mcJNPbXhU'
        address = 'pX9N6S76ZtA5BfsiJmqBbjaEgLMHpt58it'
        expected_signature = 'H/ededxXrX9m9uygWRZyfdpEKiKbsHpXZtdWqM1BP+AfDZVV1y0YRcOsGmyKEmDoD7R8Tqa2ptk3XAm71ELGZLo='
        signature = self.nodes[0].signmessagewithprivkey(priv_key, message)
        assert_equal(expected_signature, signature)
        assert(self.nodes[0].verifymessage(address, signature, message))

        self.log.info('test signing with an address with wallet')
        address = self.nodes[0].getnewaddress()
        signature = self.nodes[0].signmessage(address, message)
        assert(self.nodes[0].verifymessage(address, signature, message))

        self.log.info('test signing with a 256bit address with wallet')
        address = self.nodes[0].getnewaddress('', False, False, True)
        signature = self.nodes[0].signmessage(address, message)
        assert(self.nodes[0].verifymessage(address, signature, message))

        self.log.info('test verifying with another address should not work')
        other_address = self.nodes[0].getnewaddress()
        other_signature = self.nodes[0].signmessage(other_address, message)
        assert(not self.nodes[0].verifymessage(other_address, signature, message))
        assert(not self.nodes[0].verifymessage(address, other_signature, message))


if __name__ == '__main__':
    SignMessagesTest().main()
