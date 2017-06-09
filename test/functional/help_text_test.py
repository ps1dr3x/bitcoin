#!/usr/bin/env python3
# Copyright (c) 2016 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test RPC commands for signing and verifying messages."""

import os

from subprocess import Popen, PIPE

from test_framework.test_framework import BitcoinTestFramework

class HelpTextTest(BitcoinTestFramework):

    def __init__(self):
        super().__init__()
        self.setup_clean_chain = True
        self.num_nodes = 1

    def run_test(self):
        commands = self.nodes[0].help().split("\n")
        
        # Check the help text of each command exists and contains the command itself
        for command in commands:
            cmd = command.split(" ")[0]
            if cmd != "==":
                help_text = self.nodes[0].help(cmd)
                assert("unknown command" not in help_text)
                assert(cmd in help_text)

        # Run bitcoind with help to check the bitcoind help text
        process = Popen([os.getenv("BITCOIND", "bitcoind"), "--help", "--help-debug"], stdout=PIPE)
        (output, err) = process.communicate()
        exit_code = process.wait()
        self.log.info(str(output))
        assert("Bitcoin Core Daemon" in str(output))
        assert("-dropmessagestest=" in str(output))
        
        # Run bitcoind with version to check the license info
        process = Popen([os.getenv("BITCOIND", "bitcoind"), "--version"], stdout=PIPE)
        (output, err) = process.communicate()
        self.log.info(str(output))
        exit_code = process.wait()
        assert("The Bitcoin Core developers" in str(output))
        assert("Copyright (C)" in str(output))
        

if __name__ == '__main__':
    HelpTextTest().main()
