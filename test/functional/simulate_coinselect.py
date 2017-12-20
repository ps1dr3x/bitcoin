#!/usr/bin/env python3
# Copyright (c) 2014-2016 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test the wallet."""
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import *
from collections import deque
from statistics import mean, stdev
from decimal import *

class CoinSelectionSimulation(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 7
        self.setup_clean_chain = True
        self.extra_args = [["-dustrelayfee=0", "-walletrejectlongchains=1"], ["-dustrelayfee=0", "-walletrejectlongchains=1"], ["-dustrelayfee=0", "-walletrejectlongchains=1"], ["-dustrelayfee=0", "-walletrejectlongchains=1"], ["-dustrelayfee=0", "-walletrejectlongchains=1"], ["-dustrelayfee=0", "-walletrejectlongchains=1"], ["-dustrelayfee=0", "-walletrejectlongchains=1"]]

    def setup_network(self, split=False):
        self.setup_nodes()
        connect_nodes(self.nodes[0], 1)
        connect_nodes(self.nodes[0], 2)
        connect_nodes(self.nodes[0], 3)
        connect_nodes(self.nodes[0], 4)
        connect_nodes(self.nodes[0], 5)
        connect_nodes(self.nodes[0], 6)
        self.sync_all()

    def run_test(self):
        # Decimal precision
        getcontext().prec = 8

        # Check that there's no UTXO on none of the nodes
        assert_equal(len(self.nodes[0].listunspent()), 0)
        assert_equal(len(self.nodes[1].listunspent()), 0)
        assert_equal(len(self.nodes[2].listunspent()), 0)
        assert_equal(len(self.nodes[3].listunspent()), 0)
        assert_equal(len(self.nodes[4].listunspent()), 0)
        assert_equal(len(self.nodes[5].listunspent()), 0)
        assert_equal(len(self.nodes[6].listunspent()), 0)

        self.log.info("Mining blocks for node0 to be able to send enough coins")

        self.nodes[0].generate(500)
        withdraw_address = self.nodes[0].getnewaddress()

        # Load fees
        files = ['fees-bitcoinfees-info-repeats.csv', 'fees-bitcoinfees-info-cycle.csv']
        for FEES_FILE in files:
            files = ['derived-1I-2O.csv', 'derived-balanced.csv', 'moneypot.csv']
            for i, FILENAME in enumerate(files, start=1):
                fees = []
                with open(FEES_FILE) as f:
                    for line in f:
                        fees.append(int(line))

                self.log.info("Simulating using " + FILENAME)
                deposit_address = self.nodes[i].getnewaddress()
                with open(FILENAME) as f:
                    total_fees = Decimal()
                    withdraw_queue = deque()
                    ops = 0
                    count_sent = 0
                    count_received = 0
                    change_vals = []
                    withdraws = 0
                    input_sizes = []
                    utxo_set_sizes = []
                    total_send = 0
                    total_deposited = 0
                    for line in f:
                        if ops % 500 == 0:
                            self.log.info(str(ops) + " operations performed so far")

                        # Mine blocks if there are 20 or more txs in the mempool
                        if self.nodes[0].getmempoolinfo()['size'] >= 20:
                            self.nodes[0].generate(6)
                            #self.sync_all()

                        # Check if we can withdraw the next thing in the queue
                        self.log.debug(self.nodes[i].getbalance())
                        if len(withdraw_queue) > 0:
                            if withdraw_queue[0] < self.nodes[i].getbalance():
                                # Mine the blocks and sync before each withdraw and only if the nodes have empty mempools
                                if self.nodes[0].getmempoolinfo()['size'] > 0:
                                    self.nodes[0].generate(6)
                                    #self.sync_all()

                                # Do the withdraw
                                withdraw_val = withdraw_queue.popleft()
                                self.log.debug("Withdrawing " + str(withdraw_val))
                                try:
                                    # Set the fee
                                    self.nodes[i].settxfee(float(fees.pop(0)/100000000))
                                    txid = self.nodes[i].sendtoaddress(withdraw_address, withdraw_val)
                                    withdraws += 1
                                    utxo_set_sizes.append(len(self.nodes[i].listunspent(0)))
                                    # Get fee info
                                    gettx = self.nodes[i].gettransaction(txid)
                                    total_fees += gettx['fee']
                                    total_send += gettx['amount']
                                    # Info about tx itself
                                    decoded_tx = self.nodes[i].decoderawtransaction(gettx['hex'])
                                    # Spend utxo counts and input info
                                    count_sent += len(decoded_tx['vin'])
                                    input_sizes.append(len(decoded_tx['vin']))
                                    # Change info
                                    if len(decoded_tx['vout']) > 1:
                                        for out in decoded_tx['vout']:
                                            if out['scriptPubKey']['addresses'][0] != withdraw_address:
                                                change_vals.append(out['value'])
                                except JSONRPCException as e:
                                    if -4 != e.error["code"]:
                                        raise e

                        # Make deposit or queue next withdraw
                        value = float(int(line)/100000000)
                        if value > 0:
                            # deposit
                            self.log.debug("Depositing " + str(value))
                            self.nodes[0].sendtoaddress(deposit_address, value)
                            utxo_set_sizes.append(len(self.nodes[i].listunspent(0)))
                            count_received += 1
                            total_deposited += value
                        if value < 0:
                            # Add withdraw to queue
                            value = value * -1
                            self.log.debug("Queueing " + str(value))
                            withdraw_queue.append(value)
                        ops += 1

                self.nodes[0].generate(6)
                self.sync_all()

                unwithdrawn = []
                while len(withdraw_queue) > 0:
                    if withdraw_queue[0] < self.nodes[i].getbalance():
                        # Mine the blocks and sync before each withdraw and only if the nodes have empty mempools
                        if self.nodes[0].getmempoolinfo()['size'] > 0:
                            self.nodes[0].generate(6)
                            #self.sync_all()

                        # Do the withdraw
                        withdraw_val = withdraw_queue.popleft()
                        self.log.debug("Withdrawing " + str(withdraw_val))
                        try:
                            # Set the fee
                            self.nodes[i].settxfee(float(fees.pop(0)/100000000))
                            txid = self.nodes[i].sendtoaddress(withdraw_address, withdraw_val)
                            withdraws += 1
                            utxo_set_sizes.append(len(self.nodes[i].listunspent(0)))
                            # Get fee info
                            gettx = self.nodes[i].gettransaction(txid)
                            total_fees += gettx['fee']
                            total_send += gettx['amount']
                            # Info about tx itself
                            decoded_tx = self.nodes[i].decoderawtransaction(gettx['hex'])
                            # Spend utxo counts and input info
                            count_sent += len(decoded_tx['vin'])
                            input_sizes.append(len(decoded_tx['vin']))
                            # Change info
                            if len(decoded_tx['vout']) > 1:
                                for out in decoded_tx['vout']:
                                    if out['scriptPubKey']['addresses'][0] != withdraw_address:
                                        change_vals.append(out['value'])
                        except JSONRPCException as e:
                            if -4 != e.error["code"]:
                                raise e
                    else:
                        unwithdrawn.append(withdraw_queue.popleft())

                self.nodes[0].generate(6)
                self.sync_all()

                print(str(len(unwithdrawn)) + " Unsent payments: " + str(unwithdrawn))

                # Find change stats
                if len(change_vals) > 0:
                    change_vals = sorted(change_vals)
                    min_change = Decimal(change_vals[0])
                    max_change = Decimal(change_vals[-1])
                    mean_change = Decimal(mean(change_vals))
                    stdev_change = Decimal(stdev(change_vals))
                else:
                    min_change = 0
                    max_change = 0
                    mean_change = 0
                    stdev_change = 0

                # Remaining utxos and fee stats
                remaining_utxos = self.nodes[i].listunspent()
                cost_to_empty = Decimal(-1 * len(remaining_utxos) * 148 * 0.00001 / 1000)
                total_cost = total_fees + cost_to_empty

                # input stats
                input_sizes = sorted(input_sizes)
                min_input_size = Decimal(input_sizes[0])
                max_input_size = Decimal(input_sizes[-1])
                mean_input_size = Decimal(mean(input_sizes))
                stdev_input_size = Decimal(stdev(input_sizes))

                # Print stuff
                self.log.info("| final value | total sent | total deposited | mean #UTXO | final #UTXO | #received | #spent | #payments sent |"
                    + "#changes created | min change | max change | mean change | stDev of change | "
                    + "total fees | average fees | fees to spend remaining UTXO | total cost | "
                    + "min input set | max input set | mean size of input set | stdev of input set size | Fees file | Simulation File |")
                self.log.info(" | " + str(self.nodes[i].getbalance()) + " | " + str(total_send) + " | " + str(total_deposited) + " | " + str(Decimal(mean(utxo_set_sizes))) + " | " + str(len(remaining_utxos)) + " | " + str(count_received) + " | " + str(count_sent) + " | " + str(withdraws) + " | " 
                    + str(len(change_vals)) + " | " + str(min_change) + " | " + str(max_change) + " | " + str(mean_change) + " | " + str(stdev_change) + " | "
                    + str(total_fees) + " | " + str(total_fees / withdraws) + " | " + str(cost_to_empty) + " | " + str(total_cost) + " | "
                    + str(min_input_size) + " | " + str(max_input_size) + " | " + str(mean_input_size) + " | " + str(stdev_input_size) + " | " + str(FEES_FILE) + " | " + str(FILENAME) + " |")

if __name__ == '__main__':
    CoinSelectionSimulation().main()
