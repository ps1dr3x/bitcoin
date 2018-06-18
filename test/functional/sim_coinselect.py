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
import pprint

class CoinSelectionSimulation(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True
        self.extra_args = [["-dustrelayfee=0"], ["-dustrelayfee=0", "-deprecatedrpc=accounts"]]

    def setup_network(self, split=False):
        self.setup_nodes()
        connect_nodes(self.nodes[0], 1)
        self.sync_all()

    def add_options(self, parser):
        parser.add_option("--utxo-file", dest="utxo_file", help="Initial UTXOs", default="")

    def run_test(self):
        # Decimal precision
        getcontext().prec = 12

        # Check that there's no UTXO on none of the nodes
        assert_equal(len(self.nodes[0].listunspent()), 0)
        assert_equal(len(self.nodes[1].listunspent()), 0)

        self.log.info("Mining blocks for node0 to be able to send enough coins")

        self.nodes[0].generate(500)
        withdraw_address = self.nodes[0].getnewaddress()
        deposit_address = self.nodes[1].getnewaddress()

        if len(self.args) != 1:
            self.log.error("Not enough arguments")
            return
        scenario = self.args[0]

        if self.options.utxo_file != "":
            self.log.info("Generating UTXOs")
            with open(self.options.utxo_file) as f:
                for i, line in enumerate(f):
                    if i % 500 == 0:
                        self.log.info("{} utxos created so far".format(i))
                    value = float(int(line.strip())/100000000)
                    self.nodes[0].sendtoaddress(deposit_address, value)
                    # Mine blocks if there are 20 or more txs in the mempool
                    if self.nodes[0].getmempoolinfo()['size'] >= 20:
                        blocks = self.nodes[0].generate(6)
        self.sync_all()

        self.log.info("Simulating using scenario: {}".format(scenario))
        payments = 0
        with open(scenario) as f:
            total_fees = Decimal()
            ops = 0
            count_sent = 0
            change_vals = []
            withdraws = 0
            input_sizes = []
            utxo_set_sizes = []
            count_change = 0
            count_received = 0;
            for line in f:
                if ops % 500 == 0:
                    if utxo_set_sizes:
                        self.log.info("{} operations performed so far, current mean # utxo {:.2f}".format(ops, Decimal(mean(utxo_set_sizes))))
                    else:
                        self.log.info("{} operations performed so far".format(ops))

                # Mine blocks if there are 20 or more txs in the mempool
                if self.nodes[0].getmempoolinfo()['size'] >= 20:
                    blocks = self.nodes[0].generate(6)
                    self.nodes[1].waitforblock(blocks[-1])

                # Make deposit or withdrawal
                line_info = line.strip().split(',')
                value = float(int(line_info[0])/100000000)
                if value > 0:
                    # deposit
                    self.nodes[0].sendtoaddress(deposit_address, value)
                    count_received += 1
                    self.log.debug("{}: Deposited {}, balance is now {}".format(ops, value, self.nodes[1].getbalance("", 0)))
                if value < 0:
                    # Withdraw
                    value = value * -1
                    # Mine the blocks and sync before each withdraw and only if the nodes have empty mempools
                    if self.nodes[0].getmempoolinfo()['size'] > 0:
                        blocks = self.nodes[0].generate(6)
                        self.nodes[1].waitforblock(blocks[-1])
                    prev_bal = self.nodes[1].getbalance() - total_fees
                    # Set the fee
                    tx_feerate = int(float(line_info[1]))/100000
                    self.nodes[1].settxfee(tx_feerate)
                    txid = self.nodes[1].sendtoaddress(withdraw_address, value)
                    withdraws += 1
                    # Get fee info
                    gettx = self.nodes[1].gettransaction(txid)
                    try:
                        self.nodes[0].sendrawtransaction(gettx['hex'])
                    except JSONRPCException as e:
                        self.log.error(pprint.pformat(gettx))
                        raise e
                    blocks = self.nodes[0].generate(1)
                    self.nodes[1].waitforblock(blocks[-1])
                    total_fees += gettx['fee']
                    # Info about tx itself
                    decoded_tx = self.nodes[1].decoderawtransaction(gettx['hex'])
                    # Spend utxo counts and input info
                    count_sent += len(decoded_tx['vin'])
                    input_sizes.append(len(decoded_tx['vin']))
                    # Change info
                    if len(decoded_tx['vout']) > 1:
                        for out in decoded_tx['vout']:
                            if out['scriptPubKey']['addresses'][0] != withdraw_address:
                                change_vals.append(out['value'])
                                count_change += 1
                    payments += 1
                    csinfo = self.nodes[1].coinselectioninfo()
                    self.log.debug("{}: Withdrew {:.8f} with fee {:.8f}, bnb {}, orig {}, balance + fees now {:.8f}".format(ops, value, gettx['fee'], csinfo['BnB_Usage'], csinfo['Orig_Usage'],self.nodes[1].getbalance() - total_fees))
                    if prev_bal - Decimal(value) != self.nodes[1].getbalance() - total_fees:
                        self.log.error("Balance discrepancy of {:.8f}, Should be {:.8f}, got {:.8f}".format((self.nodes[1].getbalance() - total_fees) - (prev_bal - Decimal(value)), (prev_bal - Decimal(value)), (self.nodes[1].getbalance() - total_fees)))
                        self.log.error(pprint.pformat(gettx))
                        self.log.error(pprint.pformat(decoded_tx))
                        for input in decoded_tx['vin']:
                            self.log.error(pprint.pformat(self.nodes[1].decoderawtransaction(self.nodes[1].gettransaction(input['txid'])['hex'])))
                        return
                utxo_set_sizes.append(len(self.nodes[1].listunspent(0)))
                ops += 1

        self.nodes[0].generate(6)
        self.sync_all()

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
        remaining_utxos = self.nodes[1].listunspent()
        cost_to_empty = Decimal(-1 * len(remaining_utxos) * 148 * 0.00001 / 1000)
        total_cost = total_fees + cost_to_empty

        # input stats
        input_sizes = sorted(input_sizes)
        min_input_size = Decimal(input_sizes[0])
        max_input_size = Decimal(input_sizes[-1])
        mean_input_size = Decimal(mean(input_sizes))
        stdev_input_size = Decimal(stdev(input_sizes))
        
        csinfo = self.nodes[1].coinselectioninfo()

        # Print stuff
        self.log.info("| Simulation File | final value | mean #UTXO | final #UTXO | #received | #spent | #payments sent |"
            + "#changes created | min change | max change | mean change | stDev of change | "
            + "total fees | average fees | fees to spend remaining UTXO | total cost | "
            + "min input set | max input set | mean size of input set | stdev of input set size | BnB Usage | Orig Usage |")
        self.log.info("| {} | {:.8f} | {:.2f} | {} | {} | {} | {} | {:.8f} | {:.8f} | {:.8f} | {:.8f} | {:.8f} | {:.8f} | {:.8f} | {:.8f} | {:.8f} | {} | {} | {:.8f} | {:.8f} | {} | {} |".format( \
            scenario, self.nodes[1].getbalance(), Decimal(mean(utxo_set_sizes)), len(remaining_utxos), count_received, count_sent, \
            payments, len(change_vals), min_change, max_change, mean_change, stdev_change, total_fees, Decimal(total_fees / withdraws), \
            cost_to_empty, total_cost, min_input_size, max_input_size, mean_input_size, stdev_input_size, csinfo['BnB_Usage'], csinfo['Orig_Usage']))

if __name__ == '__main__':
    CoinSelectionSimulation().main()
