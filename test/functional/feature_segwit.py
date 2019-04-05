#!/usr/bin/env python3
# Copyright (c) 2016-2019 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test the SegWit changeover logic."""

from decimal import Decimal

from test_framework.address import (
    script_to_p2sh_p2wsh,
    script_to_p2wsh,
)
from test_framework.blocktools import witness_script, send_to_witness
from test_framework.descriptors import descsum_create
from test_framework.messages import COIN, COutPoint, CTransaction, CTxIn, CTxOut, FromHex, ToHex
from test_framework.script import CScript, OP_1, OP_CHECKMULTISIG, OP_TRUE, OP_DROP
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error, connect_nodes, hex_str_to_bytes, sync_blocks

NODE_0 = 0
NODE_2 = 2
WIT_V0 = 0
WIT_V1 = 1

def getutxo(txid):
    utxo = {}
    utxo["vout"] = 0
    utxo["txid"] = txid
    return utxo

def find_spendable_utxo(node, min_value):
    for utxo in node.listunspent(query_options={'minimumAmount': min_value}):
        if utxo['spendable']:
            return utxo

    raise AssertionError("Unspent output equal or higher than %s not found" % min_value)

class SegWitTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 3
        # This test tests SegWit both pre and post-activation, so use the normal BIP9 activation.
        self.extra_args = [
            [
                "-rpcserialversion=0",
                "-vbparams=segwit:0:999999999999",
                "-addresstype=legacy",
            ],
            [
                "-blockversion=4",
                "-rpcserialversion=1",
                "-vbparams=segwit:0:999999999999",
                "-addresstype=legacy",
            ],
            [
                "-blockversion=536870915",
                "-vbparams=segwit:0:999999999999",
                "-addresstype=legacy",
            ],
        ]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def setup_network(self):
        super().setup_network()
        connect_nodes(self.nodes[0], 2)
        self.sync_all()

    def success_mine(self, node, txid, sign, redeem_script=""):
        send_to_witness(1, node, getutxo(txid), self.pubkey[0], False, Decimal("49.998"), sign, redeem_script)
        block = node.generate(1)
        assert_equal(len(node.getblock(block[0])["tx"]), 2)
        sync_blocks(self.nodes)

    def skip_mine(self, node, txid, sign, redeem_script=""):
        send_to_witness(1, node, getutxo(txid), self.pubkey[0], False, Decimal("49.998"), sign, redeem_script)
        block = node.generate(1)
        assert_equal(len(node.getblock(block[0])["tx"]), 1)
        sync_blocks(self.nodes)

    def fail_accept(self, node, error_msg, txid, sign, redeem_script=""):
        assert_raises_rpc_error(-26, error_msg, send_to_witness, use_p2wsh=1, node=node, utxo=getutxo(txid), pubkey=self.pubkey[0], encode_p2sh=False, amount=Decimal("49.998"), sign=sign, insert_redeem_script=redeem_script)

    def run_test(self):
        self.nodes[0].generate(161)  # block 161

        self.log.info("Verify sigops are counted in GBT with pre-BIP141 rules before the fork")
        txid = self.nodes[0].sendtoaddress(self.nodes[0].getnewaddress(), 1)
        tmpl = self.nodes[0].getblocktemplate({'rules': ['segwit']})
        assert tmpl['sizelimit'] == 1000000
        assert 'weightlimit' not in tmpl
        assert tmpl['sigoplimit'] == 20000
        assert tmpl['transactions'][0]['hash'] == txid
        assert tmpl['transactions'][0]['sigops'] == 2
        tmpl = self.nodes[0].getblocktemplate({'rules': ['segwit']})
        assert tmpl['sizelimit'] == 1000000
        assert 'weightlimit' not in tmpl
        assert tmpl['sigoplimit'] == 20000
        assert tmpl['transactions'][0]['hash'] == txid
        assert tmpl['transactions'][0]['sigops'] == 2
        self.nodes[0].generate(1)  # block 162

        balance_presetup = self.nodes[0].getbalance()
        self.pubkey = []
        p2sh_ids = []  # p2sh_ids[NODE][VER] is an array of txids that spend to a witness version VER pkscript to an address for NODE embedded in p2sh
        wit_ids = []  # wit_ids[NODE][VER] is an array of txids that spend to a witness version VER pkscript to an address for NODE via bare witness
        for i in range(3):
            newaddress = self.nodes[i].getnewaddress('', 'p2sh-segwit')
            self.pubkey.append(self.nodes[i].getaddressinfo(newaddress)["pubkey"])
            multiscript = CScript([OP_1, hex_str_to_bytes(self.pubkey[-1]), OP_1, OP_CHECKMULTISIG])
            p2sh_ms_addr = self.nodes[i].addmultisigaddress(1, [self.pubkey[-1]], '', 'p2sh-segwit')['address']
            bip173_ms_addr = self.nodes[i].addmultisigaddress(1, [self.pubkey[-1]], '', 'bech32')['address']
            assert(self.nodes[i].importdescriptors([{'desc': descsum_create('wpkh(' + self.pubkey[-1] + ')'), 'timestamp': 'now'}])[0]['success'])
            assert_equal(p2sh_ms_addr, script_to_p2sh_p2wsh(multiscript))
            assert_equal(bip173_ms_addr, script_to_p2wsh(multiscript))
            p2sh_ids.append([])
            wit_ids.append([])
            for v in range(2):
                p2sh_ids[i].append([])
                wit_ids[i].append([])

        for i in range(5):
            for n in range(3):
                for v in range(2):
                    wit_ids[n][v].append(send_to_witness(v, self.nodes[0], find_spendable_utxo(self.nodes[0], 50), self.pubkey[n], False, Decimal("49.999")))
                    p2sh_ids[n][v].append(send_to_witness(v, self.nodes[0], find_spendable_utxo(self.nodes[0], 50), self.pubkey[n], True, Decimal("49.999")))

        self.nodes[0].generate(1)  # block 163
        sync_blocks(self.nodes)

        # Make sure all nodes recognize the transactions as theirs
        assert_equal(self.nodes[0].getbalance(), balance_presetup - 60 * 50 + 20 * Decimal("49.999") + 50)
        assert_equal(self.nodes[1].getbalance(), 20 * Decimal("49.999"))
        assert_equal(self.nodes[2].getbalance(), 20 * Decimal("49.999"))

        self.nodes[0].generate(260)  # block 423
        sync_blocks(self.nodes)

        self.log.info("Verify witness txs are skipped for mining before the fork")
        self.skip_mine(self.nodes[2], wit_ids[NODE_2][WIT_V0][0], True)  # block 424
        self.skip_mine(self.nodes[2], wit_ids[NODE_2][WIT_V1][0], True)  # block 425
        self.skip_mine(self.nodes[2], p2sh_ids[NODE_2][WIT_V0][0], True)  # block 426
        self.skip_mine(self.nodes[2], p2sh_ids[NODE_2][WIT_V1][0], True)  # block 427

        self.log.info("Verify unsigned p2sh witness txs without a redeem script are invalid")
        self.fail_accept(self.nodes[2], "mandatory-script-verify-flag", p2sh_ids[NODE_2][WIT_V0][1], False)
        self.fail_accept(self.nodes[2], "mandatory-script-verify-flag", p2sh_ids[NODE_2][WIT_V1][1], False)

        self.nodes[2].generate(4)  # blocks 428-431

        self.log.info("Verify previous witness txs skipped for mining can now be mined")
        assert_equal(len(self.nodes[2].getrawmempool()), 4)
        blockhash = self.nodes[2].generate(1)[0]  # block 432 (first block with new rules; 432 = 144 * 3)
        sync_blocks(self.nodes)
        assert_equal(len(self.nodes[2].getrawmempool()), 0)
        segwit_tx_list = self.nodes[2].getblock(blockhash)["tx"]
        assert_equal(len(segwit_tx_list), 5)

        self.log.info("Verify default node can't accept txs with missing witness")
        # unsigned, no scriptsig
        self.fail_accept(self.nodes[0], "mandatory-script-verify-flag", wit_ids[NODE_0][WIT_V0][0], False)
        self.fail_accept(self.nodes[0], "mandatory-script-verify-flag", wit_ids[NODE_0][WIT_V1][0], False)
        self.fail_accept(self.nodes[0], "mandatory-script-verify-flag", p2sh_ids[NODE_0][WIT_V0][0], False)
        self.fail_accept(self.nodes[0], "mandatory-script-verify-flag", p2sh_ids[NODE_0][WIT_V1][0], False)
        # unsigned with redeem script
        self.fail_accept(self.nodes[0], "mandatory-script-verify-flag", p2sh_ids[NODE_0][WIT_V0][0], False, witness_script(False, self.pubkey[0]))
        self.fail_accept(self.nodes[0], "mandatory-script-verify-flag", p2sh_ids[NODE_0][WIT_V1][0], False, witness_script(True, self.pubkey[0]))

        self.log.info("Verify block and transaction serialization rpcs return differing serializations depending on rpc serialization flag")
        assert self.nodes[2].getblock(blockhash, False) != self.nodes[0].getblock(blockhash, False)
        assert self.nodes[1].getblock(blockhash, False) == self.nodes[2].getblock(blockhash, False)

        for tx_id in segwit_tx_list:
            tx = FromHex(CTransaction(), self.nodes[2].gettransaction(tx_id)["hex"])
            assert self.nodes[2].getrawtransaction(tx_id, False, blockhash) != self.nodes[0].getrawtransaction(tx_id, False, blockhash)
            assert self.nodes[1].getrawtransaction(tx_id, False, blockhash) == self.nodes[2].getrawtransaction(tx_id, False, blockhash)
            assert self.nodes[0].getrawtransaction(tx_id, False, blockhash) != self.nodes[2].gettransaction(tx_id)["hex"]
            assert self.nodes[1].getrawtransaction(tx_id, False, blockhash) == self.nodes[2].gettransaction(tx_id)["hex"]
            assert self.nodes[0].getrawtransaction(tx_id, False, blockhash) == tx.serialize_without_witness().hex()

        self.log.info("Verify witness txs without witness data are invalid after the fork")
        self.fail_accept(self.nodes[2], 'non-mandatory-script-verify-flag (Witness program hash mismatch) (code 64)', wit_ids[NODE_2][WIT_V0][2], sign=False)
        self.fail_accept(self.nodes[2], 'non-mandatory-script-verify-flag (Witness program was passed an empty witness) (code 64)', wit_ids[NODE_2][WIT_V1][2], sign=False)
        self.fail_accept(self.nodes[2], 'non-mandatory-script-verify-flag (Witness program hash mismatch) (code 64)', p2sh_ids[NODE_2][WIT_V0][2], sign=False, redeem_script=witness_script(False, self.pubkey[2]))
        self.fail_accept(self.nodes[2], 'non-mandatory-script-verify-flag (Witness program was passed an empty witness) (code 64)', p2sh_ids[NODE_2][WIT_V1][2], sign=False, redeem_script=witness_script(True, self.pubkey[2]))

        self.log.info("Verify default node can now use witness txs")
        self.success_mine(self.nodes[0], wit_ids[NODE_0][WIT_V0][0], True)  # block 432
        self.success_mine(self.nodes[0], wit_ids[NODE_0][WIT_V1][0], True)  # block 433
        self.success_mine(self.nodes[0], p2sh_ids[NODE_0][WIT_V0][0], True)  # block 434
        self.success_mine(self.nodes[0], p2sh_ids[NODE_0][WIT_V1][0], True)  # block 435

        self.log.info("Verify sigops are counted in GBT with BIP141 rules after the fork")
        txid = self.nodes[0].sendtoaddress(self.nodes[0].getnewaddress(), 1)
        tmpl = self.nodes[0].getblocktemplate({'rules': ['segwit']})
        assert tmpl['sizelimit'] >= 3999577  # actual maximum size is lower due to minimum mandatory non-witness data
        assert tmpl['weightlimit'] == 4000000
        assert tmpl['sigoplimit'] == 80000
        assert tmpl['transactions'][0]['txid'] == txid
        assert tmpl['transactions'][0]['sigops'] == 8

        self.nodes[0].generate(1)  # Mine a block to clear the gbt cache

        self.log.info("Non-segwit miners are able to use GBT response after activation.")
        # Create a 3-tx chain: tx1 (non-segwit input, paying to a segwit output) ->
        #                      tx2 (segwit input, paying to a non-segwit output) ->
        #                      tx3 (non-segwit input, paying to a non-segwit output).
        # tx1 is allowed to appear in the block, but no others.
        txid1 = send_to_witness(1, self.nodes[0], find_spendable_utxo(self.nodes[0], 50), self.pubkey[0], False, Decimal("49.996"))
        hex_tx = self.nodes[0].gettransaction(txid)['hex']
        tx = FromHex(CTransaction(), hex_tx)
        assert tx.wit.is_null()  # This should not be a segwit input
        assert txid1 in self.nodes[0].getrawmempool()

        # Now create tx2, which will spend from txid1.
        tx = CTransaction()
        tx.vin.append(CTxIn(COutPoint(int(txid1, 16), 0), b''))
        tx.vout.append(CTxOut(int(49.99 * COIN), CScript([OP_TRUE, OP_DROP] * 15 + [OP_TRUE])))
        tx2_hex = self.nodes[0].signrawtransactionwithwallet(ToHex(tx))['hex']
        txid2 = self.nodes[0].sendrawtransaction(tx2_hex)
        tx = FromHex(CTransaction(), tx2_hex)
        assert not tx.wit.is_null()

        # Now create tx3, which will spend from txid2
        tx = CTransaction()
        tx.vin.append(CTxIn(COutPoint(int(txid2, 16), 0), b""))
        tx.vout.append(CTxOut(int(49.95 * COIN), CScript([OP_TRUE, OP_DROP] * 15 + [OP_TRUE])))  # Huge fee
        tx.calc_sha256()
        txid3 = self.nodes[0].sendrawtransaction(ToHex(tx))
        assert tx.wit.is_null()
        assert txid3 in self.nodes[0].getrawmempool()

        # Check that getblocktemplate includes all transactions.
        template = self.nodes[0].getblocktemplate({"rules": ["segwit"]})
        template_txids = [t['txid'] for t in template['transactions']]
        assert txid1 in template_txids
        assert txid2 in template_txids
        assert txid3 in template_txids

        # Check that wtxid is properly reported in mempool entry
        assert_equal(int(self.nodes[0].getmempoolentry(txid3)["wtxid"], 16), tx.calc_sha256(True))

        # Mine a block to clear the gbt cache again.
        self.nodes[0].generate(1)

if __name__ == '__main__':
    SegWitTest().main()
