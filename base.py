"""
Module docstring.
"""

import sys
import getopt
import hashlib
import base58
import pickle

import json
from fastecdsa import ecdsa
from fastecdsa.point import Point

from block import Block
from common import int_to_bytes, bytes_to_int, conn_redis, clear_bucket
from constants import TARGET_BIT, BLOCKS_BUCKET_NAME, SUBSIDY, UTXOSET_BUCKET_NAME
from logger import logging
from wallet import Wallets, hash_pubkey


class Transaction(object):

    def __init__(self, txn_id: str, inputs: list, outputs: list):
        self.txn_id = txn_id
        self.inputs = inputs
        self.outputs = outputs

    def set_id(self):
        self.txn_id = None
        self.txn_id = hashlib.sha256(pickle.dumps(self)).hexdigest()

    def to_json(self):
        return {
            'txn_id': self.txn_id,
            'inputs': self.inputs,
            'outputs': self.outputs
        }

    def serialize(self):
        r = self.to_json()
        r['inputs'] = [i.to_json() for i in r.pop('inputs')]
        r['outputs'] = [i.to_json() for i in r.pop('outputs')]
        return json.dumps(r)

    def is_coinbase(self):
        return len(self.inputs) == 1 and self.inputs[0].ref_txn_id == '' and self.inputs[0].ref_output_index == -1

    def trim_txn(self):
        trimmed_inputs = [TransactionInput(i.ref_txn_id, i.ref_output_index, None, None) for i in self.inputs]
        trimmed_outputs = [TransactionOutput(i.val, i.pub_key_hash) for i in self.outputs]  # todo reference so new output
        return Transaction(self.txn_id, trimmed_inputs, trimmed_outputs)

    def sign(self, private_key, pre_txns: list):
        if self.is_coinbase():
            return
        trimmed_txn = self.trim_txn()
        for txn_input in trimmed_txn.inputs:
            pre_txn = pre_txns[txn_input.ref_txn_id]
            txn_input.public_key = pre_txn.outputs[txn_input.ref_output_index].pub_key_hash
            trimmed_txn.set_id()
            txn_input.public_key = None
            r, s = ecdsa.sign(trimmed_txn.txn_id, private_key)
            signature = b''.join([int_to_bytes(r), int_to_bytes(s)])
            self.inputs[trimmed_txn.inputs.index(txn_input)].sig_key = signature

    def verify(self, pre_txns: list) -> bool:

        trimmed_txn = self.trim_txn()
        for i in range(len(self.inputs)):
            txn_input = self.inputs[i]

            pre_txn = pre_txns[txn_input.ref_txn_id]
            trimmed_txn.inputs[i].public_key = pre_txn.outputs[txn_input.ref_output_index].pub_key_hash
            trimmed_txn.set_id()
            trimmed_txn.inputs[i].public_key = None

            sig_length = len(txn_input.sig_key)
            r, s = bytes_to_int(txn_input.sig_key[:int(sig_length/2)]), bytes_to_int(txn_input.sig_key[int(sig_length/2):])

            key_length = len(txn_input.public_key)
            x, y = bytes_to_int(txn_input.public_key[:int(key_length/2)]), bytes_to_int(txn_input.public_key[int(key_length/2):])
            if not ecdsa.verify((r, s), trimmed_txn.txn_id, Point(x, y)):
                return False
        return True


class TransactionOutput(object):

    def __init__(self, val, pub_key_hash=None):
        self.val = val
        self.pub_key_hash = pub_key_hash

    def lock(self, address):
        # convert address to public key hash
        r = base58.b58decode(address)
        self.pub_key_hash = r[1: len(r)-4]  # version 1 byte, checksum 4 byte

    def to_json(self):
        return {
            'Value': self.val,
            'ScriptPubKey': self.pub_key_hash
        }

    def serialize(self):
        return json.dumps(self.to_json())

    def can_be_unlocked(self, payer_pub_key_hash: str):
        return self.pub_key_hash == payer_pub_key_hash.encode('utf-8')  # todo


class TransactionInput(object):

    def __init__(self, txn_id, output_index, sig_key, public_key):
        self.ref_txn_id = txn_id
        self.ref_output_index = output_index
        self.sig_key = sig_key
        self.public_key = public_key

    def to_json(self):
        return {
            'ref_txn_id': self.ref_txn_id,
            'ref_output_index': self.ref_output_index,
            'sig_key': self.sig_key
        }

    def serialize(self):
        return json.dumps(self.to_json())

    def can_unlock_with_key(self, payer_pub_key_hash):
        return hash_pubkey(self.public_key) == payer_pub_key_hash


class BlockChain(object):

    def __init__(self, genesis_creator=None):
        self.target_bits = TARGET_BIT
        self.conn = conn_redis()
        if self.conn.exists(BLOCKS_BUCKET_NAME):
            self.tip = self.conn.hget(BLOCKS_BUCKET_NAME, 'l').decode('utf-8')
            if not self.conn.exists(UTXOSET_BUCKET_NAME):
                self.reindex_utxo_set()
        else:
            if not genesis_creator:
                logging.error('genesis_creator is needed while creating a new block chain')
                sys.exit(1)
            genesis_block = self.mine_genesis_block([self.new_coinbase_transaction(genesis_creator)])
            self.add_block(genesis_block)
            if self.conn.exists(UTXOSET_BUCKET_NAME):
                clear_bucket(self.conn, UTXOSET_BUCKET_NAME)
            self.reindex_utxo_set()

    def mine_genesis_block(self, coinbase_txns: list):
        pre_hash = ''
        return Block(pre_hash, coinbase_txns, self.target_bits)

    def create_block(self, txns: list):
        # pack transactions into block chain
        new_block = self.mine_block(txns)
        self.add_block(new_block)
        self.update_utxo_set(new_block)

    def mine_block(self, txns: list):
        pre_hash = self.tip
        for txn in txns:
            if not self.verify_txn(txn):
                logging.error('Invalid transaction found: {}'.format(txn.txn_id))
                return
        return Block(pre_hash, txns, self.target_bits)

    def add_block(self, block: Block):
        # save new block into db
        self.conn.hset(BLOCKS_BUCKET_NAME, block.hash, block.serialize())
        self.conn.hset(BLOCKS_BUCKET_NAME, 'l', block.hash)
        self.tip = block.hash

    def chain_iterator(self):
        current_hash = self.tip
        while current_hash:
            current_block = pickle.loads(self.conn.hget(BLOCKS_BUCKET_NAME, current_hash))
            yield current_block
            current_hash = current_block.pre_hash

    @staticmethod
    def _deserialize_txns(block_dict):
        txns = []
        for txn in block_dict.pop('transactions'):
            txns.append(
                Transaction(
                    txn['txn_id'],
                    [TransactionInput(i['ref_txn_id'], i['ref_output_index'], i['sig_key']) for i in txn['inputs']],
                    [TransactionOutput(i['Value'], i['ScriptPubKey']) for i in txn['outputs']],
                )
            )
        block_dict['transactions'] = txns

    def new_coinbase_transaction(self, receiver: str, remark='Miner Reword'):
        print('Reward to {}'.format(receiver))
        txn_output = TransactionOutput(SUBSIDY)
        txn_output.lock(receiver)
        txn = Transaction(
            txn_id=None,
            inputs=[TransactionInput(txn_id='', output_index=-1, sig_key=None, public_key=remark)],
            outputs=[txn_output]
        )
        txn.set_id()
        return txn

    def new_utxo_transaction(self, wallets: Wallets, payer: bytes, receiver: bytes, amount: int):
        payer_wallet = wallets.get_wallet(payer)
        payer_pub_key_hash = hash_pubkey(payer_wallet.public_key)
        acc, valid_outputs = self.find_spendable_outputs(payer_pub_key_hash, amount)

        if acc < amount:
            logging.error("Not enough funds")
            return 1
        # Build a list of inputs
        txn_inputs = []
        for txn_id, output_index in valid_outputs:
            txn_input = TransactionInput(txn_id, output_index, None, payer_wallet.public_key)
            txn_inputs.append(txn_input)

        # Build a list of outputs
        txn_output = TransactionOutput(amount)
        txn_output.lock(receiver)
        txn_outputs = [txn_output]
        if acc > amount:  # change
            txn_output = TransactionOutput(acc - amount)
            txn_output.lock(payer)
            txn_outputs.append(txn_output)

        txn = Transaction(None, txn_inputs, txn_outputs)
        txn.set_id()
        self.sign_txn(txn, payer_wallet.private_key)
        return txn

    def find_spendable_outputs(self, payer: str, amount: int):
        # find all unspent outputs of payer
        acc = 0
        unspent_outputs = []
        utxo_set = self.get_utxo_set()
        for txn_id, outputs in utxo_set.items():
            txn = outputs[0]
            for output_index in outputs[1:]:
                output = txn.outputs[output_index]
                if acc < amount and output.can_be_unlocked(payer):
                    acc += output.val
                    unspent_outputs.append((txn.txn_id, output_index))
            if acc >= amount:
                break

        return acc, unspent_outputs

    # deprecated, replaced by utxo
    def find_unspent_transactions(self, payer):
        """
        find all unspent txn containing unspent output of payer
        spendable_outputs = {txn_id1: [txn, output_index1, output_index2.....], }
        spent_outputs = {txn_id1: [output_index1, output_index2.....], }
        """
        spent_outputs = {}
        spendable_outputs = {}
        for block in self.chain_iterator():
            for txn in block.transactions:
                txn_id = txn.txn_id
                if not spendable_outputs.get(txn_id):
                    spendable_outputs.update({txn_id: [txn]})
                if not spent_outputs.get(txn_id):
                    spent_outputs.update({txn_id: []})

                for output_index in range(len(txn.outputs)):
                    if output_index not in spent_outputs[txn_id] and txn.outputs[output_index].can_be_unlocked(payer):
                        spendable_outputs[txn_id].append(output_index)

                if not txn.is_coinbase():
                    for txn_input in txn.inputs:
                        if spendable_outputs.get(txn_input.ref_txn_id) and txn_input.ref_output_index in spendable_outputs[txn_input.ref_txn_id]:
                            spendable_outputs[txn_input.ref_txn_id].remove(txn_input.ref_output_index)
                        if txn_input.can_unlock_with_key(payer):
                            if spent_outputs.get(txn_input.ref_txn_id):
                                spent_outputs[txn_input.ref_txn_id].append(txn_input.ref_output_index)
                            else:
                                spent_outputs.update({txn_input.ref_txn_id: [txn_input.ref_output_index]})
        return spendable_outputs

    def find_unspent_transactions_in_utxo_set(self):
        """
        Almost the same as BlockChain.find_unspent_transactions(), the difference are:
        1. return all unspent txn containing unspent output, not just one payer
        spendable_outputs = {txn_id1: [txn, output_index1, output_index2.....], }
        spent_outputs = {txn_id1: [output_index1, output_index2.....], }
        """
        spent_outputs = {}
        spendable_outputs = {}
        for block in self.chain_iterator():
            for txn in block.transactions:
                txn_id = txn.txn_id
                if not spendable_outputs.get(txn_id):
                    spendable_outputs.update({txn_id: [txn]})
                if not spent_outputs.get(txn_id):
                    spent_outputs.update({txn_id: []})

                for output_index in range(len(txn.outputs)):
                    if output_index not in spent_outputs[txn_id]:
                        spendable_outputs[txn_id].append(output_index)

                if not txn.is_coinbase():  # todo remove
                    for txn_input in txn.inputs:
                        if spendable_outputs.get(txn_input.ref_txn_id) and txn_input.ref_output_index in spendable_outputs[txn_input.ref_txn_id]:
                            spendable_outputs[txn_input.ref_txn_id].remove(txn_input.ref_output_index)
                        if spent_outputs.get(txn_input.ref_txn_id):
                            spent_outputs[txn_input.ref_txn_id].append(txn_input.ref_output_index)
                        else:
                            spent_outputs.update({txn_input.ref_txn_id: [txn_input.ref_output_index]})
        return spendable_outputs

    def reindex_utxo_set(self):
        # init utxo
        utxo_set = self.find_unspent_transactions_in_utxo_set()
        self.conn.hmset(UTXOSET_BUCKET_NAME, self.serialize_utxo_set(utxo_set))

    def update_utxo_set(self, block: Block):
        # update utxo
        for txn in block.transactions:
            # update old output
            for txn_input in txn.inputs:
                updated_outputs = []
                utxo = self.get_utxo(self.conn, txn_input.ref_txn_id)
                for output_index in utxo[1:]:
                    if output_index != txn_input.ref_output_index:
                        updated_outputs.append(output_index)
                if len(updated_outputs) == 0:
                    self.del_utxo(self.conn, txn_input.ref_txn_id)
                else:
                    temp = [utxo[0]]
                    temp.extend(updated_outputs)
                    self.update_utxo(self.conn, txn_input.ref_txn_id, temp)

            # add new output
            self.add_utxo(self.conn, txn)

    def get_utxo_set(self):
        # get all utxo
        r = self.conn.hgetall(UTXOSET_BUCKET_NAME)
        return self.deserialize_utxo_set(r)

    def get_utxo(self, connection, txn_id: bytes):
        # get specified utxo
        r = connection.hget(UTXOSET_BUCKET_NAME, txn_id)  # todo return none
        return pickle.loads(r)

    def add_utxo(self, connection, txn: Transaction):
        # add specified utxo
        data = [txn] + list(range(len(txn.outputs)))
        connection.hset(UTXOSET_BUCKET_NAME, txn.txn_id, pickle.dumps(data))

    def del_utxo(self, connection, txn_id):
        # delete specified utxo
        connection.hdel(UTXOSET_BUCKET_NAME, txn_id)

    def update_utxo(self, connection, k, v: list):
        connection.hset(UTXOSET_BUCKET_NAME, k, pickle.dumps(v))

    @staticmethod
    def serialize_utxo_set(utxo_set):
        r = {}
        for k, v in utxo_set.items():
            r.update({k: pickle.dumps(v)})
        return r

    @staticmethod
    def deserialize_utxo_set(utxo_set):
        r = {}
        for k, v in utxo_set.items():
            r.update({k: pickle.loads(v)})
        return r

    def get_balance(self, address, wallets: Wallets):
        account = wallets.get_wallet(address)
        account_pub_key_hash = hash_pubkey(account.public_key)
        balance = 0
        utxo_set = self.get_utxo_set()
        for _, outputs in utxo_set.items():
            txn = outputs[0]
            for output_index in outputs[1:]:
                output = txn.outputs[output_index]
                if output.can_be_unlocked(account_pub_key_hash):
                    balance += output.val
        return balance

    def sign_txn(self, txn, private_key):
        pre_txns = {}
        for txn_input in txn.inputs:
            pre_txn = self.find_txn(txn_input.ref_txn_id)
            pre_txns.update({pre_txn.txn_id: pre_txn})
        txn.sign(private_key, pre_txns)

    def verify_txn(self, txn) -> bool:
        pre_txns = {}
        for txn_input in txn.inputs:
            pre_txn = self.find_txn(txn_input.ref_txn_id)
            pre_txns.update({pre_txn.txn_id: pre_txn})
        return txn.verify(pre_txns)

    def find_txn(self, txn_id):
        for block in self.chain_iterator():
            for txn in block.transactions:
                if txn.txn_id == txn_id:
                    return txn
        return  # todo return empty txn


class Usage(Exception):
    def __init__(self, msg):
        self.msg = msg


def send(wallets: Wallets, payer: str, receiver: str, amount: int, bc: BlockChain):
    payer, receiver = payer.encode('utf-8'), receiver.encode('utf-8')
    if not wallets.is_valid_address(payer):
        logging.error('Payer address is invalid')
        return
    if not wallets.is_valid_address(receiver):
        logging.error('Receiver address is invalid')
        return
    txn = bc.new_utxo_transaction(wallets, payer, receiver, amount)
    if isinstance(txn, Transaction):
        bc.create_block([txn])
        msg = 'Transfer {}BTC from {} to {} Success'.format(amount, payer, receiver)
        logging.info(msg)
        print(msg)
    else:
        print('ERROR occurred, check the log')


def main(argv=None):
    if argv is None:
        argv = sys.argv
    try:
        try:
            opts, args = getopt.getopt(argv[1:], "hpscf:t:a:b:", ["help", "print", "show_wallets", "create_wallet",
                                                                  "from=", "to=", "amount=", 'balance='])
            # short: h means switch, o means argument required; long: help means switch, output means argument required
            wallets = Wallets()
            for i in wallets.wallets.keys():
                genesis_creator = i
                break
            bc = BlockChain(genesis_creator)
            txn_opts = []
            for opt, opt_val in opts:
                if opt in ("-h", "--help"):
                    print('-p, --print: print block chain\n-a --add_block: add block')
                    sys.exit()
                if opt in ('-p', '--print'):
                    for i in bc.chain_iterator():
                        print('timestamp: {}\npre_hash: {}\nhash: {}\nnonce: {}'.format(i.timestamp,
                                                                                        i.pre_hash,
                                                                                        i.hash,
                                                                                        i.nonce))
                        for txn in i.transactions:
                            print('Transactions id: {}\nInputs:'.format(txn.txn_id))
                            for j in txn.inputs:
                                print(j.to_json())
                            print('Outputs:')
                            for j in txn.outputs:
                                print(j.to_json())
                            print('\n')
                    continue
                if opt in ('-c', '--create_wallet'):
                    wallets = Wallets()
                    address = wallets.create_wallet()
                    wallets.save_wallets_file()
                    print('You new address {}'.format(address))
                    continue
                if opt in ('-s', '--show_wallets'):
                    for i in wallets.wallets.keys():
                        print('address {}'.format(i))
                    continue
                if opt in ('-f', '--from', '-t', '--to', '-a', '--amount'):
                    txn_opts.append((opt, opt_val))
                    continue
                if opt in ('-b', '--balance'):
                    print('Balance of {}: {}'.format(opt_val, bc.get_balance(opt_val.encode('utf-8'), wallets)))
                    continue
            if txn_opts:
                for opt, opt_val in txn_opts:
                    if opt in ('-f', '--from'):
                        payer = opt_val
                    elif opt in ('-t', '--to'):
                        receiver = opt_val
                    else:
                        amount = int(opt_val)
                send(wallets, payer, receiver, amount, bc)

        except getopt.error as msg:
            raise Usage(msg)
        # more code, unchanged
    except Usage as err:
        print(sys.stderr, err.msg)
        print(sys.stderr, "for help use --help")
        return 2


if __name__ == "__main__":
    sys.exit(main())
