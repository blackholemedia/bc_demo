"""
Module docstring.
"""

import sys
import getopt
import hashlib
import logging
from datetime import date
import base58

import json
from fastecdsa import curve, keys

from common import now, int_to_bytes, conn_redis
from constants import TARGET_BIT, BLOCKS_BUCKET_NAME, SUBSIDY, VERSION, ADDRESS_CHECKSUM_LEN

LOG_FORMAT = "%(asctime)s - %(levelname)s - %(message)s"
TODAY = date.today().strftime('%Y-%m-%d')
logging.basicConfig(filename='{}.log'.format(TODAY), level=logging.DEBUG, format=LOG_FORMAT)


class Wallet(object):

    def __init__(self):
        self.private_key, self.public_key = self.new_key_pair()

    def new_key_pair(self):
        private_key = keys.gen_private_key(curve.P256)
        pub_key = keys.get_public_key(private_key, curve.P256)
        pub_key = b''.join([int_to_bytes(pub_key.x), int_to_bytes(pub_key.y)])
        return private_key, pub_key

    def get_address(self):
        pubkey_hash = self.hash_pubkey()
        versioned_payload = b''.join([int_to_bytes(VERSION) + pubkey_hash.encode('utf-8')])
        checksum = self.check_sum(versioned_payload)
        full_payload = b''.join([versioned_payload, checksum])
        address = base58.b58encode(full_payload)
        return address

    def hash_pubkey(self):
        public_hash = hashlib.sha256(self.public_key).hexdigest()
        ripemd_hasher = hashlib.new('ripemd160')
        ripemd_hasher.update(public_hash.encode('utf-8'))
        return ripemd_hasher.hexdigest()

    @staticmethod
    def check_sum(payload: bytes):
        hash_1 = hashlib.sha256(payload).hexdigest()
        hash_2 = hashlib.sha256(hash_1.encode('utf-8')).hexdigest()
        return hash_2.encode('utf-8')[:ADDRESS_CHECKSUM_LEN]


class Transaction(object):

    def __init__(self, txn_id: str, inputs: list, outputs: list):
        self.txn_id = txn_id
        self.inputs = inputs
        self.outputs = outputs

    def set_id(self):
        r = self.to_json()
        r.pop('txn_id')
        r['inputs'] = [i.serialize() for i in r.pop('inputs')]
        r['outputs'] = [i.serialize() for i in r.pop('outputs')]
        self.txn_id = hashlib.sha256(json.dumps(r).encode('utf-8')).hexdigest()

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


class TransactionOutput(object):

    def __init__(self, val, pub_key):
        self.val = val
        self.pub_key = pub_key

    def to_json(self):
        return {
            'Value': self.val,
            'ScriptPubKey': self.pub_key
        }

    def serialize(self):
        return json.dumps(self.to_json())

    def can_be_unlocked(self, payer_pub_key):
        return self.pub_key == payer_pub_key  # todo


class TransactionInput(object):

    def __init__(self, txn_id, output_index, sig_key):
        self.ref_txn_id = txn_id
        self.ref_output_index = output_index
        self.sig_key = sig_key

    def to_json(self):
        return {
            'ref_txn_id': self.ref_txn_id,
            'ref_output_index': self.ref_output_index,
            'sig_key': self.sig_key
        }

    def serialize(self):
        return json.dumps(self.to_json())

    def can_unlock_with_sig(self, payer_sig_key):
        return self.sig_key == payer_sig_key


class Block(object):

    def __init__(self, pre_hash: str, txns: list, target_bit: int):
        self.timestamp = now()
        self.pre_hash = pre_hash
        self.transactions = txns
        self.target_bit = target_bit
        self.nonce, self.hash = self.proof_of_work()

    # def set_hash(self):
    #     hash_data = str(self.timestamp) + str(self.pre_hash) + self.data
    #     result = hashlib.sha256(hash_data.encode('utf-8'))
    #     return result.hexdigest()

    def proof_of_work(self, nonce=0):
        target = 1 << (256 - self.target_bit)
        print("Mining the block containing {}".format(self.transactions[0].txn_id))
        while nonce < (1 << 64):
            hash_data = self._prepare_data(nonce)
            result = hashlib.sha256(hash_data).hexdigest()
            if int(result, 16) < target:
                print(result)
                break
            else:
                nonce += 1
        return nonce, result

    def _prepare_data(self, nonce):
        return b"".join(
            [
                int_to_bytes(self.timestamp),
                int_to_bytes(self.target_bit),
                int_to_bytes(nonce),
                bytes.fromhex(self.pre_hash),
                self._hash_transactions()
                # self.data.encode('utf-8')
            ]
        )

    def _hash_transactions(self):
        txn_ids = [i.txn_id.encode('utf-8') for i in self.transactions]
        return hashlib.sha256(b''.join(txn_ids)).hexdigest().encode('utf-8')

    def serialize(self):
        txns = []
        for txn in self.transactions:
            txn = txn.to_json()
            txn['inputs'] = [i.to_json() for i in txn.pop('inputs')]
            txn['outputs'] = [i.to_json() for i in txn.pop('outputs')]
            txns.append(txn)
        return json.dumps(
            {
                'timestamp': self.timestamp,
                'pre_hash': self.pre_hash,
                'hash': self.hash,
                'nonce': self.nonce,
                'transactions': txns,
                'target_bit': self.target_bit
            }
        )


class BlockChain(object):

    def __init__(self, genesis_creator=None):
        self.target_bits = TARGET_BIT
        self.conn = conn_redis()
        if self.conn.exists(BLOCKS_BUCKET_NAME):
            self.tip = self.conn.hget(BLOCKS_BUCKET_NAME, 'l').decode('utf-8')
        else:
            if not genesis_creator:
                logging.error('genesis_creator is needed while creating a new block chain')
                sys.exit(1)
            genesis_block = self.create_genesis_block(genesis_creator)
            self.conn.hset(BLOCKS_BUCKET_NAME, genesis_block.hash, genesis_block.serialize())
            self.conn.hset(BLOCKS_BUCKET_NAME, 'l', genesis_block.hash)
            self.tip = genesis_block.hash

    def create_genesis_block(self, genesis_creator):
        pre_hash = ''
        txns = [self.new_coinbase_transaction(genesis_creator)]
        return Block(pre_hash, txns, self.target_bits)

    def add_block(self, txns: list):
        pre_hash = self.tip
        new_block = Block(pre_hash, txns, self.target_bits)
        self.conn.hset(BLOCKS_BUCKET_NAME, new_block.hash, new_block.serialize())
        self.conn.hset(BLOCKS_BUCKET_NAME, 'l', new_block.hash)
        self.tip = new_block.hash

    def chain_iterator(self):
        current_hash = self.tip
        while current_hash:
            current_block = json.loads(self.conn.hget(BLOCKS_BUCKET_NAME, current_hash))
            self._deserialize_txns(current_block)
            yield current_block
            current_hash = current_block.get('pre_hash')

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

    def mine_block(self, txns: list):  # duplicated of add_block
        pre_hash = self.tip
        return Block(pre_hash, txns, self.target_bits)

    def new_coinbase_transaction(self, receiver: str, remark='Miner Reword'):
        print('Reward to {}'.format(receiver))
        txn = Transaction(
            txn_id=None,
            inputs=[TransactionInput(txn_id='', output_index=-1, sig_key=remark)],
            outputs=[TransactionOutput(SUBSIDY, receiver)]
        )
        txn.set_id()
        return txn

    def new_utxo_transaction(self, payer: str, receiver: str, amount: int):
        acc, valid_outputs = self.find_spendable_outputs(payer, amount)

        if acc < amount:
            logging.error("Not enough funds")
            return 1
        # Build a list of inputs
        txn_inputs = []
        for txn_id, output_index in valid_outputs:
            txn_input = TransactionInput(txn_id, output_index, payer)
            txn_inputs.append(txn_input)

        # Build a list of outputs
        txn_outputs = [TransactionOutput(amount, receiver)]
        if acc > amount:  # change
            txn_outputs.append(TransactionOutput(acc - amount, payer))

        txn = Transaction(None, txn_inputs, txn_outputs)
        txn.set_id()
        return txn

    def find_spendable_outputs(self, payer: str, amount: int):
        acc = 0
        unspent_outputs = []
        for txn_id, outputs in self.find_unspent_transactions(payer).items():
            txn = outputs[0]
            for output_index in outputs[1:]:
                output = txn.outputs[output_index]
                if acc < amount and output.can_be_unlocked(payer):
                    acc += output.val
                    unspent_outputs.append((txn.txn_id, output_index))
            if acc >= amount:
                break

        return acc, unspent_outputs

    def find_unspent_transactions(self, payer):
        # spendable_outputs = {txn_id1: [txn, output_index1, output_index2.....], }
        # spent_outputs = {txn_id1: [output_index1, output_index2.....], }
        spent_outputs = {}
        spendable_outputs = {}
        for block in self.chain_iterator():
            for txn in block['transactions']:
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
                        if txn_input.can_unlock_with_sig(payer):
                            if spent_outputs.get(txn_input.ref_txn_id):
                                spent_outputs[txn_input.ref_txn_id].append(txn_input.ref_output_index)
                            else:
                                spent_outputs.update({txn_input.ref_txn_id:[txn_input.ref_output_index]})
        return spendable_outputs

    def get_balance(self, address):
        balance = 0
        for _, outputs in self.find_unspent_transactions(address).items():
            txn = outputs[0]
            for output_index in outputs[1:]:
                output = txn.outputs[output_index]
                if output.can_be_unlocked(address):
                    balance += output.val
        return balance


class Usage(Exception):
    def __init__(self, msg):
        self.msg = msg


def send(payer: str, receiver: str, amount: int, bc: BlockChain):
    txn = bc.new_utxo_transaction(payer, receiver, amount)
    if isinstance(txn, Transaction):
        bc.add_block([txn])
        print('Transfer {}BTC from {} to {} Success'.format(amount, payer, receiver))
    else:
        print('ERROR occurred, check the log')


def main(argv=None):
    if argv is None:
        argv = sys.argv
    try:
        try:
            opts, args = getopt.getopt(argv[1:], "hpcf:t:a:b:", ["help", "print", "create_wallet", "from=", "to=", "amount=", 'balance='])
            # short: h means switch, o means argument required; long: help means switch, output means argument required
            key_map = {
                'Ivan': hashlib.sha256('Ivan'.encode('utf-8')).hexdigest(),
                'Sophia': hashlib.sha256('Sophia'.encode('utf-8')).hexdigest(),
                'Yuri': hashlib.sha256('Yuri'.encode('utf-8')).hexdigest()
            }
            for k, v in key_map.items():
                print('{}: {}'.format(k, v))
            bc = BlockChain(key_map['Ivan'])
            txn_opts = []
            for opt, opt_val in opts:
                if opt in ("-h", "--help"):
                    print('-p, --print: print block chain\n-a --add_block: add block')
                    sys.exit()
                if opt in ('-p', '--print'):
                    for i in bc.chain_iterator():
                        print('timestamp: {}\npre_hash: {}\nhash: {}\nnonce: {}'.format(i['timestamp'],
                                                                                          i['pre_hash'],
                                                                                          i['hash'],
                                                                                          i['nonce'],))
                        for txn in i['transactions']:
                            print('Transactions id: {}\nInputs:'.format(txn.txn_id))
                            for j in txn.inputs:
                                print(j.to_json())
                            print('Outputs:')
                            for j in txn.outputs:
                                print(j.to_json())
                            print('\n')
                    continue
                if opt in ('-c', '--create_wallet'):
                    wallet = Wallet()
                    print(wallet.get_address())
                    continue
                if opt in ('-f', '--from', '-t', '--to', '-a', '--amount'):
                    txn_opts.append((opt, opt_val))
                    continue
                if opt in ('-b', '--balance'):
                    print('Balance of {}: {}'.format(opt_val, bc.get_balance(key_map[opt_val])))
                    continue
            if txn_opts:
                for opt, opt_val in txn_opts:
                    if opt in ('-f', '--from'):
                        payer = key_map[opt_val]
                    elif opt in ('-t', '--to'):
                        receiver = key_map[opt_val]
                    else:
                        amount = int(opt_val)
                send(payer, receiver, amount, bc)

            # bc.add_block("Send 1 BTC to Ivan")
            # bc.add_block("Send 2 more BTC to Ivan")

                # print('timestamp: {}\npre_hash: {}\ndata: {}\nhash: {}\nnonce: {}'.format(i.timestamp, i.pre_hash,
                #                                                                           i.data, i.hash, i.nonce))
        except getopt.error as msg:
            raise Usage(msg)
        # more code, unchanged
    except Usage as err:
        print(sys.stderr, err.msg)
        print(sys.stderr, "for help use --help")
        return 2


if __name__ == "__main__":
    sys.exit(main())
