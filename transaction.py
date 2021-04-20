"""
Transaction implementation.
"""

import sys
import getopt
import hashlib
import base58
import pickle
import json

from fastecdsa import ecdsa
from fastecdsa.point import Point

from common import int_to_bytes, bytes_to_int
from wallet import hash_pubkey


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
        trimmed_outputs = [TransactionOutput(i.val, i.pub_key_hash) for i in
                           self.outputs]  # todo reference so new output
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
            r, s = bytes_to_int(txn_input.sig_key[:int(sig_length / 2)]), bytes_to_int(
                txn_input.sig_key[int(sig_length / 2):])

            key_length = len(txn_input.public_key)
            x, y = bytes_to_int(txn_input.public_key[:int(key_length / 2)]), bytes_to_int(
                txn_input.public_key[int(key_length / 2):])
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
        self.pub_key_hash = r[1: len(r) - 4]  # version 1 byte, checksum 4 byte

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


class Usage(Exception):
    def __init__(self, msg):
        self.msg = msg


def main(argv=None):
    if argv is None:
        argv = sys.argv
    try:
        try:
            opts, args = getopt.getopt(argv[1:], "hpcf:t:a:b:",
                                       ["help", "print", "create_wallet", "from=", "to=", "amount=", 'balance='])
            # short: h means switch, o means argument required; long: help means switch, output means argument required
        except getopt.error as msg:
            raise Usage(msg)
        # more code, unchanged
    except Usage as err:
        print(sys.stderr, err.msg)
        print(sys.stderr, "for help use --help")
        return 2


if __name__ == "__main__":
    sys.exit(main())
