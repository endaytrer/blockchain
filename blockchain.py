#!/usr/bin/env python3
from typing import NamedTuple
from flask import Flask, request, jsonify
from ctypes import *
import json
import random
import argparse
import requests

dylib = CDLL("libblockchain.so")

parser = argparse.ArgumentParser('blockchain.py')

parser.add_argument("-p", "--port", default="6969", help="port of management server")
parser.add_argument("-H", "--host", default="0.0.0.0", help="listen address of server")
parser.add_argument("-g", "--genesis", action="store_true", default=False, help="generate genesis block")

# Mirror of struct Transaction
WALLET_ID_SIZE = 16
POW_LOT_SIZE = 8
DIGEST_SIZE = 32
MAX_TRIALS = (1 << 32)

WalletId = c_uint8 * WALLET_ID_SIZE
Proof = c_uint8 * POW_LOT_SIZE
Digest = c_uint8 * DIGEST_SIZE

class Transaction(Structure):
    _fields_ = [("sender", WalletId), ("recipient", WalletId), ("amount", c_uint64)]

class Block(Structure):
    _fields_ = [("index", c_uint32), ("num_transactions", c_uint32), ("timestamp", c_double), ("proof", Proof), ("previous_hash", Digest)]

class ChainNode(Structure):
    pass
ChainNode._fields_ = [("prev", POINTER(ChainNode)), ("block", Block)]

class BlockChain(Structure):
    _fields_ = [("head", POINTER(ChainNode)), ("last_hash", Digest)]
    pass

class Node(Structure):
    pass

Block_new = dylib.Block_new
Block_new.argtypes = [c_uint32]
Block_new.restype = POINTER(Block)

Block_delete = dylib.Block_delete
Block_delete.argtypes = [POINTER(Block)]
Block_delete.restype = None

BlockChain_new = dylib.BlockChain_new
BlockChain_new.argtypes = []
BlockChain_new.restype = POINTER(BlockChain)

BlockChain_delete = dylib.BlockChain_delete
BlockChain_delete.argtypes = [POINTER(BlockChain)]
BlockChain_delete.restype = None

BlockChain_init = dylib.BlockChain_init
BlockChain_init.argtypes = [POINTER(BlockChain), c_bool]
BlockChain_init.restype = c_int

BlockChain_add_block = dylib.BlockChain_add_block
BlockChain_add_block.argtypes = [POINTER(BlockChain), POINTER(Block)]
BlockChain_add_block.restype = None

BlockChain_verify = dylib.BlockChain_verify
BlockChain_verify.argtypes = [POINTER(BlockChain)]
BlockChain_verify.restype = c_ssize_t

Node_new = dylib.Node_new
Node_new.argtypes = []
Node_new.restype = POINTER(Node)

Node_init = dylib.Node_init
Node_init.argtypes = [POINTER(Node), POINTER(BlockChain), POINTER(c_uint8)]
Node_init.restype = None

Node_mine = dylib.Node_mine
Node_mine.argtypes = [POINTER(Node), c_size_t, POINTER(c_uint8)]
Node_mine.restype = c_int

Node_add_transaction = dylib.Node_add_transaction
Node_add_transaction.argtypes = [POINTER(Node), POINTER(Transaction)]
Node_add_transaction.restype = int

global_block_chain: POINTER(BlockChain)
global_node: POINTER(Node)

app = Flask(__name__)
def to_str(bytes: WalletId) -> str:
    return ''.join([f"{i:02x}" for i in bytes])

def walletid_from_str(repr: str) -> WalletId:
    return WalletId(*bytes(int(repr[i:i+2], 16) for i in range(0, len(repr), 2)))

def proof_from_str(repr: str) -> Proof:
    return Proof(*bytes(int(repr[i:i+2], 16) for i in range(0, len(repr), 2)))
    
def digest_from_str(repr: str) -> Digest:
    return Digest(*bytes(int(repr[i:i+2], 16) for i in range(0, len(repr), 2)))

def create_blockchain_from_json(obj) -> POINTER(BlockChain):
    new_bc = BlockChain_new()
    BlockChain_init(new_bc, False)
    new_bc.contents.last_hash = digest_from_str(obj["last_hash"])
    for i in obj['chain']:
        block = Block_new(len(i['transactions']))
        block.contents.index = i['index']
        block.contents.timestamp = i['timestamp']
        block.contents.previous_hash = digest_from_str(i['previous_hash'])
        block.contents.proof = proof_from_str(i['proof'])

        for j in range(len(i['transactions'])):
            transaction_ptr = cast(addressof(block.contents) + sizeof(Block) + j * sizeof(Transaction), POINTER(Transaction))
            transaction_ptr.contents.sender = walletid_from_str(i['transactions'][j]['sender'])
            transaction_ptr.contents.recipient = walletid_from_str(i['transactions'][j]['recipient'])
            transaction_ptr.contents.amount = i['transactions'][j]['amount']

        BlockChain_add_block(new_bc, block)
        Block_delete(block)
    return new_bc
        


def jsonify_block(b):
    temp = {
        "index": b.contents.index,
        "timestamp": b.contents.timestamp,
        "transactions": [],
        "previous_hash": to_str(b.contents.previous_hash),
        "proof": to_str(b.contents.proof)
    }
    for i in range(b.contents.num_transactions):
        transaction_ptr = cast(addressof(b.contents) + sizeof(Block) + i * sizeof(Transaction), POINTER(Transaction))
        transact = {
            "sender": to_str(transaction_ptr.contents.sender),
            "recipient": to_str(transaction_ptr.contents.recipient),
            "amount": transaction_ptr.contents.amount
        }
        temp["transactions"].append(transact) 
    return temp

def jsonify_chain(b):
    ptr = b.contents.head
    nodes = []
    while ptr:
        nodes.insert(0, jsonify_block(pointer(ptr.contents.block)))
        ptr = ptr.contents.prev

    return {
        "chain": nodes,
        "last_hash": to_str(b.contents.last_hash),
        "length": len(nodes)
    }

@app.route("/")
def hello():
    return "Hello world!"

@app.get("/chain")
def show():
    return jsonify(jsonify_chain(global_block_chain))

@app.get("/mine")
def mine():
    nullptr = POINTER(c_uint8)()
    return jsonify({"success": Node_mine(global_node, MAX_TRIALS, nullptr) == 0})

@app.get("/verify")
def verify():
    return jsonify({"value": BlockChain_verify(global_block_chain)})
    
@app.post("/transactions/new")
def new_transaction():
    values = request.get_json()
    required = ['sender', 'recipient', 'amount']
    if not all(k in values for k in required):
        return 'Missing values', 400
    try:
        sender = walletid_from_str(values['sender'])
        recipient = walletid_from_str(values['recipient'])
    except:
        return json.dumps({"success": False, "error": "Invalid form"}), 400
    if values['amount'] is not int and values['amount'] < 0:
        return json.dumps({"success": False, "error": "Invalid amount"}), 400
        
    
    transact = Transaction(sender, recipient, values['amount'])
    return json.dumps({"success": Node_add_transaction(global_node, pointer(transact)) == 0})

neighbors: set[str] = set()

@app.post("/nodes/register")
def register_node():
    global neighbors
    values = request.get_json()

    nodes = values.get('nodes')
    if nodes is None:
        return "Error: Please supply a valid list of nodes", 400

    for node in nodes:
        neighbors.add(node)

    response = {
        'message': 'New nodes have been added',
        'total_nodes': list(neighbors),
    }
    return jsonify(response), 201
    
@app.get("/nodes/resolve")
def consensus():
    global global_block_chain
    blockchain_list = [global_block_chain]
    hashes = set(to_str(global_block_chain.contents.last_hash))
    for node in neighbors:
        resp = requests.get(node + "/chain")

        if not resp or resp.status_code != 200:
            print(f"[WARNING] Node {node} is down")
        
        jason = resp.json()
        if jason['last_hash'] in hashes:
            break
        new_b = create_blockchain_from_json(jason)
        blockchain_list.append(new_b)
        hashes.add(jason['last_hash'])
    
    longest_id = 0
    longest_len = BlockChain_verify(blockchain_list[0])
    for i in range(1, len(blockchain_list)):
        current_len = BlockChain_verify(blockchain_list[i])
        if current_len > longest_len:
            longest_id = i
            longest_len = current_len
    
    if (longest_id != 0):
        nullptr = POINTER(c_uint8)()
        global_block_chain = blockchain_list[longest_id]
        Node_init(global_node, global_block_chain, nullptr)
        print(f"[INFO] Block chain changed to {to_str(global_block_chain.contents.last_hash)}")
    
    for i, ptr in enumerate(blockchain_list):
        if i != longest_id:
            BlockChain_delete(ptr)
    
    return jsonify({"changed": longest_id != 0})
    
if __name__ == "__main__":
    namespace = parser.parse_args()
    
    global_block_chain = BlockChain_new()
    BlockChain_init(global_block_chain, namespace.genesis)
    global_node = Node_new()
    node_id = WalletId(*random.randbytes(WALLET_ID_SIZE))
    Node_init(global_node, global_block_chain, node_id)
    app.run(host=namespace.host, port=int(namespace.port))