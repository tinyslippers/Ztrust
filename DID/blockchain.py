import hashlib
import json
import time
import os

class Block:
    def __init__(self, index, timestamp, data, previous_hash):
        self.index = index
        self.timestamp = timestamp
        self.data = data
        self.previous_hash = previous_hash
        self.hash = self.calculate_hash()

    def calculate_hash(self):
        block_string = json.dumps(self.__dict__, sort_keys=True).encode()
        return hashlib.sha256(block_string).hexdigest()

class Blockchain:
    def __init__(self, filename="ledger.json"):
        self.filename = filename
        self.chain = []
        if os.path.exists(filename):
            self.load_chain()
        else:
            self.create_genesis_block()

    def create_genesis_block(self):
        genesis_block = Block(0, time.time(), "Genesis Block - Debut du registre DePIN", "0")
        self.chain.append(genesis_block)
        self.save_chain()

    def add_identity(self, did, public_key):
        previous_block = self.chain[-1]
        new_data = {"did": did, "public_key": public_key}
        new_block = Block(previous_block.index + 1, time.time(), new_data, previous_block.hash)
        self.chain.append(new_block)
        self.save_chain()

    def get_public_key(self, did_to_find):
        for block in reversed(self.chain):
            if isinstance(block.data, dict) and block.data.get("did") == did_to_find:
                return block.data.get("public_key")
        return None

    def save_chain(self):
        chain_data = [b.__dict__ for b in self.chain]
        with open(self.filename, 'w') as f:
            json.dump(chain_data, f, indent=4)

    def load_chain(self):
        with open(self.filename, 'r') as f:
            chain_data = json.load(f)
            self.chain = []
            for item in chain_data:
                block = Block(item['index'], item['timestamp'], item['data'], item['previous_hash'])
                block.hash = item['hash']
                self.chain.append(block)
