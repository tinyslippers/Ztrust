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
        fields = {k: v for k, v in self.__dict__.items() if k != 'hash'}
        block_string = json.dumps(fields, sort_keys=True).encode()
        return hashlib.sha256(block_string).hexdigest()

class Blockchain:
    def __init__(self, filename="ledger.json"):
        self.filename = filename
        self.chain = []
        if os.path.exists(filename):
            self.load_chain()
            if not self.is_valid():
                raise ValueError("BLOCKCHAIN COMPROMISED — ledger.json has been tampered with")
        else:
            self.create_genesis_block()

    def is_valid(self):
        for i in range(1, len(self.chain)):
            current  = self.chain[i]
            previous = self.chain[i - 1]

            if current.hash != current.calculate_hash():
                print(f"[BLOCKCHAIN] ⚠️  Block {i} tampered — invalid hash")
                return False

            if current.previous_hash != previous.hash:
                print(f"[BLOCKCHAIN] ⚠️  Chain broken between block {i-1} and {i}")
                return False

        return True

    def create_genesis_block(self):
        genesis_block = Block(0, time.time(), "Genesis Block - DePIN registry root", "0")
        self.chain.append(genesis_block)
        self.save_chain()

    def add_identity(self, did, public_key_hex, flow_policy=None):
        did_document = {
            "@context": "https://www.w3.org/ns/did/v1",
            "id": did,
            "verificationMethod": [{
                "id": f"{did}#keys-1",
                "type": "EcdsaSecp256k1VerificationKey2019",
                "controller": did,
                "publicKeyHex": public_key_hex
            }],
            "authentication": [f"{did}#keys-1"],
            "service": [{
                "id": f"{did}#sdn",
                "type": "SDNEndpoint",
                "serviceEndpoint": "udp://controller:9999"
            }],
            "flow_policy": flow_policy or {
                "allowed_flows": [],
                "default": "deny"
            }
        }
        previous_block = self.chain[-1]
        new_block = Block(
            previous_block.index + 1,
            time.time(),
            did_document,
            previous_block.hash
        )
        self.chain.append(new_block)
        self.save_chain()

    def resolve(self, did) -> dict | None:
        """W3C-compliant DID resolution — returns the latest DID Document."""
        for block in reversed(self.chain):
            data = block.data
            if not isinstance(data, dict):
                continue
            if data.get("id") == did and data.get("revoked"):
                return None
            if data.get("id") == did and not data.get("revoked"):
                return data
        return None

    def revoke_identity(self, did):
        """Adds a revocation block — resolve() returns None after this."""
        previous_block = self.chain[-1]
        new_block = Block(
            previous_block.index + 1,
            time.time(),
            {"id": did, "revoked": True, "revocation_time": time.time()},
            previous_block.hash
        )
        self.chain.append(new_block)
        self.save_chain()

    def get_public_key(self, did) -> str | None:
        doc = self.resolve(did)
        if not doc:
            return None
        for method in doc.get("verificationMethod", []):
            if "keys-1" in method.get("id", ""):
                return method.get("publicKeyHex")
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
