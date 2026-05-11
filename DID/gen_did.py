import ecdsa
import hashlib
import json
import os
# Make sure blockchain.py is in the same directory
from blockchain import Blockchain

def generate_key_pair():
    # Generate elliptic curve key pair (SECp256k1 - Bitcoin/Ethereum standard)
    sk = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)
    vk = sk.get_verifying_key()
    return sk.to_string().hex(), vk.to_string().hex()

def generate_did_and_store():
    # Reset blockchain to start fresh
    if os.path.exists("ledger.json"):
        os.remove("ledger.json")
    
    my_blockchain = Blockchain("ledger.json")
    keystore = {}

    print("--- 🏭 USINE À IDENTITÉS : Démarrage de la production ---")
    print(f"🎯 Cible : 22 Switchs IoT")

    # Generate identities for all 22 switches
    for i in range(1, 23):
        switch_name = f"switch_{i}"  # e.g. switch_1, switch_22

        # 1. Cryptography
        priv, pub = generate_key_pair()

        # 2. Create DID (Decentralized Identifier)
        # Hash the public key to get a short unique identifier
        pub_hash = hashlib.sha256(bytes.fromhex(pub)).hexdigest()[:8]
        did = f"did:sdn:{switch_name}:{pub_hash}"

        # 3. Secure storage (what the switch keeps secret)
        keystore[switch_name] = {
            "name": switch_name,
            "did": did,
            "private_key": priv,
            "public_key": pub  # Kept here for reference, but is public
        }

        # 4. Publish to ledger (public information)
        my_blockchain.add_identity(did, pub)
        print(f"✅ [Switch {i:02d}] Identité forgeé et minée : {did}")

    # Save the keystore (wallet)
    if not os.path.exists('keystore'):
        os.makedirs('keystore')
    
    with open('keystore/secrets.json', 'w') as f:
        json.dump(keystore, f, indent=4)
    
    print("\n" + "="*50)
    print("📚 REGISTRE DISTRIBUÉ (LEDGER) MIS À JOUR")
    print("🔐 22 Identités prêtes à être déployées.")
    print("="*50)

if __name__ == '__main__':
    generate_did_and_store()
