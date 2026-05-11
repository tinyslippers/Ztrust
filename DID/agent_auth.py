import socket
import json
import time
import sys
import os
import binascii
from ecdsa import SigningKey, SECP256k1

# --- CONFIGURATION ---
CONTROLLER_IP    = '10.255.255.255'
AUTH_PORT        = 9999
KEYSTORE_PATH    = os.path.join(os.path.dirname(__file__), 'keystore/secrets.json')
WATCHDOG_INTERVAL = 1500   # Watchdog interval: 25 min (AUTH_LIFETIME - 5 min margin)

def load_secret(switch_name):
    """Loads the switch private key from the JSON keystore."""
    if not os.path.exists(KEYSTORE_PATH):
        print(f"ERREUR: Le fichier {KEYSTORE_PATH} n'existe pas.")
        sys.exit(1)

    with open(KEYSTORE_PATH, 'r') as f:
        data = json.load(f)
    
    if switch_name in data:
        return data[switch_name]
    else:
        print(f"ERREUR: Pas de clé trouvée pour '{switch_name}' dans secrets.json")
        sys.exit(1)

def send_auth(switch_name):
    # 1. Retrieve identity (DID + Private Key)
    identity = load_secret(switch_name)
    did = identity['did']
    priv_key_hex = identity['private_key']

    # 2. Build the message to sign (challenge with timestamp to prevent replay)
    timestamp = str(int(time.time()))
    message_content = f"AuthRequest:{did}:{timestamp}"
    
    print(f"--- Authentification DID pour {switch_name} ---")
    print(f"DID: {did}")
    print(f"Message signé: {message_content}")
    
    # 3. Cryptographic signature
    sk = SigningKey.from_string(binascii.unhexlify(priv_key_hex), curve=SECP256k1)
    # Sign the message bytes
    signature = sk.sign(message_content.encode('utf-8'))
    signature_hex = binascii.hexlify(signature).decode()
    
    # 4. Build the final JSON payload
    payload = {
        "did": did,
        "message": message_content,
        "signature": signature_hex,
        "timestamp": timestamp
    }
    json_payload = json.dumps(payload)
    
    # 5. Send packet via UDP
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)  # Enable broadcast

    print(f"Sending token to controller on port {AUTH_PORT}...")

    # Send 3 times for reliability (UDP is unreliable)
    for i in range(3):
        sock.sendto(json_payload.encode('utf-8'), (CONTROLLER_IP, AUTH_PORT))
        time.sleep(0.1)
        
    print(">>> Token envoyé. Vérifie le terminal du contrôleur Ryu !")

def watchdog(switch_name):
    """Watchdog mode: periodic re-auth independent of the controller."""
    while True:
        send_auth(switch_name)
        time.sleep(WATCHDOG_INTERVAL)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 agent_auth.py <nom_du_switch> [--watchdog]")
        print("Exemple: python3 agent_auth.py switch_1")
        print("         python3 agent_auth.py switch_1 --watchdog")
    else:
        target_switch = sys.argv[1]
        if '--watchdog' in sys.argv:
            watchdog(target_switch)
        else:
            send_auth(target_switch)
